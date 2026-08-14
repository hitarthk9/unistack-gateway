"""
UniStack's security additions to the gateway — MOUNTED, not baked.

Two things live here, and both exist because stock LiteLLM cannot do them:

1. `UniStackSecrets` — the built-in `hide-secrets` guardrail masks credentials but records
   NOTHING, so a redacted leak is invisible to the platform. This subclass reuses its detector
   (and therefore its ~200 detect_secrets plugins) and *records what it redacted*, so the
   dashboard can answer "did anything leak in this activity, even if we caught it?".

2. `SecuritySink` — ships findings to `unistack-api`, which owns MongoDB.

WHY HTTP AND NOT A DIRECT MONGO WRITE: the stock image has no Mongo driver and no pip, so
writing to Mongo directly needs a custom image, which turns "docker run" into "docker build
first". `httpx` is already in the image, so posting to a service that already owns the database
keeps the gateway on the **stock image with two volume mounts**. It also keeps Mongo
credentials out of a container that holds provider API keys.

WHY THE `post_call` HOOKS AND NOT `async_log_success_event` — verified, not assumed: a guardrail
that BLOCKS short-circuits the request and fires NEITHER logging callback, so a sink built on
those records clean calls and misses every block. The `post_call` hooks do fire, and they carry
the request `data`, where guardrails stash findings — in TWO buckets, `metadata` and
`litellm_metadata`, depending on the guardrail.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import httpx
from litellm.integrations.custom_logger import CustomLogger
from litellm.types.guardrails import GuardrailEventHooks
from litellm_enterprise.enterprise_callbacks.secret_detection import (
    _ENTERPRISE_SecretDetection,
)

logger = logging.getLogger("unistack.gateway.security")

SINK_VERSION = "3"
_GUARDRAIL_KEY = "standard_logging_guardrail_information"
_REDACTED = "[REDACTED]"

_API_URL = os.environ.get("UNISTACK_API_URL", "http://host.docker.internal:8001")
_API_TOKEN = os.environ.get("UNISTACK_API_TOKEN", "")
_TIMEOUT = float(os.environ.get("UNISTACK_SINK_TIMEOUT_S", "2"))


# ── Which guardrails run on which traffic ───────────────────────────────────────────────────
#
# Every guardrail in config.yaml is `default_on: false`; `_select_guardrails` below decides per
# request. That indirection is what makes the judge unblockable, and it is the free-tier
# substitute for the per-key scoping LiteLLM gates behind Enterprise.

#: Non-blocking hygiene. Runs on EVERYTHING, including the judge: redacting a credential the
#: judge does not need is harmless, and it still records the finding.
_ALWAYS = ("unistack-secrets",)

#: Rules that can BLOCK. Never applied to the models below.
_BLOCKING = ("unistack-no-code-exec", "unistack-red-lines")

#: The control plane — every model whose prompt is, by design, someone else's output.
#:
#: `judge-fast` (the SDK's guardrail judge) and `evaluator-fast` (Langfuse's forensic quality
#: judges) both read untrusted agent output, so their prompts contain exactly the material a
#: content rule looks for. Two distinct failures follow if blocking rules run on them:
#:
#:   judge-fast     — the judge gets blocked, `evaluate_guardrail` fails CLOSED, and the activity
#:                    pauses with "guardrail judge unavailable", pointing the operator at the
#:                    wrong subsystem. Observed live.
#:   evaluator-fast — the scoring call carrying the flagged output is blocked, so the observation
#:                    is never scored. **The worse the content, the less likely it is to be
#:                    measured** — a forensic control that goes dark precisely when there is
#:                    something to find.
#:
#: A blocking rule must never be able to stop the control plane, and never be able to destroy
#: evidence. Non-blocking hygiene (`_ALWAYS`) still applies to these models.
_EXEMPT_MODELS = frozenset(
    m.strip() for m in os.environ.get("UNISTACK_GUARDRAIL_EXEMPT_MODELS",
                                      "judge-fast,evaluator-fast").split(",")
    if m.strip())


#: Per-AGENT relaxations of the blocking set, as `key_alias:guardrail[,key_alias:guardrail]`.
#: e.g. UNISTACK_GUARDRAIL_OPT_OUT="unistack-coding-agent:unistack-no-code-exec"
#:
#: WHY THIS EXISTS: `unistack-no-code-exec` is the one domain-dependent rule in config.yaml —
#: a CODING agent's ordinary traffic is exactly what it blocks. Before this, the only way to
#: relax it was editing `_BLOCKING` below, which relaxes it for EVERY agent on the gateway.
#:
#: WHY IT IS AN ENV VAR AND NOT A PER-AGENT config.yaml: config.yaml configures one LiteLLM
#: PROCESS, and one gateway serves every agent — per-agent copies would mean a gateway, a
#: Postgres and a port per agent. The unit of per-agent policy here is the VIRTUAL KEY, which
#: already carries that agent's model allow-list and budget.
def _parse_opt_outs(raw: str) -> dict:
    out: dict[str, set] = {}
    for entry in raw.split(","):
        alias, _, guardrail = entry.strip().partition(":")
        if alias.strip() and guardrail.strip():
            out.setdefault(alias.strip(), set()).add(guardrail.strip())
    return out


_OPT_OUTS = _parse_opt_outs(os.environ.get("UNISTACK_GUARDRAIL_OPT_OUT", ""))


def _select_guardrails(model: str, key_alias: str | None = None) -> list[str]:
    """
    The guardrails this request may run.

    Three tiers, in this order — the order is the security property:
      1. An EXEMPT MODEL (the control plane) gets non-blocking hygiene only. Checked FIRST and
         unconditionally, so no per-agent configuration can ever re-arm a blocking rule on the
         judge and take the control plane down.
      2. A key alias with declared opt-outs gets the blocking set MINUS those rules.
      3. Everything else gets the full set — the default, unchanged.

    `key_alias` is the identity of the VIRTUAL KEY that authenticated this request. See the
    caller for why it must not come from request metadata.
    """
    if model in _EXEMPT_MODELS:
        return list(_ALWAYS)
    opted_out = _OPT_OUTS.get(key_alias or "", set())
    return list(_ALWAYS) + [g for g in _BLOCKING if g not in opted_out]


# ── 1. A secrets guardrail that reports what it redacted ────────────────────────────────────

class UniStackSecrets(_ENTERPRISE_SecretDetection):
    """
    `hide-secrets` with an audit trail.

    The base class masks in place and returns nothing, so the platform could never show
    "a credential was caught here". This re-implements the pass so the finding is recorded.

    SECURITY: the record carries the secret's TYPE and a count, **never its value**. An audit
    log that quotes the credential it just redacted has leaked it into a second store.
    """

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        started = datetime.now().timestamp()
        counts: dict[str, int] = {}
        try:
            for message in data.get("messages") or []:
                content = message.get("content")
                if not isinstance(content, str):
                    continue                      # multimodal parts are left alone
                for secret in self.scan_message_for_secrets(content) or []:
                    value, kind = secret.get("value"), str(secret.get("type", "secret"))
                    if not value:
                        continue
                    content = content.replace(value, _REDACTED)
                    counts[kind] = counts.get(kind, 0) + 1
                message["content"] = content
        except Exception as exc:
            # Fail OPEN on a detector error: this guardrail's job is hygiene, and it must not
            # take the gateway down. A detector outage is logged, not fatal.
            logger.warning("[unistack-security] secret scan failed: %s", exc)
            return data

        if counts:
            logger.warning("[unistack-security] redacted %s", counts)
            try:
                self.add_standard_logging_guardrail_information_to_request_data(
                    guardrail_json_response=[
                        {"type": kind, "count": n, "action_taken": "mask"}
                        for kind, n in counts.items()
                    ],
                    request_data=data,
                    guardrail_status="success",
                    start_time=started,
                    end_time=datetime.now().timestamp(),
                    duration=datetime.now().timestamp() - started,
                    masked_entity_count=counts,
                    guardrail_provider="unistack-secrets",
                    event_type=GuardrailEventHooks.pre_call,
                )
            except Exception as exc:
                logger.warning("[unistack-security] could not record redaction: %s", exc)
        return data


# ── 2. Findings → unistack-api ──────────────────────────────────────────────────────────────

def _fired(item: dict) -> bool:
    """
    Did this guardrail actually detect something?

    NOT the same question as `guardrail_status`, which means "the guardrail executed without
    erroring" and reads `"success"` on a clean call AND on a block. The detection lives in
    `guardrail_response` / `match_details`, empty when nothing was found.
    """
    return bool(item.get("guardrail_response")
                or item.get("match_details")
                or item.get("masked_entity_count")
                or item.get("violation_categories")
                or (item.get("guardrail_status") not in (None, "success")))


def _findings(data: dict) -> list[dict]:
    """
    Findings on this request, deduped, clean passes dropped.

    TWO buckets, verified the hard way: `block_code_execution` writes into `metadata`,
    `litellm_content_filter` into `litellm_metadata`. Reading one silently loses every finding
    from the other, which looks exactly like "the guardrail never fired".
    """
    data = data or {}
    seen, out = set(), []
    for bucket in ("metadata", "litellm_metadata"):
        raw = (data.get(bucket) or {}).get(_GUARDRAIL_KEY)
        items = raw if isinstance(raw, list) else ([raw] if isinstance(raw, dict) else [])
        for item in items:
            if not isinstance(item, dict) or not _fired(item):
                continue
            key = (item.get("guardrail_name"), str(item.get("guardrail_mode")),
                   item.get("start_time"))
            if key not in seen:
                seen.add(key)
                out.append(item)
    return out


def _detections(finding: dict) -> list[dict]:
    """Per-detection detail, from whichever field this guardrail populates."""
    return [i for f in ("guardrail_response", "match_details")
            for i in (finding.get(f) or []) if isinstance(i, dict)]


def _action(finding: dict) -> str | None:
    """
    "block" or "mask".

    Guardrails disagree on the key: `block_code_execution` uses `action_taken` inside
    `guardrail_response`, `litellm_content_filter` uses `action` there and `action_taken` in
    `match_details`. Check both, then fall back to the status — `guardrail_intervened` means
    the guardrail stopped the request, which is a block by any other name.
    """
    for detection in _detections(finding):
        for key in ("action_taken", "action"):
            if detection.get(key):
                return str(detection[key]).lower()
    if finding.get("guardrail_action"):
        return str(finding["guardrail_action"]).lower()
    if finding.get("guardrail_status") == "guardrail_intervened":
        return "block"                     # inferred from the status, not reported directly
    return None


def _categories(finding: dict) -> list[str]:
    """Violation categories — reported directly by some guardrails, per-detection by others."""
    direct = finding.get("violation_categories") or []
    if direct:
        return [str(c) for c in direct]
    out = []
    for detection in _detections(finding):
        cat = detection.get("category") or detection.get("type")
        if cat and str(cat) not in out:
            out.append(str(cat))
    return out


def _reason(detector: str, action: str | None, finding: dict) -> str:
    """One human-readable line for the dashboard, naming what actually matched."""
    bits = []
    for detection in _detections(finding):
        # `snippet`/`keyword` are the matched TEXT; for a secret only its type is present,
        # deliberately — see the security note on UniStackSecrets.
        snippet = detection.get("snippet") or detection.get("keyword") or detection.get("language")
        label = detection.get("category") or detection.get("type")
        bit = f"{label}: {snippet!r}" if snippet else str(label)
        if bit and bit not in bits:
            bits.append(bit)
    return f"{detector} {action or 'flagged'} — {'; '.join(bits[:3]) or 'detected'}"


def _jsonable(value):
    """Findings carry enums (e.g. GuardrailEventHooks) that json cannot encode."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _event(data: dict, finding: dict) -> dict:
    """
    One finding → one `security_events` document.

    `activity_id` and `node` are null for agent traffic: only the SDK's guardrail JUDGE sends
    request metadata, so the gateway's honest ceiling is workflow-level attribution via the
    virtual key alias. `litellm_call_id` is kept so an exact join stays possible later.
    """
    meta = (data or {}).get("metadata") or {}
    alias = meta.get("user_api_key_alias")
    detector = finding.get("guardrail_name") or "unknown"
    action = _action(finding)
    call_id = (data or {}).get("litellm_call_id") or "unknown"
    return _jsonable({
        "_id":                 f"gw:{call_id}:{detector}",
        "source":              "gateway",
        "detector":            detector,
        "provider":            finding.get("guardrail_provider"),
        "action":              action,                      # "block" | "mask"
        "outcome":             finding.get("guardrail_status"),
        "reason":              _reason(detector, action, finding),
        "mode":                finding.get("guardrail_mode"),
        "detections":          finding.get("guardrail_response") or [],
        "match_details":       finding.get("match_details"),
        "categories":          _categories(finding),
        "risk_score":          finding.get("risk_score"),
        "masked_entity_count": finding.get("masked_entity_count"),
        "activity_id":         meta.get("activity_id"),     # judge calls only
        "workflow":            meta.get("workflow") or alias,
        "node":                meta.get("node"),
        "litellm_call_id":     (data or {}).get("litellm_call_id"),
        "model":               (data or {}).get("model"),
        "api_key_alias":       alias,
        "sink_version":        SINK_VERSION,
        "detected_at":         datetime.now(timezone.utc).isoformat(),
    })


class SecuritySink(CustomLogger):
    """
    Posts guardrail findings to unistack-api. Never raises into the gateway.

    This is the ONE permitted entry in `litellm_settings.callbacks`. The rule that list
    enforces is "no second writer of LLM spans" — the SDK already writes those to Langfuse,
    and a duplicate would double every generation and its cost in the data the projector reads
    (BUILD_PLAN item 7). This is not a generation logger: on a clean call it writes nothing,
    makes no request, and does no IO.
    """

    def __init__(self):
        super().__init__()
        # Deliberately at warning level: a typo in `callbacks:` makes LiteLLM skip the sink
        # SILENTLY, so this line is the only cheap proof at boot that it actually loaded.
        # The exempt list is logged so "which models can never be blocked" is visible at boot
        # rather than inferred from code.
        logger.warning("[unistack-security] sink v%s loaded (api=%s, token=%s, "
                       "blocking-exempt models=%s, per-agent opt-outs=%s)",
                       SINK_VERSION, _API_URL, "set" if _API_TOKEN else "MISSING",
                       sorted(_EXEMPT_MODELS) or "none",
                       {k: sorted(v) for k, v in sorted(_OPT_OUTS.items())} or "none")

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        """
        Choose this request's guardrails by model, and by which agent's key is calling.

        SECURITY, two parts:

        1. This **overwrites** `data["guardrails"]` unconditionally and never merges with a
           caller-supplied value. LiteLLM checks the request body first, so honouring it would
           let any caller opt out of every guardrail by sending `{"guardrails": []}` — the exact
           hole LiteLLM's own design closes by refusing body-level disabling.
        2. The agent's identity is read from `user_api_key_dict`, which LiteLLM resolved from
           the AUTHENTICATED key — never from `data["metadata"]`, which the caller writes. The
           sink reads `metadata["user_api_key_alias"]` for reporting, and that is fine there;
           using it HERE would let any agent name another agent's alias and inherit its
           opt-outs, which is the same hole as (1) wearing a different hat.
        """
        try:
            data["guardrails"] = _select_guardrails(
                str(data.get("model") or ""),
                getattr(user_api_key_dict, "key_alias", None))
        except Exception as exc:
            # Fail SAFE, not open: on any error apply the full set. The worst case is that a
            # judge call gets blocked (a visible pause), never that agent traffic goes ungated.
            logger.warning("[unistack-security] guardrail selection failed (%s) — applying all",
                           exc)
            data["guardrails"] = list(_ALWAYS) + list(_BLOCKING)
        return data

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        # Fires for clean calls AND for guardrail blocks that synthesise a 200 response.
        await self._handle(data)

    async def async_post_call_failure_hook(self, request_data, original_exception,
                                           user_api_key_dict, traceback_str=None):
        # Fires for guardrails that raise instead of synthesising a response.
        await self._handle(request_data)

    async def _handle(self, data) -> None:
        try:
            findings = _findings(data)
            if not findings:
                return                       # the common case: no work, no IO, no request
            events = [_event(data, f) for f in findings]
            try:
                await asyncio.wait_for(self._post(events), timeout=_TIMEOUT + 1)
            except Exception as exc:
                # Fail open — a security record is an audit trail, not a gate; the guardrail has
                # already acted and a sink problem must never become a gateway error. But do not
                # simply lose it: emit the record to stdout so it stays recoverable from
                # container logs when unistack-api is down.
                logger.warning("[unistack-security] api unreachable (%s) — emitting to stdout",
                               exc)
                for event in events:
                    logger.warning("[unistack-security][finding] %s", json.dumps(event))
        except Exception as exc:
            logger.warning("[unistack-security] dropped a finding: %s", exc)

    async def _post(self, events: list[dict]) -> None:
        headers = {"Authorization": f"Bearer {_API_TOKEN}"} if _API_TOKEN else {}
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(f"{_API_URL.rstrip('/')}/security-events",
                                     json={"events": events}, headers=headers)
            if resp.status_code >= 300:
                logger.warning("[unistack-security] api rejected findings: %s %s",
                               resp.status_code, resp.text[:200])


#: What `litellm_settings.callbacks: ["unistack_security.sink"]` resolves to — an INSTANCE.
#: (Guardrails resolve a CLASS instead, hence `unistack_security.UniStackSecrets` in config.)
sink = SecuritySink()
