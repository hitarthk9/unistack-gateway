# UniStack Gateway

The LiteLLM gateway every UniStack model call transits. **This repo owns everything
LiteLLM-specific** — the model catalogue, aliases, budgets, rate limits, virtual keys, and how
the service is run.

## Why it is its own repo

`unistack-sdk` is a LangGraph/Langfuse SDK for HITL and guardrails. It must not grow a
dependency on one particular gateway product. So the split is:

| Repo | Knows about |
|---|---|
| `unistack-sdk` | An **OpenAI-compatible endpoint**. Takes `llm_base_url` + `llm_api_key`, nothing more. Zero LiteLLM references — swap the gateway and the SDK is unchanged. |
| **`unistack-gateway`** (here) | LiteLLM: models, aliases, budgets, keys, deployment. |
| `unistack-agents` | Points at the gateway via env. One folder per agent; each carries **its own virtual key**, so budgets are genuinely per agent. |

## What it gives you

- **Budgets that actually stop spend**, per virtual key — one runaway workflow cannot spend
  another team's allowance.
- **A model allow-list.** A key may only call the aliases the config declares.
- **Aliases, not model ids.** Nothing in UniStack names a raw model, so switching provider or
  model is a one-line change here.
- **Rate limits** and provider failover.

## Model aliases

| Alias | Used by | Backed by (today) |
|---|---|---|
| `agent-primary` | the graph's own nodes | `anthropic/claude-sonnet-5` |
| `judge-fast` | the SDK's guardrail judge | `anthropic/claude-haiku-4-5-20251001` |

## Two rules that are easy to break

1. **No GENERATION logger in `litellm_settings.callbacks`.** The UniStack SDK already writes
   LLM spans to Langfuse; a second writer would emit every generation twice, doubling spend and
   token counts in exactly the data the projector reads (BUILD_PLAN item 7).

   *This used to read "the list MUST stay empty", which was too strong.* `security_sink.sink`
   is the **one permitted entry**: it writes only guardrail findings to
   `unistack.security_events`, and on a clean call it writes nothing at all — verified, a full
   guarded activity produces zero documents and exactly two Langfuse generations. Adding any
   **other** entry requires making that argument again from scratch.
2. **Use the OpenAI-compatible route (`/v1`), never the Anthropic passthrough**
   (`/anthropic/v1/messages`). LiteLLM does not reliably meter spend or enforce budgets on
   passthrough — you would get a model allow-list and nothing else.

## The security layer (BUILD_PLAN item 5)

Deterministic only — **nothing here calls an LLM.** The LLM security judge is item 6 and runs
forensically on completed traces, never in the request path.

| Guardrail | Does | Records a finding? |
|---|---|---|
| `unistack-secrets` (`UniStackSecrets`) | Masks credentials outbound, `pre_call` | **Yes** — type + count, never the value |
| `unistack-no-code-exec` (`block_code_execution`) | Blocks code-execution requests | Yes |
| `unistack-red-lines` (`litellm_content_filter`) | Blocks self-harm + illegal-weapons | Yes |

All three are `default_on: false` in config and **selected per request by model** — see the
judge exemption below. That is deliberate, not disabled.

**`unistack-secrets` is ours, not stock.** `hide-secrets` masks but records nothing, so a
redacted leak was invisible — the platform could never answer *"did a credential leak in this
activity?"*. `UniStackSecrets` subclasses it, reuses its ~200 `detect_secrets` plugins, and
records the finding. It stores the secret's **type and count, never its value**: an audit log
that quotes the credential it just redacted has leaked it into a second store.

**`unistack-no-code-exec` is the one domain-dependent choice here.** A *coding* agent's normal
traffic is exactly what it blocks — so that agent opts out **by name**, without changing the
rule for anyone else. See "Per-agent policy" below.

**Why so few content categories.** Two reasons, and the second was measured.

*Policy categories are the wrong tool here.* The filter also ships `bias_*`,
`denied_medical_advice`, `denied_legal_advice` and `claims_*`. Those encode **client-specific
business policy**, and UniStack already has a mechanism for that — the business-policy guard,
which judges node output against a policy string and pauses a **human**. A gateway keyword rule
would be a second, dumber copy of an existing control, in the one place where a false positive
kills the request instead of asking someone.

⚠️ *`harm_toxic_abuse` and `harmful_child_safety` are excluded because they are broken for
general use.* Their obfuscated-profanity patterns (e.g. `sh*i*t`, where `*` is a wildcard) match
ordinary English. Measured: **"This shift is a great insight for your workflow."** and **"A
standing desk helps you shift posture through it."** were both BLOCKED — 2 of 4 innocuous
business sentences. `harmful_child_safety` inherits the same list via
`inherit_from: harm_toxic_abuse.json`. A rule that rejects half of normal copy is not a security
control. `severity_threshold` is `high` for the same reason. **Re-run that four-sentence probe
before enabling any new category.**

**Why the prompt-injection categories are still off.** The judge is now exempt from blocking
rules, so they no longer endanger it — but they remain unproven against *agent* traffic, and the
two categories removed above are a warning about how loose these pattern sets can be. They stay
deferred to the kill-switch / egress item, where they get the same four-sentence probe before
being enabled.

### Two blind spots to state plainly

- **Masking does not protect the trace.** The SDK writes `input.value` to Langfuse *before* the
  gateway masks anything, so a secret redacted here is still in Langfuse in cleartext. Gateway
  masking protects the *provider*, not the *trace*. (The finding itself is recorded — that was
  fixed by `UniStackSecrets` — but the redaction only applies downstream of the SDK.)
- **This sees model calls, not the agent.** A node that calls an API directly never transits the
  gateway. Read "0 findings" as *"nothing in the model traffic was flagged"*, never as
  *"nothing left the process"*.

### The judge is exempt from blocking rules — and why that is not optional

The SDK's guardrail judge transits this gateway too, and **its prompt embeds the agent's raw
output**. So a content rule ends up inspecting exactly the quarantined material it is looking
for. Observed live before the fix: a rule matched inside a judge prompt, the call was blocked,
`evaluate_guardrail` **failed closed**, and the activity paused with *"guardrail judge
unavailable"* — pointing the operator at the wrong subsystem entirely.

LiteLLM's own answer is per-key scoping, and **both mechanisms are Enterprise-gated**
(`disable_global_guardrails` and per-key `guardrails`). Since Enterprise is permanently out of
scope, the free-tier equivalent lives in `unistack_security.py`: every guardrail is
`default_on: false`, and `SecuritySink.async_pre_call_hook` selects them per request by model.

| Traffic | Secrets masking (non-blocking) | Blocking rules |
|---|---|---|
| Agent models | ✅ | ✅ |
| `judge-fast` (the control plane) | ✅ | ❌ **never** |

The split is the principle, not a workaround: **non-blocking hygiene applies everywhere; a
blocking rule must never be able to stop the control plane.** Masking still runs on the judge
because redacting a credential it does not need is harmless and the finding is still recorded —
so a leak in agent output is caught even when it surfaces on the judge's call.

Two properties the hook must keep, both covered by the verification below:

- It **overwrites** `data["guardrails"]` unconditionally and never honours a caller-supplied
  value. LiteLLM checks the request body first, so merging would let any caller disable every
  guardrail with `{"guardrails": []}`.
- On any internal error it applies the **full** set. The worst case is a visible judge pause,
  never silently ungated agent traffic.

Change the exempt models with `UNISTACK_GUARDRAIL_EXEMPT_MODELS` (default
`judge-fast,evaluator-fast`); the resolved list is printed in the startup line so it is visible
at boot rather than inferred.

### Per-agent policy — the virtual key is the unit

`unistack-agents` holds one folder per agent, and everything agent-specific lives in it. **The
gateway is the one place that cannot follow that rule literally**, and it is worth being precise
about why: `config.yaml` configures a single LiteLLM **process**, and one gateway serves every
agent. Per-agent config files would mean a gateway, a Postgres and a port per agent.

So per-agent differentiation attaches to the **virtual key** instead, which every agent already
has:

| Per-agent concern | Mechanism | Where it is declared |
|---|---|---|
| Which models it may call | key `models` | `/key/generate` |
| What it may spend | key `max_budget` | `/key/generate` |
| Which **blocking** guardrails it opts out of | key **alias** | `UNISTACK_GUARDRAIL_OPT_OUT` |

```bash
UNISTACK_GUARDRAIL_OPT_OUT="unistack-coding-agent:unistack-no-code-exec"
```

Comma-separated `alias:guardrail` pairs; absent means today's behaviour exactly. The resolved
map is printed in the startup line beside the exempt models.

⚠️ **The agent's identity is read from `user_api_key_dict.key_alias`, never from
`data["metadata"]`.** LiteLLM resolves the alias from the *authenticated* key; request metadata
is written by the caller. Keying on metadata would let any agent name another agent's alias and
inherit its opt-outs — the same hole as a caller-supplied `data["guardrails"]`, wearing a
different hat. (The sink reads `metadata["user_api_key_alias"]` for *reporting*, which is fine:
a mislabelled report is not a bypassed control.)

**Order is a security property.** The exempt-model check runs **first and unconditionally**, so
no per-agent configuration can re-arm a blocking rule on the judge and take the control plane
down. Then opt-outs. Then the full set by default — an unknown alias gets everything.

> Because the judge is exempt, a **code-generating agent no longer breaks its own judge**. It
> still needs its own `unistack-no-code-exec` opt-out, since its own traffic is what that rule
> blocks — but that is now one env entry, not an edit to a constant shared by every agent.

### How findings get out — and the trap in it

`unistack_security.py` reads findings off the request and posts them to `unistack-api`, which
owns MongoDB. Two things about it are non-obvious and were both found the hard way:

1. It hooks `async_post_call_success_hook` / `async_post_call_failure_hook`, **not**
   `async_log_success_event`. A guardrail that blocks short-circuits the request and fires
   *neither* logging callback — a sink built on those records clean calls and misses every block.
2. It reads **both** `metadata` and `litellm_metadata`. `block_code_execution` writes findings to
   the first, `litellm_content_filter` to the second. Reading one bucket silently loses every
   finding from the other, and looks exactly like "the guardrail never fired".

**Why HTTP rather than a direct Mongo write:** the stock image ships no Mongo driver *and no
pip* (it is built with uv), so writing to Mongo directly requires a custom image — turning
`docker run` into `docker build` first. `httpx` is already present, so posting to the service
that already owns the database keeps this on the **stock image with two volume mounts**. It also
keeps Mongo credentials out of a container that holds provider API keys.

## Config policy

Anything that changes **what is allowed** — models, aliases, budgets, rate limits — lives in
`config.yaml`, under review. Only **operational** actions happen in the portal: issuing or
revoking a virtual key, an emergency budget bump, viewing spend. A budget widened by a click
leaves no diff and no reviewer, and LiteLLM's own audit log is an enterprise feature; git gives
it free.

## Running it

```bash
cp .env.example .env          # add your real ANTHROPIC_API_KEY, set a master key
set -a && source .env && set +a

# 1. Postgres — backs budgets, virtual keys and the spend ledger
docker run -d --name unistack-litellm-db \
  -e POSTGRES_USER=litellm -e POSTGRES_PASSWORD=litellm -e POSTGRES_DB=litellm \
  -p 5432:5432 postgres:16

# 2. The gateway — STOCK image, no build. Two mounts: the config and the security module.
#    Both are mounted, so a guardrail change or a sink change is an edit plus a restart.
#    Note host paths must be host.docker.internal from inside the container, not localhost.
docker run -d --name unistack-litellm -p 4000:4000 \
  -v "$PWD/config.yaml:/app/config.yaml" \
  -v "$PWD/unistack_security.py:/app/unistack_security.py:ro" \
  -e ANTHROPIC_API_KEY -e LITELLM_MASTER_KEY \
  -e DATABASE_URL="${DATABASE_URL/localhost/host.docker.internal}" \
  -e UNISTACK_API_URL=http://host.docker.internal:8001 \
  -e UNISTACK_API_TOKEN="$UNISTACK_API_TOKEN" \
  ghcr.io/berriai/litellm:main-latest --config /app/config.yaml --port 4000

curl -s localhost:4000/health/liveliness      # -> "I'm alive!"

# ALWAYS check this after a restart. A typo in `callbacks:` makes LiteLLM skip the sink
# SILENTLY — this line is the only cheap proof it loaded.
docker logs unistack-litellm 2>&1 | grep unistack-security
# -> [unistack-security] sink v2 loaded (api=http://host.docker.internal:8001, token=set)
```

### Check what the guardrails caught

```bash
mongosh --quiet --eval '
  db.getSiblingDB("unistack").security_events.find({source:"gateway"})
    .sort({detected_at:-1}).limit(5).forEach(d => print(d.action + "  " + d.reason))'
# -> block  unistack-red-lines block — harmful_illegal_weapons: 'ghost gun'
```

Portal: <http://localhost:4000/ui> (log in with the master key).

### Issue a virtual key

Services never use the master key — they get a scoped virtual key with its own budget:

```bash
curl -s -X POST localhost:4000/key/generate \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H "Content-Type: application/json" \
  -d '{"models": ["agent-primary", "judge-fast"], "max_budget": 5.0, "key_alias": "unistack-content-marketing"}'
```

Returns `{"key": "sk-..."}` → that is `UNISTACK_LLM_API_KEY` in **that agent's** `.env`.

⚠️ **One key per agent, always.** Budgets and the model allow-list are enforced per key, so two
agents sharing a key share a budget — a runaway agent then spends the other's allowance, which
is the exact failure this gateway exists to prevent. The alias is also how per-agent guardrail
policy is addressed (above), so a shared key makes that unaddressable too.

**To prove budget enforcement**, issue one with `"max_budget": 0.0000001` — the next call is
rejected and the agent pauses for a human with "LLM budget exceeded" instead of crashing.

### Check spend

```bash
curl -s -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
  "localhost:4000/spend/logs" | python3 -m json.tool | head -40
```

Each row carries the model, the virtual key, token counts and the computed cost. This is the
**authoritative billing number** — it is what budget enforcement acts on.

> **Spend here is per key and per model, not per activity.** The SDK does send `activity_id` /
> `workflow` / `node` as request metadata, but it does not surface in `/spend/logs` on this
> LiteLLM build (tested two request shapes; calls bill correctly, the tag just is not
> queryable). **Per-activity cost comes from Langfuse instead**, which already groups every span
> by `session.id = activity_id` — see BUILD_PLAN.md, "Activity cost". Treat the two numbers as
> answering different questions and never sum them: Langfuse estimates what an activity cost,
> LiteLLM records what a key actually spent.

## Files

```
config.yaml           ← models, aliases, budgets, guardrails. The reviewed source of truth
unistack_security.py  ← the recording secrets guardrail + the findings sink
.env.example          ← provider keys, master key, DATABASE_URL, UNISTACK_API_* (no real values)
```

**No Dockerfile, by design.** Both files are mounted into the stock image, so the gateway stays
`docker run` — no build step, and nothing to rebuild when a rule changes. That is only possible
because the sink posts findings over HTTP instead of writing Mongo directly; see above.
