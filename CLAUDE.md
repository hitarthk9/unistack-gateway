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
| `unistack-agents` | Points at the gateway via env. |

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

1. **`litellm_settings.callbacks` MUST stay empty.** The UniStack SDK already writes LLM spans
   to Langfuse. LiteLLM logging the same calls would emit every generation twice, doubling
   spend and token counts in exactly the data the projector reads (BUILD_PLAN item 7).
2. **Use the OpenAI-compatible route (`/v1`), never the Anthropic passthrough**
   (`/anthropic/v1/messages`). LiteLLM does not reliably meter spend or enforce budgets on
   passthrough — you would get a model allow-list and nothing else.

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

# 2. The gateway
docker run -d --name unistack-litellm -p 4000:4000 \
  -v "$PWD/config.yaml:/app/config.yaml" \
  -e ANTHROPIC_API_KEY -e LITELLM_MASTER_KEY \
  -e DATABASE_URL=postgresql://litellm:litellm@host.docker.internal:5432/litellm \
  ghcr.io/berriai/litellm:main-latest --config /app/config.yaml --port 4000

curl -s localhost:4000/health/liveliness      # -> "I'm alive!"
```

Portal: <http://localhost:4000/ui> (log in with the master key).

### Issue a virtual key

Services never use the master key — they get a scoped virtual key with its own budget:

```bash
curl -s -X POST localhost:4000/key/generate \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H "Content-Type: application/json" \
  -d '{"models": ["agent-primary", "judge-fast"], "max_budget": 5.0, "key_alias": "unistack-demo"}'
```

Returns `{"key": "sk-..."}` → that is `UNISTACK_LLM_API_KEY` for `unistack-agents`.

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
config.yaml     ← the model catalogue, aliases, budgets. The reviewed source of truth
.env.example    ← provider keys + master key + DATABASE_URL (never committed with real values)
```
