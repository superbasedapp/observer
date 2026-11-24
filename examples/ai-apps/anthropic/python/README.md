# Anthropic Python SDK chatbot

Three Messages API turns (one calls a tool: `tool_use` and `tool_result`
blocks), one call with summarized thinking, one streamed call
(`messages.stream`) and a prompt-caching pair (a long system prompt with
`cache_control`, sent twice: the first call writes the cache, the second
reads it), through `sb.instrument(["anthropic"])`. Optionally routed through
the organization's AI gateway (`gateway_exact` cost, app budgets).

Every call uses `claude-haiku-5-5` at low effort (`output_config.effort`).
Haiku 5.5 thinks adaptively by default; it refuses a non-default
`temperature`/`top_p`/`top_k` and a thinking budget
(`thinking: {type: "enabled", budget_tokens}`), so the example sends neither.
Each turn is one trace, carrying the end user (`user-ada`), a session and a
customer tenant (`acme`).

Anthropic reports `usage.input_tokens` net of the prompt cache. superbased
stores a span's input tokens gross (input + cache write + cache read) and
prices each part at its own rate, so `run.json` records the gross figure for
`verify.py` to compare.

## Install

Python 3.10 to 3.13. The examples install the SDK from a
checkout of the repository, then the pinned framework:

```bash
python -m venv .venv && . .venv/bin/activate
pip install "<repo>/sdk/python[anthropic]"
pip install -r requirements.txt
```

## Run against this machine

superbased must be running with app observability on
(`observer components add obs --yes`, `observer config set observability.enabled true`,
then `observer start`); see the machine quickstart.

```bash
export ANTHROPIC_API_KEY=...         # your Anthropic key; the example reads it from the environment only
export SUPERBASED_DESTINATION=local
python chatbot.py                    # prints each turn; writes run.json
./verify.sh                          # reads the machine's API and checks spans, tokens and cost
```

A machine on other ports: set `SUPERBASED_NODE_URL` (its dashboard API); the
SDK asks it for its OTLP receiver. With `SUPERBASED_DISCOVER=0`, also set
`SUPERBASED_OTLP_ENDPOINT` (the receiver's `/v1/traces`).

## Run against your organization

```bash
export SUPERBASED_DESTINATION=online           # or both: the machine and the organization
export SUPERBASED_ORG_URL=https://otlp.example.com
export SUPERBASED_API_KEY=<key_id>.<secret>    # an SDK key with signal traces (+ sdk:read for verify)
python chatbot.py
./verify.sh --target org
```

On a signed-in machine (`observer sdk sign-in`) the default destination is
`both` and the SDK finds the gateway and key itself.

### Through the organization's AI gateway

With `AI_GATEWAY_URL` (the gateway root, for example `https://ai.example.com`;
the SDK adds `/v1/messages`) and `AI_GATEWAY_KEY` (an AI gateway key,
`sbo-vk-...`) set, the client calls the gateway instead of Anthropic. The key
goes as a bearer token (`auth_token=`; `api_key=`, sent as `x-api-key`, works
too), and the client sends
`X-Superbased-Service` and `X-Superbased-User`, the headers the gateway's app
budgets key on (the Python SDK does not send them for you). The gateway needs
an `anthropic` upstream; `claude-haiku-5-5` is priced from the organization's
price book (Settings > Pricing) or, without a row there, the list prices
shipped with superbased.

```bash
export AI_GATEWAY_URL=https://ai.example.com AI_GATEWAY_KEY=sbo-vk-...
python chatbot.py
./verify.sh --target org --cost-source gateway_exact
```

## Expected output

`instrument: {'anthropic': 'instrumented'}`, three turn lines, the thinking
answer with `(1 thinking block(s))`, `1 2 3`, then
`cached-1: cache write 8xxx, cache read 0` and
`cached-2: cache write 0, cache read 8xxx`. From `./verify.sh`:
`all checks passed`: one root span per trace, every parent link resolved,
8 LLM spans with model `claude-haiku-5-5`, gross input and output tokens equal
to Anthropic's usage, and a cost equal to that usage at Haiku 5.5's rates
(cache writes at 1.25x input, reads at 0.1x).
