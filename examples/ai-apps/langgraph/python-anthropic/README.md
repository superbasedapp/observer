# LangGraph ReAct chatbot on Claude (Python)

A LangGraph prebuilt ReAct agent with one tool and an in-memory checkpointer,
three turns on one thread, on `claude-haiku-5-5` through `langchain-anthropic`.
`sb.instrument(["langgraph"])` records graph, node, tool and model spans. The
system prompt is a long policy marked with `cache_control`: the first model
call writes Anthropic's prompt cache and the later ones read it.

Every call uses `claude-haiku-5-5` at low effort (`output_config.effort`).
Haiku 5.5 thinks adaptively by default; it refuses a non-default
`temperature`/`top_p`/`top_k` and a thinking budget
(`thinking: {type: "enabled", budget_tokens}`), so the example sends neither.
Each turn is one trace, carrying the end user (`user-ada`), a session and a
customer tenant (`acme`). Effort is `ChatAnthropic(effort="low")`.

**Each call is recorded once.** Since `anthropic` 1.14 the Anthropic SDK also
starts an OpenTelemetry span for every API call on the global tracer
provider; under a framework instrumentor that would be a second LLM span for
the same call. `sb.init()` turns the SDK's own tracing off
(`ANTHROPIC_OPEN_TELEMETRY=false` when you have not set it), so the example
needs no setting of its own. Set `ANTHROPIC_OPEN_TELEMETRY=true` before
`sb.init()` only if you want the SDK's spans as well.

`usage_metadata.input_tokens` from LangChain is already the whole prompt. With
Anthropic's per-TTL cache split, LangChain reports the cache write under
`input_token_details.ephemeral_5m_input_tokens` and `cache_creation` reads 0;
the example adds them up.

## Install

Python 3.10 to 3.13. The SDK is not on PyPI yet; install it from a
checkout of the repository, then the pinned framework:

```bash
python -m venv .venv && . .venv/bin/activate
pip install "<repo>/sdk/python[langchain]"
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

## Expected output

Three turn lines and `all checks passed` from `./verify.sh`: 4 LLM spans
(`ChatAnthropic`) with model `claude-haiku-5-5`, gross tokens equal to
Anthropic's usage, and a cost equal to that usage at Haiku 5.5's rates
(the first call's cache write at 1.25x input, the rest's cache reads at 0.1x).
