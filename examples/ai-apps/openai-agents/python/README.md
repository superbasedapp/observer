# OpenAI Agents SDK chatbot (Python)

An Agents SDK agent with one function tool and an in-memory `SQLiteSession`, three turns. While instrumented, the Agents SDK's own trace upload to OpenAI is replaced, so runs go to superbased only.

Every call uses `gpt-5-nano`, a reasoning model: it takes a completion-token
cap and a reasoning effort, and refuses a non-default temperature. Each
turn is one trace, carrying the end user (`user-ada`), a session and a
customer tenant (`acme`) set with `sb.propagate_attributes`.

## Install

Python 3.10 to 3.13. The SDK is not on PyPI yet; install it from a
checkout of the repository, then the pinned framework:

```bash
python -m venv .venv && . .venv/bin/activate
pip install "<repo>/sdk/python[openai-agents]"
pip install -r requirements.txt
```

## Run against this machine

superbased must be running with app observability on
(`observer components add obs --yes`, `observer config set observability.enabled true`,
then `observer start`); see the machine quickstart.

```bash
export OPENAI_API_KEY=...            # your OpenAI key; the example reads it from the environment only
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

`instrument: {"openai-agents": 'instrumented'}`, three (or more) turn lines,
and from `./verify.sh`: `all checks passed`. On the machine each trace
has one root span, every parent link resolves, 4 LLM spans with
model `gpt-5-nano-...`, input and output tokens equal to what OpenAI
reported, and a `cost_source` (`computed` from the price book).

Note: the price book shipped with superbased lists `gpt-5-nano` at $0, so
costs read $0 unless you set a price (machine: `[intelligence.pricing.models."gpt-5-nano"]`;
organization: Settings > Pricing).
