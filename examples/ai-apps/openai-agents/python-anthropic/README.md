# OpenAI Agents SDK chatbot on Claude (Python, through LiteLLM)

An agent with one function tool, three turns on one session, on
`claude-haiku-5-5` through the Agents SDK's LiteLLM model
(`LitellmModel(model="anthropic/claude-haiku-5-5")`, extra
`openai-agents[litellm]`). `sb.instrument(["openai-agents"])` records the
workflow, agent, turn, generation and tool spans.

Every call uses `claude-haiku-5-5` at low effort (`output_config.effort`).
Haiku 5.5 thinks adaptively by default; it refuses a non-default
`temperature`/`top_p`/`top_k` and a thinking budget
(`thinking: {type: "enabled", budget_tokens}`), so the example sends neither.
Each turn is one trace, carrying the end user (`user-ada`), a session and a
customer tenant (`acme`).

Effort: `ModelSettings(extra_args={"output_config": {"effort": "low"}})`.
LiteLLM forwards extra keyword arguments into the Anthropic request body.
`extra_body` does not work here: LiteLLM sends it as a literal `extra_body`
field and Anthropic answers `400 extra_body: Extra inputs are not permitted`.
LiteLLM calls the API over HTTP itself, not through the Anthropic SDK, so
there is no second span from the SDK.

LiteLLM names the model `anthropic/claude-haiku-5-5`; superbased stores and
prices it as `claude-haiku-5-5` (the provider prefix is dropped) and keeps
the name LiteLLM sent as the span's request model.

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

Three turn lines and `all checks passed` from `./verify.sh`: 4 `generation`
LLM spans with model `claude-haiku-5-5`, tokens equal to Anthropic's
usage and the cost at Haiku 5.5's rates.
