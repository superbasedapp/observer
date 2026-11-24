# LangGraph.js ReAct chatbot on Claude (TypeScript)

A `createReactAgent` with one tool and a `MemorySaver`, three turns on one
thread, on `claude-haiku-5-5` through `@langchain/anthropic`.
`instrument(["langgraph"])` gets `@langchain/core/callbacks/manager` handed
over. The system prompt is a long policy marked with `cache_control`, so the
first call writes Anthropic's prompt cache and the later ones read it.

Every call uses `claude-haiku-5-5` at low effort (`output_config.effort`).
Haiku 5.5 thinks adaptively by default; it refuses a non-default
`temperature`/`top_p`/`top_k` and a thinking budget
(`thinking: {type: "enabled", budget_tokens}`), so the example sends neither.
Each turn is one trace, carrying the end user (`user-ada`), a session and a
customer tenant (`acme`). Effort is `new ChatAnthropic({ outputConfig: { effort: "low" } })`.

**Each call is recorded once.** `@langchain/anthropic` calls the Anthropic
SDK, which also starts a span of its own for every call on the provider
`init()` registers; `init()` turns that off (`ANTHROPIC_OPEN_TELEMETRY=false`
when you have not set it), so the example needs no setting of its own.

**Cache writes:** LangChain.js reports Anthropic's cache write in the model's
usage (`input_token_details.cache_creation`, or the `ephemeral_5m_input_tokens`
bucket), and the LangChain instrumentation records no cache-write count.
superbased reads it from the model's serialized output, so the write is
priced at the cache-write rate while content capture is on; `./verify.sh`
checks the cost at Haiku 5.5's rates.

## Install

Node 22 (the file is plain `.ts`, run with Node's built-in type
stripping). The examples test the SDK beside them: `package.json` installs it from
this checkout (`file:../../../../sdk/typescript`). Build the SDK once
first; `npm install` here alone fails with `Cannot find module
'typescript/bin/tsc'`, because npm does not install a linked folder's
build tools:

```bash
(cd ../../../../sdk/typescript && npm install)   # installs its build tools and builds dist/
npm install
```

## Run against this machine

superbased must be running with app observability on (see the machine
quickstart).

```bash
export ANTHROPIC_API_KEY=...         # read from the environment only
export SUPERBASED_DESTINATION=local
node chatbot.ts                      # prints each turn; writes run.json
./verify.sh                          # needs python3; reads the machine's API
```

A machine on other ports: set `SUPERBASED_NODE_URL` (its dashboard API); the
SDK asks it for its OTLP receiver. With `SUPERBASED_DISCOVER=0`, also set
`SUPERBASED_OTLP_ENDPOINT` (the receiver's `/v1/traces`).

## Run against your organization

```bash
export SUPERBASED_DESTINATION=online           # or both
export SUPERBASED_ORG_URL=https://otlp.example.com
export SUPERBASED_API_KEY=<key_id>.<secret>    # signal traces (+ sdk:read for verify)
node chatbot.ts
./verify.sh --target org
```

## Expected output

`instrument: { langchain: 'instrumented' }`, three turn lines, and
`all checks passed` from `./verify.sh`: 4 LLM spans (`ChatAnthropic`) with
model `claude-haiku-5-5` and gross tokens equal to Anthropic's usage.
