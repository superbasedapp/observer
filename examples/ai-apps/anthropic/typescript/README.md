# Anthropic TypeScript SDK chatbot

The same chatbot as [../python](../python): three turns (one with a tool
call), one call with summarized thinking, one streamed call
(`messages.stream(...).finalMessage()`) and a prompt-caching pair, through
`instrument(["anthropic"])` (ESM: the module is handed over). With
`AI_GATEWAY_URL` set, calls go through the organization's AI gateway with
`gatewayFetch()`, which sends the app identity headers and stamps the
gateway's request id on the LLM span (the key goes as `authToken`, the base
URL is the gateway root).

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

`instrument: { anthropic: 'instrumented' }`, three turn lines, the thinking
answer, `"1\n2\n3"`, the cache write then cache read lines, and
`all checks passed` from `./verify.sh`: 8 LLM spans with model
`claude-haiku-5-5`, gross tokens and a cost equal to Anthropic's usage at Haiku
5.5's rates.
