# OpenAI Agents SDK (JS) chatbot (TypeScript)

An `Agent` with one function tool, three turns passing `result.history` along. The instrumentation ADDS a tracing processor: the Agents SDK's own trace upload to OpenAI keeps running beside it, unlike the Python target, which replaces it.

Every call uses `gpt-5-nano`, a reasoning model: a completion-token cap and
a reasoning effort, no temperature. Each turn is one trace with the end
user (`user-ada`), a session and a customer tenant (`acme`) set with
`propagateAttributes`.

## Install

Node 22 (the file is plain `.ts`, run with Node's built-in type
stripping). The SDK is not on npm yet: `package.json` installs it from
this checkout (`file:../../../../sdk/typescript`); the first install also
builds the SDK (it fetches the SDK's compiler and its OpenTelemetry
dependencies, pinned by the SDK's lockfile):

```bash
npm install
```

## Run against this machine

superbased must be running with app observability on (see the machine
quickstart).

```bash
export OPENAI_API_KEY=...            # read from the environment only
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

`instrument: { 'openai-agents': 'instrumented' }`, three turn lines, and
`all checks passed` from `./verify.sh`: one root span per trace, every
parent link resolved, 4 LLM spans with model `gpt-5-nano...`,
tokens and a `cost_source` on each.
