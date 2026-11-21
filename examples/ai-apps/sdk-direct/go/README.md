# A chatbot on the superbased SDK directly (Go, no framework)

The Go twin of [`../python`](../python): `chatbot/` is a three-turn support bot
around a raw OpenAI call (standard-library HTTP, `internal/chat`). Per turn it:

- screens the user's message with `superbased.Admit` before the model runs (turn
  3, "Tell me about competitor pricing.", is refused by the machine policy
  below);
- uses a system prompt from the prompt registry
  (`superbased.GetPrompt(ctx, "support-system", ...)`, label `production`),
  compiled with `company`, and stamps the LLM span with the prompt's name and
  version (`LLMOptions{Prompt: prompt}`);
- wraps the OpenAI call in a manual LLM span with `SetUsage` (input, output,
  cached and reasoning tokens) and the messages and reply;
- records a score (`concise`) and end-user feedback (`user_feedback`);
- reads the trace's cost with `superbased.GetTraceCost` once it is ingested;
- carries the end user, session and customer tenant on every span
  (`PropagateAttributes`).

`experiment/` runs a two-item golden set through the same kind of call with an
exact-match evaluator and a CI gate (`FailUnder: 0.5`: exit 1 below it).

Every call uses `gpt-5-nano` (`max_completion_tokens`, `reasoning_effort`, no
temperature). The OpenAI key comes from `OPENAI_API_KEY` only;
`OPENAI_BASE_URL` overrides the API address.

## Build

Go 1.25 or newer. `go.mod` points at the SDK in this checkout
(`replace ... => ../../../../sdk/go`), so the example tests the SDK beside it.

```bash
go build -o bin/ ./chatbot ./experiment
```

## Set up the machine (once)

The same as the Python example:

```bash
observer components add obs --yes
observer config set observability.enabled true
observer obs prompts create support-system --label production \
  --text 'You are a terse support bot for {{ company }}. Answer in one sentence. Returns are accepted within 30 days.'
observer obs admission setup --yes --mode enforce --adopt denied_topics --denied-topics "competitor pricing"
```

Then set the `denied_topics` rule's decision to `deny` (dashboard: Your AI
apps > Policies > Guardrails) to see turn 3 refused; see `../python/README.md`.

## Run against this machine

```bash
export OPENAI_API_KEY=...
export SUPERBASED_DESTINATION=local
./bin/chatbot        # three turns, the admit verdicts, each trace's cost; writes run.json
./verify.sh          # 3 traces, 2 LLM spans (turn 3 refused), tokens, cost, identity
./bin/experiment     # pass_rate: 1, exit 0; a dataset "capitals-golden" appears on the machine
```

## Run against your organization

```bash
export SUPERBASED_DESTINATION=online SUPERBASED_ORG_URL=https://otlp.example.com
export SUPERBASED_API_KEY=<key_id>.<secret>   # scopes admit, sdk:read, sdk:write
./bin/chatbot && ./verify.sh --target org --llm-spans 3
SUPERBASED_API_KEY=<a CI key with sdk:eval,sdk:read> ./bin/experiment
```

To route the model calls through the organization's AI gateway (exact cost,
app budgets), point `OPENAI_BASE_URL` at the gateway and give the HTTP client
`superbased.GatewayTransport(nil)` as its transport: it sends the end user and
service the gateway budgets on and stamps the gateway's request id on the LLM
span.

## Expected output

```
prompt: support-system v1 label="production"
turn 1: "Hi! What can you do?" -> "..." (admit: allow)
turn 2: "What is your return window?" -> "...30 days..." (admit: allow)
turn 3: "Tell me about competitor pricing." -> "Sorry, I can't help with that here." (admit: deny)
cost <trace>: {"cost_usd":0,"from":"local","label":"computed"}
```
