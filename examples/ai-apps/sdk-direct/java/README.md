# A chatbot on the superbased SDK directly (Java, no framework)

`Chatbot.java` is a three-turn support bot around a raw OpenAI Chat Completions
call (the JDK `HttpClient`, no OpenAI SDK). Per turn it:

- screens the user's message with `Superbased.admit()` before the model runs
  (turn 3, "Tell me about competitor pricing.", is refused by the machine
  policy below);
- uses a system prompt from the prompt registry
  (`Superbased.getPrompt("support-system")`, label `production`), compiled
  with `company`, and stamps the LLM span with the prompt's name and version
  (`llmSpan(...).prompt(<Prompt>)`);
- wraps the OpenAI call in a manual LLM span with `setUsage` (input, output,
  cached and reasoning tokens) and the messages and reply;
- records a score (`concise`) and end-user feedback (`user_feedback`);
- reads the trace's cost with `Superbased.getTraceCost()` once it is ingested;
- carries the end user, session and customer tenant on every span.

`Experiment.java` runs a two-item golden set through the same kind of call with
an exact-match evaluator and a CI gate (`failUnder(0.5)`: exit 1 below it).

Every call uses `gpt-5-nano` (`max_completion_tokens`, `reasoning_effort`, no
temperature). Java 17 or later.

## Install

The SDK is not on Maven Central yet; install it from a checkout first:

```bash
mvn -q -f <repo>/sdk/java install -DskipTests
```

```bash
mvn -q compile
```

## Set up the machine (once)

```bash
observer components add obs --yes
```

```bash
observer config set observability.enabled true
```

```bash
observer obs prompts create support-system --label production \
  --text 'You are a terse support bot for {{ company }}. Answer in one sentence. Returns are accepted within 30 days.'
```

```bash
observer obs admission setup --yes --mode enforce --adopt denied_topics --denied-topics "competitor pricing"
```

`admission setup` writes the `denied_topics` criterion with `decision = "flag"`,
which admits. To see a refusal, start superbased (`observer start`; restart it
if it was running), then set the rule's decision to `deny` on the dashboard,
Your AI apps > Policies > Guardrails. The Python example's README
(`../python/README.md`) has the details.

## Run against this machine

```bash
export OPENAI_API_KEY=...
export SUPERBASED_DESTINATION=local
```

```bash
mvn -q exec:java                                    # three turns, the admit verdicts, each trace's cost; writes run.json
```

```bash
./verify.sh                                         # 3 traces, 2 LLM spans (turn 3 refused), tokens, cost, identity
```

```bash
mvn -q exec:java -Dexec.mainClass=example.Experiment   # pass_rate: 1.0, exit 0; a dataset "capitals-golden" appears on the machine
```

## Run against your organization

The org needs the same prompt and, for `Experiment`, a dataset named
`capitals-golden` (see `../python/README.md`).

```bash
export SUPERBASED_DESTINATION=online SUPERBASED_ORG_URL=https://otlp.example.com
export SUPERBASED_API_KEY=<key_id>.<secret>   # scopes admit, sdk:read, sdk:write
```

```bash
mvn -q exec:java && ./verify.sh --target org --llm-spans 3
```

Under `online` or `both`, `admit()` asks the organization. With no admission
policy published there, the organization answers mode `off`; under `both` the
machine's policy then decides, under `online` the verdict is degraded
`admission-off` and the turn is answered (3 LLM spans).

## Expected output

```
prompt: support-system v1 label='production'
turn 1: 'Hi! What can you do?' -> '...' (admit: allow)
turn 2: 'What is your return window?' -> '...30 days...' (admit: allow)
turn 3: 'Tell me about competitor pricing.' -> 'Sorry, I can't help with that here.' (admit: deny)
cost <trace>: {cost_usd=1.6E-5, label=computed, from=local}
```

`./verify.sh` prints `all checks passed`. The run record (`run.json`) has the
same fields as the Python example's, so `../../verify.py` checks either.
