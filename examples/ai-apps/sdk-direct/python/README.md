# A chatbot on the superbased SDK directly (Python, no framework)

`chatbot.py` is a three-turn support bot around a raw OpenAI call. Per turn it:

- screens the user's message with `sb.admit()` before the model runs (turn 3,
  "Tell me about competitor pricing.", is refused by the machine policy below);
- uses a system prompt from the prompt registry (`sb.get_prompt("support-system")`,
  label `production`), compiled with `company`, and stamps the LLM span with the
  prompt's name and version (`llm_span(prompt=<Prompt>)`);
- wraps the OpenAI call in a manual LLM span with `set_usage` (input, output,
  cached and reasoning tokens) and the messages and reply;
- records a score (`concise`) and end-user feedback (`user_feedback`);
- reads the trace's cost with `sb.get_trace_cost()` once it is ingested;
- carries the end user, session and customer tenant on every span.

`experiment.py` runs a two-item golden set through the same kind of call with an
exact-match evaluator and a CI gate (`fail_under=0.5`: exit 1 below it).

Every call uses `gpt-5-nano` (`max_completion_tokens`, `reasoning_effort`, no
temperature).

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install "<repo>/sdk/python"
pip install -r requirements.txt
```

## Set up the machine (once)

```bash
observer components add obs --yes
observer config set observability.enabled true
observer obs prompts create support-system --label production \
  --text 'You are a terse support bot for {{ company }}. Answer in one sentence. Returns are accepted within 30 days.'
observer obs admission setup --yes --mode enforce --adopt denied_topics --denied-topics "competitor pricing"
```

`admission setup` writes the `denied_topics` criterion with `decision = "flag"`,
which admits. To see a refusal, start superbased (`observer start`; restart it
if it was running, so admission is on), then set the rule's decision to `deny`
on the dashboard, Your AI apps > Policies > Guardrails; it applies at once and
is saved to the config. Or set `decision = "deny"` in
`[[observability.admission.criterion]]` of `~/.observer/config.toml` and
restart. `setup` rewrites the whole config file (it keeps a `config.toml.bak`). A judged criterion (`on_scope`) with an OpenAI GPT-5 model
as the judge fails open today (L-02 in the live e2e findings).

## Run against this machine

```bash
export OPENAI_API_KEY=...
export SUPERBASED_DESTINATION=local
python chatbot.py        # three turns, the admit verdicts, each trace's cost; writes run.json
./verify.sh              # 3 traces, 2 LLM spans (turn 3 refused), tokens, cost, identity
python experiment.py     # pass_rate: 1.0, exit 0; a dataset "capitals-golden" appears on the machine
```

## Run against your organization

The org needs the same prompt (`observer-org prompts create support-system --label production --text '...'`,
or the Prompts page) and, for `experiment.py`, a dataset named `capitals-golden`
(Datasets page, or `POST /api/org/obs/datasets`).

```bash
export SUPERBASED_DESTINATION=online SUPERBASED_ORG_URL=https://otlp.example.com
export SUPERBASED_API_KEY=<key_id>.<secret>   # scopes admit, sdk:read, sdk:write
python chatbot.py && ./verify.sh --target org --llm-spans 3
SUPERBASED_API_KEY=<a CI key with sdk:eval,sdk:read> python experiment.py
```

Under `online` or `both`, `admit()` asks the organization. With no admission
policy published there, the organization answers a clean `allow` (mode `off`)
and the machine's policy is not consulted, so turn 3 is answered (3 LLM spans).

## Expected output

```
prompt: support-system v1 label='production'
turn 1: 'Hi! What can you do?' -> '...' (admit: allow, ...)
turn 2: 'What is your return window?' -> '...30 days...' (admit: allow, ...)
turn 3: 'Tell me about competitor pricing.' -> "Sorry, I can't help with that here." (admit: deny, prefiltered)
cost <trace>: {'cost_usd': 1.6e-05, 'label': 'computed', 'from': 'local'}
```

`./verify.sh`: `all checks passed`. The machine's `/api/obs/trace/<id>/scores`
shows `concise` (source `sdk`) and `user_feedback` (source `feedback`) per trace.
`gpt-5-nano` is listed at $0 in the price book shipped with superbased; set a
price to see non-zero costs.
