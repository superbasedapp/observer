# A chatbot on the superbased SDK directly, on Claude (Python, no framework)

The Anthropic version of [../python](../python): a three-turn support bot
around a raw Anthropic Messages call. Per turn it screens the message with
`sb.admit()`, uses the registry prompt `support-system` (label `production`)
compiled with `company`, wraps the call in a manual LLM span
(`llm_span(..., provider="anthropic", prompt=<Prompt>)`) with `set_usage`,
records a score and end-user feedback, and reads the trace's cost with
`sb.get_trace_cost()`. `experiment.py` runs a two-item golden set with an
exact-match evaluator and `fail_under=0.5`.

Every call uses `claude-haiku-5-5` at low effort (`output_config.effort`).
Haiku 5.5 thinks adaptively by default; it refuses a non-default
`temperature`/`top_p`/`top_k` and a thinking budget
(`thinking: {type: "enabled", budget_tokens}`), so the example sends neither.
Each turn is one trace, carrying the end user (`user-ada`), a session and a
customer tenant (`acme`).

**`set_usage` takes the GROSS input; Anthropic's `usage.input_tokens` is NET.**
Pass `input_tokens = usage.input_tokens + usage.cache_creation_input_tokens +
usage.cache_read_input_tokens`, plus `cache_read_tokens` and
`cache_write_tokens`. An `input_tokens` below the cache counts is read as
Anthropic's net figure: `set_usage` records input + cache, counts it in
`diagnostics()["usage_net_input_corrected"]` and logs one warning.

The app opens its own LLM spans. The Anthropic SDK would also trace each call
itself; `sb.init()` turns that off (`ANTHROPIC_OPEN_TELEMETRY`), so the client
is a plain `anthropic.Anthropic()`.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install "<repo>/sdk/python"
pip install -r requirements.txt
```

## Set up and run

The machine and organization setup (the `support-system` prompt, the
`capitals-golden` dataset, an admission policy) is the same as for
[../python](../python#set-up-the-machine-once). Then:

```bash
export ANTHROPIC_API_KEY=...
export SUPERBASED_DESTINATION=local        # or online / both, with SUPERBASED_ORG_URL and SUPERBASED_API_KEY
python chatbot.py
./verify.sh                                # --target org for the organization
python experiment.py                       # pass_rate: 1.0, exit 0
```

With no admission policy on the machine, the machine answers `allow` (mode
`off`) and turn 3 is answered: 3 LLM spans. With the machine's `denied_topics` policy set to deny, turn 3 is
refused: run `./verify.sh --llm-spans 2`.

## Expected output

```
prompt: support-system v1 label='production'
turn 1: 'Hi! What can you do?' -> "I'm Acme Widgets' support bot, ..." (admit: allow, ...)
turn 2: 'What is your return window?' -> 'Returns are accepted within 30 days of purchase.' (admit: allow, ...)
turn 3: 'Tell me about competitor pricing.' -> ... (admit: ...)
cost <trace>: {'cost_usd': 2.57e-05, 'label': 'computed', 'from': 'local'}
```

`./verify.sh`: `all checks passed`.
