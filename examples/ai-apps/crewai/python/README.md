# CrewAI chatbot (Python), traced to your machine

A one-agent CrewAI crew that answers a short question with one tool
(`word_length`) on OpenAI's `gpt-5-nano`. The superbased SDK sends every span
to the superbased app on this machine (destination `local` by default; set
`SUPERBASED_DESTINATION=online` or `both` to send to your organization too):

- the crew (`Crew_<id>.kickoff`) and its task, which the CrewAI instrumentor
  records as an agent span named after the agent's role
  (`Geography helper._execute_core`)
- the tool call (`word_length.run`) under the agent span
- each model call as an LLM span (`ChatCompletion`) from the OpenAI
  instrumentor, with model, input, output and reasoning tokens, the OpenAI
  response id and a cost
- the end user and session on the trace

CrewAI also asks OpenAI to count input tokens before model calls and after
tool results (a context-window check). The OpenAI instrumentor records each of
those as an LLM span named `InputTokenCountResponse`, with no model and no
token usage; they add nothing to the trace's tokens or cost.

## Install

Python 3.10 to 3.13 (CrewAI's instrumentor does not support 3.14). The examples
install the SDK from this checkout. From the repository root:

```bash
python3.12 -m venv .venv
```

```bash
.venv/bin/pip install -e "./sdk/python" -r examples/ai-apps/crewai/python/requirements.txt
```

`requirements.txt` pins the set this example was tested with (CrewAI
1.15.44, openai 2.54.0). With uv, use `uv pip install` the same way, without
`--prerelease=disallow`: CrewAI needs `opentelemetry-semantic-conventions`,
which only has beta releases.

## Turn on app observability on the machine

```bash
observer components add obs --yes
```

```bash
observer config set observability.enabled true
```

Then start (or restart) superbased with `observer start`; see
`docs/sdk/quickstart-machine.md`. `curl -s http://127.0.0.1:8081/api/obs/enabled`
answers `{"enabled":true}` when the receiver is up.

## Environment

| Variable | Needed | Meaning |
|---|---|---|
| `OPENAI_API_KEY` | yes | your OpenAI key, read from the environment only |
| `CHATBOT_USER` | no | end user on the trace (default `demo-user`) |
| `CHATBOT_SESSION_ID` | no | session id (default `crewai-chat-<random>`) |
| `CHATBOT_MODEL` | no | default `gpt-5-nano` |
| `SUPERBASED_CAPTURE_CONTENT` | no | `false` sends no prompt or response bodies |

`chatbot.py` sets `CREWAI_DISABLE_TELEMETRY=true` and
`CREWAI_TRACING_ENABLED=false` unless you set them, so CrewAI sends nothing to
CrewAI. `gpt-5-nano` is a reasoning model: the example passes no
`temperature`, and sets `max_completion_tokens=4000` (reasoning tokens count
against it) and `reasoning_effort="low"`.

## Run

```bash
.venv/bin/python examples/ai-apps/crewai/python/chatbot.py "How many letters are in the capital of France?"
```

Expected output (token numbers vary a little from run to run):

```
instrument: {'crewai': 'instrumented', 'openai': 'instrumented'}
answer: 5
crewai usage: requests=2 prompt=455 completion=160 total=615
session: crewai-chat-1a2b3c4d
```

## Verify

```bash
EXPECT_INPUT_TOKENS=455 EXPECT_OUTPUT_TOKENS=160 examples/ai-apps/crewai/python/verify.sh crewai-chat-1a2b3c4d
```

It reads the trace from the machine's local API (`/api/obs/traces` and
`/api/obs/trace/<id>`) and prints one `ok` or `FAIL` line per check: the crew,
agent and tool spans and their parents, one LLM span per model call with
model, tokens and request id, end user, session, token totals and a cost
above zero. It exits non-zero if anything is missing. The two `EXPECT_*`
values are the `crewai usage` line, which is what OpenAI reported; without
them the totals only have to be above zero.

On the 2026-11-20 build the machine's built-in price list has `gpt-5-nano`
at $0, so the cost check fails until the machine has a non-zero price for it
(from the pricing feed, `observer pricing sync`, or a local price in
`~/.observer/config.toml`):

```toml
[intelligence.pricing.models."gpt-5-nano"]
input = 0.05
output = 0.40
cache_read = 0.005
```

## Look at it

```bash
observer obs traces list --days 1
```

or the dashboard at `http://127.0.0.1:8081`, under app observability, Traces.
