# Native OTLP export fixtures (T-475)

Real exports captured 2026-10-06 from installed vendor CLIs, plus the transcript
each run wrote, so a test can prove both that the export lands on a node and that
its turns fold against the transcript capture of the same run.

| Directory | Tool and version | Export file | Wire encoding on the real exporter | Transcript |
|---|---|---|---|---|
| `codex/` | codex-cli 0.154.0 (`codex exec`) | `logs.json` | OTLP/HTTP protobuf, stored here as protojson | `rollout-*.jsonl` |
| `gemini-cli/` | gemini-cli 0.53.1 | `logs.json` | OTLP/HTTP JSON (`otlpProtocol: "http"`) | `session-*.jsonl` |
| `qwen-code/` | qwen-code 0.21.0 | `logs.json` | OTLP/HTTP JSON | `<uuid>.jsonl` |
| `copilot-cli/` | @github/copilot 1.0.77 (BYOK offline mode) | `traces.json` | OTLP/HTTP JSON (traces only) | `events.jsonl` |
| `cursor-team/` | Cursor Enterprise OpenTelemetry export (team grain, org server); **vendor-doc-shaped, NOT a live capture** (no Enterprise team available, T-535) | `logs.json` | OTLP/HTTP protobuf, stored here in OTLP/HTTP JSON form | none (team export) |
| `ibm-bob/` | bobshell 2.0.6, a real signed-in session (AP-131, 2026-10-22) | `traces.json` | OTLP/HTTP JSON | none (bob.db task store; no token counts in the export) |
| `codebuddy/` | codebuddy-code 2.171.0 against the mock (AP-131, 2026-10-22) | `traces.json` (`OTEL_SEMCONV=agentlens`), `traces-default-semconv.json` | OTLP/HTTP JSON | `<uuid>.jsonl` |
| `kimchi/` | kimchi 1.17.0 against the mock, telemetry redirected in a throwaway `config.json` (AP-131, 2026-10-22) | `logs.json` | OTLP/HTTP JSON | `<ts>_<uuid>.jsonl` |
| `custom-agent/` | a developer's own agent (PT-55, 2026-11-03): the stock OpenTelemetry Python SDK 1.45.2 with `opentelemetry-instrumentation-openai-v2` 2.3b0 and `openai` 3.42.1, against a local chat-completions mock | `traces.json` | OTLP/HTTP protobuf, stored here as protojson | none (no transcript: the agent is the developer's code) |

## How they were captured

* Each tool ran with a throwaway HOME inside a private mount and network namespace
  (`unshare -rmn`): no internet, only an isolated loopback, `/mnt/c` hidden. No vendor
  account, login or credential file was used or read.
* The model endpoint was a local mock speaking the OpenAI Responses, Chat Completions
  and Gemini APIs, scripted to return fixed usage (1234 input tokens of which 1000
  cached, reasoning and output counts) and one shell tool call, so the expected token
  figures in the tests are known exactly.
* Each tool's exporter pointed at a local OTLP sink that wrote the request bodies.
  Codex used `[otel] exporter = { otlp-http = { protocol = "binary" } }` in its
  throwaway config.toml; Gemini and Qwen used the `telemetry` settings block; Copilot
  used `COPILOT_OTEL_ENABLED` with `COPILOT_OFFLINE=true` and a BYOK provider base URL.

### AP-131 captures (2026-10-22)

* IBM Bob ran signed in with the operator's account (the CLI needs an IBM login; there
  is no mock path), env vars only (`OTEL_EXPORTER_OTLP_ENDPOINT` to a local sink). Its
  task id is replaced by a synthetic 32-hex id, and the resource's account, team and
  session attributes are dropped.
* CodeBuddy and Kimchi ran with a throwaway HOME against the same loopback mock
  (chat-completions), so their usage is the mock's 1234 / 1000 / 56 / 16. Their
  transcripts are included so `cmd/observer` can prove the export and transcript turns
  for the same call do NOT fold (why those rows keep `TokensWithTranscript` off).
* Each tool's own internal spans irrelevant to the mapping (CodeBuddy's hook and
  interceptor spans) are dropped, and every prompt or completion body attribute is
  removed (only the mock's reply text and role attributes remain).

### PT-55 capture (2026-11-03): a developer's own agent

* `custom-agent/agent.py.txt` is the whole agent: a `TracerProvider` whose resource
  carries `service.name=fixture-agent`, `sbo.agent=fixture-bot` and
  `session.id=run-1`, the OTLP/HTTP protobuf span exporter, the OpenAI GenAI
  instrumentor, two `chat.completions.create` calls and one hand-made
  `execute_tool list_files` span following the GenAI semantic conventions.
  `custom-agent/servers.py.txt` is the mock (port 18801, fixed usage of 1234 prompt
  tokens of which 1000 cached, 56 completion tokens of which 16 reasoning) and the
  OTLP sink (port 18802). Both are stored as `.txt` so no tool treats them as code
  to run; nothing in them reaches a network beyond loopback.
* Finding recorded by the fixture: this instrumentor version reports
  `gen_ai.usage.input_tokens` = 1234 (gross of the cached tokens) and sends no
  cache-read or reasoning attribute, so a span-only turn carries input 1234 with no
  cache split. The proxy's row for the same `gen_ai.response.id` carries the exact
  split and wins (docs/own-agents.md "Token figures").
* Nothing was anonymized: the resource holds only the SDK identity, the random
  `service.instance.id` and the three attributes the script set.

## Anonymization

* Resource attributes describing the capture host (`host.*`, `process.*`,
  `installation.id`, OS strings) are dropped, the throwaway HOME path becomes
  `/home/fixture`, and the host name becomes `fixture-host`.
* Every string longer than 200 characters is replaced by `[fixture: truncated]`:
  those are vendor-authored system prompts and tool definitions (not ours to commit)
  or mock payloads. Ids, names and token counts are short and kept verbatim.

Used by `internal/otlpvendor/fixture_test.go`,
`internal/otlpvendor/ownagent_test.go`, `cmd/observer/otlp_vendor_ingest_test.go`
and `cmd/observer/otlp_ownagent_ingest_test.go`. The Copilot VS Code, Goose, OpenCode,
Grok, ZCode, Cursor and Cowork rows are pinned by doc-derived records in
`internal/otlpvendor/docrows_test.go` instead (labelled there as doc or source, not live).
