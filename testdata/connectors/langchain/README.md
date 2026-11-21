# LangChain / LangGraph connector fixtures (W2)

REAL CAPTURES, per the connectors spec §7.1 step 1 (fixture must be a real
capture, never hand-authored). Raw OTLP/HTTP `ExportTraceServiceRequest`
protobuf bodies, byte-identical to what the instrumentor POSTed.

- Captured: 2026-08-15, live run against OpenRouter free model
  `nvidia/nemotron-3.5-lightning:free` through the Observer scratch proxy
  `/up/auto` lane (mechanism B) with OTLP export via a capture tee
  (mechanism A).
- Emitter: `openinference-instrumentation-langchain 0.1.70` (scope name
  `openinference.instrumentation.langchain`, empty schema_url), driven by
  the Python SDK under its old name `superbased-observer-sdk` (now `superbased-sdk`,
  import `superbased_sdk`) (`superbased.init(service_name, user,
  session_id)`) + `langchain-openai` + `langgraph` (`create_react_agent`).
- `otlp-export-001.bin` — the plain `llm.invoke` path: `ChatOpenAI` (LLM)
  + `Prompt` (CHAIN).
- `otlp-export-002.bin` — the LangGraph ReAct agent run: `LangGraph`
  (CHAIN root), 2× `agent` (AGENT), `get_word_length` (TOOL), 2×
  `ChatOpenAI` (LLM), plus `call_model` / `should_continue` /
  `RunnableSequence` / `Prompt` / `tools` chains.
- Identity in the capture: resource carries `service.name`, `sbo.user`,
  `session.id`; EVERY span additionally carries per-span `session.id`
  propagated by the instrumentor from LangChain `config.metadata` — the
  per-conversation-grain question the spec's §3.1 verify gate left open,
  answered positively by this capture.
- Verified pitfall LC-P1 (pinned by the fixture test): the instrumentor
  emits NO provider response id anywhere on the wire (no
  `llm.response.id`, no recoverable id in `output.value` — grep for the
  OpenRouter `gen-…` ids returns zero hits in both files), so the
  per-request proxy-turn join (`RealLLMSpanExists` /
  `supersedeSyntheticBatch` / the K1 response-id fallback) can never match
  for LangChain. Composition dedup rests entirely on the session-window
  suppression (`RecentRealLLMSpanForSession`).

Prompt/response bodies inside are from the synthetic harness prompt
("capital of France" / "letters in 'superbased'") — no user data.

Consumed by `internal/obs/ingest/langchain_fixture_test.go`.
