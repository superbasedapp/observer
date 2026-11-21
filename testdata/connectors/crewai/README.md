# CrewAI connector fixtures (W3)

REAL CAPTURES, per the connectors spec §7.1 step 1. Raw OTLP/HTTP
`ExportTraceServiceRequest` protobuf bodies, byte-identical off the wire.

- Captured: 2026-08-15, live `Crew.kickoff()` run (one agent, one task)
  against OpenRouter free model `nvidia/nemotron-3.5-lightning:free`
  through the Observer scratch proxy `/up/auto` lane (mechanism B, LiteLLM
  `openai/<rest>` provider prefix so the lane sees `openrouter/<model>`)
  with OTLP export via a capture tee (mechanism A).
- Emitter: `openinference-instrumentation-crewai 1.1.12` (scope
  `openinference.instrumentation.crewai`), `crewai 1.15.16`, driven by
  the Python SDK under its old name `superbased-observer-sdk` (now `superbased-sdk`,
  import `superbased_sdk`) (`superbased.init(service_name, user,
  session_id)`).
- Each capture holds one crew run: `Crew_<uuid>.kickoff` (CHAIN) +
  `Word analyst._execute_core` (AGENT).
- Verified pitfall CW-P2 (pinned by the fixture test): the CrewAI
  instrumentor ALONE emits **no LLM spans** — crew/agent structure only,
  no model, no tokens. The token-bearing LLM record arrives exclusively as
  the proxy-turn synthetic (`chat.turn`/`chat.completions`) on the lane,
  in a SEPARATE trace. For LLM-level OTLP spans, install
  `openinference-instrumentation-litellm` alongside (unverified here).
- Verified positives on `crewai 1.15.16`: `base_url`+`api_base` reach
  LiteLLM (5 `api_turns` rows across two runs — the §3.3 silent-fallback
  bug did NOT reproduce on this version, verified per the mandatory
  step-3 gate), and `extra_headers` pass through, so
  `X-Superbased-User` / `X-Superbased-Session` identity rides the lane.

Prompt/response bodies inside are from the synthetic harness task
("letters in 'superbased'") — no user data.

Consumed by `internal/obs/ingest/crewai_fixture_test.go`.
