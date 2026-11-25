// Package otlp embeds a minimal OTLP logs receiver in the agent so a coding
// assistant's native telemetry (Claude Code with CLAUDE_CODE_ENABLE_TELEMETRY=1)
// can be sent straight to Observer without an OpenTelemetry Collector
// (native-console integration, Phase 2b).
//
// It accepts OTLP/gRPC and OTLP/HTTP logs exports, hands each decoded
// ExportLogsServiceRequest to an injected handler, and returns the OTLP success
// response. It owns ONLY the network seam — decoding bytes and lifecycle; it
// knows nothing about Claude Code's schema or the store. The handler the daemon
// injects (cmd/observer otlpLogsHandler) composes otlpvendor.ParseLogs, the
// vendor mapping table whose claude-code row reads Claude Code's events, with
// store.UpsertTurnByRequestID.
//
// Network posture (template §2.2 / L3): the receiver binds loopback-only by
// default and New refuses a non-loopback address unless AllowNonLoopback is set
// explicitly — opening this listener to a network is an operator decision with
// a documented threat model, never a default. The echo guard that stops
// Observer re-ingesting its own emitted telemetry lives one layer up in
// otlpvendor.ParseLogs (otlpvendor.IsEcho drops sbo.emitted_by=observer
// resources).
package otlp
