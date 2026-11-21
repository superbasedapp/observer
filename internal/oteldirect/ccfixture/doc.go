// Package ccfixture builds a synthetic Claude Code OpenTelemetry export: one
// interactive session as Claude Code's own OTLP exporter would send it,
// faithful to the vendor's documented event schema
// (code.claude.com/docs/en/monitoring-usage, read 2026-11-16). The repo holds
// no full-session Claude Code export, so tests of the OTel-direct ingest path
// (internal/oteldirect and the org route that calls it) build one here.
//
// It is a non-test package so other packages' tests can import it. It was
// lifted from the OTel-direct spike
// (internal/orgserver/ingest/otelspike_test.go, spkLogRecords and friends)
// without changing the shape it emits.
//
// Shape notes the generator encodes:
//
//   - the standard attributes (session.id, app.version, app.entrypoint, the
//     organization/user identity attributes, terminal.type) ride on EVERY
//     log record and metric data point, not on the resource;
//   - every event's log body is the event name ("claude_code.tool_result");
//   - tool_decision and tool_result come in pairs sharing a tool_use_id and
//     the request_id of the model call that asked for the tool;
//   - prompt text (OTEL_LOG_USER_PROMPTS), tool parameters
//     (OTEL_LOG_TOOL_DETAILS) and the vcs.repository.* attributes
//     (OTEL_METRICS_INCLUDE_REPOSITORY) appear only under their flags;
//   - logs are batched one export per 5 s window that has a record (the SDK's
//     default OTEL_LOGS_EXPORT_INTERVAL), metrics one export per minute with
//     delta temporality.
package ccfixture
