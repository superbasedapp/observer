// Package oteldirect is the pure core of OTel-direct ingest
// (docs/plans/otel-direct-ingest-design-2026-11-16.md): a developer points an
// AI coding tool's own OpenTelemetry exporter at their organization, with no
// observer node on the machine, and the org server turns each OTLP export
// into the same push-envelope rows a node push lands.
//
// The package holds every decision of that path and no I/O:
//
//   - decode.go: the OTLP/HTTP body (protobuf or OTLP JSON, optionally
//     gzip, inflated size capped so a gzip bomb is safe) and the OTLP export
//     responses (partial_success only when something was rejected);
//   - tools.go: the closed tool table. The tool comes from the resource's
//     service.name through this table (provisional default 7: no per-token
//     tool binding); each row carries the tool's event vocabulary,
//     attribute keys, target rules and surface vocabulary as DATA, so the
//     mapper never branches on a tool name (CLAUDE.md rule 3);
//   - mapper.go: MapLogs, the logs-to-envelope mapper. Turns, content and
//     cloud-execution markers come from internal/otlpvendor (the same rows
//     the node's own OTLP receiver uses); actions and the per-export session
//     rows are synthesized here. Identity attributes in the export
//     (user.email, user.id, user.account_uuid, organization.id) are never
//     read: identity comes from the token, outside this package;
//   - admit.go: the closed admission table (sessions, actions, api_turns,
//     otel_content);
//   - posture.go: the metadata-only posture, which hashes every raw content
//     column into its *_hash counterpart exactly as the org ingest's
//     hashOrComputed would and clears the raw value;
//   - quota.go: the per-token request and row rate limiter, clock injected.
//
// The ccfixture subpackage builds a synthetic Claude Code export faithful to
// the vendor's documented schema for tests.
//
// Purity is pinned by imports_test.go: no database/sql, net/http, os or
// fsnotify.
package oteldirect
