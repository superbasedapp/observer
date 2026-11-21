// Package otelident is the one owner of the OpenTelemetry identity
// vocabulary that more than one plane reads: Observer's echo marker (the
// resource attribute Observer stamps on telemetry it exports itself, so no
// receiver reads it back in) and the hosted-app identity contract (plan of
// record docs/plans/plane-a-sdk-buildout, §3 principle 3, task W1a-2).
//
// The identity contract, per trace:
//   - service: from the RESOURCE only (ServiceKeys);
//   - end user (PII), session and the customer's own tenant: per trace, with
//     a per-span override; a span-level value beats a resource-level value
//     (FieldSet records which level each value came from);
//   - environment and release: same precedence as end user;
//   - tags (bounded list) and metadata (bounded map).
//
// Org, workspace and the Observer environment come from the ingest
// credential, never from these attributes.
//
// Plane A maps traces with these keys; the Plane B own-agent claim
// (internal/ownagent) uses HostedAppKeys to keep a hosted application's
// resource out of the developer plane (PT-55). One list, so the planes can
// never disagree about what a hosted app looks like.
//
// The package is data plus pure helpers: no SQL, no HTTP, no fsnotify, no
// OTel types (pinned by otelident_test.go), so every plane, edition and build
// can import it.
package otelident
