// Package cline holds the pure drivers of Cline Cloud Agents (Cline Cloud
// sessions) on api.cline.bot (lane CA-V6, cloud agents arc; plan
// docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md,
// connector cline-cloud; spec: the Cline section of
// docs/plans/cloud-agents/grounding/wave-c-vendors-2026-11-01.md).
//
// The session API is NOT publicly documented. Every surface here is read
// from the vendor's own client: the type declarations and compiled code of
// npm @cline/core 0.2.0 (dist/cloud/api.d.ts, dist/cloud/index.js), the
// message type of npm @cline/shared 0.2.0 (dist/llms/messages.d.ts), and the
// VS Code extension source on github.com/cline/cline main at
// a6507a62a147db4a35e27f4294589742ccac5060 (apps/vscode/src/sdk/
// sdk-cloud-session-coordinator.ts, apps/vscode/src/shared/cloud/
// cloud-sessions.ts). The connector carries the coverage level "Observed in
// vendor client, undocumented" (internal/cloudagents grounding table): the
// shapes can change without notice, so each surface has a schema-drift test
// (cline_test.go TestSchemaDrift*) and every fixture sidecar records the
// package version and the commit it was read from.
//
// Three surfaces are built, all "synthetic, awaiting live validation":
//
//   - cline.cloud.sessions: GET /api/v1/session, the account's cloud
//     sessions ({data: [CloudSessionRecord]}); one snapshot per session.
//   - cline.cloud.session_status: GET /api/v1/session/{id}/status
//     ({data: {sessionId, status, phase, statusReason}}); one snapshot.
//   - cline.cloud.session_history: GET /api/v1/session/{id}/history, the
//     archived conversation ({version: 1, messages: [MessageWithMetadata]},
//     NOT wrapped in data; HTTP 404 means no archive yet). Messages land as
//     metadata-only content items and tool-call rows; the per-message
//     metrics land as ONE session usage row, and only when a message carries
//     a figure (absent, never zero).
//
// All three authenticate with a Cline API key as Bearer (created at
// app.cline.bot, Account > API Keys; live check 2026-11-02). Text
// fields (titles, prompts, message text, tool input and output, status
// reasons) are never decoded: the closed DTOs have no member for them. The
// drivers are consumed by the node cloud-agents connector through the node's
// own egress package (internal/cloudagentsnet); they have no entry in the org
// driver table. A driver here never touches SQL, logs or HTTP: Build returns
// a path, ParseResponse turns one response into a vendorapi.Page.
// imports_test.go pins the package pure.
package cline
