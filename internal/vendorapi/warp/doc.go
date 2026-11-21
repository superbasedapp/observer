// Package warp holds the pure drivers of the Warp Agent API (lane CA-V1,
// cloud agents arc; docs/plans/cloud-agents/grounding/wave-c-vendors-2026-11-01.md
// section 1, connector warp-cloud).
//
// Four surfaces are built, all written from Warp's own OpenAPI document
// (github.com/warpdotdev/docs at 4aa3f12, developers/agent-api-openapi.yaml),
// never from a live response, so all are "synthetic, awaiting live
// validation":
//
//   - warp.agent_api.runs_list: GET /api/v1/agent/runs, the runs the key can
//     see, always asked with execution_location=REMOTE (the same list also
//     carries runs executed in the user's local Warp app, which the local
//     side owns);
//   - warp.agent_api.run_detail: GET /api/v1/agent/runs/{runId};
//   - warp.agent_api.run_conversation: GET
//     /api/v1/agent/runs/{runId}/conversation, the normalized conversation;
//   - warp.agent_api.run_harness_usage: GET
//     /api/v1/agent/runs/{runId}/harness-usage, the latest cumulative native
//     token counters of a Claude Code or Codex harness run.
//
// Every surface authenticates with a Warp API key (or a Warp-issued user
// token) as Bearer on app.warp.dev. The run transcript route
// (/agent/runs/{runId}/transcript, a 302 to a time-limited download URL off
// the host) has no driver here: it is never fetched.
//
// The drivers are consumed by the node cloud-agents connector through the
// node's own egress package; they have no entry in the org driver table. A
// driver here never touches SQL, logs or HTTP: Build returns a path and a
// query, ParseResponse turns one response into a vendorapi.Page.
// imports_test.go pins the package pure.
package warp
