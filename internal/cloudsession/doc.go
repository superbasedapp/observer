// Package cloudsession is the pure planner behind `observer cloud-session`
// (Rail S of the cloud-agents arc, docs/cloud-sessions.md; plan of record
// docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md
// section 7, decisions CA-D7, CA-D8 and CA-D9).
//
// Rail S runs the ordinary Observer inside a vendor's managed cloud sandbox
// as a short-lived node with no daemon. The sandbox keeps files but not
// processes, so:
//
//   - `observer cloud-session init` writes repository files for one agent
//     (hooks config, a setup script that installs a pinned, signature-checked
//     observer, the vendor's setup-step file) as a diff the developer reviews
//     and commits. This package renders those files; it never writes them.
//   - The committed hooks call the existing `observer hook <tool> <event>`
//     and `observer cloud-session flush`, each gated on the vendor's cloud
//     marker so the same committed config is a no-op on a developer machine.
//   - `observer cloud-session flush` scans the VM's own agent store with the
//     existing adapters, builds the existing org push envelope from the local
//     database and hands it to a destination. This package decides WHETHER a
//     flush runs (marker table, trigger cadence) and WHERE it goes (the
//     destination table); the envelope and the delivery live elsewhere.
//
// Lane CA-C2 adds two opt-in init features (agents.go Feature; off, init
// writes exactly what it wrote before):
//
//   - --guard: the signed sandbox policy file (policy.go: the org's guard
//     bundle and budget document, or a policy the owner's node signs), the
//     gate entries and their per-vendor dialect and fail-closed tables
//     (gate.go), and the soft budget stop at prompt submit (budget.go). The
//     committed gate verifies the file against the key pin and digest its
//     command carries and evaluates it with no network call.
//   - --mcp: Observer's MCP server in the repository MCP config, or the JSON
//     to paste where the vendor keeps it elsewhere (mcp.go), and the setup
//     script's post-install step that builds its database in the snapshot.
//
// Every decision here is a table walked top-down: the agent table (Agents),
// the cloud-marker table (each agent's Markers), the destination table
// (Destinations) and the flush-trigger table (Triggers). Nothing branches on
// a tool name (CLAUDE.md module rules #3 and #5). The CA-C2 tables join
// them: the policy check table, the gate dialect and failure tables, and the
// budget skip and window tables.
//
// The package is PURE (CLAUDE.md module rule #1): no os, os/exec, net,
// net/http, database/sql or fsnotify; environment lookups and file contents
// are passed in. Its one internal import beyond textdiff and integration is
// the wire contract internal/orgcontract, which owns the policy-bundle and
// budget signing messages, so the sandbox verifies with the same recipe the
// org signs with. The ONE egress package of this feature is
// internal/cloudsessionnet, pinned by
// tests/invariant/cloudsession_egress_test.go.
package cloudsession
