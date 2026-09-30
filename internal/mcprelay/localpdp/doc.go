// Package localpdp is the node relay's local policy decision point: it
// evaluates the compiled node decision table (mcpaccess.CompileNodeTable)
// that the four-gate accept (internal/orgclient/policyresource.go, family
// tools.mcp_access) verified, so node-local stdio servers get the SAME
// policy the org gateway enforces (doc3 §12.4, §11.7 W4c).
//
// Shape: the Request / Decision / Decider types mirror internal/mcpgw/pdp's
// but are node-scoped and this package never imports internal/mcpgw (the
// reverse-import boundary; pinned by imports_test.go). It is a PURE package
// per CLAUDE.md §1: no database/sql, net/http, fsnotify, store or orgclient;
// the only I/O is Cache, which writes ONE derived file beside the guard
// org-bundle cache through internal/fsatomic.
//
// Decision order (engine.go, fixed): table availability -> method dispatch
// (tasks/* are STRIPPED in v1, R8.27.b) -> vserver -> addressed name ->
// require invariants + grant evaluation -> observe/enforce. Only the grant
// evaluation is a POLICY verdict subject to observe-mode would-deny
// (R8.27.h); every other refusal blocks in both modes.
//
// Attestation (attest.go): the node never trusts a self-claimed client
// attestation above what the transport proves. The transport -> attestation
// mapping is a table, and the effective value is the LOWER of the transport's
// and the claimed rank, so product-scoped grants are honoured only at
// process_attested (stdio wrapper) / ipc_bound (owner-only IPC) - exactly the
// R2 rule mcpaccess.subjectMatches enforces.
package localpdp
