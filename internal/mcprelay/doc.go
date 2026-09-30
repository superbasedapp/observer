// Package mcprelay is the node-side Agent Access relay (doc3 §12.2/§12.3,
// wave P4 W4b): the ONE mediation point between an AI client's MCP traffic
// on this node and either a node-local stdio MCP server or the org's public
// MCP policy front (internal/mcpgw/mcpfront on :8851).
//
// Three serving modes, one core (Relay.Handle):
//
//   - stdio wrapper (ServeStdioWrapper, PRIMARY - finding-28): the AI client
//     spawns `observer mcp relay --server <id>` in place of the original
//     stdio server. The wrapper spawns the ORIGINAL server from the approved
//     launch spec (cwd / env / signals preserved), relays newline-delimited
//     JSON-RPC frames BYTE-EXACTLY in both directions, and mediates every
//     client request through the local PDP + the decision/completion record
//     BEFORE the child ever sees it. Because the client spawned it, the
//     wrapper can attest its parent (Attestor, R8.24.o): a verified parent
//     yields `process_attested`; any unknown / racy / unsupported case
//     DOWNGRADES to `configured`. The original config is restored from the
//     crash-safe launch journal (R8.18) on disable/uninstall.
//   - ipc (ServeIPC): an owner-only endpoint - internal/attachsock's
//     Transport seam, an AF_UNIX socket under a 0700 directory on unix, an
//     owner-only DACL named pipe on Windows; never a new primitive - plus a
//     per-client bootstrap secret on the first frame -> `ipc_bound`.
//   - loopback (ServeLoopbackHTTP): the streamable-HTTP relay a client's
//     `superbased-relay` remote entry points at (`/mcp/<vserver>`); loopback
//     HTTP cannot attest its caller, so it is the node-wide `configured`
//     principal.
//
// For a REMOTE vserver the relay (1) resolves the vserver, (2) obtains a
// short-lived token from the org STS through TokenClient (RFC 8693 token
// exchange: subject = the enrolment bearer, actor = an sbo-actor+jwt signed
// by the `agent-access-key` keychain slot, a token-endpoint DPoP proof by the
// SAME key - the relay ALWAYS mints DPoP-bound tokens, R9.1), (3) sends
// `Authorization: DPoP <at+jwt>` + a per-request `DPoP:` proof carrying the
// `sbo_corr` claim {call_id, coding_session_id, turn_ref, action_ref}
// (R11.8), (4) refreshes early and transparently, rotating-and-retrying ONCE
// on a 401 invalid_token. The access token lives in memory only: no keychain
// slot, no file, never logged.
//
// Records (record.go, R12.7/R14.4): the decision record is appended to Lane
// N-M's node store seam BEFORE the forward and the completion AFTER; a failed
// append in async mode fsyncs+renames the `mcp-relay-loss.json` sidecar
// FIRST and forwards only after that commit (blocks if the sidecar fails
// too); strict mode blocks on any append failure.
//
// Boundaries: the package owns net/http (it IS a relay) and os/exec (the
// wrapper spawns the original server) but never database/sql or fsnotify,
// and never imports internal/orgserver or internal/mcpgw (imports_test.go
// pins it) - every store is an injected seam.
package mcprelay
