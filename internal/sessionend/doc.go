// Package sessionend decides a session's end time from its lifecycle
// actions. It is pure logic (no SQL, no HTTP, no fsnotify; pinned by
// imports_test.go). The node store (internal/store/sessionlifecycle.go)
// loads a session's latest close / reopen timestamps and writes
// sessions.ended_at at ingest; any other reader that must agree with the
// node (e.g. an org-side derivation from the shipped session_end actions)
// applies the same EndedAt rather than re-deriving it.
//
// The decision is by EVENT TYPE, never by tool: every adapter that emits a
// session_end action (claude-code, cursor, copilot-cli, cline-cli, hermes,
// muse, poolside) closes its session the same way, and a later human turn
// (user_prompt) or session_start reopens it, which is how a resumed session
// that reuses its id reads as live again instead of ending in the past.
package sessionend
