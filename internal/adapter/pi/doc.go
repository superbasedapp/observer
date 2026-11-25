// Package pi implements an adapter for Pi (pi.dev), the pi-mono coding
// agent, reading its session transcripts.
//
// # Format and roots
//
// Pi writes one JSONL file per session, per upstream docs/session-format.md
// (v3), at ~/.pi/agent/sessions/--<path>--/<timestamp>_<uuid>.jsonl. The
// sessions subpath is the same on every OS and is watched under every
// cross-mount-resolved home (a WSL2 observer reads /mnt/c/Users/<u>/.pi and
// the reverse); PI_CODING_AGENT_DIR adds <agentDir>/sessions on the native
// side. The session id is the file name's trailing UUID, which equals the
// `session` line's id, so it stays stable across incremental re-parses that
// seek past that line. The cursor is a byte offset.
//
// # What is captured
//
// The user, assistant, toolResult and bashExecution message roles. A
// terminal stopReason (stop, length, error, aborted) emits a task_complete
// row with success=false for the failures; a mid-turn toolUse pause is
// skipped. Thinking content blocks become PrecedingReasoning. The
// `session` line's cwd is resolved through git.ResolveIdentity onto
// GitBranch / GitRemote and the project identity bundle
// (adapter.ApplyProjectIdentity).
//
// # Tokens
//
// Each assistant message's usage (input, output, cacheRead, cacheWrite)
// becomes one TokenEvent with Source jsonl and Reliability approximate, and
// usage.cost.total is carried as EstimatedCostUSD. The counts are taken as
// the record states them; no netting is applied.
//
// docs/adapters.md carries the operator-facing row for this adapter.
package pi
