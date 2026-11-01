// Package hookliveness answers "did the hooks Observer registers actually
// fire?" (surface-gap review 2026-10-25, findings OBS-7 and CC-2, Wave 5
// item 1). It is pure logic: no SQL, no HTTP, no fsnotify (pinned by
// imports_test.go). The rows come from the node-local hook_activity table
// (agent migration 198), which only the daemon's hook spool drainer writes
// (internal/store/hookactivity.go::UpsertHookActivity); the registry's hook
// bindings and the captured sessions are handed in by the caller (the doctor
// row hooks.liveness in internal/diag).
//
// Three pieces:
//
//   - Classify walks an ordered rule table per tool (toolRules) and one per
//     registered or observed event (eventRules), so "registered", "seen"
//     and "never seen" are each one row with one test case. It generalises
//     the Cursor-only "registered but silent" rule of internal/cursorusage
//     to every tool with hook bindings.
//   - EnvClasses records the route-relevant environment variable NAMES a
//     hook process saw, each reduced to a coarse class (EnvProbes). A value
//     never leaves this package: a URL becomes loopback / provider_direct /
//     other_host / invalid, a toggle on / off / set, a config directory a
//     16-hex hash.
//   - PayloadSessionID reads the session id a hook payload carries with a
//     streaming decode that stops at a session_id key, so the hook path
//     pays almost nothing for it; other spellings follow one precedence
//     order (sessionKeys).
//
// # The unattributed bucket
//
// An invocation whose payload carried no session id lands in the row with
// an empty session_id. That row proves the tool's hooks run on this node; it
// never proves any one session's hooks ran, and no rule here reads it as if
// it did (rule unattributed_only says so out loud).
//
// # Out-of-file switches (W-3b reconciliation)
//
// A switch that turns hooks off from the command line or the environment
// (DimCode --no-hooks / DIM_DISABLE_HOOKS, Cortex --setting-sources, VT Code
// exec, Autohand --bare) is in no file internal/hookdisable can read. Its
// only trace is silence: sessions captured with no hook activity. Rules
// hooks_never_seen and hooks_silent_on_surface are that reconciliation, and
// OutOfFileSwitches names the switch a developer should look for.
package hookliveness
