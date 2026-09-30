// Package shellwrap plans the "wrapped command" shell integration (backlog
// item 7): an opt-in setting that makes typing a vendor command - `claude`,
// `codex`, `code` - run its observer-wrapped form (`observer claude`,
// `observer ide vscode`) instead.
//
// Mechanism (decided 2026-09-27, see docs/proxy-wrappers.md "Command
// wrapping"): observer writes small SHIMS - one executable per replaced
// command name - into an observer-owned directory (default
// ~/.observer/shims), and puts that directory first on PATH through a
// clearly delimited, idempotent, removable block in each selected shell's
// start-up file (bash / zsh: a marked block appended to the rc file; fish: an
// observer-owned conf.d file; PowerShell: a marked block in the profile). A
// PATH shim, unlike an alias or a shell function, also reaches
// non-interactive children (scripts, editors started from the shell) and is
// one mechanism across every shell.
//
// Safety properties the renderers carry, each pinned by a test:
//
//   - Never locked out. A shim whose observer binary is missing runs the real
//     vendor command instead; SBO_SHIM_BYPASS=1 always runs the real command.
//   - No recursion. A shim resolves the real command by walking PATH while
//     skipping its own directory and any file carrying ShimMarker; the
//     observer launchers skip shims the same way (internal/toolresolve's
//     Env.ExcludeDirs / ExcludeMarker). As a last guard a shim that finds
//     SBO_SHIM_GUARD already naming itself (observer resolved back into the
//     shim) runs the real command.
//   - Exact undo. Removing a block restores the file byte-for-byte outside the
//     block, including a newline the insert had to add and a file the insert
//     had to create (RemoveBlock).
//
// The package is PURE (CLAUDE.md "Module Boundaries" #1): no os, os/exec,
// database/sql, net/http or fsnotify - pinned by imports_test.go. It plans
// and renders text; internal/shellwrap/host is the I/O applier. It dispatches
// on the capability shape integration.WrappedCommandFor returns (Kind, Args,
// Replaces, Routes, TrafficProven) and never on a tool name (CLAUDE.md #3/#5).
package shellwrap
