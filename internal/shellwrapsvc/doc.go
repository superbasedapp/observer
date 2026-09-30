// Package shellwrapsvc is the I/O half of the "wrapped command" shell
// integration (backlog item 7). internal/shellwrap plans and renders; this
// package reads the machine (home, shell environment, the shim directory,
// the shell start-up files), applies a plan idempotently and reversibly, and
// records the operator's choice in [shell_wrap] of config.toml.
//
// It is the ONE writer of the shim directory and of the marked blocks in
// shell start-up files (CLAUDE.md #4). Both the CLI (`observer shell-wrap`)
// and the dashboard (POST /api/shell-wrap/apply, via a seam cmd wires) call
// Service; neither writes a file itself.
//
// Write discipline:
//
//   - Nothing is written unless the operator asked (Apply / Disable); Status
//     and a dry run only read. The daemon never calls Apply on its own. Its
//     one call is RefreshStale at `observer start`: with [shell_wrap].enabled
//     recorded, a marked shim for a recorded tool whose baked observer binary
//     is gone is re-rendered to run the running binary (one that still exists
//     is another install and is kept). It never creates a shim, adds a tool,
//     edits a start-up file or records config.
//   - Every file is written atomically (internal/fsatomic). A start-up file
//     keeps its permission bits; a symlinked one (dotfile managers) is edited
//     at its target so the link survives.
//   - A start-up file with malformed markers aborts the whole apply before
//     anything is written.
//   - Only files carrying shellwrap.ShimMarker are ever deleted from the shim
//     directory, and the directory itself only when empty.
package shellwrapsvc
