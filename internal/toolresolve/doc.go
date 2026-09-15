// Package toolresolve is the pure resolution ladder that decides WHERE a
// launchable AI-tool binary lives and CLASSIFIES the result into an honest
// verdict the launcher, doctor, and dashboard render identically.
//
// It exists to fix a live class of failure (docs/audits/
// opencode-wsl-troubleshooting-note.md): a WSL daemon whose frozen PATH
// resolved a Windows npm interop shim under /mnt (which crashes under Linux
// node) instead of the native binary — which itself lived off the daemon's
// PATH in an npm/volta/nvm prefix. Resolve walks a merged PATH (process +
// login-shell), then a table of common native probe dirs, then — on WSL —
// the Windows user homes reachable over /mnt, and returns a Verdict:
//
//   - ok            native, first on PATH
//   - ok_off_path   native, found via a probe dir or login-only PATH entry
//   - shadowed      native on PATH but a /mnt interop shim precedes it
//   - foreign_only  only a Windows install exists — NOT launchable here
//   - not_found     nothing anywhere
//
// Two facts the resolver reports alongside the verdict serve the EXECUTION
// side (the launcher), not the resolution side:
//
//   - Resolution.LoginOnlyDirs — the merged-PATH dirs the login shell
//     contributed that the daemon's own process PATH lacks. A launcher
//     prepends them to the child's PATH; MergedPathDirs exposes the same
//     merge to callers that need it before a Resolve.
//   - Resolution.Interpreter — the `#!/usr/bin/env <name>` interpreter of the
//     chosen binary. An npm shim launched by a daemon whose PATH lacks node
//     starts fine and dies at exit 127; when the interpreter is off the
//     process PATH the resolver says so in a Note rather than letting the
//     launch fail silently later.
//
// The package is PURE (CLAUDE.md "Module Boundaries" #1): all I/O — stat,
// symlink evaluation, globbing, and the login-shell PATH capture — is
// injected through the Env struct. imports_test.go pins it free of
// database/sql, net/http, os/exec, fsnotify, and even os. The impure
// production Env is built by the sibling internal/toolresolve/host package;
// per-tool facts (binary spellings, extra probe dirs, install hints) are
// registry DATA on integration.BinaryResolveSpec — Resolve dispatches on
// that capability shape, never on tool name (CLAUDE.md #3).
package toolresolve
