// Package guilaunch composes the ARGV and the routing-wrap ENVIRONMENT for a
// detached GUI-app launch (docs/plans/ide-desktop-launch-plan-2026-09-03.md
// §2.4). It answers exactly one question — "given this registry row, this
// resolved binary and this host shape, what do we exec and with what extra
// environment?" — and returns a plain Plan. It never spawns anything: the one
// exec seam is cmd/observer's guiLauncher.
//
// The package is PURE (CLAUDE.md "Module Boundaries" #1): no os/exec, no
// database/sql, no net/http, no fsnotify, no filesystem. Every host fact
// arrives as data on Inputs (GOOS, the resolved binary, the project root, the
// proxy URL, whether the launch crosses the WSL interop boundary), so every
// row of both decision tables is table-testable.
//
// Two tables drive it, per CLAUDE.md #5 — an ordered rule set, never an
// if-ladder:
//
//   - launchRules pick the launch MECHANISM by shape: a macOS .app bundle
//     (`open -a`), a Windows packaged app (`explorer.exe shell:AppsFolder\…`),
//     or a plain executable. A project directory is appended only for a row
//     that declares ProjectDirArgv; on a row that does not, a requested
//     directory is IGNORED with a Note, never an error (the operator asked for
//     an app that takes no such argument).
//   - wrapRules resolve the WrapKind into (Env, WrapApplied, WrapNote). The
//     honest-zero rule is strict: a wrap is reported APPLIED only when the
//     variables actually reach the child. An interop launch (no WSLENV), an
//     explorer-launched packaged app, a config-file route the launch does not
//     write, and a WrapNone row all record WrapApplied=false with the grounded
//     reason — never a silent claim that routing took effect.
package guilaunch
