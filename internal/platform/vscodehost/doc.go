// Package vscodehost is the ONE owner of "how does the VS Code user-data
// layout look under this home directory" for every VS Code-family editor
// this codebase cares about — not just upstream "Code".
//
// Before this package existed, four adapters each hand-rolled the same
// per-OS switch over crossmount.HomeRoot for exactly one product:
// internal/adapter/cline (Code), internal/adapter/copilot (Code),
// internal/adapter/kilocode (Code + the .vscode-server remote layout), and
// internal/adapter/cursor (Cursor). None of them covered the other VS Code
// forks an extension can also be installed into — Code - Insiders,
// VSCodium, Windsurf, Kiro, Qoder, Trae — so an extension-hosted adapter
// silently missed every session recorded inside a fork host (audit finding
// IDE-14). This package generalizes the convention into one product table
// and one set of path builders so every consumer enumerates the same forks
// the same way.
//
// # The VS Code user-data convention
//
// Every product in the table follows the same per-OS root, with the
// product's directory name substituted in:
//
//   - Windows:            <home>/AppData/Roaming/<Dir>/User
//   - Windows (native):   %APPDATA%/<Dir>/User (when the process itself is
//     running natively on Windows against its own home — the same
//     native-home override every existing hand-rolled helper applies, so a
//     roaming profile relocated off the default drive is still found)
//   - macOS:               <home>/Library/Application Support/<Dir>/User
//   - Linux:               <home>/.config/<Dir>/User
//   - Remote server:       <home>/<server-dir>/data/User (VS Code Server /
//     Cursor Server layouts reached over SSH, WSL, or a dev container —
//     same subpath on every OS, since the server always runs on a
//     POSIX-shaped remote regardless of what OS the client desktop is on)
//
// globalStorage and workspaceStorage are subdirectories of that User dir;
// GlobalStorageDirs and WorkspaceStorageDirs append them.
//
// # Host-token contract
//
// Each Product carries a lowercase Host token meant to be paired with
// models.SessionSurface / models.SurfaceIDE — e.g. Host "vscode" for
// desktop Code, "cursor-remote" for a Cursor Server session. Consumers stamp
// this token as-is; it is never derived from source identity elsewhere
// (CLAUDE.md Module Boundaries #3). ProductForPath goes the other
// direction: given a concrete path an adapter is already reading (a
// globalStorage or workspaceStorage entry it discovered), it recovers which
// Product that path belongs to by sniffing the product-directory path
// segment, so an adapter that enumerates UserDirs/GlobalStorageDirs once
// can still stamp the right host per file without re-deriving the OS
// convention itself.
//
// # Consumers
//
// internal/adapter/cline, internal/adapter/copilot,
// internal/adapter/kilocode (the legacy Code-extension half), and
// internal/adapter/cursor are the intended callers; they replace their
// hand-rolled per-product helpers with calls into this package. This
// package never imports any of them (CLAUDE.md Module Boundaries #1): it is
// pure, taking only a crossmount.HomeRoot and returning plain strings.
package vscodehost
