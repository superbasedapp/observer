// Package pathnorm normalizes path strings that arrive from external
// sources (AI tool session logs, hook stdin payloads, SQLite columns)
// into a canonical form the current process can use for filesystem
// operations and git.Resolve.
//
// Why: every adapter today builds its own path-handling — claudecode
// has TranslateForeignPath, copilot has decodeFileURI, antigravity
// has decodeFileURIToPath, the rest just store paths verbatim. When
// an upstream tool changes the shape it emits paths in — file://
// URIs, surrounding quotes, Git Bash drive prefix, UNC paths, etc. —
// the ad-hoc handlers fail silently and the adapter mis-attributes
// the session. This package centralises path normalisation so every
// adapter benefits from the same robustness.
//
// Design constraints:
//
//   - NEVER returns an error. Every layer has a "pass through as-is"
//     fallback so an unrecognised format ends up the same as it would
//     today (best-effort downstream consumption).
//   - Pipeline is a fixed sequence of transforms. Each layer is a
//     no-op when its trigger doesn't match.
//   - Format detection runs as a side effect of the pipeline; callers
//     who want to telemeter the source format use NormalizeWithFormat.
//
// Pipeline order:
//
//  1. Trim ASCII whitespace.
//  2. Strip matched surrounding quotes (`'...'` or `"..."`).
//  3. Decode `file:` URIs (case-insensitive scheme): `file:///C:/x`,
//     the authority-less `file:/C:/x`, and the malformed `file://C:\x`
//     a caller builds by prefixing `file://` to a bare Windows path.
//  4. Strip Windows extended-length prefix (`\\?\`).
//  5. Rewrite UNC-to-WSL (`\\wsl.localhost\<distro>\...` and
//     `\\wsl$\<distro>\...`) when the distro matches
//     $WSL_DISTRO_NAME on a Linux host.
//  6. Rewrite Git Bash drive prefix (`/c/`, `/d/`, etc.) to
//     `/mnt/c/`, `/mnt/d/`, etc. on non-Windows hosts.
//  7. Rewrite Windows drive-letter absolute (`C:\foo`, `C:/foo`,
//     `c:\foo`) to `/mnt/c/foo` on non-Windows hosts. A leading slash
//     in front of the drive letter (`/c:/foo` — the `Uri.fsPath`
//     spelling VS Code / Cursor emit) is stripped first so that shape
//     canonicalises to the SAME `/mnt/c/foo`; without it one
//     directory splits into two project identities.
//  8. Expand `~/` and `~` to $HOME on POSIX hosts (NOT `~user/`,
//     NOT environment variables — too unsafe).
//  9. Classify the result for the returned Format value.
//
// Output is always forward-slash on non-Windows (matches WSL/POSIX
// convention). Windows separators are preserved when running on
// Windows itself (Go's filesystem APIs accept both, but staying
// native is friendlier to Windows-side log output).
package pathnorm
