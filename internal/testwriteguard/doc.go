// Package testwriteguard keeps a `go test` binary from writing an AI tool's
// config file outside the OS temp directory. It is the one test-write guard:
// every writer of a hook, MCP or proxy-route config (and the cmd/observer
// config writers) calls Check before it creates, writes, renames or removes
// a file.
//
// INCIDENT 2026-10-20: a live check on the operator's Windows laptop found
// hook entries that ran a `go test` binary from WSL in the operator's REAL
// Windows ~/.qwen, ~/.qoder, ~/.gemini and ~/.factory configs. INCIDENT
// 2026-10-21: a cmd/observer test run inside WSL rewrote the real Windows
// C:\Users\<u>\.claude\settings.json so that every Claude Code hook ran the
// (since deleted) test binary. The read-side guard in
// internal/platform/crossmount keeps a test binary from DISCOVERING a foreign
// home, but it has a deliberate escape hatch for read-only adapter grounding,
// and a path can reach a writer in other ways (a pinned home, a caller's own
// resolution). This is the WRITE-side guard: inside a test binary Check
// refuses an empty path, a path under a real foreign-OS mount
// (crossmount.RealForeignMountRoots) and any path outside os.TempDir()
// (where every t.TempDir lives). Outside a test binary it never refuses. No
// environment variable opens it.
//
// A refusal is an *fs.PathError wrapping ErrRefused, so the writers'
// credential-file error filters (credfile.Withhold and the hook package's
// equivalent) pass its message through unchanged, and callers and tests can
// match it with errors.Is. A refusal is also recorded, so Run (called from a
// package's TestMain) fails the package run even when the calling test only
// logged the error.
//
// The two guards built for the two incidents (crossmount.CheckTestWrite and
// this package's first Check) were merged here on 2026-10-25 (R-160): one
// rule table, one record, one error.
package testwriteguard
