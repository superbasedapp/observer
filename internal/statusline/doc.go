// Package statusline is the pure rendering core behind `observer
// statusline` and, indirectly (via a hand-kept sibling literal — see
// wordmark.go), the VS Code status bar's wordmarked cost text
// (docs/plans/observer-statusline-plan-2026-07-30.md).
//
// This package answers one question: given whatever data happens to be
// available this invocation (a Claude Code statusLine stdin-JSON payload,
// a daemon-sourced cost tile, both, or neither), produce EXACTLY ONE line
// of text for a host tool's status bar. It never fabricates a datum that
// wasn't supplied — an absent figure OMITS its segment entirely rather
// than rendering a misleading "$0.00" (plan §4.1) — and it never prints
// savings/percentage language of any kind (plan §4.2, the same honesty
// discipline internal/oneshot's render_test.go pins for `observer usage`).
//
// This package is PURE (CLAUDE.md "Module Boundaries" #1): it holds no
// database/sql, net/http, os/exec, or github.com/fsnotify/fsnotify import,
// and it does not import internal/store, internal/db, or
// internal/intelligence/cost — imports_test.go pins the forbidden set.
// Every piece of I/O this feature needs (reading stdin, dialing the
// daemon over loopback with a bounded timeout, checking the daemon
// lockfile) happens at the cmd/observer/statusline.go boundary; that seam
// maps raw bytes and an HTTP response into the plain Input / DaemonTile
// value types defined here (CLAUDE.md #2: one seam, no type leakage past
// it).
//
// The four files:
//
//   - wordmark.go defines the single Wordmark constant printed on every
//     render, degraded or not.
//   - input.go defines Input (the parsed Claude Code statusLine stdin-JSON
//     shape) and ParseInput / ParsePayload, a tolerant parser: unknown
//     fields are ignored, every field is optional-representable (nil,
//     never a fabricated zero), and malformed/non-JSON input returns an
//     error alongside a still-usable zero Input the caller can render
//     from. The other hosts' payloads (Kimchi's nested session{}, VT
//     Code's session-less payload) are detected by a table of shapes and
//     normalized onto the same Input.
//   - segments.go defines DaemonTile (the small slice of the lean
//     `/api/statusline` daemon response this package needs), the ordered
//     segment-kind vocabulary ("wordmark", "session", "today", "model"),
//     and one render function per segment kind.
//   - render.go defines RenderOptions and Render, which walks the
//     requested segment list, keeps only the segments with data, joins
//     them per the plan §4.1 output design, and applies color only when
//     asked.
package statusline
