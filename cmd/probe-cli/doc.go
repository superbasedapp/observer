// Command probe-cli parses ONE antigravity-CLI .pb file via the
// production adapter and prints what ParseResult would look like —
// without persisting to the DB. Diagnostic tool for the 2026-05-23
// "bridge works but actions don't land" investigation.
//
// Usage: go run ./cmd/probe-cli /path/to/file.pb
package main
