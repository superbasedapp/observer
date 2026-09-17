// Package guidance discovers the AI-guidance files a project (and the
// operator's home) carries for each coding-agent tool Observer knows
// about — CLAUDE.md, AGENTS.md, .cursor/rules/*.mdc, skills, sub-agents,
// slash commands, and the handful of JSON config files that point at
// more instructions.
//
// The package is PURE (CLAUDE.md module-boundary rule #1): no
// database/sql, no net/http, no fsnotify, and no os outside the single
// fs_os.go adapter. Every filesystem read arrives through the injected
// [FS] interface, so the scanner is exercised in tests against an
// in-memory tree and in production against the real disk.
//
// Discovery is table-driven (rule #5): [Rules] is an ordered data table
// of (tool, glob, kind, scope) rows walked top-down, never a branching
// ladder, and every Tool value is an id that exists in
// internal/integration's registry — the one owner of Observer's closed
// tool vocabulary. Adding a tool's convention is adding a row.
//
// The scanner never retains file bodies: a body is read, hashed
// (sha256), mined for its front matter, and dropped. Only paths,
// names, descriptions, sizes and hashes leave the package — the same
// posture as the rest of Observer (CLAUDE.md "Don'ts": don't store file
// contents in the DB).
//
// One file matched by several tools' rows (AGENTS.md is read by a dozen
// harnesses) yields one [File] PER TOOL. That is intended: the question
// the feature answers is "what guidance does THIS tool see", and the
// store keys on (project_root, tool, scope, rel_path) accordingly.
package guidance
