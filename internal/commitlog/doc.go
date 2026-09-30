// Package commitlog parses `git log` output into structured commits, for
// internal/commitscan's read-only capture of a project's commit history
// (docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md
// §2 R2, §3.1).
//
// It is a PURE package (CLAUDE.md module-boundary rule #1): no
// database/sql, no net/http, no fsnotify, no os/exec, and no
// internal/store import — the single git-exec seam is a new exported
// helper on internal/gitview (RunReadOnly, added in W2), and
// internal/commitscan wires that exec result into ParseLog. Pinned by
// imports_test.go.
//
// Args builds the argv (after "git" itself) for the one invocation this
// package understands; ParseLog decodes its output. Both agree on ONE
// tformat/--numstat layout (see Args's doc comment on logFormat) so a git
// log invocation elsewhere in the tree cannot silently drift out of sync
// with the parser.
//
// The join key between a commit's files and file_changes (the AI-edit
// ledger) is internal/loc.PathHash — see PathHash usage in parse.go and
// R3 in the plan above.
package commitlog
