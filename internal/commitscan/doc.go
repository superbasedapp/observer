// Package commitscan is the daemon-lifetime read-only git-commit-history
// scanner (docs/plans/projects-page-roi-and-commit-alignment-plan-2026-09-21.md
// §2 R2, §3.2).
//
// It polls every ACTIVE project root on a ticker, HEAD only, via a single
// injected exec seam (internal/gitview.RunReadOnly in production), parses
// the output with internal/commitlog.ParseLog, and hands the result to an
// injected store sink (internal/store.UpsertCommits). It never installs a
// git hook and never writes to a repository.
//
// PURE ORCHESTRATION (CLAUDE.md module-boundary rule #1): no database/sql,
// no net/http, no fsnotify, no os/exec and no internal/store import —
// every dependency (which roots to scan, how to run git, where scan state
// lives, where parsed commits land, how reachability is revalidated) is a
// plain func on Options, injected by the host (cmd/observer). Pinned by
// imports_test.go.
//
// Failure handling is fail-soft throughout: a root that errors is logged,
// its failure recorded in its own durable State (so the doctor / page
// capture-banner surfaces can read it back), and retried on a later tick
// with exponential backoff — never fatal to the scanner or to a sibling
// root's scan. Git being entirely unavailable is the one process-wide
// condition: after the first Exec call reports it, the scanner logs one
// WARN and stops attempting further scans for its remaining lifetime
// (R9 — "no git => scanner idle").
package commitscan
