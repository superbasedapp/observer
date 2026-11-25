// Package dblease provides a flock-based, cross-process advisory lease so
// multiple independent `observer` processes (proxy, watcher, dashboard,
// backfill, or several daemons pointed at the same DB) don't each
// independently run the same heavy maintenance pass at once (T2.3,
// docs/plans/observer-disk-compute-remediation-plan-2026-08-26.md P1-F).
//
// It is deliberately narrow: one function, no retries, no queueing. A
// caller that fails to acquire a named lease is expected to skip its own
// pass for this round and let whichever process holds the lease do the
// work: never to wait or block, and never to treat a lease error as a
// reason not to proceed (fail-open; see [TryAcquire]'s doc comment).
//
// Pure-ish per the module boundary discipline (CLAUDE.md "Module
// Boundaries"): file I/O only, no database/sql, no net/http, no fsnotify.
package dblease
