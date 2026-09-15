// Package runstate reconciles stale in-flight records to a terminal state.
//
// Several node-local surfaces persist an in-flight lifecycle status that is
// only ever advanced by the process that owns the work: an Arena candidate is
// stamped "running" by its driver goroutine and moved to done/failed/timeout
// when the harness exits; an Arena run walks pending -> running -> judging ->
// complete; a dashboard terminal run is "live" while its PTY is attached. When
// the owning goroutine or the whole daemon dies without finalizing the row, the
// record is stranded in its in-flight status forever and the history lies about
// what is still live (a candidate shows "running" ten days later; a terminal
// attach row stays "running" across a crash).
//
// This package is the single, pure decision authority that maps such a
// stranded record to its reconciled terminal status. It is table-driven per
// CLAUDE.md module-boundary discipline #5: the rules are an ordered data table
// walked top-down, one Rule per row, and callers supply the observable Signal.
// It performs no I/O — no database/sql, net/http, or fsnotify — so the store
// seams and dashboard read paths that apply it own all persistence and
// liveness discovery; this package only decides.
package runstate
