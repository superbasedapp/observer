// Package contentcap caps free-form text bodies (tool inputs and outputs)
// at a safe upper bound before they reach the store, appending a marker
// when truncation occurred so downstream consumers can tell the
// difference between "exactly N bytes" and "≥ N bytes, the rest is gone".
//
// The cap is a defensive belt against pathological rows — an operator
// running `cat /var/log/syslog` through their AI tool can produce a
// multi-MB tool_output that, stored unbounded, would balloon SQLite's
// page count and slow every subsequent query. Adapters call Cap at
// emit time so the in-memory ToolEvent is bounded; the store layer
// trusts the bounded value.
//
// The marker is human-readable (mirrors cmd/observer/backfill_run.go's
// `…(output truncated at 1 MiB)…` pattern) so an operator copying
// the body sees immediately that they're looking at a truncated tail.
package contentcap
