// Package surfaceenrich is the daemon-side loop that stamps a capture
// surface onto sessions ANOTHER adapter already ingested, from the record
// of the layer that HOSTED them. It exists for orchestration hosts that
// keep no conversation of their own but do keep a pointer to the agent
// session they drove — today the JetBrains AI Assistant's
// `aia-task-history/<task>.agentsession` files (internal/platform/
// jetbrainshost). Such a host is not a capture adapter: building one over
// its UI-event log would double-count every agent's conversation and add
// no tokens or model the agent's own store lacks (the JetBrains .events
// files carry neither). What the host knows that the agent cannot is
// WHERE the session ran, and that is exactly one column pair —
// sessions.surface / surface_host — written through the hosted branch of
// Store.SetSessionSurface (models.SessionSurface.Hosted: host-wins over
// the agent's own self-report, empty never clears, identical no-op).
//
// # Why a loop and not a watcher adapter
//
// The watcher dispatches files to adapters and every registered adapter
// is a TOOL (registry row, EnabledAdapters entry, taxonomy, basename rows
// — tests/invariant/adapter_registry_sync_test.go pins all three in
// lockstep). A host that owns no sessions.tool value has no place in
// that machinery, and forcing it in would advertise a capture row for a
// product that captures nothing. So the enricher runs beside the watcher
// with the daemon's own store handle, on its own ticker, and stays
// inert on a box with no JetBrains vendor directory (one failed readDir
// per home per tick).
//
// # The timing problem the loop solves
//
// A hosted stamp can only land on a session row that exists. The host
// writes its pointer file the moment the agent session starts, often
// before the agent's own transcript has been ingested, so a single-shot
// stamp would silently miss. Each candidate is therefore RESOLVED against
// the store first (Options.Load): a session that is not there yet is
// retried on later ticks while its pointer file is younger than
// Options.Window; one that is there and already carries the hosted value
// is marked landed without a write; one that carries anything else is
// stamped and marked landed. The in-memory ledger is per process — after
// a daemon restart every pointer file is resolved once more (a no-op
// read for the landed ones), which is the whole cost of not persisting
// state.
//
// # Module boundary
//
// Pure with respect to I/O: the filesystem (ReadDir / ReadFile / Stat),
// the clock, the home list and both store seams are injected as funcs,
// so the package imports no database/sql, net/http, os/exec or fsnotify
// (pinned by imports_test.go). cmd/observer/start.go is the one wiring
// site.
package surfaceenrich
