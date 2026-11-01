// Package captureprogress is the ONE progress model for a node's history
// capture: how far the watcher's first walk of each AI tool's session store
// has got (files found, files read, files that failed) since this daemon
// started. It backs the dashboard's first-run view (T-922), which shows the
// owner that pre-existing history is being captured instead of leaving that
// work invisible.
//
// One seam each way. The watcher FEEDS it through Tracker.Record (the
// initial full scan, and the scoped walk of a tool's store that appears
// after start); the dashboard READS it through Tracker.Snapshot, a plain
// value with no live references. The API never re-scans the filesystem to
// answer "how far along are we".
//
// Pure: in-memory counters behind one mutex, no database, HTTP, filesystem or
// fsnotify (pinned by imports_test.go). Nothing is persisted, so a restart
// starts a new count, which is honest: the restart's own initial scan is the
// work in progress. Node-local by construction: nothing here is reachable
// from the org push seam.
//
// State decisions are table-driven (toolStateRules), one test row per rule.
package captureprogress
