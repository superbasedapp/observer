// Package firstrunstate is the ONE owner of the node's first-run view state
// (T-922): whether this install was fresh when the daemon first recorded it,
// and whether the owner has seen (or turned off) the dashboard's first-run
// capture view. A small JSON file beside the node database,
// firstrun-state.json, written atomically (internal/fsatomic).
//
// It is a file, not a table, for the same reasons as internal/notify/
// feedstate: a lost file only means the view may show once more, so it needs
// no schema migration; it is node-local by construction (nothing here is
// reachable from the org push seam); and it is not browser storage, so a
// second browser, or the remote dashboard on a phone, sees the same answer.
//
// The install kind is recorded ONCE, at the first daemon start that has this
// code: an empty database then is a fresh install (the view opens by itself on
// the first dashboard visit); a database that already holds sessions is an
// existing install (the view never opens by itself, it stays reachable from
// Help, the command palette and Settings).
package firstrunstate
