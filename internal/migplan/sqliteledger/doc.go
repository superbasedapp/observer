// Package sqliteledger is the SQLite side of the per-step migration ledger
// (internal/migplan): it reads a database's schema_meta into a migplan.Ledger,
// runs the late-step column probes, and writes a plan's bookkeeping (forgotten
// records, the ledger horizon, per-step records, the version record).
//
// It is shared by every SQLite runner, which all keep their version in a
// schema_meta(key, value) table: the node (agent) database (internal/db), the
// edge WAL (internal/edge/wal), the cold archive (internal/archivestore) and
// the org server's SQLite engine (internal/orgserver/db, T-981; its
// PostgreSQL twin keeps its own ledger in pgmigrations).
// The per-step records live in that same table under migration:<n> keys, so
// no runner spends a lineage number on bookkeeping.
//
// Plan and Apply own no transaction and no migration body. A runner pins its
// connection, takes its own lock, calls Plan and Apply on that connection, and
// supplies the callback that executes one step's SQL from its own embedded
// lineage. The plan itself is decided by migplan.Decide.
//
// Run (with ReadEntries) is that whole sequence for a runner with no extra
// needs: bootstrap schema_meta, pin a connection, BEGIN IMMEDIATE, Plan,
// Apply, COMMIT, with the deferred ROLLBACK on a context that ignores
// cancellation. The cold archive uses it; the node database (lock wait and
// lock-free no-op fast path), the edge WAL and the org server keep their
// own sequence.
package sqliteledger
