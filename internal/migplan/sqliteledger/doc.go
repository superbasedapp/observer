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
// The package owns no transaction and no migration body. A runner pins its
// connection, takes its own lock, calls Plan and Apply on that connection, and
// supplies the callback that executes one step's SQL from its own embedded
// lineage. The plan itself is decided by migplan.Decide.
package sqliteledger
