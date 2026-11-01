// Package migplan decides which numbered schema migrations a database still
// needs. It is the one pure core shared by every migration runner in the
// tree: the node (agent) runner (internal/db), the edge WAL runner
// (internal/edge/wal), the cold archive runner (internal/archivestore), and
// both org-server runners (internal/orgserver/db for SQLite,
// internal/orgserver/db/pgmigrations for PostgreSQL). Each runner reads its
// version store and probes, calls Decide, and executes the returned plan in
// its own transaction. The SQLite runners share that read and write through
// internal/migplan/sqliteledger. No SQL, HTTP or filesystem access lives
// here, and it sits outside internal/orgserver so the node can import it.
//
// Why a per-step ledger. The runners used to record only the highest applied
// version and skip every embedded step at or below it. Two branches that take
// interleaved numbers (one ships 239 and 241, the other owns 240) then leave a
// database that reached 241 first without 240 forever, silently, once the
// lines combine. The plan therefore records every step it applies or adopts
// under its own schema_meta key and runs any embedded step that has no record,
// including one numbered below the recorded maximum.
//
// Databases written before the ledger existed hold only the 'version' record.
// Their steps are adopted (recorded without running) up to that version, the
// exact pre-ledger behaviour, EXCEPT the steps in each runner's closed
// LateStep table: a late step is decided by a schema probe, so a known
// skipped step runs and a step that really ran is adopted. An unlisted step
// can never be marked applied by the probe path, and a listed one is marked
// applied only when the probe sees its schema.
package migplan
