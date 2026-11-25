// Package ledgertest drives a SQLite migration runner that uses the per-step
// ledger (internal/migplan, internal/migplan/sqliteledger) through one table
// of scenarios, so every runner (the node, the edge WAL, the cold archive) is
// held to the same contract by the same cases. It is test support only:
// production code must not import it.
package ledgertest
