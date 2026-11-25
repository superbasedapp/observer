// Package pgthrow is the migration-free half of the cloudserver Postgres test
// fixture: it reads the admin DSN (SBCI_TEST_PG_DSN, with the
// SBCI_TEST_PG_REQUIRED fail-instead-of-skip rule), creates a uniquely named
// throwaway database on that cluster and drops it on cleanup.
//
// It exists as its own package because it imports nothing from this module:
// internal/cloudserver/cloudtestpg builds a MIGRATED database on top of it
// and imports internal/cloudserver/db for that, so db's own internal tests
// (which drive the lineage to an intermediate version themselves) cannot
// import cloudtestpg without an import cycle. They import this package
// instead.
//
// Like cloudtestpg it imports "testing" and is referenced only from tests, so
// it never enters a production binary.
package pgthrow
