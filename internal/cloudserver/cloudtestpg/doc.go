// Package cloudtestpg is a Postgres test-support helper for the cloudserver
// suites. It reads SBCI_TEST_PG_DSN (the admin DSN of a throwaway Postgres,
// e.g. a local docker container) and hands each test its OWN freshly-migrated
// database, dropped on cleanup, so RLS/lease/reservation tests are fully
// isolated — including the global system rows (budget_pools, kill_switches).
//
// It is a normal package (not a _test.go file) so every cloudserver test
// package can import it, but it imports "testing" and is referenced only from
// tests, so it never enters a production binary.
package cloudtestpg
