// Package migrations embeds the hosted cloud-intelligence service's OWN
// Postgres migration lineage (plan of record §6 CI-P3). This lineage is
// entirely separate from the agent SQLite lineage (internal/db/migrations) and
// the org-server lineage (internal/orgserver/db/migrations): a different
// database (Postgres), a different driver (pgx), and a version counter that
// starts at 0001.
package migrations
