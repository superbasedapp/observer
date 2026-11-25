// Package db owns the hosted cloud-intelligence service's Postgres connection
// pool and its OWN migration lineage (plan of record §6 CI-P3). It is separate
// in every dimension from the agent SQLite side (internal/db) and the
// org-server SQLite side (internal/orgserver/db): a different database, the pgx
// driver, and a version counter that begins at migration 0001.
package db
