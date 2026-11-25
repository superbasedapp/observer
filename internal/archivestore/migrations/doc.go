// Package migrations embeds the cold-storage (archive.db) migration lineage.
//
// This is a SEPARATE lineage from the agent DB (internal/db/migrations), the
// org-server DB (internal/orgserver/db/migrations) and the edge WAL
// (internal/edge/wal/migrations). archive.db holds ONLY cold copies of
// node-local tables, so its versions start at 001 and are applied by
// internal/archivestore's own migration runner.
//
// The file is node-local, never on any wire, and has no cross-version
// compatibility surface: an older binary that does not know a table exists
// simply never reads it. That is why a new bucket may land its tables in a
// fresh migration here rather than being speculatively pre-created.
package migrations
