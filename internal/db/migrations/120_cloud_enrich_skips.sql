-- 120_cloud_enrich_skips.sql — durable node-local backoff for the background
-- enrichment sweep's permanently-failing candidates (2026-09-16 follow-up to
-- the value-upgrade plan's W3 background-by-default arc,
-- docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md §4 W3).
--
-- Before this migration, cmd/observer/cloudautoenrich.go's
-- cloudAutoEnrichLoop kept a session whose `observer cloud consent` spawn
-- just failed in an IN-MEMORY map for one fixed hour. A daemon restart
-- forgot the map immediately, so a session that can never succeed (a
-- malformed transcript, say) was retried on the very next tick after every
-- restart, and internal/store's ListCloudAutoEnrichCandidates join kept
-- re-surfacing it forever.
--
-- cloud_enrich_skips makes the skip durable and puts the exclusion in SQL:
-- internal/store/cloudenrichskip.go's RecordCloudEnrichSkip upserts one row
-- per session on a failed spawn, with exponential backoff (1h * 2^(attempts-1),
-- capped at 7 days) computed in Go; ListCloudAutoEnrichCandidates
-- (internal/store/cloudautoenrich.go) excludes any session whose next_at is
-- still in the future. A successful spawn deletes the row via
-- ClearCloudEnrichSkip.
--
-- Content-free by construction, same posture as every other cloud_* table:
-- last_error_class is a short fixed CLASS token (e.g. "spawn_timeout" /
-- "consent_spawn_failed"), never subprocess output. NODE-LOCAL: no org share
-- key, no paired orgserver migration; its name joins the forbidden-table
-- sentinel walked by tests/invariant/privacy_test.go.
CREATE TABLE cloud_enrich_skips (
    session_id       TEXT PRIMARY KEY,
    attempts         INTEGER NOT NULL,
    next_at          TEXT NOT NULL,
    last_error_class TEXT NOT NULL DEFAULT '',
    updated_at       TEXT NOT NULL
);
CREATE INDEX idx_cloud_enrich_skips_next_at ON cloud_enrich_skips(next_at);
