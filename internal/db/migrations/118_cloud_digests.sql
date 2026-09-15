-- 118_cloud_digests.sql — weekly project digest storage + the account plan
-- facts the last `observer cloud sync` observed (value-upgrade plan of
-- record, docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md
-- §4 W5).
--
-- cloud_digests holds one row per weekly project-digest result pulled from
-- the hosted service (cloudcontract.ResultKindProjectDigest,
-- schema project_digest.v1): headline / themes / cost trend / recurring
-- error classes / unfinished threads / a suggested next session, over a
-- bounded window of a project's own already-uploaded session_enrichment
-- results. NO new content ever left this node to produce a digest — the
-- server built it entirely from data it already held — so this table is
-- node-local storage of a RECEIVED product, the same posture as
-- cloud_results for a session enrichment. `local_project_id` is '' when the
-- project pseudonym the digest names was never minted by (or has since been
-- forgotten on) this device — the digest is still kept, just unassociated
-- (mirrors how a session-enrichment result for an unrecognized
-- cloud_session_id is reported "for sessions not on this device", except a
-- digest is small enough that keeping the unassociated ones costs nothing
-- and may resolve later after an identity merge).
--
-- cloud_sync_last (migration 117) gains the account plan facts the most
-- recent `observer cloud sync` observed via GET /v1/usage: which plan the
-- account resolved to, its daily/monthly caps, whether the plan includes
-- the weekly digest job kind, and how long the hosted service keeps
-- results. All six are read-only reflections of a SERVER-SIDE fact — this
-- node never authors a plan — and every nullable column means exactly
-- "this device does not know" (an older server that predates this wave, or
-- a sync that has never run), never "false"/"zero". plan_name/plan_label
-- default to '' (NOT NULL) because they are always meaningful once a sync
-- has ever recorded anything; the CLI/dashboard read an empty plan_name as
-- "unknown until the next sync", the same convention id=1's absence already
-- uses for "never synced".
--
-- Both tables are NODE-LOCAL like every other cloud_* table: no org share
-- key, no paired orgserver migration, and both join the forbidden-table
-- sentinel walked by tests/invariant/privacy_test.go.
CREATE TABLE cloud_digests (
    id               TEXT PRIMARY KEY,          -- server result id
    cloud_project_id TEXT NOT NULL,
    local_project_id TEXT NOT NULL DEFAULT '',  -- '' when the pseudonym is not on this device
    period_start     TEXT NOT NULL,
    period_end       TEXT NOT NULL,
    schema_version   TEXT NOT NULL,
    result_json      TEXT NOT NULL,
    received_at      TEXT NOT NULL,
    superseded_by    TEXT
);
CREATE INDEX idx_cloud_digests_project ON cloud_digests(local_project_id, period_end DESC);

ALTER TABLE cloud_sync_last ADD COLUMN plan_name TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_sync_last ADD COLUMN plan_label TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_sync_last ADD COLUMN digest_weekly INTEGER;          -- NULL = unknown
ALTER TABLE cloud_sync_last ADD COLUMN results_retention_days INTEGER; -- NULL = unknown
ALTER TABLE cloud_sync_last ADD COLUMN daily_cap INTEGER;              -- NULL = unknown
ALTER TABLE cloud_sync_last ADD COLUMN monthly_cap INTEGER;            -- NULL = unknown
