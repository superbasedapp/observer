-- 117_cloud_auto_enrich.sql — background-by-default enrichment support
-- (value-upgrade plan of record, docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md
-- §4 W3).
--
-- Two additions, both node-local, same posture as every other cloud_* table
-- (never on the org-push wire; joins the forbidden-table sentinel walked by
-- tests/invariant/privacy_test.go):
--
--   1. cloud_enrich_policy.since — WHEN the developer's standing policy
--      (migration 115) last flipped from off to on. Set only by
--      internal/store/cloudpolicy.go::SetCloudEnrichPolicy on that exact
--      transition, carried forward unchanged on every later update while the
--      policy stays on (a background/level tweak does not reset it), and
--      cleared back to '' the moment the policy goes off again. It bounds the
--      background sweep in cmd/observer/cloudautoenrich.go: a session
--      STARTED before `since` is never auto-enqueued, so turning background
--      enrichment on never reaches back and uploads history — the developer
--      still can, one session at a time, with "Enrich now".
--
--   2. cloud_sync_last — the outcome of the most recent `observer cloud
--      sync` run, however it was triggered (a dashboard button, the R2a
--      auto-sync spawn, or a manual terminal run). Content-free BY
--      CONSTRUCTION: it holds only the counts the sync command already
--      prints (sent / waiting_provider / reconfirm / failed / results) plus
--      a closed error_class vocabulary — never a session id, a title, or raw
--      output text. `observer cloud status` and the dashboard's
--      GET /api/cloud/status read it to answer "did the last sync work"
--      without re-running one. Singleton row (id=1), same shape as
--      cloud_enrich_policy: each new run overwrites the previous outcome, so
--      this is a status snapshot, not a history log (the outbox / results
--      tables already are the history).
ALTER TABLE cloud_enrich_policy ADD COLUMN since TEXT NOT NULL DEFAULT '';

CREATE TABLE cloud_sync_last (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    started_at       TEXT NOT NULL,
    finished_at      TEXT NOT NULL,
    ok               INTEGER NOT NULL,
    sent             INTEGER NOT NULL DEFAULT 0,
    waiting_provider INTEGER NOT NULL DEFAULT 0,
    reconfirm        INTEGER NOT NULL DEFAULT 0,
    failed           INTEGER NOT NULL DEFAULT 0,
    results          INTEGER NOT NULL DEFAULT 0,
    sign_in_expired  INTEGER NOT NULL DEFAULT 0,
    error_class      TEXT NOT NULL DEFAULT ''
);
