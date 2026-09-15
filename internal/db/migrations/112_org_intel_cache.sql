-- Org-served Cloud Intelligence, node side (org-served-cloud-intelligence plan
-- §1.3/§2.4/§3.5, W3). NODE-LOCAL: the org server's own derived per-session
-- enrichment results coming BACK to the node that owns the session, pulled over
-- GET /api/agent/intel/results and cached here so the node dashboard can render
-- them. Never copied by org push or foreign import — the table name is in the
-- privacy sentinel's forbidden set (tests/invariant/privacy_test.go, INV-3), so
-- internal/store/orgpush.go can never reference it.
--
-- No session FK: a result can arrive (the server derived it from already-pushed
-- rows) before, or independently of, anything the node still holds locally. A
-- delete trigger covers explicit session removal; normal age retention covers
-- orphans. The text-list columns (taxonomy_tags, suggested_tags, limitations)
-- hold JSON-encoded arrays. fetched_at is the NODE's own pull time (the wire's
-- generated_at is the server's production time and is not persisted).
CREATE TABLE org_intel_cache (
    session_id     TEXT NOT NULL,
    job_id         TEXT NOT NULL,
    title          TEXT NOT NULL DEFAULT '',
    taxonomy_tags  TEXT NOT NULL DEFAULT '[]',
    suggested_tags TEXT NOT NULL DEFAULT '[]',
    description    TEXT NOT NULL DEFAULT '',
    confidence     TEXT NOT NULL DEFAULT '',
    limitations    TEXT NOT NULL DEFAULT '[]',
    schema_version TEXT NOT NULL DEFAULT '',
    fetched_at     TEXT NOT NULL,
    PRIMARY KEY(session_id, job_id)
);
CREATE INDEX idx_org_intel_cache_session ON org_intel_cache(session_id);
CREATE INDEX idx_org_intel_cache_age ON org_intel_cache(fetched_at);
CREATE TRIGGER delete_session_org_intel_cache AFTER DELETE ON sessions
BEGIN
    DELETE FROM org_intel_cache WHERE session_id = OLD.id;
END;
