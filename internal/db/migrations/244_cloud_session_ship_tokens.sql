-- 244_cloud_session_ship_tokens.sql - node-minted cloud-session ship tokens
-- (cloud-agents arc, lane CA-B3; decision CA-D8 and section 7.2 of
-- docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md;
-- ledger CLOUDSESS-3).
--
-- The INDIVIDUAL destination of Rail S: a developer with a node reachable
-- from a vendor cloud sandbox (Tailscale, or a remote-exposed dashboard)
-- mints a ship token on that node, and the sandbox's flush posts its push
-- envelope to POST /api/cloud-session/ingest with it. The route answers 404
-- while no active token exists, so a node that never mints one has no ingest
-- route at all.
--
-- NODE-LOCAL, one store owner (internal/store/cloudsessiontokens.go). It
-- never reaches the org-push wire: the name joins the forbidden-table
-- sentinel in tests/invariant/privacy_test.go, and there is no paired server
-- migration (the org server's own ship tokens are server migration 301, a
-- separate credential minted by the org).
--
-- token_hash is sha256 hex of the secret (internal/shiptoken.Hash); the
-- secret is shown once at mint and never stored. label is the owner's own
-- bounded, printable note. Revocation stamps revoked_at; rows are kept so
-- the settings list says what happened.
--
-- Numbered 244 inside the cloud-agents reservation (node 240-249, CA-D14).
CREATE TABLE IF NOT EXISTS cloud_session_ship_tokens (
    token_id     TEXT PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    label        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    revoked_at   TEXT,
    last_used_at TEXT,
    use_count    INTEGER NOT NULL DEFAULT 0
);
