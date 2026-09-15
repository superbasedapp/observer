-- 0035_browser_session_idle.sql — portal session idle timeout + rolling
-- refresh (Wave C, gap 2.4 residual (a); operator ruling 2026-09-11: 24h
-- absolute expiry, 2h idle with rolling refresh on authenticated activity).
--
-- Before this migration browser_sessions carried only an ABSOLUTE expires_at
-- fixed at sign-in (12h) — no idle timeout, no rolling refresh, and the portal
-- had no data to build a "sign out everywhere" list from beyond what already
-- existed for that purpose. Two nullable columns:
--
--   idle_expires_at — the sliding idle boundary. IntrospectBrowserSession
--     refuses a session once EITHER this or the absolute expires_at has
--     passed, and rolls this forward (capped at expires_at — the absolute
--     boundary always wins) on a sufficiently-stale-since-last-write
--     successful introspection. NULL means "no idle limit observed yet" — a
--     session minted before this migration reads that way until its next use,
--     at which point the roll establishes an idle boundary going forward. It
--     is deliberately NOT refused for being NULL: retroactively logging out
--     every live session at deploy time would be a self-inflicted outage for
--     no security gain (the absolute boundary already bounds it).
--   last_seen_at — when idle_expires_at was last rolled. The write-coalescing
--     field: a roll only fires when this is more than ~5 minutes old (or
--     unset), so a tab polling the session-bootstrap endpoint costs one
--     UPDATE per several minutes of activity, not one per request.
--
-- Nullable, no backfill needed, no new GRANT needed: browser_sessions is
-- already fully granted to sbci_app (0004_rls_grants.sql) and sbci_api
-- (0015_role_split.sql) as an ordinary tenant table, and adding a column does
-- not change that grant.
--
-- sbci_introspect_browser_session (0006_browser_session_introspect.sql) must
-- also read the two new columns so the store can apply the idle gate off the
-- SAME round trip that already resolves the session — Postgres refuses
-- CREATE OR REPLACE FUNCTION across a changed RETURNS TABLE shape, hence the
-- drop-and-recreate below; owner and grants are re-applied identically to
-- 0006 (sbci_defs owns it) and 0015 (sbci_api may EXECUTE it, alongside
-- sbci_app's original grant).

ALTER TABLE browser_sessions ADD COLUMN idle_expires_at timestamptz;
ALTER TABLE browser_sessions ADD COLUMN last_seen_at timestamptz;

COMMENT ON COLUMN browser_sessions.idle_expires_at IS
    'Sliding idle boundary (2h default, DefaultBrowserSessionIdleTTL). NULL = not yet observed under the idle model; refreshed, never refused, on next use.';
COMMENT ON COLUMN browser_sessions.last_seen_at IS
    'When idle_expires_at was last rolled forward by IntrospectBrowserSession; coalesces the refresh write to roughly once per 5 minutes of activity.';

DROP FUNCTION sbci_introspect_browser_session(text);

CREATE FUNCTION sbci_introspect_browser_session(p_session_hash text)
RETURNS TABLE (
    account_id      uuid,
    session_id      uuid,
    csrf_hash       text,
    expires_at      timestamptz,
    revoked_at      timestamptz,
    account_status  text,
    idle_expires_at timestamptz,
    last_seen_at    timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
    RETURN QUERY
    SELECT b.account_id, b.id, b.csrf_hash, b.expires_at, b.revoked_at, a.status,
           b.idle_expires_at, b.last_seen_at
      FROM browser_sessions b
      JOIN accounts a ON a.account_id = b.account_id
     WHERE b.session_hash = p_session_hash;
END$$;

ALTER FUNCTION sbci_introspect_browser_session(text) OWNER TO sbci_defs;

REVOKE ALL ON FUNCTION sbci_introspect_browser_session(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_introspect_browser_session(text) TO sbci_app, sbci_api;
