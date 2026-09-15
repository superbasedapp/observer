-- 0006_browser_session_introspect.sql — the portal cookie-auth bootstrap lookup.
--
-- The portal BFF (app.superbased.app; internal/cloudserver/api/portal.go) reads
-- a __Host-sbci session cookie and must resolve it to an account BEFORE any
-- tenant context is known — exactly the pre-tenant situation that
-- sbci_introspect_token (0003) solves for the device-API bearer token. The
-- cookie's raw value hashes to browser_sessions.session_hash; that table is
-- RLS-protected (0004) and keyed on the sbci.account_id GUC, so a plain SELECT
-- under WithSystem (no tenant GUC) matches NO rows. This SECURITY DEFINER
-- function is the portal's only window past RLS for that one bootstrap read,
-- mirroring sbci_introspect_token: owned by sbci_defs (BYPASSRLS, NOLOGIN),
-- SET search_path = public, REVOKEd from PUBLIC, EXECUTE granted only to
-- sbci_app. It returns at most one row; validity gates (expiry, revocation,
-- account status) are applied in Go so the caller gets a single verdict.

CREATE OR REPLACE FUNCTION sbci_introspect_browser_session(p_session_hash text)
RETURNS TABLE (
    account_id     uuid,
    session_id     uuid,
    csrf_hash      text,
    expires_at     timestamptz,
    revoked_at     timestamptz,
    account_status text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    RETURN QUERY
    SELECT b.account_id, b.id, b.csrf_hash, b.expires_at, b.revoked_at, a.status
      FROM browser_sessions b
      JOIN accounts a ON a.account_id = b.account_id
     WHERE b.session_hash = p_session_hash;
END$$;

ALTER FUNCTION sbci_introspect_browser_session(text) OWNER TO sbci_defs;

-- The definer function reads browser_sessions (and accounts, already granted in
-- 0004); grant the base-table SELECT the function body needs under sbci_defs.
GRANT SELECT ON browser_sessions TO sbci_defs;

REVOKE ALL ON FUNCTION sbci_introspect_browser_session(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_introspect_browser_session(text) TO sbci_app;
