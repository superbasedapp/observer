-- 0083_oidc_auth_time.sql - the platform OIDC issuer signs a truthful
-- auth_time (lane w9-issuer-authtime; docs/security.md STEPUP-1 / PLATRAIL-1).
--
-- step: expand
--
-- OIDC Core 2 defines auth_time as when the End-User authenticated, and
-- 3.1.2.1 makes it REQUIRED when the relying party sent max_age; the tenant's
-- platform rail sends prompt=login and max_age=0 on every privileged step-up
-- and refuses a forced sign-in whose id_token has none, or one from before the
-- step-up started. Three nullable or constant-default columns carry the time
-- from the AuthKit sign-in to the id_token:
--
--   * auth_transactions.force_reauth: the portal's AuthKit start sent
--     prompt=login and max_age=0 (a step-up always; a login when the issuer
--     asked for a fresh sign-in, ?reauth=1). Recorded server-side so the
--     callback, not the browser, decides whether the sign-in it completes was
--     a fresh authentication: a browser that drops reauth=1 gets a session
--     with no authentication time, and the issuer asks again.
--   * browser_sessions.authenticated_at: when the person authenticated to
--     establish the session, written ONLY by a sign-in that was a fresh
--     authentication (a forced AuthKit leg, or the dev-auth login). NULL means
--     not known: an ordinary AuthKit sign-in may have been answered silently
--     from AuthKit's own session, so its completion time is not an
--     authentication time, and created_at is never passed off as one.
--   * oidc_codes.auth_time: the session's authenticated_at, recorded at
--     authorize and signed at token time (the two requests may land on
--     different replicas; codes live only in the database). NULL when the
--     session's time is not known: the token then carries no auth_time, which
--     the issuer allows only for a request that asked for no freshness.
--
-- Rolling: a row written by the previous build has force_reauth false and
-- NULL times, which reads as "not known" (the truth: that build never
-- recorded one), so a session from before the roll answers a freshness
-- request with a forced sign-in. No backfill, no new GRANT: sbci_api's and
-- sbci_app's grants on all three tables are table-level (0004, 0009, 0015,
-- 0019, 0032, 0052) and so cover the new columns, and consumed_at stays the
-- only oidc_codes column sbci_api may UPDATE.

SET LOCAL lock_timeout = '5s';

ALTER TABLE auth_transactions ADD COLUMN force_reauth boolean NOT NULL DEFAULT false;

ALTER TABLE browser_sessions ADD COLUMN authenticated_at timestamptz;

ALTER TABLE oidc_codes ADD COLUMN auth_time timestamptz;

COMMENT ON COLUMN auth_transactions.force_reauth IS
    'The AuthKit start sent prompt=login and max_age=0; a login completed from it records the session''s authenticated_at.';

COMMENT ON COLUMN browser_sessions.authenticated_at IS
    'When the person authenticated to establish the session, written only by a fresh authentication (a forced AuthKit leg or the dev-auth login); NULL means not known. The platform OIDC issuer''s auth_time.';

COMMENT ON COLUMN oidc_codes.auth_time IS
    'The authenticated_at of the portal session the code was issued from (the id_token auth_time); NULL when not known, and the token then carries none.';
