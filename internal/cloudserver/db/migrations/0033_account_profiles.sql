-- 0033_account_profiles.sql — the signed-in developer's own display identity.
--
-- The portal top bar could only show the account UUID: the session bootstrap
-- (`GET /portal/api/session`) returned `account_id` and nothing else, because
-- nothing in the schema held a name or an email. `identity_links` holds the
-- provider SUBJECT (an opaque WorkOS user id), not a human-readable label, and
-- the AuthKit ACCESS TOKEN carries no email claim either — so neither the
-- verifier seam nor the identity link could supply one.
--
-- WorkOS does return it, once, in the SERVER-SIDE code-exchange response
-- (`POST /user_management/authenticate` → `user: {email, first_name,
-- last_name, ...}`). This table is where that one-shot fact is kept so the
-- portal can render "you" instead of a UUID. It is upserted on every sign-in,
-- so a change at the provider (a rename, a new primary email) converges on the
-- next login rather than needing its own sync path.
--
-- SHAPE — one row per account, and deliberately nothing more:
--
--   * DISPLAY ONLY. No unique index on email, no lookup path by email, no
--     authentication or authorization decision reads this table. The identity
--     of record stays (provider, subject) in `identity_links`; making an email
--     addressable here would quietly turn a display cache into a second
--     identity authority (CLAUDE.md #4, one owner per piece of state).
--   * TENANT table with FORCE ROW LEVEL SECURITY, like every other
--     account-scoped table (portal_consent_choices is the closest precedent):
--     a row is readable and writable only inside the owning account's tenant
--     context, so a defect in one request can never surface another
--     developer's email.
--   * ON DELETE CASCADE on the account FK. The row is PURGED outright at
--     account deletion (deletionCompleteTx), which is what actually removes it
--     — but a NO-ACTION FK would let any stray row block the 24-month sweep's
--     `DELETE FROM accounts` and roll back the whole sweep for every due
--     account, which is exactly the class migration 0027 (Sol F5(b)) had to
--     repair for leaderboard_contributions. CASCADE makes that class
--     impossible here without touching the sweep function; the explicit purge
--     is still what deletes the data at deletion time, 24 months earlier.
--
-- Nullable columns: an account can exist with no profile at all (a dev-auth
-- subject with no email, or a WorkOS response that carried no user object), and
-- "unknown" must stay distinguishable from "empty string" — the portal renders
-- the account id in that case rather than a blank chip.

CREATE TABLE account_profiles (
    account_id   uuid NOT NULL PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    -- The provider's primary email for this user. Display only; bounded to 254
    -- bytes (the RFC 5321 address maximum) by the writer before it gets here.
    email        text,
    -- "First Last" as the provider spells it, falling back to the email when
    -- the provider gave no name. Bounded to 128 bytes by the writer.
    display_name text,
    updated_at   timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE account_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY account_profiles_tenant ON account_profiles
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

COMMENT ON TABLE account_profiles IS
    'Display-only identity for the signed-in portal user (email + name captured from the WorkOS code-exchange response, upserted on each login). Never an authentication or lookup key; the identity of record is identity_links(provider, subject). Purged at account deletion.';

-- Grants. sbci_api is the ONLY runtime writer (the sign-in leg upserts it, the
-- session bootstrap reads it, the deletion purge deletes it), so it takes full
-- DML. sbci_app is the test/operator role and mirrors it. sbci_worker gets
-- NOTHING: a job runner never needs to know who the developer is, and the
-- least-privilege matrix (rolesplit_test.go) pins that it cannot find out.
GRANT SELECT, INSERT, UPDATE, DELETE ON account_profiles TO sbci_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON account_profiles TO sbci_app;
