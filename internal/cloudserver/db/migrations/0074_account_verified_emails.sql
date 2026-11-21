-- 0074_account_verified_emails.sql - the provider-asserted email the platform
-- OIDC issuer signs, with the provider's own verification flag (managed-SaaS
-- plan 07, operator item A4 option (a) and the Fable 5.2 review's revised A4;
-- design docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 3.3:
-- "the email claim is the WorkOS-verified email").
--
-- step: expand
--
-- WHY A TABLE OF ITS OWN. account_profiles (0033) is display data: it is also
-- written by the dev-auth leg and the user.updated webhook, it is truncated to
-- fit the top bar, and its contract is "never an authentication input". The
-- issuer's email claim is an authentication input for every tenant that
-- matches invitations by address, so it gets a separate row that only the
-- WorkOS sign-in leg writes (the code exchange and the step-up
-- re-authentication), refreshed at every such sign-in from the user object
-- WorkOS returns: the address exactly as WorkOS sent it and WorkOS's
-- `email_verified` flag (absent is recorded as false). The issuer refuses to
-- issue an ID token unless email_verified is true.
--
-- It is never a lookup key: every statement on it is keyed by account_id,
-- under the same no-merge-by-email tripwire as account_profiles
-- (internal/cloudserver/api/nomerge_test.go). Account resolution stays
-- identity_links(provider, subject).
--
-- Deletion: purged explicitly at account deletion beside account_profiles;
-- ON DELETE CASCADE only covers the 24-month sweep that drops the tombstone
-- (the 0033 reasoning: a NO ACTION key would let a stray row roll back the
-- sweep).
--
-- Row-level security is 0075, a step of its own (migcheck).

SET LOCAL lock_timeout = '5s';

CREATE TABLE account_verified_emails (
    account_id     uuid NOT NULL PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    -- The address WorkOS returned, trimmed. Bounded like the issuer's claim
    -- rule (RFC 5321 forward-path maximum) and checked to look like an
    -- address; the writer refuses anything else and clears the row instead.
    email          text NOT NULL CHECK (octet_length(email) BETWEEN 3 AND 254 AND position('@' in email) > 1),
    -- WorkOS's `email_verified` from the same user object; false when the
    -- provider sent no flag.
    email_verified boolean NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE account_verified_emails IS
    'The provider-asserted email and its email_verified flag, refreshed at each WorkOS sign-in; the platform OIDC issuer signs it and refuses unless verified. Keyed by account_id only, never a lookup key. Purged at account deletion.';

-- Grants mirror account_profiles: sbci_api is the runtime reader and writer
-- (the sign-in leg upserts it, the issuer reads it, the deletion purge
-- deletes it); sbci_app is the test/operator role and mirrors it. sbci_worker
-- gets nothing. No function is added, so there is no EXECUTE to grant.
GRANT SELECT, INSERT, UPDATE, DELETE ON account_verified_emails TO sbci_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON account_verified_emails TO sbci_app;
