-- 0145_device_approvals_recovery_failures.sql - FR-6 and FR-24 of the
-- 2026-11-17 review (docs/audits/fable-review-2026-11-17.md; docs/security.md
-- PORTALMFA-1).
--
-- step: expand
--
-- device_approvals: a passkey-verified portal session approves ONE device
-- thumbprint for a short window. /v1/auth/exchange registers a NEW device of
-- an account that holds an active passkey only when such an approval exists
-- (single use). Accounts without a passkey never read this table.
--
-- portal_recovery_failures: a dedicated failure counter per account for
-- recovery-code guesses, so a 50-bit guess is locked out after a handful of
-- tries instead of being bounded only by the shared portal rate limits.
--
-- Both are account-keyed tables under the same row-level security as 0131's.

SET LOCAL lock_timeout = '5s';

CREATE TABLE device_approvals (
    account_id  uuid        NOT NULL REFERENCES accounts (account_id) ON DELETE CASCADE,
    thumbprint  text        NOT NULL CHECK (char_length(thumbprint) BETWEEN 1 AND 64),
    session_id  uuid        NOT NULL,
    approved_at timestamptz NOT NULL,
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    PRIMARY KEY (account_id, thumbprint),
    CONSTRAINT device_approvals_short_lived CHECK (expires_at > approved_at AND expires_at <= approved_at + interval '1 hour')
);

COMMENT ON TABLE device_approvals IS
    'FR-6: a passkey-verified portal session''s single-use approval of one new device thumbprint (class S).';

CREATE TABLE portal_recovery_failures (
    account_id   uuid        NOT NULL PRIMARY KEY REFERENCES accounts (account_id) ON DELETE CASCADE,
    failures     integer     NOT NULL CHECK (failures >= 0),
    window_start timestamptz NOT NULL,
    locked_until timestamptz
);

COMMENT ON TABLE portal_recovery_failures IS
    'FR-24: recovery-code failure counter and lockout per account (class S).';

ALTER TABLE device_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY device_approvals_tenant ON device_approvals
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

ALTER TABLE portal_recovery_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_recovery_failures FORCE ROW LEVEL SECURITY;
CREATE POLICY portal_recovery_failures_tenant ON portal_recovery_failures
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

GRANT SELECT, INSERT, UPDATE, DELETE ON device_approvals, portal_recovery_failures TO sbci_api, sbci_app;
