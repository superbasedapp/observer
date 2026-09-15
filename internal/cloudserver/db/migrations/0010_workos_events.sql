-- 0010_workos_events.sql — WorkOS account-lifecycle event intake (W1 of the
-- cloud-intelligence divergence remediation plan, §3 W1 "Lifecycle phase 1";
-- starts D18).
--
-- workos_events is a SYSTEM table (no RLS), the same tenancy class as
-- exchange_nonces (0002) and auth_transactions (0009). The webhook arrives
-- unauthenticated-by-cookie and pre-tenant — the account it concerns is
-- resolved from the event payload AFTER signature verification — so an
-- RLS-scoped table could not be written at intake time at all.
--
-- It exists for exactly ONE job: IDEMPOTENT INTAKE. WorkOS delivers
-- at-least-once, so the provider's event id is the primary key and a redelivery
-- is an `ON CONFLICT (event_id) DO NOTHING` no-op that answers 200 without
-- re-processing.
--
-- NO PAYLOAD IS STORED. We ACT on an event (revoke access) and record that it
-- was seen and when it finished processing; we do not archive the provider's
-- message. There is deliberately no account_id column either: knowing WHICH
-- account a lifecycle event touched is not needed to dedupe, and adding it
-- would turn a dedupe ledger into an account data record.
--
-- Deletion/export classification (the rev-4 F6 pattern that already governs
-- exchange_nonces and auth_transactions): these rows are NOT account-linked, so
-- they are EXCLUDED from account export and are NOT part of the
-- account-deletion matrix. The account-side fact of a revocation lives in the
-- audit trail and in the revoked device/token/session rows themselves.

CREATE TABLE workos_events (
    -- The provider's own event id (e.g. "event_01H..."). Primary key ⇒ the
    -- dedupe guard is the table itself, not a read-then-write.
    event_id     text PRIMARY KEY,
    -- The provider's event type (e.g. "user.deleted"). Recorded for operator
    -- forensics and so an unrecognised type is visibly acknowledged rather than
    -- silently dropped.
    event_type   text NOT NULL,
    received_at  timestamptz NOT NULL,
    -- NULL until phase-1 handling finished. A row with received_at set and
    -- processed_at NULL is an event we took delivery of but did not complete —
    -- the honest state to investigate, never mistaken for "handled".
    processed_at timestamptz
);

-- Supports the age-ordered scan a retention sweep will use (no sweeper ships
-- with this migration; the index is the cheap half that must exist before one
-- can be added without a table rewrite).
CREATE INDEX workos_events_received ON workos_events (received_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON workos_events TO sbci_app;
