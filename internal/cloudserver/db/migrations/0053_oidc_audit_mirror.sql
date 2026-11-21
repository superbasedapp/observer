-- 0053_oidc_audit_mirror.sql - the audit-mirror outbox of the OIDC issuer
-- (managed-SaaS M6.2; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.4, A10;
-- lead decision L-9 Q9).
--
-- step: expand
--
-- Every platform-rail sign-in is mirrored into the tenant's audit_log with the
-- token's jti (plan 06 5.4), the cross-check the control plane cannot be
-- accused of forging (RK-12). The issuer inserts one row here in the SAME
-- transaction as the oidc_issued row, before the token is returned: a failed
-- insert fails the sign-in (audit before act).
--
-- Delivery is a host-API verb (`audit-mirror`, L-9 Q9) that does not exist
-- yet in internal/platformcontract; until it does, rows stay pending. The
-- sender (the M6.4 outbox worker, or a follow-up lane) adds its own grant.
--
-- Class S. The payload carries the jti, sub, org, client, kid and the two
-- times; never an email and never the token.

SET LOCAL lock_timeout = '5s';

CREATE TABLE oidc_audit_mirror (
    jti              text        NOT NULL PRIMARY KEY REFERENCES oidc_issued (jti),
    org_id           uuid        NOT NULL REFERENCES orgs (org_id),
    payload          jsonb       NOT NULL CHECK (payload->>'jti' = jti),
    state            text        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'sent', 'acked', 'failed')),
    attempts         int         NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error_class text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    done_at          timestamptz
);

-- The sender's queue scan (FOR UPDATE SKIP LOCKED over due rows).
CREATE INDEX oidc_audit_mirror_due ON oidc_audit_mirror (next_attempt_at) WHERE state IN ('pending', 'sent');
CREATE INDEX oidc_audit_mirror_org ON oidc_audit_mirror (org_id);

-- The issuer inserts only; the sender's grant comes with the sender.
GRANT INSERT                 ON oidc_audit_mirror TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON oidc_audit_mirror TO sbci_app;

COMMENT ON TABLE oidc_audit_mirror IS 'M6.2 OIDC issuer: per-sign-in audit-mirror outbox to the tenant audit_log (class S); delivery verb pending (L-9 Q9).';
