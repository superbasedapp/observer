-- 0060_org_reconcile_findings.sql - the host-API reconciler's findings
-- (managed-SaaS plan 07 M6.4; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.6).
--
-- step: expand
--
-- Class S: no RLS, explicit grants only. One OPEN row per (org, kind): the
-- reconciler compares each org's desired state (orgs) with its host's
-- verified route-check and health answers; a mismatch opens a finding or
-- refreshes the open one (last_seen, seen_count, the latest observation),
-- and a pass that no longer sees it sets resolved_at. Resolved rows stay as
-- the history an operator reads. kind is the closed vocabulary of
-- internal/cloudserver/hostapi KnownFindingKinds (a hostclient test compares
-- the two). correction_key names the outbox row the finding enqueued, NULL
-- when it is alert-only. No row carries personal data or free text.

SET LOCAL lock_timeout = '5s';

CREATE TABLE org_reconcile_findings (
    finding_id     uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         uuid        NOT NULL REFERENCES orgs (org_id),
    kind           text        NOT NULL
        CHECK (kind IN ('not_served', 'unreachable', 'state_behind', 'state_diverged', 'gen_ahead', 'unhealthy')),
    desired_state  text        NOT NULL,
    desired_gen    bigint      NOT NULL CHECK (desired_gen >= 0),
    -- NULL when the host was not asked or did not answer verifiably.
    served         boolean,
    host_state     text,
    host_gen       bigint,
    health         text,
    correction_key text,
    first_seen     timestamptz NOT NULL DEFAULT now(),
    last_seen      timestamptz NOT NULL DEFAULT now(),
    seen_count     int         NOT NULL DEFAULT 1 CHECK (seen_count >= 1),
    resolved_at    timestamptz
);

-- At most one open finding per (org, kind): the reconciler's upsert target.
CREATE UNIQUE INDEX org_reconcile_findings_open ON org_reconcile_findings (org_id, kind) WHERE resolved_at IS NULL;
CREATE INDEX org_reconcile_findings_org ON org_reconcile_findings (org_id);

GRANT SELECT, INSERT, UPDATE ON org_reconcile_findings TO sbci_worker;
GRANT SELECT, INSERT, UPDATE ON org_reconcile_findings TO sbci_app;

COMMENT ON TABLE org_reconcile_findings IS 'M6.4 host-API reconciliation findings (class S): one open row per (org, kind), resolved_at when it clears.';
