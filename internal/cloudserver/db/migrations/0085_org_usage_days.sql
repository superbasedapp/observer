-- 0085_org_usage_days.sql - the control plane keeps each org's daily usage
-- report (managed-SaaS M7b.2; plan 06 5.8.5; lead decision Q11: "M6.4 pulls
-- usage, M7b.2 stores it"; docs/security.md ENTL-5).
--
-- step: expand
--
-- One row per (org, receipt day): the tenant host's signed daily report
-- (platformcontract.UsageResponse, one TenantUsage per tenant), as the
-- outbox worker pulls it. seat_member_ids are the distinct member ids that
-- made a billable seat that day (internal/orgserver/usage: machine
-- identities and backfill excluded); a billing period's seat count is the
-- union over its days (usage.PeriodSeats), and it sets the Paddle seat
-- quantity (internal/cloudserver/seatbilling).
--
-- A day pulled twice MERGES (store.RecordOrgUsageDay): the seat members are
-- the union and the counts the larger, so a later partial pull can never
-- lower what was already reported and the bill is never silently reduced.
-- report_digest is the SHA-256 (hex) of the signed report body the row came
-- from, for reconciliation.
--
-- Class S like the rest of the org registry's system tables (no row-level
-- security, reachable only through explicit grants): the worker writes and
-- reads; the admin role reads and repairs.

SET LOCAL lock_timeout = '5s';

CREATE TABLE org_usage_days (
    org_id             uuid        NOT NULL REFERENCES orgs (org_id),
    day                date        NOT NULL,
    seat_member_ids    text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(seat_member_ids) <= 100000),
    machine_identities bigint      NOT NULL CHECK (machine_identities >= 0),
    sessions           bigint      NOT NULL CHECK (sessions >= 0),
    members            bigint      NOT NULL CHECK (members >= 0),
    report_digest      text        NOT NULL CHECK (report_digest ~ '^[0-9a-f]{64}$'),
    received_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, day)
);

COMMENT ON TABLE org_usage_days IS 'M7b.2: one org''s daily usage report from its tenant host; seats are the distinct member ids (class S).';

GRANT SELECT, INSERT, UPDATE ON org_usage_days TO sbci_worker;
GRANT SELECT, INSERT, UPDATE ON org_usage_days TO sbci_app;
