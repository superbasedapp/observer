-- 0058_org_outbox_dispatch.sql - what the host-API client needs to send the
-- org outbox (managed-SaaS plan 07 M6.4; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.6; the
-- M6.4 block 0058-0060 in docs/migration-numbering.md).
--
-- step: expand
--
-- One step of three: 0058 the dispatch columns and the worker's grants, 0059
-- the worker's policies on orgs (a policy step of its own), 0060 the
-- reconciliation findings table.
--
-- NEW org_outbox COLUMNS (all nullable, no rewrite)
--
--   seq                 per-org send order. A sequence default, set after the
--                       column is added (a volatile default on ADD COLUMN
--                       would rewrite the table). Rows from before this step
--                       keep NULL and sort first.
--   lease_token         the claim's fencing token: a worker claims due rows
--   lease_until         FOR UPDATE SKIP LOCKED, stamps a fresh token and an
--                       expiry, commits, sends, and records the outcome only
--                       WHERE lease_token matches. A second worker never
--                       claims a row whose lease is live, and a worker whose
--                       lease was taken over cannot record over the new one.
--   last_attempt_at     when the latest attempt was claimed.
--   host_state          what the host reported in the verified answer that
--   host_lifecycle_gen  acked the row (create and set_state), for the
--                       reconciler and the operator.
--
-- The state vocabulary of 0049 is unchanged: pending (due or backing off),
-- sent (claimed, in flight), acked (the host acted), failed (parked for an
-- operator after a refusal that must not be resent blind).
--
-- GRANTS. sbci_worker (the outbox worker) reads and updates the outbox and
-- inserts the reconciler's corrections; on orgs it may read exactly the
-- columns it routes and reconciles by, and update only host_id (placement),
-- status and lifecycle_gen (adopting the host's answer to create while the
-- org is still provisioning) and updated_at. orgs keeps FORCE ROW LEVEL
-- SECURITY: these grants reach no row until 0059's worker policies. The
-- sequence default needs USAGE for every role that inserts into the outbox
-- (sbci_api's provisioning transaction among them).

SET LOCAL lock_timeout = '5s';

CREATE SEQUENCE org_outbox_seq;

ALTER TABLE org_outbox ADD COLUMN seq bigint;
ALTER TABLE org_outbox ALTER COLUMN seq SET DEFAULT nextval('org_outbox_seq');
ALTER TABLE org_outbox ADD COLUMN lease_token uuid;
ALTER TABLE org_outbox ADD COLUMN lease_until timestamptz;
ALTER TABLE org_outbox ADD COLUMN last_attempt_at timestamptz;
ALTER TABLE org_outbox ADD COLUMN host_state text;
ALTER TABLE org_outbox ADD COLUMN host_lifecycle_gen bigint;

GRANT USAGE ON SEQUENCE org_outbox_seq TO sbci_api, sbci_app, sbci_worker;

GRANT SELECT, INSERT, UPDATE ON org_outbox TO sbci_worker;

GRANT SELECT (org_id, display_name, status, lifecycle_gen, host_id) ON orgs TO sbci_worker;
GRANT UPDATE (status, lifecycle_gen, host_id, updated_at) ON orgs TO sbci_worker;

COMMENT ON COLUMN org_outbox.lease_token IS 'M6.4 claim fencing token; the outcome is recorded only by the lease holder.';
