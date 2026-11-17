-- 0089_worker_org_kind.sql - the outbox worker may read orgs.kind
-- (managed-SaaS plan 07 M6.3 worker side, wave 13 lane cloud-worker;
-- docs/security.md ENTLWORK-2).
--
-- step: expand
--
-- The worker composes each org's signed entitlements document
-- (internal/cloudserver/entitlementwork) and the document binds a kind
-- (internal/entitlements: personal or team; a personal document never
-- verifies on a team org). The org's kind is orgs.kind, which 0058 left out
-- of the worker's column grant. This step adds that one column. The worker
-- still reads no slug, tenancy, creator or membership, and gains no write.
--
-- Column-level, like 0058's: the worker reads orgs through 0059's
-- USING (true) policy, so the column grant is the whole bound on what it
-- sees.

SET LOCAL lock_timeout = '5s';

GRANT SELECT (kind) ON orgs TO sbci_worker;
