-- 0092_worker_org_slug.sql - the outbox worker may read orgs.slug
-- (managed-SaaS plan 07 M6.4, wave 14 lane tenant-cloud; docs/security.md
-- ENTLWORK-9).
--
-- step: expand
--
-- A pooled tenant host routes an org by its slug (<slug>.superbased.app,
-- plan 06 5.5; lead decision W14-D6) and refuses a create_tenant request
-- that carries none (internal/orgserver/tenantprov ValidateSlug). The worker
-- builds that request (internal/cloudserver/hostapi), so it must read the
-- org's current slug when it sends the create. The slug is the org's public
-- host name, not personal data. This step adds that one column to 0058's and
-- 0089's column grant. The worker still reads no tenancy, creator or
-- membership row, and gains no write.
--
-- Column-level, like 0058's: the worker reads orgs through 0059's
-- USING (true) policy, so the column grant is the whole bound on what it
-- sees.

SET LOCAL lock_timeout = '5s';

GRANT SELECT (slug) ON orgs TO sbci_worker;
