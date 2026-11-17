-- 0050_billing_org_id.sql - a nullable org_id on the two billing tables
-- (managed-SaaS M6.1a; design
-- docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.1 and A8).
--
-- step: expand
--
-- Plan 06 5.8.6 re-keys billing to the org. This step only adds the column:
--
--   paddle_subscriptions.org_id  the org a subscription pays for
--   checkout_intents.org_id      the org a checkout was started for
--
-- M6.5 writes it for new team orgs; M9.3 backfills the personal-plane rows in
-- a data step of its own; the account_id columns stay until M9 plus one
-- release. Nullable with no default, so ADD COLUMN changes only the catalog.
--
-- Left out on purpose:
--   - The unique partial index on live subscriptions per org (design 4.1).
--     It must be built CONCURRENTLY in a non-transactional step, and the
--     cloud runner refuses that class today (internal/cloudserver/db,
--     applyStep). Nothing writes org_id before M6.5, so the lane that first
--     writes it adds the index once the runner has the class.
--   - A foreign key to orgs: it would lock orgs and both billing tables, and
--     it can be added NOT VALID and validated later by the same lane.
--
-- No grant: both tables carry table-level grants (0024, 0030), which cover a
-- new column, and their account_id RLS policies are unchanged.

SET LOCAL lock_timeout = '5s';

ALTER TABLE paddle_subscriptions ADD COLUMN org_id uuid;
ALTER TABLE checkout_intents ADD COLUMN org_id uuid;
