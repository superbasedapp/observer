-- 0157_org_usage_days_aigw.sql - the control plane keeps each org's hosted
-- AI gateway usage beside its daily usage report (hosted AI gateway plan
-- 3.13 and section 4 item 8k, lane L4; L-172).
--
-- step: expand
--
-- The tenant host's daily report (platformcontract.TenantUsage) gains two
-- additive fields, which the outbox worker stores here:
--
--   aigw_requests   the AI gateway's forwarded model calls in the UTC month
--                   of the report's day, as the host counted them when it
--                   answered (month to date: the host's meter is monthly).
--                   A day pulled twice keeps the larger (store.
--                   RecordOrgUsageDay), as sessions does.
--   aigw_refusals   the usage gate's refusals that month by reason
--                   ({"refused_quota": n, ...}); each reason keeps the larger
--                   on a merge.
--
-- Read by the staff console's org usage card and, later, billing. Counts
-- only, no content and no member id, so the W16-D9 minimisation leaves them.
-- Two new columns with constant defaults: no table rewrite, no lock beyond
-- the brief ACCESS EXCLUSIVE of ADD COLUMN; an older release never reads or
-- writes them. Their CHECKs are added NOT VALID here (migcheck's online
-- rule: no scan under the ADD's lock) and validated by 0158.

SET LOCAL lock_timeout = '5s';

ALTER TABLE org_usage_days
    ADD COLUMN IF NOT EXISTS aigw_requests bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS aigw_refusals jsonb NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE org_usage_days
    ADD CONSTRAINT org_usage_days_aigw_requests_check CHECK (aigw_requests >= 0) NOT VALID;

ALTER TABLE org_usage_days
    ADD CONSTRAINT org_usage_days_aigw_refusals_check CHECK (jsonb_typeof(aigw_refusals) = 'object') NOT VALID;
