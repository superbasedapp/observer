-- 0158_org_usage_days_aigw_validate.sql - validates the two CHECKs 0157 added
-- NOT VALID on org_usage_days (hosted AI gateway lane L4; migcheck's online
-- rule: the validating scan runs under SHARE UPDATE EXCLUSIVE, which lets
-- the worker's reads and writes go on).
--
-- step: expand
--
-- Every existing row holds the columns' defaults (0 and '{}'), which both
-- checks accept.

SET LOCAL lock_timeout = '5s';

ALTER TABLE org_usage_days VALIDATE CONSTRAINT org_usage_days_aigw_requests_check;
ALTER TABLE org_usage_days VALIDATE CONSTRAINT org_usage_days_aigw_refusals_check;
