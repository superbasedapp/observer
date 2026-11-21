-- 254: cloud_sync_last records the token budgets GET /v1/usage reports
-- (managed-SaaS ruling R-AI1, plan v5; docs/cloud-intelligence.md "Plan v5:
-- token budgets").
--
-- On a token-budgeted plan the hosted service refuses an evidence envelope
-- whose estimated evidence tokens exceed the tier's evidence budget
-- (413 evidence_over_budget). The node fits instead: before preview and
-- consent it steps its own evidence settings down with
-- cloudevidence.FitToBudget until the envelope fits, so it must know the
-- budget at build time, which is long after the sync that read it. This step
-- adds the budget columns to the existing singleton cloud_sync_last row
-- (migration 117) beside the plan columns migration 118 added.
--
--   budget_unit           - "count" or "tokens" as the server reported it;
--                           '' = unknown (a pre-v5 server, or no usage read)
--   enrichment_tier       - the tier in force ("free", "paid"); '' = none
--   evidence_token_budget - the most evidence tokens one envelope may carry;
--                           0 = the plan sets no evidence budget. LAST-KNOWN:
--                           a sync whose usage read failed keeps the stored
--                           value (store.RecordCloudSyncLast), because it is a
--                           build input, not a display fact. NULL = never
--                           read; the node then uses the free tier's 4,000
--                           (cloudcontract.DefaultEvidenceTokenBudget)
--   session_token_budget, daily_tokens_used, daily_token_budget,
--   monthly_tokens_used, monthly_token_budget
--                         - the token windows for display, NULL = unknown;
--                           like the plan columns they are rewritten on every
--                           sync, so a failed read shows "unknown", never a
--                           stale number
--
-- Additive only: existing rows keep every value and read the new columns as
-- '' / NULL. A binary predating this step never names them.
--
-- NODE-LOCAL: cloud_sync_last is already in the privacy sentinel's forbidden
-- table list (tests/invariant/privacy_test.go) and orgpush.go never names it;
-- budget_unit and enrichment_tier get the sentinel seed there like the
-- table's other text columns.

ALTER TABLE cloud_sync_last ADD COLUMN budget_unit TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_sync_last ADD COLUMN enrichment_tier TEXT NOT NULL DEFAULT '';
ALTER TABLE cloud_sync_last ADD COLUMN evidence_token_budget INTEGER; -- NULL = never read
ALTER TABLE cloud_sync_last ADD COLUMN session_token_budget INTEGER;  -- NULL = unknown
ALTER TABLE cloud_sync_last ADD COLUMN daily_tokens_used INTEGER;     -- NULL = unknown
ALTER TABLE cloud_sync_last ADD COLUMN daily_token_budget INTEGER;    -- NULL = unknown
ALTER TABLE cloud_sync_last ADD COLUMN monthly_tokens_used INTEGER;   -- NULL = unknown
ALTER TABLE cloud_sync_last ADD COLUMN monthly_token_budget INTEGER;  -- NULL = unknown
