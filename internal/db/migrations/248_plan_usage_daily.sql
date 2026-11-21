-- 248_plan_usage_daily.sql - daily usage reconciliation for Plans & limits
-- (docs/plans-and-limits.md "Daily usage reconciliation"; grounding
-- docs/plans/cloud-agents/grounding/codex-cloud-probe-2026-11-02.md).
--
-- One row per Plans & limits account and UTC day: the account-wide token
-- total the vendor reports for that day (today the Codex app-server method
-- account/usage/read, read in the same session as the rate limits). The
-- page sets it beside what this node captured for the same day.
--
--   account_id - the plan_accounts id the reading came from
--   provider   - the account's provider id (chatgpt)
--   day        - YYYY-MM-DD, as the vendor labels the bucket
--   tokens     - the vendor's total for the day (account-wide: every
--                surface and device on the login)
--   fetched_at - unix seconds of the reading that last wrote the row
--
-- Upserted per reading: the latest value for a day wins, and a day missing
-- from a later reading is NOT deleted. Removing the account removes its rows
-- (internal/store/planlimits.go DeletePlanAccount, in the same transaction
-- as plan_snapshots and plan_runs).
--
-- NODE-LOCAL. One owner: internal/store/planlimits.go, the only writer of
-- the plan_* tables. Never on the org push wire (the privacy sentinel's
-- forbidden set, tests/invariant/privacy_test.go); no server pair.
--
-- Numbered 248, inside the cloud-agents reservation (node 240-249, CA-D14).
-- The plans line may renumber it at fold.
CREATE TABLE IF NOT EXISTS plan_usage_daily (
    account_id TEXT NOT NULL,
    provider   TEXT NOT NULL,
    day        TEXT NOT NULL,
    tokens     INTEGER NOT NULL,
    fetched_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, day)
);
