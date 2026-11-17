-- 0079_plan_v5_token_budgets.sql - plan catalogue v5: both plans move from
-- enrichment COUNT caps to the token budgets of an enrichment tier (ruling
-- R-AI1; 0078 has the schema and the why).
--
-- step: data
--
-- WHAT MOVES
--
--   free v5       copied from free v4; enrichment_tier = 'free' (gpt-oss-20b,
--                 4,000 evidence tokens, the tier's token budgets).
--   plus_beta v5  copied from plus_beta v4; enrichment_tier = 'paid'
--                 (gpt-oss-120b, 12,000 evidence tokens).
--
-- Everything else is COPIED from v4 by INSERT ... SELECT, including
-- daily_cap / monthly_cap and route_id. Under a tier those three are INERT
-- for session enrichment (the tier's budgets and route are read instead);
-- they are kept so a binary that predates the tier, run against this
-- database after a rollback, still serves every account exactly as v4 did
-- instead of reading a zero cap as "refuse everything". The weekly project
-- digest keeps its count caps (they bound digests per project, not data).
-- concurrency_cap, the budget pool and its USD ceiling (0044) are unchanged.
--
-- IMMUTABILITY AND ASSIGNMENTS: exactly 0043's mechanism. v5 is a NEW
-- (name, version) row; v1-v4 stay as they were. Unassigned accounts resolve
-- store.DefaultFreePlanVersion, which the same commit bumps to 5. Accounts
-- with a row on an older free / plus_beta version move to v5: (a) a row in
-- force that started strictly before now() is closed at now() and a v5 row
-- opened at now() preserving its end and source; (b) a row that has not
-- started yet is repointed in place. Paddle renewals cannot revert the move
-- (store/paddle.go's version floor).
--
-- DATA STEP. The two statements that move assignments are bounded by their
-- WHERE (account_plans holds one or two rows per account), so there is no
-- batch to resume. The cloud runner keeps no progress table (its ledger is
-- sbci_migrations, which records this step's label), so migcheck holds a
-- cloud data step to being transactional instead (L-79): this step commits
-- whole or not at all, and a rerun starts it over.

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';

-- ---------------------------------------------------------------------------
-- 1) The v5 plan rows.
-- ---------------------------------------------------------------------------
INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap,
                   budget_pool, digest_weekly, results_retention_days, route_id, enrichment_tier)
SELECT 'free', 5, p.label, p.daily_cap, p.monthly_cap, p.concurrency_cap,
       p.budget_pool, p.digest_weekly, p.results_retention_days, p.route_id, 'free'
  FROM plans p
 WHERE p.name = 'free' AND p.version = 4
ON CONFLICT (name, version) DO NOTHING;

INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap,
                   budget_pool, digest_weekly, results_retention_days, route_id, enrichment_tier)
SELECT 'plus_beta', 5, p.label, p.daily_cap, p.monthly_cap, p.concurrency_cap,
       p.budget_pool, p.digest_weekly, p.results_retention_days, p.route_id, 'paid'
  FROM plans p
 WHERE p.name = 'plus_beta' AND p.version = 4
ON CONFLICT (name, version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2) Move every assignment on an OLDER free / plus_beta version to v5.
-- ---------------------------------------------------------------------------
-- (a) Rows IN FORCE that started strictly before now(): close each at now()
--     and open its v5 row at now(), preserving its end and source. One
--     statement (a data step holds DML only, so 0043's temp table is not
--     available): the UPDATE's self-join `old` reads each row as it was before
--     the update, so the closed row's own effective_until carries over, and
--     the INSERT consumes only rows the UPDATE has already closed.
WITH closed AS (
    UPDATE account_plans ap
       SET effective_until = now()
      FROM account_plans old
      JOIN plans p ON p.plan_id = old.plan_id
     WHERE old.id = ap.id
       AND p.name IN ('free', 'plus_beta')
       AND p.version < 5
       AND old.effective_from < now()
       AND (old.effective_until IS NULL OR old.effective_until > now())
    RETURNING ap.account_id, old.source, old.effective_until AS old_until, p.name AS plan_name
)
INSERT INTO account_plans (account_id, plan_id, effective_from, effective_until, source)
SELECT c.account_id, v5.plan_id, now(), c.old_until, c.source
  FROM closed c
  JOIN plans v5 ON v5.name = c.plan_name AND v5.version = 5;

-- (b) Rows that have NOT STARTED (effective_from >= now()): repoint in place.
UPDATE account_plans ap
   SET plan_id = v5.plan_id
  FROM plans old, plans v5
 WHERE old.plan_id = ap.plan_id
   AND old.name IN ('free', 'plus_beta')
   AND old.version < 5
   AND v5.name = old.name
   AND v5.version = 5
   AND ap.effective_from >= now();
