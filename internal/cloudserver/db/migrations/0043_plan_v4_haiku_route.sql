-- 0043_plan_v4_haiku_route.sql - plan catalogue v4: both plans pin the
-- Claude Haiku 5.5 route (operator ruling "Pin Haiku", 2026-10-20).
--
-- WHAT MOVES
--
--   free v4       copied from free v3 (100/day, 3000/month, concurrency 2,
--                 pool, digest, retention, label), route_id moves from
--                 'session_enrichment.gpt-6-luna.v1' to
--                 'session_enrichment.claude-haiku-5-5.v1' (migration 0042).
--   plus_beta v4  copied from plus_beta v3 (500/day, 15000/month,
--                 concurrency 4, pool, digest, retention, label), same route
--                 move.
--
-- Nothing else moves: the ruling names only the route. Azure is gone, so the
-- GPT-6 Luna deployment the v3 rows pin will never exist; every v3 submission
-- therefore degrades to the feature default and writes a
-- plan_route_unavailable audit row. Pinning the Haiku route the box actually
-- runs makes new submissions route directly.
--
-- IMMUTABILITY. Exactly 0041's mechanism: plan rows are immutable (0012's
-- sbci_plans_immutable BEFORE UPDATE trigger), so v4 is a NEW (name, version)
-- row and the v1/v2/v3 rows stay byte-for-byte as they were (readable
-- history; analysis results keep their own route snapshot). Only INSERTs into
-- plans, every column not deliberately moved is COPIED from v3 by
-- INSERT ... SELECT, and every insert is ON CONFLICT DO NOTHING.
--
-- THE ROUTE IS NOT MUTATED HERE. 0042's Haiku row ships inactive and unbound;
-- `observer-cloud route bind-anthropic --activate` binds, prices and
-- activates it. Until then a v4 plan degrades to the feature default exactly
-- like v3 did (store.ResolveRouteForPlan, reason 'inactive'): service stays up
-- and the signal stays visible. After the bind the pin serves directly and no
-- fallback row is written.
--
-- ASSIGNMENTS. Unassigned accounts resolve store.DefaultFreePlanVersion, which
-- the same commit bumps to 4. Accounts WITH a row on an older free /
-- plus_beta version move to v4 with 0041's two shapes: (a) a row in force that
-- started strictly before now() is closed at now() and a v4 row opened at
-- now() preserving its end and source; (b) a row that has not started yet
-- (a scheduled cycle-boundary change, or a row an earlier migration in the
-- SAME runner transaction opened at exactly now()) is repointed in place.
-- Paddle renewals cannot revert the move: the version floor in
-- store/paddle.go keeps an account on the highest version it holds.
--
-- PRIVILEGE NOTE. Identical to 0039 / 0041: table-level grants, migrator
-- connection, no new grant.

-- ---------------------------------------------------------------------------
-- 1) The v4 plan rows.
-- ---------------------------------------------------------------------------
INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap,
                   budget_pool, digest_weekly, results_retention_days, route_id)
SELECT 'free', 4, p.label, p.daily_cap, p.monthly_cap, p.concurrency_cap,
       p.budget_pool, p.digest_weekly, p.results_retention_days, 'session_enrichment.claude-haiku-5-5.v1'
  FROM plans p
 WHERE p.name = 'free' AND p.version = 3
ON CONFLICT (name, version) DO NOTHING;

INSERT INTO plans (name, version, label, daily_cap, monthly_cap, concurrency_cap,
                   budget_pool, digest_weekly, results_retention_days, route_id)
SELECT 'plus_beta', 4, p.label, p.daily_cap, p.monthly_cap, p.concurrency_cap,
       p.budget_pool, p.digest_weekly, p.results_retention_days, 'session_enrichment.claude-haiku-5-5.v1'
  FROM plans p
 WHERE p.name = 'plus_beta' AND p.version = 3
ON CONFLICT (name, version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 2) Move every assignment on an OLDER free / plus_beta version to v4.
-- ---------------------------------------------------------------------------
-- (a) Rows IN FORCE that started strictly before now().
CREATE TEMP TABLE sbci_0043_moves ON COMMIT DROP AS
SELECT ap.id, ap.account_id, ap.source, ap.effective_until AS old_until, p.name AS plan_name
  FROM account_plans ap
  JOIN plans p ON p.plan_id = ap.plan_id
 WHERE p.name IN ('free', 'plus_beta')
   AND p.version < 4
   AND ap.effective_from < now()
   AND (ap.effective_until IS NULL OR ap.effective_until > now());

UPDATE account_plans
   SET effective_until = now()
 WHERE id IN (SELECT id FROM sbci_0043_moves);

INSERT INTO account_plans (account_id, plan_id, effective_from, effective_until, source)
SELECT m.account_id, v4.plan_id, now(), m.old_until, m.source
  FROM sbci_0043_moves m
  JOIN plans v4 ON v4.name = m.plan_name AND v4.version = 4;

-- (b) Rows that have NOT STARTED (effective_from >= now()): repoint in place.
UPDATE account_plans ap
   SET plan_id = v4.plan_id
  FROM plans old, plans v4
 WHERE old.plan_id = ap.plan_id
   AND old.name IN ('free', 'plus_beta')
   AND old.version < 4
   AND v4.name = old.name
   AND v4.version = 4
   AND ap.effective_from >= now();
