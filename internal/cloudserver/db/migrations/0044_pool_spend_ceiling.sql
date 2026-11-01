-- 0044_pool_spend_ceiling.sql - USD spend per budget pool per UTC day and
-- per UTC month (T-946, open sign-up on cloud.superbased.app).
--
-- WHY. budget_pools.cap (0012) counts reservations over a pool's whole life
-- and never resets, so once anyone can sign up it does not bound what the
-- provider bill reaches in a day. The store now keeps a USD ceiling per pool
-- (store/spend.go; the Free pool defaults to USD 5 a day and USD 50 a month,
-- SBCI_FREE_POOL_DAILY_USD / SBCI_FREE_POOL_MONTHLY_USD) and this table is
-- what it measures against: the worker adds each job's provider cost to the
-- two windows of the pool the job's reservation drew from, the API refuses a
-- new reservation once a window reached its ceiling, and the worker parks a
-- queued job before its provider call for the same reason.
--
-- SYSTEM table like budget_pools: no RLS, no account linkage (one row per
-- pool per window, sums only), so the account-deletion matrix classifies it
-- "excluded". Rows are never deleted by the service; a year of them is two
-- rows a day per pool.
--
-- PRIVILEGES. sbci_api only reads (the reservation check). sbci_worker reads
-- and upserts (the cost of accepted results and of rejected attempts).
-- sbci_app gets the same as the worker for the operator paths that drive the
-- pipeline as the admin role.

CREATE TABLE budget_pool_spend (
    pool        text NOT NULL,
    window_kind text NOT NULL CHECK (window_kind IN ('daily', 'monthly')),
    window_key  text NOT NULL,
    spent_usd   numeric(18, 6) NOT NULL DEFAULT 0 CHECK (spent_usd >= 0),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (pool, window_kind, window_key)
);

GRANT SELECT                 ON budget_pool_spend TO sbci_api;
GRANT SELECT, INSERT, UPDATE ON budget_pool_spend TO sbci_worker;
GRANT SELECT, INSERT, UPDATE ON budget_pool_spend TO sbci_app;
