-- 145_reprice.sql - opt-in retroactive re-pricing of stored node costs
-- (lane G-REPRICE, 2026-09-29, closes gap PRICE-REPRICE-1; docs/pricing.md
-- "Re-pricing stored costs"). NODE-LOCAL, no server pair (the org's own
-- re-price of its rows is a server migration of its own).
--
-- WHY. Cost is stamped at capture: the proxy writes api_turns.cost_usd as a
-- turn lands and the rolling summariser writes summary_calls.cost_usd as a
-- summary call returns. A price corrected later - a vendor list price the
-- public feed restated, an org rate authored after the fact - never reached a
-- row captured before it, so a dashboard total spanning the correction mixed
-- two rate cards and nothing could say which row was priced under which.
-- `observer reprice` (and the Settings card over the same service,
-- internal/repricesvc) re-prices the stored rows at the price in force AT
-- EACH ROW'S OWN TIMESTAMP, dry run first, operator-invoked only, never
-- automatic. The decisions are internal/reprice's (pure, table-driven); this
-- migration only gives them somewhere durable and reversible to land.
--
-- WHAT.
--
--   api_turns / summary_calls gain two columns each:
--     cost_usd_captured  the cost the row held BEFORE its FIRST re-price (the
--                        originally captured figure, which may be NULL = the
--                        row was captured unpriced). NULL on a row that was
--                        never re-priced - the live cost_usd IS the captured
--                        cost then. A second re-price never overwrites it.
--     cost_repriced_run  reprice_runs.id of the run that last re-priced the
--                        row; NULL = never re-priced (or reverted back to
--                        its captured cost, which also clears
--                        cost_usd_captured).
--   Every write to them is a compare-and-swap on the old cost_usd
--   (`WHERE id = ? AND cost_usd IS ?`), so a capture path that rewrote the row
--   between the dry run and the apply wins and the miss is counted, never
--   overwritten.
--
--   reprice_runs     one row per run (kind apply | revert): who, when, the
--                    window and model filter, the planner's rule_version, the
--                    pricing source + version the run priced under, and the
--                    totals over the rows ACTUALLY written (not the plan).
--                    A revert run names the run it reverted (reverts_run);
--                    the reverted run points back (reverted_by_run) and its
--                    status becomes 'reverted', which is what refuses a
--                    second revert. summary_json carries the skipped-by-
--                    reason counts and the per-table / per-model breakdown.
--   reprice_changes  the per-row change log a revert replays: the cost before
--                    (old_cost) and after (new_cost) and the row's marker
--                    before the run (prev_run). WITHOUT ROWID on its natural
--                    key; the (tbl, row_id) index finds a row's history.
--
-- TRIGGERS. ALTER TABLE ADD COLUMN drops no trigger. The two new columns are
-- deliberately in NO trigger's column list:
--   * org_push_change_api_turns (migration 142) already fires on cost_usd, so
--     a re-priced api_turns row is re-queued for the org by itself; the
--     marker / captured columns are node-local bookkeeping and must not cause
--     a re-send of their own.
--   * spend_verdict_dirty_api_turns_update (migration 143) likewise fires on
--     cost_usd and marks the session's verdicts dirty; nothing here touches
--     the spend_verdict tables directly.
-- summary_calls has no push trigger (it never crosses the org wire).
--
-- PRIVACY. reprice_runs / reprice_changes and the two columns are NODE-LOCAL:
-- internal/store/orgpush.go never selects them, and the table names are in
-- the privacy sentinel (tests/invariant/privacy_test.go).
ALTER TABLE api_turns ADD COLUMN cost_usd_captured REAL;
ALTER TABLE api_turns ADD COLUMN cost_repriced_run INTEGER;
ALTER TABLE summary_calls ADD COLUMN cost_usd_captured REAL;
ALTER TABLE summary_calls ADD COLUMN cost_repriced_run INTEGER;

CREATE TABLE IF NOT EXISTS reprice_runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    kind             TEXT    NOT NULL CHECK (kind IN ('apply', 'revert')),
    created_at       TEXT    NOT NULL,
    actor            TEXT    NOT NULL DEFAULT '',
    since            TEXT    NOT NULL DEFAULT '',
    until            TEXT    NOT NULL DEFAULT '',
    model            TEXT    NOT NULL DEFAULT '',
    rule_version     INTEGER NOT NULL DEFAULT 0,
    pricing_source   TEXT    NOT NULL DEFAULT '',
    pricing_version  INTEGER NOT NULL DEFAULT 0,
    scanned          INTEGER NOT NULL DEFAULT 0,
    changed          INTEGER NOT NULL DEFAULT 0,
    filled           INTEGER NOT NULL DEFAULT 0,
    cas_missed       INTEGER NOT NULL DEFAULT 0,
    old_usd          REAL    NOT NULL DEFAULT 0,
    new_usd          REAL    NOT NULL DEFAULT 0,
    delta_usd        REAL    NOT NULL DEFAULT 0,
    reverts_run      INTEGER,
    reverted_by_run  INTEGER,
    status           TEXT    NOT NULL DEFAULT 'running'
                     CHECK (status IN ('running', 'applied', 'partial', 'reverted')),
    summary_json     TEXT    NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS reprice_changes (
    run_id    INTEGER NOT NULL,
    tbl       TEXT    NOT NULL,
    row_id    INTEGER NOT NULL,
    old_cost  REAL,
    new_cost  REAL,
    prev_run  INTEGER,
    PRIMARY KEY (run_id, tbl, row_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_reprice_changes_row ON reprice_changes(tbl, row_id);
