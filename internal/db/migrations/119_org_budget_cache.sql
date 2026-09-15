-- 119_org_budget_cache.sql -- the node's persisted copy of the ORG's signed
-- per-caller BUDGET document (org-observer fundamentals plan 2026-09-13, W2
-- adversarial finding H3).
--
-- ONE table, NODE-LOCAL, and its name belongs in tests/invariant/
-- privacy_test.go's forbidden set: it must never appear as a string literal
-- inside internal/store/orgpush.go. The direction is what makes that
-- unambiguous -- this row is a document the SERVER authored and SIGNED,
-- travelling server -> node on GET /api/agent/budget. The node's only
-- contribution back is the enum-only orgcontract.BudgetPostureRow. It is the
-- 106_org_pricing_cache shape, one rail over.
--
-- WHY IT IS NOW PERSISTED, having deliberately been memory-only. The original
-- reasoning was sound for a FAIL-OPEN node: "a daemon that restarts and has
-- not polled yet simply runs its own looser numbers for one cycle and then
-- tightens". Ruling R2 made that false in both directions on a MANAGED node
-- holding enforce.budget:
--
--   * With the body in memory only, every restart began with no verified body.
--     A node that is required to hold one therefore either BLOCKED every
--     proxied request until its first successful poll (during an org outage,
--     indefinitely), or -- if it had not yet been marked required -- ran
--     UNCAPPED and UNARMED for a full push interval. The second is a bypass a
--     developer can trigger at will by restarting the daemon.
--   * Persisting the last VERIFIED body makes a restart continue exactly where
--     the process left off: the caps stay in force, the fail-closed row stays
--     disarmed, and the posture reports last_fetch_ok=false until the first
--     poll of the new process succeeds -- which is the honest description of
--     that state, and the same one an outage produces without a restart.
--
-- WHAT IT STORES (one row, id = 1 -- a node holds exactly one per-caller body,
-- and two rows would be two answers to "what cap is in force here"):
--   version              the document's monotonic version, the replay floor.
--   etag                 the server's strong validator, so a restarted daemon
--                        can still make a CONDITIONAL first request and get a
--                        304 instead of re-downloading.
--   org_key_fingerprint  which TOFU-pinned org key verified this body. A later
--                        key ROTATION is then diagnosable rather than merely
--                        fatal: a version that went backwards under a NEW key
--                        is a legitimate lineage restart, under the SAME key a
--                        replay.
--   body_json            the accepted document's bytes -- the org's own signed
--                        document coming BACK, never node data going out.
--   fetched_at           when the 200 that produced this row landed. It is
--                        what a later freshness check measures against.
--
-- Only a SIGNED body may ever replace or empty this row: every non-200 path
-- writes NOTHING, so an unsigned signal is never a lever to drop a fleet's
-- caps. A SIGNED EXPLICIT NONE (resolved_scope "none") is a legitimate stored
-- body -- it is the org saying, verifiably, that it authored nothing.
--
-- No paired SERVER migration: the org half is `budgets` (server migration
-- 125), which shares no column with this.

CREATE TABLE IF NOT EXISTS org_budget_cache (
    -- id is pinned to 1: this is the node's single applied budget document.
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    version             INTEGER NOT NULL DEFAULT 0,
    etag                TEXT    NOT NULL DEFAULT '',
    org_key_fingerprint TEXT    NOT NULL DEFAULT '',
    body_json           TEXT    NOT NULL DEFAULT '',
    fetched_at          TEXT    NOT NULL DEFAULT ''
);

INSERT INTO org_budget_cache (id, version, etag, org_key_fingerprint, body_json, fetched_at)
VALUES (1, 0, '', '', '', '')
ON CONFLICT (id) DO NOTHING;
