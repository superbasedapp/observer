-- 0156_plans_label_is_copy.sql - a plan's label is copy that the plans
-- generator keeps equal to the catalog; every entitlement column stays
-- immutable (operator ruling 2026-11-24: "Personal Pro" is the only name a
-- customer sees for the paid individual plan; lane fix/personal-pro-name,
-- docs/audits/personal-pro-name-2026-11-24.md; docs/security.md PPNAME-1).
--
-- step: contract
--
-- Contract because it replaces a function an earlier step created (0012's
-- sbci_plans_immutable), which the running release's trigger calls. The
-- running release never updates plans (the application roles hold SELECT
-- only, and its generator only inserts and checks), so nothing it does
-- changes.
--
-- Why. plans.label is what GET /v1/usage sends as plan_label, which the
-- portal, `observer cloud status` and the node dashboard show verbatim. The
-- plus_beta rows still read "Plus" (0037 set v1's; 0039-0079 copied it), the
-- name of the September beta. The row is immutable (0012) and generated from
-- internal/entitlements (0084: no migration writes plans), so neither a data
-- step that rewrites the label nor a new plan version is honest:
--   * a data step would be a migration authoring a plans row, the path 0084
--     closed, and could not disable 0012's trigger (DDL is refused in a data
--     step);
--   * a plus_beta v6 that differs only in its label would need its holders
--     moved, but an account resolves its plan from account_plans in SQL
--     (store.resolvePlanTx, sbci_sweep_results_retention), never through the
--     catalog's carries rule, and no migration can point account_plans at a
--     row the generator inserts only after the migrations run.
-- The label is not an entitlement: nothing branches on it, it bounds no cap,
-- and an account-kind template is never issued as a signed document (the
-- entitlement issuer composes org kinds only). So it is made copy: the
-- generator (store.GeneratePlans, run by `observer-cloud migrate` after the
-- migrations) updates a catalog row's label when it differs and still
-- refuses every other difference as drift.
--
-- What changes. The trigger lets an UPDATE through when the transaction is
-- the generator's (sbci.plan_writer = 'generator', 0084's mark: a guard
-- against authoring by mistake, not a credential; only the table's owner can
-- write plans at all) AND the row is unchanged in every column but label
-- (compared as jsonb, so a column added later is covered without a new
-- step). Every other UPDATE is refused as before, by the table's owner too.
-- DELETE stays unguarded (0012). The function is SECURITY INVOKER, reads one
-- setting and touches no table; search_path is pinned like the lineage's
-- other functions.
--
-- This step writes no row. The label changes when `observer-cloud migrate`
-- runs the generator with a catalog whose plus_beta v5 label is "Personal
-- Pro". History rows (free and plus_beta v1-v4) are not catalog rows and keep
-- their labels; no assignment names them since 0079 moved every holder to v5.

SET LOCAL lock_timeout = '5s';

CREATE OR REPLACE FUNCTION sbci_plans_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public, pg_temp
AS $$
BEGIN
    IF coalesce(current_setting('sbci.plan_writer', true), '') = 'generator'
       AND (to_jsonb(NEW) - 'label') = (to_jsonb(OLD) - 'label') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'plans rows are immutable (W4/R4): publish a new (name, version) instead of updating %/% (only the plans generator may change label, the one copy column)',
        OLD.name, OLD.version;
END$$;
