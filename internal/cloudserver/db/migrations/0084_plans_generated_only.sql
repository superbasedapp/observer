-- 0084_plans_generated_only.sql - plans rows are generated from the
-- entitlements plan catalog, never authored (managed-SaaS M7b.1; plan 06
-- 17.2 "the cloud plans and account_plans tables stop being an authored
-- source"; docs/security.md ENTL-3).
--
-- step: expand
--
-- The one authored source of a plan is now its template in
-- internal/entitlements (catalog.go). `observer-cloud migrate` runs
-- store.GeneratePlans after the migrations: it inserts each catalog plan
-- whose (name, version) is missing and checks each one that exists, failing
-- on drift. That transaction sets sbci.plan_writer = 'generator'; this
-- trigger refuses an INSERT from any transaction that has not, so a plan can
-- no longer arrive by a migration step or by hand. The application roles hold
-- SELECT only on plans (0012), so only the table's owner (the migrating
-- login) can insert at all; the setting is a guard against authoring by
-- mistake, not a credential.
--
-- Rows already present (free and plus_beta v1-v5, written by 0012 to 0079)
-- are history and are untouched: a trigger on INSERT does not run over them.
-- UPDATE stays refused by 0012's immutability trigger; DELETE of an
-- unreferenced version stays an operator action, as 0012 decided.
--
-- The function is SECURITY INVOKER (it reads one setting and touches no
-- table), with search_path pinned like every other function of the lineage.

SET LOCAL lock_timeout = '5s';

CREATE FUNCTION sbci_plans_generated_only()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF coalesce(current_setting('sbci.plan_writer', true), '') <> 'generator' THEN
        RAISE EXCEPTION 'plans rows are generated from the entitlements plan catalog (M7b.1): add % v% to internal/entitlements/catalog.go and run observer-cloud migrate instead of inserting it',
            NEW.name, NEW.version;
    END IF;
    RETURN NEW;
END$$;

CREATE TRIGGER sbci_plans_generated_only
    BEFORE INSERT ON plans
    FOR EACH ROW EXECUTE FUNCTION sbci_plans_generated_only();
