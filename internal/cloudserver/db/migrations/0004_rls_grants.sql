-- 0004_rls_grants.sql — RLS enable/force + policies + the grant structure.
--
-- Tenant isolation model (Sol SC5): every account-owned table has RLS ENABLEd
-- and FORCEd, with a single policy keyed on the transaction-scoped GUC
-- sbci.account_id. A missing or empty context matches NO rows
-- (missing-context-DENY): sbci_current_account() returns NULL when the GUC is
-- unset or '', and `account_id = NULL` is never true.
--
-- The application connects as a login role that is a member of sbci_app, then
-- runs `SET LOCAL ROLE sbci_app` + set_config('sbci.account_id', ...) per
-- transaction (internal/cloudserver/store). Because sbci_app is NOBYPASSRLS
-- and never the table owner, RLS constrains it. FORCE additionally constrains a
-- non-superuser table owner in production (defense in depth).

-- Current-tenant helper: NULL when unset/empty ⇒ deny-by-default.
CREATE OR REPLACE FUNCTION sbci_current_account()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    SELECT nullif(current_setting('sbci.account_id', true), '')::uuid
$$;

-- ---------------------------------------------------------------------------
-- Enable + force RLS and install the tenant policy on every account-owned
-- table.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
    t text;
    tenant_tables text[] := ARRAY[
        'identity_links', 'device_registrations', 'api_tokens', 'browser_sessions',
        'consent_receipts', 'consent_events', 'entitlements', 'usage_cycles',
        'usage_reservations', 'cloud_projects', 'cloud_sessions', 'evidence_objects',
        'analysis_jobs', 'analysis_results', 'analysis_usage_ledger',
        'deletion_requests', 'pop_replay'
    ];
BEGIN
    FOREACH t IN ARRAY tenant_tables LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'CREATE POLICY %I ON %I USING (account_id = sbci_current_account()) '
            || 'WITH CHECK (account_id = sbci_current_account())',
            t || '_tenant', t);
    END LOOP;
END$$;

-- ---------------------------------------------------------------------------
-- Grants to sbci_app.
-- ---------------------------------------------------------------------------

-- System (non-RLS) control-plane tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    accounts, exchange_nonces, route_registry, kill_switches,
    free_tier_budget, security_audit_events
TO sbci_app;

-- Tenant tables: full DML (RLS still constrains each row).
GRANT SELECT, INSERT, UPDATE, DELETE ON
    identity_links, device_registrations, api_tokens, browser_sessions,
    consent_receipts, consent_events, entitlements, usage_cycles,
    usage_reservations, cloud_projects, cloud_sessions, evidence_objects,
    analysis_jobs, analysis_results, deletion_requests, pop_replay
TO sbci_app;

-- Append-only ledger: no UPDATE/DELETE for the app.
GRANT SELECT, INSERT ON analysis_usage_ledger TO sbci_app;

-- Sequences (analysis_results identity column).
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sbci_app;

-- Base grants the SECURITY DEFINER functions need under sbci_defs (BYPASSRLS
-- removes the row filter but base-table privileges are still required).
GRANT SELECT, UPDATE ON analysis_jobs TO sbci_defs;
GRANT SELECT ON api_tokens, device_registrations, accounts, identity_links TO sbci_defs;

-- Function execution.
GRANT EXECUTE ON FUNCTION sbci_current_account() TO sbci_app;
REVOKE ALL ON FUNCTION sbci_lease_next_job(text, timestamptz, text[], int) FROM PUBLIC;
REVOKE ALL ON FUNCTION sbci_introspect_token(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION sbci_find_identity_link(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_lease_next_job(text, timestamptz, text[], int) TO sbci_app;
GRANT EXECUTE ON FUNCTION sbci_introspect_token(text) TO sbci_app;
GRANT EXECUTE ON FUNCTION sbci_find_identity_link(text, text) TO sbci_app;

-- ---------------------------------------------------------------------------
-- Seed rows.
-- ---------------------------------------------------------------------------

-- A generous global free-tier budget for staging; the operator narrows it in
-- production. Enforcement (locking this row, checking used < cap) is real; the
-- value is not the point in the foundation phase.
INSERT INTO free_tier_budget (id, cap, used) VALUES (1, 100000000, 0)
    ON CONFLICT (id) DO NOTHING;

-- Global kill switch, default OFF.
INSERT INTO kill_switches (scope, key, active, generation)
    VALUES ('global', 'all', false, 0)
    ON CONFLICT (scope, key) DO NOTHING;

-- Placeholder route for the only feature this arc: session_enrichment via the
-- Luna deployment, Chat Completions dialect (plan §2.3).
INSERT INTO route_registry (route_id, feature, deployment, dialect, route_version, prompt_version, price_version, active)
    VALUES ('session_enrichment.luna.v1', 'session_enrichment', 'luna', 'chat_completions', 1, 1, 'unset', true)
    ON CONFLICT (route_id) DO NOTHING;

-- Per-route kill switch for that route, default OFF.
INSERT INTO kill_switches (scope, key, active, generation)
    VALUES ('route', 'session_enrichment.luna.v1', false, 0)
    ON CONFLICT (scope, key) DO NOTHING;
