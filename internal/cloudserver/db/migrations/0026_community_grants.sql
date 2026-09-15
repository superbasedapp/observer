-- 0026_community_grants.sql — W5 contribution-upload path (cloud-intelligence
-- divergence-remediation plan §3 W5 "contribution-upload path"). This is the
-- SERVER-SIDE registration of the node's STANDING community_cohort_benchmarking
-- grant, the exact analogue of structural_grants (0013) for the cohort-
-- benchmarking purpose. The read surface + delayed-band materialization
-- (0022/0023) already exist; this closes D5 phase 1 by giving a consenting node
-- a place to upload its derived per-window value under a checked standing grant.
--
-- WHY a NEW table rather than reusing structural_grants:
--   * one owner per table (CLAUDE.md #4): structural_grants is the structural
--     rail's registration and carries a structural-only binding field
--     (source_window_rule). A community contribution names its own window
--     explicitly, so that field has no meaning here — a leaner table is the
--     honest shape, not an overloaded one branched on purpose.
--
-- DELETION MATRIX = "retain" (mirrors structural_grants): the 0019 deletion pass
-- REVOKES the registration (sets revoked_at) but keeps the row as the consent-
-- registration fact, exactly like structural_grants. Because the row therefore
-- SURVIVES immediate deletion with its account_id still set, it MUST be aged out
-- by the 24-month retention sweep before the account row is deleted — otherwise
-- its NO-ACTION FK to accounts would block `DELETE FROM accounts` at 24 months
-- (the same F9 class the Paddle billing_events FK hit). This migration therefore
-- CREATE-OR-REPLACEs sbci_sweep_retention to purge community_grants on the
-- 24-month clock alongside structural_grants, and grants sbci_defs the
-- SELECT+DELETE it needs to do so.

-- ===========================================================================
-- community_grants (TENANT) — standing cohort-benchmarking grant registration.
-- ===========================================================================
CREATE TABLE community_grants (
    account_id             uuid NOT NULL REFERENCES accounts(account_id),
    -- The consent purpose this registration authorizes, derived SERVER-SIDE from
    -- the single-purpose route the upload arrived on — never a client field.
    purpose                text NOT NULL,
    -- The schema-level digest the grant binds
    -- (cloudcontract.CommunityDataDictionaryDigest). A contribution whose
    -- declared dictionary digest is not this one is not covered by this grant.
    data_dictionary_digest text NOT NULL,
    -- The contribution schema version the terms were agreed against.
    schema_version         text NOT NULL,
    -- The monotonic consent generation the terms were last agreed at. A HIGHER
    -- generation on an arriving upload means the developer re-agreed newer terms
    -- and updates this row; a LOWER one is a stale client and is refused.
    consent_generation     bigint NOT NULL CHECK (consent_generation >= 1),
    -- The IANA zone the account declared (recorded for parity with the
    -- structural registration; a contribution's window is UTC-absolute, so this
    -- is metadata, not a gate).
    declared_timezone      text NOT NULL DEFAULT '',
    first_seen_at          timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    -- Set when the registration is withdrawn server-side (today: account
    -- deletion). A revoked registration refuses every upload; it is never
    -- silently re-registered by a later upload.
    revoked_at             timestamptz,
    PRIMARY KEY (account_id, purpose)
);

ALTER TABLE community_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE community_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY community_grants_tenant ON community_grants
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

COMMENT ON TABLE community_grants IS
    'W5 server-side registration of the node standing community_cohort_benchmarking grant; retained-then-swept like structural_grants.';

-- Application-role grants. Both sbci_api (production device front door) and
-- sbci_app (the single-login staging/test role) get full DML, mirroring
-- leaderboard_contributions (0022) so the intake works under either binding.
GRANT SELECT, INSERT, UPDATE, DELETE ON community_grants TO sbci_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON community_grants TO sbci_app;

-- The DEFINER retention sweep needs SELECT (the DELETE WHERE reads account_id)
-- + DELETE, exactly as it holds on structural_grants.
GRANT SELECT, DELETE ON community_grants TO sbci_defs;

-- ===========================================================================
-- Age community_grants out on the 24-month clock (F9-class FK safety). This is
-- a faithful extension of 0021's sbci_sweep_retention: the ONLY change is a new
-- DELETE (d4) for community_grants in the 24-month CTE, so a retained grant is
-- gone before the account row it references is deleted.
-- ===========================================================================
CREATE OR REPLACE FUNCTION sbci_sweep_retention(p_now timestamptz)
RETURNS TABLE (consent_purged int, audit_purged int, accounts_purged int)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_consent  int := 0;
    v_audit    int := 0;
    v_accounts int := 0;
    v_n        int;
BEGIN
    -- 12-month clock: consent-proof + billing rows of tombstoned accounts.
    WITH due AS (
        SELECT account_id FROM accounts
         WHERE status = 'deleted' AND deleted_at IS NOT NULL
           AND deleted_at <= p_now - interval '12 months'
    ), d1 AS (DELETE FROM consent_receipts      WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d2 AS (DELETE FROM consent_events        WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d3 AS (DELETE FROM portal_consent_events WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d4 AS (DELETE FROM analysis_usage_ledger WHERE account_id IN (SELECT account_id FROM due) RETURNING 1)
    SELECT (SELECT count(*) FROM d1) + (SELECT count(*) FROM d2)
         + (SELECT count(*) FROM d3) + (SELECT count(*) FROM d4)
      INTO v_consent;

    -- 24-month clock: audit + lifecycle rows, then the account row itself. The
    -- retained standing-grant registrations (structural + community) age out
    -- here so their NO-ACTION FKs cannot block the account DELETE.
    WITH due AS (
        SELECT account_id FROM accounts
         WHERE status = 'deleted' AND purge_after IS NOT NULL
           AND purge_after <= p_now
    ), d1 AS (DELETE FROM security_audit_events WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d2 AS (DELETE FROM deletion_requests     WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d3 AS (DELETE FROM structural_grants     WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d4 AS (DELETE FROM community_grants       WHERE account_id IN (SELECT account_id FROM due) RETURNING 1)
    SELECT (SELECT count(*) FROM d1) + (SELECT count(*) FROM d2)
         + (SELECT count(*) FROM d3) + (SELECT count(*) FROM d4)
      INTO v_audit;

    -- Account rows last (cascades any residual auth_transactions).
    DELETE FROM accounts
     WHERE status = 'deleted' AND purge_after IS NOT NULL AND purge_after <= p_now;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    v_accounts := v_n;

    RETURN QUERY SELECT v_consent, v_audit, v_accounts;
END$$;

ALTER FUNCTION sbci_sweep_retention(timestamptz) OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_sweep_retention(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_sweep_retention(timestamptz) TO sbci_api, sbci_app;
