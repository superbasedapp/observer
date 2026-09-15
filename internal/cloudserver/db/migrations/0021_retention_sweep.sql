-- 0021_retention_sweep.sql — W6d retention-TTL hygiene (cloud-intelligence
-- divergence remediation plan rev 4.2, §3 "W6d"; completes E6/W6d). The 0019
-- deletion pass immediately PURGES the enrichment cluster + credentials and
-- pseudonymizes the account, RETAINING only the rows with a legal/billing/
-- consent/audit basis; 0019 set the retention clocks (accounts.deleted_at /
-- accounts.purge_after) but nothing aged the retained rows out. This adds the
-- cross-tenant retention sweeper that finishes the lifecycle:
--
--   * 12-month clock (deleted_at + 12mo): the consent-proof + billing rows —
--     consent_receipts, consent_events, portal_consent_events,
--     analysis_usage_ledger — are purged.
--   * 24-month clock (purge_after = deleted_at + 24mo, the abuse/forensics
--     basis, same clock as security_audit_events): the audit + lifecycle rows —
--     security_audit_events, deletion_requests, structural_grants — are purged,
--     then the pseudonymized account ROW itself. Every FK referencing accounts
--     is NO ACTION except auth_transactions (ON DELETE CASCADE), so the account
--     DELETE must run AFTER every other child is gone; it is ordered last and
--     cascades any residual auth_transactions. purge_after > deleted_at+12mo by
--     construction, so an account that reaches the 24-month clock has always
--     passed the 12-month one — the child rows are always gone first (FK-safe).
--
-- The sweeper is SECURITY DEFINER (owned by BYPASSRLS sbci_defs) so it reaches
-- every tenant, mirroring sbci_sweep_expired_evidence/_exports; the retained
-- tables are RLS'd, so a plain application role could not delete another
-- tenant's rows. It NEVER touches a live account (status='deleted' gate) and is
-- purely clock-driven.

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

    -- 24-month clock: audit + lifecycle rows, then the account row itself.
    WITH due AS (
        SELECT account_id FROM accounts
         WHERE status = 'deleted' AND purge_after IS NOT NULL
           AND purge_after <= p_now
    ), d1 AS (DELETE FROM security_audit_events WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d2 AS (DELETE FROM deletion_requests     WHERE account_id IN (SELECT account_id FROM due) RETURNING 1),
       d3 AS (DELETE FROM structural_grants      WHERE account_id IN (SELECT account_id FROM due) RETURNING 1)
    SELECT (SELECT count(*) FROM d1) + (SELECT count(*) FROM d2) + (SELECT count(*) FROM d3)
      INTO v_audit;

    -- Account rows last (cascades any residual auth_transactions).
    DELETE FROM accounts
     WHERE status = 'deleted' AND purge_after IS NOT NULL AND purge_after <= p_now;
    GET DIAGNOSTICS v_n = ROW_COUNT;
    v_accounts := v_n;

    RETURN QUERY SELECT v_consent, v_audit, v_accounts;
END$$;

ALTER FUNCTION sbci_sweep_retention(timestamptz) OWNER TO sbci_defs;

-- Base-table privileges the DEFINER body needs past BYPASSRLS. SELECT is
-- required alongside DELETE because every DELETE's WHERE clause reads the row's
-- account_id (a column read needs SELECT even inside a DELETE — DELETE alone is
-- not enough; mirrors the evidence sweep's SELECT+DELETE grant).
GRANT SELECT, DELETE ON accounts              TO sbci_defs;
GRANT SELECT, DELETE ON consent_receipts      TO sbci_defs;
GRANT SELECT, DELETE ON consent_events        TO sbci_defs;
GRANT SELECT, DELETE ON portal_consent_events TO sbci_defs;
GRANT SELECT, DELETE ON analysis_usage_ledger TO sbci_defs;
GRANT SELECT, DELETE ON security_audit_events TO sbci_defs;
GRANT SELECT, DELETE ON deletion_requests     TO sbci_defs;
GRANT SELECT, DELETE ON structural_grants     TO sbci_defs;

REVOKE ALL ON FUNCTION sbci_sweep_retention(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_sweep_retention(timestamptz) TO sbci_api, sbci_app;
