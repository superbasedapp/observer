-- 0020_account_export.sql — W6d Export (cloud-intelligence divergence
-- remediation plan rev 4.2, §3 "W6d"; closes D11). The deletion half of W6d
-- landed in 0019; this adds the LIVE-ACCOUNT export half: a signed-in developer
-- assembles a portable copy of everything the W6d per-object matrix marks "in
-- export" into an encrypted, expiring artifact they can download (≤7 days), then
-- the artifact is deleted at expiry AND by the account-deletion pass (an
-- assembled export is itself account data — plan §3 W6d "Export/deletion
-- ordering").
--
-- One new table, export_artifacts, holds the ENCRYPTED assembled document (the
-- same envelope-encryption seam evidence_blobs uses — AES-256-GCM at rest, key
-- from SBCI_EVIDENCE_KEY in a multi-process deployment so the assembling replica
-- and the serving replica share a key). It is a TENANT table (RLS ENABLE +
-- FORCE + the sbci_current_account() policy), so every read/insert/delete can
-- only ever touch the acting account's own artifacts — the download of one
-- account's export can never reach another's rows.
--
-- Retention: expiry is enforced two ways. (1) A per-row TTL: expires_at =
-- created_at + ≤7 days, swept cross-tenant by expires_at through a SECURITY
-- DEFINER function mirroring sbci_sweep_expired_evidence (the sweep NEVER
-- consults account state — an artifact expires purely by its own clock).
-- (2) The account-deletion pass purges export_artifacts alongside the rest of
-- the enrichment cluster (the DELETE grant below; the purge itself is in
-- store/deletion.go, and the W6d deletion-matrix test classifies this table as
-- "purge").

-- 1. The artifact table.
CREATE TABLE IF NOT EXISTS export_artifacts (
    export_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id     uuid NOT NULL REFERENCES accounts(account_id),
    schema_version text        NOT NULL,
    ciphertext     bytea       NOT NULL,
    size_bytes     bigint      NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    downloaded_at  timestamptz
);

-- Sweep + per-account listing both key on expiry / account, newest-first.
CREATE INDEX IF NOT EXISTS export_artifacts_expiry_idx  ON export_artifacts (expires_at);
CREATE INDEX IF NOT EXISTS export_artifacts_account_idx ON export_artifacts (account_id, created_at DESC);

-- 2. Tenant RLS (ENABLE + FORCE + the standard account policy).
ALTER TABLE export_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE export_artifacts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS export_artifacts_tenant ON export_artifacts;
CREATE POLICY export_artifacts_tenant ON export_artifacts
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- 3. Grants. The serve role (sbci_api) assembles (INSERT), lists/downloads
-- (SELECT), stamps downloaded_at (UPDATE), and purges on deletion (DELETE);
-- sbci_app is the shared/admin + test role. RLS is the isolation boundary —
-- every one of these is filtered by sbci_current_account().
GRANT SELECT, INSERT, UPDATE, DELETE ON export_artifacts TO sbci_api, sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_sweep_expired_exports — the cross-tenant TTL sweeper for export
-- artifacts. Deletes every artifact past its own expires_at REGARDLESS of
-- account state (mirrors sbci_sweep_expired_evidence). SECURITY DEFINER, owned
-- by the BYPASSRLS sbci_defs role so it reaches every tenant; the search_path is
-- pinned so no tenant-settable path can redirect the referenced objects.
-- EXECUTE is granted to sbci_api (the serve-loop role that runs the sweep) and
-- sbci_app; the counter-table DELETE grant to sbci_defs is what the DEFINER body
-- needs past BYPASSRLS.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sbci_sweep_expired_exports(p_now timestamptz)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_deleted int;
BEGIN
    DELETE FROM export_artifacts WHERE expires_at <= p_now;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END$$;

ALTER FUNCTION sbci_sweep_expired_exports(timestamptz) OWNER TO sbci_defs;
GRANT SELECT, DELETE ON export_artifacts TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_sweep_expired_exports(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_sweep_expired_exports(timestamptz) TO sbci_api, sbci_app;
