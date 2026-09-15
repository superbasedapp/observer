-- 0005_foundry_worker.sql — the CI-P4 Foundry inference worker substrate.
--
-- Adds, on top of the CI-P3 foundation:
--
--   * route_registry binding + Foundry-call columns: the ARM identifiers the
--     ContentLogging attestation is keyed to (plan §2.2), the route generation
--     (any bump invalidates a bound attestation), the Azure OpenAI endpoint /
--     api-version / deployment sizing, and a per-token price snapshot for the
--     provenance cost figure (plan §2.5 Luna rates).
--   * provider_attestations — the persisted ContentLogging canary records
--     (plan §2.2): keyed by tenant/subscription/ARM-resource/audience + route
--     generation, with the raw capability value and a fetched-at freshness
--     stamp. SYSTEM (control-plane) table: it is global route policy, never
--     tenant data, and the worker reads it on the system connection.
--   * dialect_verification_records — the plan §2.3 Responses-`store:false`
--     verification record. Its ABSENCE keeps the responses_store_false dialect
--     DARK; the route resolver refuses that dialect unless a live, unexpired
--     record names the api-version + deployment + evidence. SYSTEM table.
--   * evidence_blobs — the encrypted evidence BYTES (CI-P3 stored only
--     digests). TENANT table (RLS + FORCE): the ciphertext is account-owned,
--     read by the worker under the execution lease. The Azure Blob Storage
--     driver is a later swap behind the same store.BlobStore seam (substrate
--     §1); this pg bytea table is the dev/staging driver.
--   * sbci_sweep_expired_evidence — a SECURITY DEFINER sweep that deletes
--     expired evidence bytes + marks the objects deleted ACROSS tenants,
--     purely by expires_at, REGARDLESS of any job/queue state (plan §2.8: the
--     dead-letter/park/crash paths never extend the raw-object lifetime).
--   * analysis_results provenance columns (plan §6 CI-P4): the model route,
--     resolved versions, price snapshot, prompt hash, token counts, cost, and
--     the retry count that produced the result, plus a superseded flag for a
--     later regeneration arc.

-- ---------------------------------------------------------------------------
-- route_registry: attestation binding + Foundry-call + price columns.
-- ---------------------------------------------------------------------------
ALTER TABLE route_registry
    ADD COLUMN generation            bigint           NOT NULL DEFAULT 1,
    ADD COLUMN endpoint              text             NOT NULL DEFAULT '',
    ADD COLUMN api_version           text             NOT NULL DEFAULT '',
    ADD COLUMN max_output_tokens     int              NOT NULL DEFAULT 1024,
    ADD COLUMN input_price_per_mtok  double precision NOT NULL DEFAULT 0,
    ADD COLUMN output_price_per_mtok double precision NOT NULL DEFAULT 0,
    ADD COLUMN tenant_id             text             NOT NULL DEFAULT '',
    ADD COLUMN subscription_id       text             NOT NULL DEFAULT '',
    ADD COLUMN arm_resource_id       text             NOT NULL DEFAULT '',
    ADD COLUMN endpoint_audience     text             NOT NULL DEFAULT '';

-- Give the shipped Luna route its plan §2.5 price snapshot (Global Standard,
-- 2026-08-01 cut). Binding identifiers stay empty ⇒ the attestation is
-- UNHEALTHY and the credential absent ⇒ every job parks provider_policy_
-- unverified until an operator provisions the resource post-approval. Failing
-- closed by default is the point (plan §2.1).
UPDATE route_registry
   SET input_price_per_mtok  = 0.20,
       output_price_per_mtok = 1.20,
       max_output_tokens     = 1024
 WHERE route_id = 'session_enrichment.luna.v1';

-- ---------------------------------------------------------------------------
-- provider_attestations (SYSTEM) — persisted ContentLogging canary records.
-- ---------------------------------------------------------------------------
CREATE TABLE provider_attestations (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id          text        NOT NULL,
    route_generation  bigint      NOT NULL,
    tenant_id         text        NOT NULL,
    subscription_id   text        NOT NULL,
    arm_resource_id   text        NOT NULL,
    endpoint_audience text        NOT NULL,
    -- content_logging_value is the RAW capability value as read from ARM
    -- ('false' when disabled; anything else — absent, duplicate, malformed,
    -- non-boolean — is UNHEALTHY per plan §2.2).
    content_logging_value text    NOT NULL DEFAULT '',
    healthy           boolean     NOT NULL,
    reason            text        NOT NULL DEFAULT '',
    fetched_at        timestamptz NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX provider_attestations_route ON provider_attestations (route_id, created_at DESC);

-- ---------------------------------------------------------------------------
-- dialect_verification_records (SYSTEM) — plan §2.3 Responses store:false
-- verification. No row ⇒ the responses_store_false dialect stays dark.
-- ---------------------------------------------------------------------------
CREATE TABLE dialect_verification_records (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id    text        NOT NULL,
    dialect     text        NOT NULL,
    api_version text        NOT NULL,
    deployment  text        NOT NULL,
    evidence    text        NOT NULL,
    approved_by text        NOT NULL DEFAULT '',
    active      boolean     NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);

CREATE INDEX dialect_verification_lookup
    ON dialect_verification_records (route_id, dialect, active, expires_at);

-- ---------------------------------------------------------------------------
-- evidence_blobs (TENANT, RLS) — encrypted evidence BYTES. blob_ref is the
-- opaque account-scoped key the evidence_objects row carries.
-- ---------------------------------------------------------------------------
CREATE TABLE evidence_blobs (
    account_id uuid        NOT NULL REFERENCES accounts(account_id),
    blob_ref   text        NOT NULL,
    ciphertext bytea       NOT NULL,
    size_bytes bigint      NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, blob_ref)
);

ALTER TABLE evidence_blobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_blobs FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_blobs_tenant ON evidence_blobs
    USING (account_id = sbci_current_account())
    WITH CHECK (account_id = sbci_current_account());

-- ---------------------------------------------------------------------------
-- analysis_results provenance columns (plan §6 CI-P4).
-- ---------------------------------------------------------------------------
ALTER TABLE analysis_results
    ADD COLUMN model_route_id text             NOT NULL DEFAULT '',
    ADD COLUMN route_version  bigint           NOT NULL DEFAULT 0,
    ADD COLUMN prompt_version bigint           NOT NULL DEFAULT 0,
    ADD COLUMN price_version  text             NOT NULL DEFAULT '',
    ADD COLUMN prompt_hash    text             NOT NULL DEFAULT '',
    ADD COLUMN tokens_in      bigint           NOT NULL DEFAULT 0,
    ADD COLUMN tokens_out     bigint           NOT NULL DEFAULT 0,
    ADD COLUMN cost_usd       double precision NOT NULL DEFAULT 0,
    ADD COLUMN retry_count    int              NOT NULL DEFAULT 0,
    ADD COLUMN superseded     boolean          NOT NULL DEFAULT false;

-- ---------------------------------------------------------------------------
-- Grants.
-- ---------------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE ON
    provider_attestations, dialect_verification_records
TO sbci_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON evidence_blobs TO sbci_app;

-- ---------------------------------------------------------------------------
-- sbci_sweep_expired_evidence — the cross-tenant TTL sweeper (plan §2.8).
-- Deletes evidence bytes and marks the objects deleted purely by expires_at,
-- regardless of the owning job's state (queued/leased/parked/dead-lettered/
-- succeeded) — the sweep NEVER consults the queue, so a dead-letter can never
-- extend the raw-object lifetime. SECURITY DEFINER (owned by the BYPASSRLS
-- sbci_defs role) so it reaches every tenant, mirroring the lease primitive.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION sbci_sweep_expired_evidence(p_now timestamptz)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_deleted int;
BEGIN
    DELETE FROM evidence_blobs b
     USING evidence_objects o
     WHERE b.account_id = o.account_id
       AND b.blob_ref   = o.blob_ref
       AND o.expires_at <= p_now;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    UPDATE evidence_objects
       SET deleted_at = p_now
     WHERE expires_at <= p_now
       AND deleted_at IS NULL;

    RETURN v_deleted;
END$$;

ALTER FUNCTION sbci_sweep_expired_evidence(timestamptz) OWNER TO sbci_defs;

-- Base-table privileges the DEFINER function needs (BYPASSRLS removes the row
-- filter but not the table grant).
GRANT SELECT, DELETE ON evidence_blobs TO sbci_defs;
GRANT SELECT, UPDATE ON evidence_objects TO sbci_defs;

REVOKE ALL ON FUNCTION sbci_sweep_expired_evidence(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_sweep_expired_evidence(timestamptz) TO sbci_app;
