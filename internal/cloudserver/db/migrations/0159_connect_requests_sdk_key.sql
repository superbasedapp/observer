-- 0159_connect_requests_sdk_key.sql - the AI Apps SDK quickstart's device
-- sign-in (docs/plans/sdk-quickstart-one-command-plan-2026-11-25.md section
-- 3.6, rulings R1 and R13; docs/security.md SDKQS-1 and SDKQS-2): a connect
-- request gains a second purpose, sdk_key, beside the machine connect of
-- 0150.
--
-- step: expand
--
-- connect_requests stays one system table with one status machine. What a
-- request is for and how its poll proves itself are capabilities of the
-- ROW, decided at create and never changed:
--
--   purpose    'machine' (every row before this step, and the default) or
--              'sdk_key' (`npx @superbased/sdk setup` / `uvx superbased-sdk
--              setup` asking for the member's own SDK key);
--   auth_kind  'pop' (the machine's Ed25519 proof of possession, 0150) or
--              'device_code' (an SDK poll's bearer device code: Python's
--              standard library has no Ed25519, so the SDK proves itself with
--              a 256-bit secret returned once by the create).
--
-- device_code_hash is the hex SHA-256 of that secret (the raw code is never
-- stored); redeem_hash is the SHA-256 the SDK sent of its redeem secret
-- (unpadded base64url, internal/sdkkeygrant.RedeemHash), carried into the
-- signed key grant so the tenant host can bind the redeem to the process
-- that asked. client, client_version and project_name are what the approval
-- page shows beside the machine name. An SDK request carries no device key
-- and no Observer version, so those three columns lose NOT NULL; the CHECKs
-- added here make each purpose's row whole (a machine row keeps every
-- column it had, an SDK row has a device code and no device key).
--
-- Every existing row is a machine row with the defaults, which every CHECK
-- below accepts. The CHECKs are added NOT VALID (no table scan under the
-- ACCESS EXCLUSIVE lock): PostgreSQL enforces them on every row written from
-- now on; validating the old rows needs a later VALIDATE step, which the
-- swept table (requests live at most 30 days) makes optional.
--
-- deliveries keeps counting the polls that received the request's answer:
-- the sign-in for a machine, the key grant for an SDK request (the same
-- three deliveries within ten minutes of approval).

SET LOCAL lock_timeout = '5s';

ALTER TABLE connect_requests
    ADD COLUMN purpose text NOT NULL DEFAULT 'machine',
    ADD COLUMN auth_kind text NOT NULL DEFAULT 'pop',
    ADD COLUMN device_code_hash text,
    ADD COLUMN redeem_hash text,
    ADD COLUMN client text,
    ADD COLUMN client_version text,
    ADD COLUMN project_name text,
    ALTER COLUMN device_public_key DROP NOT NULL,
    ALTER COLUMN device_thumbprint DROP NOT NULL,
    ALTER COLUMN observer_version DROP NOT NULL;

ALTER TABLE connect_requests
    ADD CONSTRAINT connect_requests_purpose CHECK (purpose IN ('machine', 'sdk_key')) NOT VALID;

ALTER TABLE connect_requests
    ADD CONSTRAINT connect_requests_auth_kind CHECK (auth_kind IN ('pop', 'device_code')) NOT VALID;

ALTER TABLE connect_requests
    ADD CONSTRAINT connect_requests_sdk_fields CHECK (
        (device_code_hash IS NULL OR device_code_hash ~ '^[0-9a-f]{64}$')
        AND (redeem_hash IS NULL OR redeem_hash ~ '^[A-Za-z0-9_-]{43}$')
        AND (client IS NULL OR client ~ '^[a-z0-9-]{1,64}$')
        AND (client_version IS NULL OR client_version ~ '^[0-9A-Za-z.+_-]{1,32}$')
        AND (project_name IS NULL OR project_name ~ '^[a-z0-9._-]{1,64}$')
    ) NOT VALID;

-- A row is whole for its purpose: a machine polls with its device key, an
-- SDK request with its device code, and neither carries the other's fields.
ALTER TABLE connect_requests
    ADD CONSTRAINT connect_requests_purpose_whole CHECK (
        (purpose = 'machine' AND auth_kind = 'pop'
            AND device_public_key IS NOT NULL AND device_thumbprint IS NOT NULL
            AND observer_version IS NOT NULL
            AND device_code_hash IS NULL AND redeem_hash IS NULL
            AND client IS NULL AND client_version IS NULL AND project_name IS NULL)
     OR (purpose = 'sdk_key' AND auth_kind = 'device_code'
            AND device_public_key IS NULL AND device_thumbprint IS NULL
            AND observer_version IS NULL
            AND device_code_hash IS NOT NULL AND redeem_hash IS NOT NULL
            AND client IS NOT NULL AND client_version IS NOT NULL AND project_name IS NOT NULL
            AND delivered_token IS NULL)
    ) NOT VALID;

COMMENT ON COLUMN connect_requests.purpose IS
    'machine (observer connect) or sdk_key (the SDK setup device sign-in; SDKQS-1).';
COMMENT ON COLUMN connect_requests.auth_kind IS
    'How a poll proves itself: pop (device key proof) or device_code (bearer; SDKQS-1).';
COMMENT ON COLUMN connect_requests.device_code_hash IS
    'Hex SHA-256 of the SDK request''s device code; the code itself is never stored.';
COMMENT ON COLUMN connect_requests.redeem_hash IS
    'base64url SHA-256 of the SDK''s redeem secret, signed into the key grant (SDKQS-2).';

-- sbci_my_org_entitlements: the SDK key approval page lists a team whose
-- plan does not include AI Apps as disabled (the plan's ruling R14), so the
-- front door must read the plan in force of a dashboard the caller belongs
-- to, which a plain team member cannot read through the subscription tables.
-- sbci_api holds no grant on org_entitlement_docs (0056: no customer-session
-- handler reads a signed document) and gets none here. It reads this view
-- instead: owned by sbci_defs (0133 gave it SELECT on the document columns,
-- 0047 on org_members), it shows only the newest document's version and body
-- of an org the caller's OWN account (sbci_current_account(), set by
-- WithAccount; NULL without one, so no row) is a member of. No signature,
-- key id or issuer, and no other org. security_barrier keeps a caller's
-- predicate from running before the membership filter. A new view has no
-- PUBLIC privilege, so no REVOKE is needed; the names are schema-qualified
-- and bound at creation (no search_path at read time).
CREATE VIEW sbci_my_org_entitlements WITH (security_barrier) AS
SELECT d.org_id, d.version, d.body
  FROM public.org_entitlement_docs d
  JOIN public.org_members m
    ON m.org_id = d.org_id AND m.account_id = public.sbci_current_account()
 WHERE d.version = (SELECT max(d2.version) FROM public.org_entitlement_docs d2 WHERE d2.org_id = d.org_id);

ALTER VIEW sbci_my_org_entitlements OWNER TO sbci_defs;

COMMENT ON VIEW sbci_my_org_entitlements IS
    'The caller''s own orgs'' newest entitlement body, for the SDK key approval page (SDKQS-1; R14).';

GRANT SELECT ON sbci_my_org_entitlements TO sbci_api, sbci_app;
