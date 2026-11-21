-- 0130_team_create_allowlist.sql - who may create a TEAM org while the
-- pooled server is limited to internal and canary orgs (managed-SaaS plan 07
-- wave 17 lane portal-guardrails; completion audit 2026-11-16 gap 8; lead
-- decisions L-111 A5 and L-124; docs/security.md TEAMGATE-1).
--
-- step: contract
--
-- Contract label: the REVOKE of PUBLIC's default EXECUTE on the new definer
-- (migcheck's revoke rule, the 0082 / 0091 / 0094 pattern). The table and the
-- function are new in this step, so no running release can hold or lose a
-- privilege; the label is the rule's, not a real contraction.
--
-- WHY. The operator's A5 waiver runs the document signer on app-0 for
-- internal and canary orgs only until GO-3, yet any signed-in account could
-- create a team org from the console (capped at 3 by 0094). The allow-list
-- closes that: while the platform switch SBCI_TEAM_CREATE_ALLOWLIST is on
-- (the production kit's default), ProvisionOrg refuses a TEAM create unless
-- the caller's account, or the domain of the caller's VERIFIED email, has an
-- active entry here. A personal org is never checked.
--
-- ENTRIES. One row per entry; removing one stamps removed_* (never a DELETE),
-- so the table is its own history. Every add and remove also writes a
-- staff_actions row in the same transaction (verbs team_allowlist.added /
-- team_allowlist.removed), which is the audit trail the staff log shows.
-- No email address is stored: an account entry names an account id, a
-- domain entry names a domain only.
--
-- WHO WRITES. sbci_staff (the staff console's process and the operator's
-- `observer-cloud staff team-allowlist` verbs, both through WithStaff) holds
-- SELECT and INSERT, and UPDATE of the three removed_* columns only. sbci_app
-- (the test and operator role) mirrors it. sbci_api holds nothing.
--
-- WHO READS AT CREATE. The console's provisioning transaction (sbci_api)
-- calls sbci_team_create_allowed(), a SECURITY DEFINER owned by sbci_defs
-- that takes NO argument and answers only for the caller's own account
-- context (sbci_current_account(); false without one). A domain matches only
-- when the account's provider-asserted email is verified (0074's
-- email_verified, the flag the OIDC issuer itself refuses without). It lists
-- nothing and cannot be pointed at another account. Executable by sbci_api
-- and sbci_app; PUBLIC revoked (pinned by TestDefinerFunctionExecuteGrants).

SET LOCAL lock_timeout = '5s';

CREATE TABLE team_create_allowlist (
    entry_id       uuid        NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 'account': value is an account id (canonical lower-case uuid text).
    -- 'email_domain': value is a lower-case DNS name; it matches a verified
    -- email whose domain is exactly it (no subdomain wildcard).
    kind           text        NOT NULL CHECK (kind IN ('account', 'email_domain')),
    value          text        NOT NULL,
    added_by       text        NOT NULL CHECK (added_by = 'operator' OR added_by ~ '^staff:[0-9a-f-]{36}$'),
    added_reason   text        NOT NULL CHECK (char_length(btrim(added_reason)) BETWEEN 1 AND 1000),
    added_at       timestamptz NOT NULL DEFAULT now(),
    removed_at     timestamptz,
    removed_by     text        CHECK (removed_by IS NULL OR removed_by = 'operator' OR removed_by ~ '^staff:[0-9a-f-]{36}$'),
    removed_reason text        CHECK (removed_reason IS NULL OR char_length(btrim(removed_reason)) BETWEEN 1 AND 1000),
    CONSTRAINT team_create_allowlist_value_shape CHECK (
        (kind = 'account' AND value ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
        OR (kind = 'email_domain' AND char_length(value) BETWEEN 3 AND 253
            AND value ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')
    ),
    CONSTRAINT team_create_allowlist_removed_shape CHECK (
        (removed_at IS NULL) = (removed_by IS NULL) AND (removed_at IS NULL) = (removed_reason IS NULL)
    )
);

-- At most one ACTIVE entry per (kind, value); a removed one may be added again.
CREATE UNIQUE INDEX team_create_allowlist_active ON team_create_allowlist (kind, value) WHERE removed_at IS NULL;

COMMENT ON TABLE team_create_allowlist IS
    'W17 portal-guardrails: accounts and verified email domains allowed to create a team org while SBCI_TEAM_CREATE_ALLOWLIST is on (until GO-3); removal stamps removed_*, never deletes (class S).';

GRANT SELECT, INSERT ON team_create_allowlist TO sbci_staff;
GRANT UPDATE (removed_at, removed_by, removed_reason) ON team_create_allowlist TO sbci_staff;
GRANT SELECT, INSERT ON team_create_allowlist TO sbci_app;
GRANT UPDATE (removed_at, removed_by, removed_reason) ON team_create_allowlist TO sbci_app;
GRANT SELECT (kind, value, removed_at) ON team_create_allowlist TO sbci_defs;

CREATE FUNCTION sbci_team_create_allowed()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT public.sbci_current_account() IS NOT NULL AND EXISTS (
        SELECT 1
          FROM public.team_create_allowlist a
         WHERE a.removed_at IS NULL
           AND (
                (a.kind = 'account' AND a.value = public.sbci_current_account()::text)
             OR (a.kind = 'email_domain' AND EXISTS (
                    SELECT 1
                      FROM public.account_verified_emails e
                     WHERE e.account_id = public.sbci_current_account()
                       AND e.email_verified
                       AND lower(substring(e.email FROM '@([^@]+)$')) = a.value))
           )
    )
$$;

ALTER FUNCTION sbci_team_create_allowed() OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_team_create_allowed() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_team_create_allowed() TO sbci_api, sbci_app;
