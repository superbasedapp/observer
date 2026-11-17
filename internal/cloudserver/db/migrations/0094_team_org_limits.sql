-- 0094_team_org_limits.sql - at most N team orgs per account, raised on
-- request (managed-SaaS plan 07 wave 15 lane console-fixes; lead decisions
-- W15-D12 and L-113 C2.front-door-3; docs/security.md PORTALORG-1 and
-- PORTALORG-10).
--
-- step: contract
--
-- Contract label: the REVOKE of PUBLIC's default EXECUTE on the new definer
-- (migcheck's revoke rule, the 0082 / 0091 / 0093 pattern). The table and the
-- function are new in this step, so no running release can hold or lose a
-- privilege; the label is the rule's, not a real contraction.
--
-- WHY. Any signed-in account can create team orgs from the console, and each
-- create enqueues a create_tenant intent (PORTALORG-1). The default cap is a
-- Go constant (store.DefaultMaxTeamOrgs, 3), enforced inside the provisioning
-- transaction under a per-account advisory lock so two concurrent creates
-- cannot both pass the count. "Raised on request" is this table: an operator
-- raise (observer-cloud grant-plan team-orgs) appends a row; the newest row
-- of an account is its limit. No row: the default.
--
-- APPEND-ONLY, AND ITS OWN AUDIT. Every raise or lowering is a new row with
-- the actor and a required reason; no role holds UPDATE or DELETE, so the
-- history of an account's limit cannot be rewritten by the application
-- roles. The rows go when the account's tombstone is swept (ON DELETE
-- CASCADE, the 24-month sweep), like every other account-keyed system row.
--
-- READ. sbci_api never reads the table: the console's provisioning
-- transaction calls sbci_team_org_limit(), a SECURITY DEFINER owned by
-- sbci_defs that takes NO argument and answers only for the caller's own
-- account context (sbci_current_account(); NULL without one). It lists
-- nothing and cannot be pointed at another account. Executable by sbci_api
-- and sbci_app (the test / operator role); PUBLIC revoked (pinned by
-- TestDefinerFunctionExecuteGrants).

SET LOCAL lock_timeout = '5s';

CREATE TABLE account_team_org_limits (
    seq           bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id    uuid        NOT NULL REFERENCES accounts (account_id) ON DELETE CASCADE,
    -- 0 bars the account from creating team orgs; the console says so.
    max_team_orgs integer     NOT NULL CHECK (max_team_orgs BETWEEN 0 AND 1000),
    -- 'operator' for the CLI (the staff_actions convention).
    actor         text        NOT NULL CHECK (actor = 'operator'),
    reason        text        NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    at            timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX account_team_org_limits_account ON account_team_org_limits (account_id, seq DESC);

COMMENT ON TABLE account_team_org_limits IS
    'W15-D12: operator raises of an account''s team org cap; append-only, newest row wins, no row means store.DefaultMaxTeamOrgs (class S).';

GRANT SELECT, INSERT ON account_team_org_limits TO sbci_app;
GRANT SELECT (account_id, max_team_orgs, seq) ON account_team_org_limits TO sbci_defs;

CREATE FUNCTION sbci_team_org_limit()
RETURNS integer
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT l.max_team_orgs
      FROM public.account_team_org_limits l
     WHERE l.account_id = public.sbci_current_account()
     ORDER BY l.seq DESC
     LIMIT 1
$$;

ALTER FUNCTION sbci_team_org_limit() OWNER TO sbci_defs;
REVOKE ALL ON FUNCTION sbci_team_org_limit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sbci_team_org_limit() TO sbci_api, sbci_app;
