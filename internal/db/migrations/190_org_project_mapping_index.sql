-- 190_org_project_mapping_index.sql - the node's index of the org-signed
-- project mapping (security plan section 7.11, spike JSP-10, lane sec-p).
-- One row per (identity hash, kind, org project) of the mapping the org client
-- last ACCEPTED (kind: 'remote' for a remote or upstream remote hash, 'root'
-- for a root commit hash), with the epoch and mapping digest it came under,
-- so the daemon's launch and session-start matcher looks a directory up
-- without decoding the mapping file. The signed mapping itself stays a file
-- beside the org bundle cache (internal/projectmatch.Layout), which is what
-- the hook reads.
--
-- NODE-LOCAL: in the privacy sentinel's forbidden-table list, so
-- internal/store/orgpush.go can never select it by name. NO server pair (the
-- server's tables are server migration 247 / pg 0114). One writer:
-- internal/store/projectaudience.go (ReplaceOrgProjectMappingIndex, which
-- replaces the whole index in one transaction).
--
-- An existing install sees one empty table: nothing writes a row until an
-- org publishes a project-scoped guard bundle and the node accepts a v3
-- delivery.

CREATE TABLE IF NOT EXISTS org_project_mapping_index (
    hash           TEXT    NOT NULL,
    kind           TEXT    NOT NULL CHECK (kind IN ('remote', 'root')),
    org_project_id TEXT    NOT NULL,
    epoch          INTEGER NOT NULL,
    mapping_digest TEXT    NOT NULL,
    PRIMARY KEY (hash, kind, org_project_id)
);
