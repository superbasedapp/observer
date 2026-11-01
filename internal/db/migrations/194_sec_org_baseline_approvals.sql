-- 194_sec_org_baseline_approvals.sql - the org's approvals of this node's
-- baseline references (security plan 4.5.2 and 7.5; lane LEFT-SHARED).
--
-- The security managed pull (GET /api/agent/security) serves a managed node
-- the org's approvals of the baseline references its own finding rows
-- reported (orgcontract approved_baselines, only to a node that advertised
-- security.baseline_approvals). The daemon writes the in-force list here,
-- replacing it whole on every applied pull and clearing it when no pull is
-- in force; the node only LABELS a baseline it already has "approved by the
-- org". No verdict reads this table.
--
-- project_key is the project key the wire row carried (org_project_id, else
-- project_identity_hash); ref_kind and ref the reference; approved_at when
-- the org approved it; pull_version the managed-pull version it came with.
--
-- NODE-LOCAL: in the privacy sentinel's forbidden-table list; the org row
-- builder never selects it. NO server pair (the org's approvals are server
-- 256 / pg 0123). One writer: internal/store/secorgrows_approvals.go.

CREATE TABLE IF NOT EXISTS sec_org_baseline_approvals (
    project_key  TEXT    NOT NULL,
    ref_kind     TEXT    NOT NULL,
    ref          TEXT    NOT NULL,
    approved_at  TEXT    NOT NULL DEFAULT '',
    pull_version INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (project_key, ref_kind, ref)
);
