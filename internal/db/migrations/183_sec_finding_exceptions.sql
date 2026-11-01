-- 183_sec_finding_exceptions.sql - the security pillar's local finding
-- exceptions (security pillar plan sections 5.12 and 6.3, Phase C, lane
-- sec-c3). "This is not a real problem" on an individual node is an
-- exception scoped to ONE finding's location-free lifecycle key in ONE
-- project, with a required expiry; it is never rule-wide, so it can never
-- lower a rule for a project or a repository (adversarial case X8).
--
-- NODE-LOCAL: in the privacy sentinel's forbidden-table list, so
-- internal/store/orgpush.go can never select it by name; the org's
-- finding_exception requests are Phase E's access-grant flow. NO server
-- pair. One writer: internal/store/secexceptions.go.
--
-- Never content: the file fingerprint is a hash of the file the finding
-- sits in at the time of the grant (for the "until the file changes"
-- expiry), never the file.

CREATE TABLE IF NOT EXISTS sec_finding_exceptions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id        TEXT    NOT NULL,
    project_root_hash TEXT    NOT NULL,
    local_key         TEXT    NOT NULL,
    rule_id           TEXT    NOT NULL,
    -- The closed reason picker (internal/secexcept.Reasons).
    reason            TEXT    NOT NULL CHECK (reason IN ('false_positive', 'accepted_risk', 'test_fixture')),
    -- The closed expiry picker (internal/secexcept.Expiries).
    expiry            TEXT    NOT NULL CHECK (expiry IN ('1d', '7d', '30d', 'until_change')),
    -- '' for until_change; RFC 3339 otherwise.
    expires_at        TEXT    NOT NULL DEFAULT '',
    -- sha256 hex of the finding's file at grant time (until_change only).
    file_hash         TEXT    NOT NULL DEFAULT '',
    -- Where the grant was made: 'cli' or 'dashboard' (a local owner, never
    -- a repository file or an agent).
    granted_by        TEXT    NOT NULL,
    granted_at        TEXT    NOT NULL,
    -- Set once, when the exception stops applying.
    ended_at          TEXT    NOT NULL DEFAULT '',
    end_reason        TEXT    NOT NULL DEFAULT '' CHECK (end_reason IN ('', 'expired', 'file_changed', 'revoked'))
);
CREATE INDEX IF NOT EXISTS idx_sec_finding_exceptions_open ON sec_finding_exceptions (ended_at, project_root_hash);
CREATE INDEX IF NOT EXISTS idx_sec_finding_exceptions_finding ON sec_finding_exceptions (finding_id, id);
