-- 241_cloud_agents_state.sql - node-local state for cloud-agent connectors
-- (cloud-agents arc, lane CA-A1; plan section 4.1 and decision CA-D11 of
-- docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md).
--
-- Three NODE-LOCAL tables, one store owner each
-- (internal/store/cloudagentstate.go). None ever reaches the org-push wire:
-- all three names join the forbidden-table sentinel walked by
-- tests/invariant/privacy_test.go, and there is no paired server migration.
-- Nothing writes them until a cloud-agent connector exists (wave B), so a
-- node that never opts in carries three empty tables.
--
--   cloud_connector_accounts - one linked vendor account per row: which
--       connector, the provider, the issuer or tenant, the vendor's
--       IMMUTABLE account id, a display e-mail for the settings page, the
--       current coverage state and the last error CLASS (a short token,
--       never raw output). Secrets are never stored here: they live in the
--       OS keychain (internal/keystore service sbo-cloudagents-v1, CA-D5).
--       Unique on (connector, issuer, account_id), so re-linking the same
--       account updates its row instead of adding a second one.
--
--   cloud_sync_checkpoints - one checkpoint per (account, stream, scope):
--       stream is 'discovery', 'session_history', 'usage' or 'live'; scope is
--       '' for an account-wide stream and the session id for a per-session
--       history cursor. Holds the provider cursor, the overlap window, the
--       last attempt and last success, and the GAP INTERVALS (JSON array of
--       {"from","to"}) a stream that resumed late could not cover, so a
--       missed window is recorded rather than erased. Deleting an account
--       removes its checkpoints (ON DELETE CASCADE): they are collection
--       state, not history.
--
--   cloud_usage_ledger - provider usage in its NATIVE unit (CA-D11): ACUs,
--       credits, quota, vendor-reported USD, seconds. Real token counts go to
--       token_usage, not here. One row per reported figure with its
--       measurement source, value type (snapshot / delta / interval /
--       cumulative / gauge), unit, value, scope ids (run, session, user,
--       account, org, model), interval, monetary status, whether the figure
--       already includes child runs (NULL = not stated), reported_at, and the
--       row it supersedes. Rows are NEVER summed across units; a cumulative
--       counter is never summed across snapshots. Ledger rows reference their
--       account by the vendor account id text, not a foreign key, so unlinking
--       an account stops collection without deleting history. (connector,
--       source_record_id) is unique when the record id is set, so a re-pulled
--       page lands each figure once.
--
-- Numbered 241, inside the cloud-agents arc's reservation (node 240-249,
-- CA-D14).
CREATE TABLE cloud_connector_accounts (
    id               INTEGER PRIMARY KEY,
    connector        TEXT NOT NULL,
    provider         TEXT NOT NULL,
    issuer           TEXT NOT NULL DEFAULT '',
    account_id       TEXT NOT NULL,
    display_email    TEXT NOT NULL DEFAULT '',
    coverage_state   TEXT NOT NULL DEFAULT '',
    last_error_class TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL,
    UNIQUE (connector, issuer, account_id)
);

CREATE TABLE cloud_sync_checkpoints (
    account_pk      INTEGER NOT NULL REFERENCES cloud_connector_accounts(id) ON DELETE CASCADE,
    stream          TEXT NOT NULL CHECK (stream IN ('discovery', 'session_history', 'usage', 'live')),
    scope           TEXT NOT NULL DEFAULT '',
    cursor          TEXT NOT NULL DEFAULT '',
    overlap_seconds INTEGER NOT NULL DEFAULT 0 CHECK (overlap_seconds >= 0),
    last_attempt_at TEXT NOT NULL DEFAULT '',
    last_success_at TEXT NOT NULL DEFAULT '',
    gaps_json       TEXT NOT NULL DEFAULT '[]',
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (account_pk, stream, scope)
);

CREATE TABLE cloud_usage_ledger (
    id                 INTEGER PRIMARY KEY,
    connector          TEXT NOT NULL,
    source_record_id   TEXT NOT NULL DEFAULT '',
    measurement_source TEXT NOT NULL CHECK (measurement_source IN
                           ('exporter', 'provider_run_total', 'org_report', 'invoice')),
    value_type         TEXT NOT NULL CHECK (value_type IN
                           ('snapshot', 'delta', 'interval', 'cumulative', 'gauge')),
    unit               TEXT NOT NULL,
    value              REAL NOT NULL,
    monetary_status    TEXT NOT NULL CHECK (monetary_status IN
                           ('not_monetary', 'reported_charge', 'estimated_charge',
                            'quota_allocation', 'api_equivalent')),
    scope_run          TEXT NOT NULL DEFAULT '',
    scope_session      TEXT NOT NULL DEFAULT '',
    scope_user         TEXT NOT NULL DEFAULT '',
    scope_account      TEXT NOT NULL DEFAULT '',
    scope_org          TEXT NOT NULL DEFAULT '',
    scope_model        TEXT NOT NULL DEFAULT '',
    interval_start     TEXT NOT NULL DEFAULT '',
    interval_end       TEXT NOT NULL DEFAULT '',
    includes_children  INTEGER CHECK (includes_children IN (0, 1)),
    reported_at        TEXT NOT NULL,
    observed_at        TEXT NOT NULL,
    supersedes_id      INTEGER REFERENCES cloud_usage_ledger(id)
);

CREATE UNIQUE INDEX idx_cloud_usage_ledger_record
    ON cloud_usage_ledger (connector, source_record_id)
    WHERE source_record_id <> '';

CREATE INDEX idx_cloud_usage_ledger_session
    ON cloud_usage_ledger (scope_session)
    WHERE scope_session <> '';
