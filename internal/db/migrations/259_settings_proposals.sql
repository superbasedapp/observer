-- 259: settings_proposals, the settings changes an AI agent asked for that
-- wait for the user's approval (Plane A build-out lane B6, W2-8, ruling D19;
-- docs/plans/plane-a-sdk-buildout/02-plan-of-record-2026-11-19.md).
--
-- MCP `set_setting` applies an ordinary key directly. A security-sensitive
-- key (guard, capture and content, sharing, egress, admission mode, budgets,
-- an SDK destination that sends data online; internal/settingsgate) is never
-- applied by the agent: it lands here as a PENDING row. The user approves it
-- on the dashboard (Settings > Changes waiting for you) or with
-- `observer config proposals approve <id>`, which writes the value through
-- the one config write owner and then marks the row; or rejects it.
--
--   key            the dotted config key
--   value          the value as the agent typed it (the `config set`
--                  spelling); a credential-shaped value is refused before a
--                  row is written, so no secret is stored here
--   prev_value     the value in force when the proposal was filed (display)
--   category       the settingsgate category (guard, sharing, egress, ...)
--   reason         why the key needs approval, one plain sentence
--   requested_by   who asked ("mcp:<client name>"); free text, display only
--   note           the agent's own explanation, bounded, display only
--   status         pending | approved | rejected | superseded
--   decided_by     who decided ("dashboard", "cli:<os user>"); '' while pending
--
-- A newer proposal for the same key supersedes an older pending one, so the
-- user never approves a stale value by mistake.
--
-- NODE-LOCAL: never on the push wire (orgpush.go never names it; the privacy
-- sentinel lists it).

CREATE TABLE IF NOT EXISTS settings_proposals (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    key          TEXT    NOT NULL,
    value        TEXT    NOT NULL,
    prev_value   TEXT    NOT NULL DEFAULT '',
    category     TEXT    NOT NULL DEFAULT '',
    reason       TEXT    NOT NULL DEFAULT '',
    requested_by TEXT    NOT NULL DEFAULT '',
    note         TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'approved', 'rejected', 'superseded')),
    created_at   TEXT    NOT NULL,
    decided_at   TEXT    NOT NULL DEFAULT '',
    decided_by   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_settings_proposals_status
    ON settings_proposals (status, id);
