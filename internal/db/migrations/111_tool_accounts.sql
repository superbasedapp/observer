-- Node-local login observations. Never copied by org push or foreign import.
-- No session FK: hooks can precede the transcript/session insert. A delete
-- trigger covers explicit session removal; normal age retention covers orphans.
CREATE TABLE tool_account_observations (
    session_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    binding_kind TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    role TEXT NOT NULL,
    account_key TEXT NOT NULL,
    email TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    account_id TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    scope TEXT NOT NULL,
    stage TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY(session_id, tool, binding_kind, binding_id, role, account_key, source, scope, stage)
);
CREATE INDEX idx_tool_accounts_age ON tool_account_observations(observed_at);
CREATE TRIGGER delete_session_tool_accounts AFTER DELETE ON sessions
BEGIN
    DELETE FROM tool_account_observations WHERE session_id = OLD.id;
END;
