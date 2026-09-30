-- 140_org_push_changes.sql - org push RE-SEND tracking (lane R2-RESEND,
-- 2026-09-27; paired with server migration 178 / pg 0044).
--
-- WHY. The node pushes each cursor-wire row (sessions, actions, api_turns,
-- token_usage) ONCE, by an id/rowid cursor, and the org ingest was
-- FIRST-WINS. A row the node CHANGES after it shipped - a token_usage
-- MAX-upgrade from a session-cumulative adapter, a gen_ms stamp, an action
-- outcome filled in at PostToolUse, a transcript folded into its child
-- session (session_source.go), an api_turns merge (merge.go), a session's
-- model / ended_at / total_actions / surface filled in later, a project that
-- learns its git remote, or any `observer backfill` repair - was never
-- re-sent, so the org kept the first version forever (live: a Claude Code
-- session read 69.4K tokens on the node and 45.7K on the org).
--
-- HOW. Mutation paths are many (store seams, cmd/observer backfills that
-- write SQL directly, future migrations), so the change marker is a TRIGGER
-- per shipped table: the one seam every UPDATE passes through, present or
-- future. A trigger fires only when (a) the node is enrolled - the
-- org_push_floor_<table> schema_meta key exists (written with the cursor by
-- store.SavePushCursor, removed by store.DeleteEnrolment) - and the row is
-- ABOVE that floor, so pre-enrolment history the cursor seed deliberately
-- skipped is never shipped by the back door; and (b) at least one WIRE
-- column actually changed, compared the way the push reads it (NULL and 0 /
-- '' are the same wire value, exactly the COALESCEs of the push's SELECT), so
-- an idempotent re-parse that rewrites identical values queues nothing. The node-local score / summary / metadata
-- columns that never ship are not listed and never fire.
--
-- org_push_rev is ONE monotonic counter bumped by every queued change; a
-- queue row carries the counter value of its latest change (seq). The push
-- reads the counter once per batch and stamps it on every cursor-wire row as
-- orgcontract.*Row.NodeRev; the org applies a row only when its NodeRev is
-- newer than the stored one (newer-wins by NODE version, never by arrival
-- order). A batch acknowledges only queue rows with seq <= the counter it
-- read, so a change that lands while the batch is in flight stays queued.
--
-- NODE-LOCAL: neither table is ever selected onto the wire (the privacy
-- sentinel pins both names out of internal/store/orgpush.go's wire SQL).
CREATE TABLE IF NOT EXISTS org_push_changes (
    tbl    TEXT    NOT NULL,
    row_id INTEGER NOT NULL,
    seq    INTEGER NOT NULL,
    PRIMARY KEY (tbl, row_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_org_push_changes_seq ON org_push_changes(tbl, seq);

CREATE TABLE IF NOT EXISTS org_push_rev (
    k   INTEGER PRIMARY KEY CHECK (k = 1),
    rev INTEGER NOT NULL
);
INSERT OR IGNORE INTO org_push_rev (k, rev) VALUES (1, 0);

-- A node ALREADY enrolled when it upgrades gets floors at its current cursor:
-- its original enrolment seed was never recorded, so the only floor known to
-- exclude pre-enrolment rows is the cursor itself. Rows shipped before the
-- upgrade are therefore not re-queued automatically; `observer org resync`
-- (store.EnqueuePushResync) lowers the floor to a provably post-enrolment id
-- and re-queues a bounded recent window.
INSERT OR IGNORE INTO schema_meta (key, value)
SELECT 'org_push_floor_' || substr(key, length('org_push_cursor_') + 1), value
  FROM schema_meta
 WHERE key IN ('org_push_cursor_sessions', 'org_push_cursor_actions',
               'org_push_cursor_api_turns', 'org_push_cursor_token_usage')
   AND EXISTS (SELECT 1 FROM org_enrolment);

CREATE TRIGGER org_push_change_sessions
AFTER UPDATE OF
    project_id, tool, model, git_branch, started_at,
    ended_at, total_actions, workspace_hash, workspace, is_worktree,
    surface, surface_host, tool_version, parent_thread_id
ON sessions
WHEN NEW.rowid > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_sessions') AS INTEGER)
 AND ( OLD.project_id IS NOT NEW.project_id
           OR COALESCE(OLD.tool, '') IS NOT COALESCE(NEW.tool, '')
           OR COALESCE(OLD.model, '') IS NOT COALESCE(NEW.model, '')
           OR COALESCE(OLD.git_branch, '') IS NOT COALESCE(NEW.git_branch, '')
           OR COALESCE(OLD.started_at, '') IS NOT COALESCE(NEW.started_at, '')
           OR COALESCE(OLD.ended_at, '') IS NOT COALESCE(NEW.ended_at, '')
           OR COALESCE(OLD.total_actions, 0) IS NOT COALESCE(NEW.total_actions, 0)
           OR COALESCE(OLD.workspace_hash, '') IS NOT COALESCE(NEW.workspace_hash, '')
           OR COALESCE(OLD.workspace, '') IS NOT COALESCE(NEW.workspace, '')
           OR COALESCE(OLD.is_worktree, 0) IS NOT COALESCE(NEW.is_worktree, 0)
           OR COALESCE(OLD.surface, '') IS NOT COALESCE(NEW.surface, '')
           OR COALESCE(OLD.surface_host, '') IS NOT COALESCE(NEW.surface_host, '')
           OR COALESCE(OLD.tool_version, '') IS NOT COALESCE(NEW.tool_version, '')
           OR COALESCE(OLD.parent_thread_id, '') IS NOT COALESCE(NEW.parent_thread_id, '') )
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq)
    VALUES ('sessions', NEW.rowid, (SELECT rev FROM org_push_rev WHERE k = 1));
END;

CREATE TRIGGER org_push_change_actions
AFTER UPDATE OF
    session_id, target_hash, source_file_hash, source_file, source_event_id,
    timestamp, tool, action_type, target, turn_index,
    success, duration_ms, is_sidechain, raw_tool_input, raw_tool_output,
    preceding_reasoning, error_message, metadata, message_id
ON actions
WHEN NEW.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_actions') AS INTEGER)
 AND ( COALESCE(OLD.session_id, '') IS NOT COALESCE(NEW.session_id, '')
           OR COALESCE(OLD.target_hash, '') IS NOT COALESCE(NEW.target_hash, '')
           OR COALESCE(OLD.source_file_hash, '') IS NOT COALESCE(NEW.source_file_hash, '')
           OR COALESCE(OLD.source_file, '') IS NOT COALESCE(NEW.source_file, '')
           OR COALESCE(OLD.source_event_id, '') IS NOT COALESCE(NEW.source_event_id, '')
           OR COALESCE(OLD.timestamp, '') IS NOT COALESCE(NEW.timestamp, '')
           OR COALESCE(OLD.tool, '') IS NOT COALESCE(NEW.tool, '')
           OR COALESCE(OLD.action_type, '') IS NOT COALESCE(NEW.action_type, '')
           OR COALESCE(OLD.target, '') IS NOT COALESCE(NEW.target, '')
           OR COALESCE(OLD.turn_index, 0) IS NOT COALESCE(NEW.turn_index, 0)
           OR COALESCE(OLD.success, 1) IS NOT COALESCE(NEW.success, 1)
           OR COALESCE(OLD.duration_ms, 0) IS NOT COALESCE(NEW.duration_ms, 0)
           OR COALESCE(OLD.is_sidechain, 0) IS NOT COALESCE(NEW.is_sidechain, 0)
           OR COALESCE(OLD.raw_tool_input, '') IS NOT COALESCE(NEW.raw_tool_input, '')
           OR COALESCE(OLD.raw_tool_output, '') IS NOT COALESCE(NEW.raw_tool_output, '')
           OR COALESCE(OLD.preceding_reasoning, '') IS NOT COALESCE(NEW.preceding_reasoning, '')
           OR COALESCE(OLD.error_message, '') IS NOT COALESCE(NEW.error_message, '')
           OR (CASE WHEN json_valid(OLD.metadata) THEN json_extract(OLD.metadata, '$.effort_level') END)
              IS NOT (CASE WHEN json_valid(NEW.metadata) THEN json_extract(NEW.metadata, '$.effort_level') END)
           OR (CASE WHEN json_valid(OLD.metadata) THEN json_extract(OLD.metadata, '$.stop_reason') END)
              IS NOT (CASE WHEN json_valid(NEW.metadata) THEN json_extract(NEW.metadata, '$.stop_reason') END)
           OR COALESCE(OLD.message_id, '') IS NOT COALESCE(NEW.message_id, '') )
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq)
    VALUES ('actions', NEW.id, (SELECT rev FROM org_push_rev WHERE k = 1));
END;

CREATE TRIGGER org_push_change_api_turns
AFTER UPDATE OF
    session_id, project_id, timestamp, provider, model,
    request_id, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens,
    cache_creation_1h_tokens, web_search_requests, cost_usd, message_count, tool_use_count,
    system_prompt_hash, message_prefix_hash, time_to_first_token_ms, total_response_ms, stop_reason,
    http_status, error_class, route, routing_generation, authority_source
ON api_turns
WHEN NEW.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_api_turns') AS INTEGER)
 AND ( COALESCE(OLD.session_id, '') IS NOT COALESCE(NEW.session_id, '')
           OR OLD.project_id IS NOT NEW.project_id
           OR COALESCE(OLD.timestamp, '') IS NOT COALESCE(NEW.timestamp, '')
           OR COALESCE(OLD.provider, '') IS NOT COALESCE(NEW.provider, '')
           OR COALESCE(OLD.model, '') IS NOT COALESCE(NEW.model, '')
           OR COALESCE(OLD.request_id, '') IS NOT COALESCE(NEW.request_id, '')
           OR COALESCE(OLD.input_tokens, 0) IS NOT COALESCE(NEW.input_tokens, 0)
           OR COALESCE(OLD.output_tokens, 0) IS NOT COALESCE(NEW.output_tokens, 0)
           OR COALESCE(OLD.cache_read_tokens, 0) IS NOT COALESCE(NEW.cache_read_tokens, 0)
           OR COALESCE(OLD.cache_creation_tokens, 0) IS NOT COALESCE(NEW.cache_creation_tokens, 0)
           OR COALESCE(OLD.cache_creation_1h_tokens, 0) IS NOT COALESCE(NEW.cache_creation_1h_tokens, 0)
           OR COALESCE(OLD.web_search_requests, 0) IS NOT COALESCE(NEW.web_search_requests, 0)
           OR COALESCE(OLD.cost_usd, 0) IS NOT COALESCE(NEW.cost_usd, 0)
           OR COALESCE(OLD.message_count, 0) IS NOT COALESCE(NEW.message_count, 0)
           OR COALESCE(OLD.tool_use_count, 0) IS NOT COALESCE(NEW.tool_use_count, 0)
           OR COALESCE(OLD.system_prompt_hash, '') IS NOT COALESCE(NEW.system_prompt_hash, '')
           OR COALESCE(OLD.message_prefix_hash, '') IS NOT COALESCE(NEW.message_prefix_hash, '')
           OR COALESCE(OLD.time_to_first_token_ms, 0) IS NOT COALESCE(NEW.time_to_first_token_ms, 0)
           OR COALESCE(OLD.total_response_ms, 0) IS NOT COALESCE(NEW.total_response_ms, 0)
           OR COALESCE(OLD.stop_reason, '') IS NOT COALESCE(NEW.stop_reason, '')
           OR COALESCE(OLD.http_status, 0) IS NOT COALESCE(NEW.http_status, 0)
           OR COALESCE(OLD.error_class, '') IS NOT COALESCE(NEW.error_class, '')
           OR COALESCE(OLD.route, '') IS NOT COALESCE(NEW.route, '')
           OR COALESCE(OLD.routing_generation, 0) IS NOT COALESCE(NEW.routing_generation, 0)
           OR COALESCE(OLD.authority_source, '') IS NOT COALESCE(NEW.authority_source, '') )
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq)
    VALUES ('api_turns', NEW.id, (SELECT rev FROM org_push_rev WHERE k = 1));
END;

CREATE TRIGGER org_push_change_token_usage
AFTER UPDATE OF
    session_id, timestamp, tool, model, input_tokens,
    output_tokens, cache_read_tokens, cache_creation_tokens, cache_creation_1h_tokens, reasoning_tokens,
    web_search_requests, estimated_cost_usd, source, reliability, source_file_hash,
    source_file, source_event_id, message_id, is_sidechain, fast,
    turn_id, gen_ms, gen_basis
ON token_usage
WHEN NEW.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_token_usage') AS INTEGER)
 AND ( COALESCE(OLD.session_id, '') IS NOT COALESCE(NEW.session_id, '')
           OR COALESCE(OLD.timestamp, '') IS NOT COALESCE(NEW.timestamp, '')
           OR COALESCE(OLD.tool, '') IS NOT COALESCE(NEW.tool, '')
           OR COALESCE(OLD.model, '') IS NOT COALESCE(NEW.model, '')
           OR COALESCE(OLD.input_tokens, 0) IS NOT COALESCE(NEW.input_tokens, 0)
           OR COALESCE(OLD.output_tokens, 0) IS NOT COALESCE(NEW.output_tokens, 0)
           OR COALESCE(OLD.cache_read_tokens, 0) IS NOT COALESCE(NEW.cache_read_tokens, 0)
           OR COALESCE(OLD.cache_creation_tokens, 0) IS NOT COALESCE(NEW.cache_creation_tokens, 0)
           OR COALESCE(OLD.cache_creation_1h_tokens, 0) IS NOT COALESCE(NEW.cache_creation_1h_tokens, 0)
           OR COALESCE(OLD.reasoning_tokens, 0) IS NOT COALESCE(NEW.reasoning_tokens, 0)
           OR COALESCE(OLD.web_search_requests, 0) IS NOT COALESCE(NEW.web_search_requests, 0)
           OR COALESCE(OLD.estimated_cost_usd, 0) IS NOT COALESCE(NEW.estimated_cost_usd, 0)
           OR COALESCE(OLD.source, '') IS NOT COALESCE(NEW.source, '')
           OR COALESCE(OLD.reliability, 'unknown') IS NOT COALESCE(NEW.reliability, 'unknown')
           OR COALESCE(OLD.source_file_hash, '') IS NOT COALESCE(NEW.source_file_hash, '')
           OR COALESCE(OLD.source_file, '') IS NOT COALESCE(NEW.source_file, '')
           OR COALESCE(OLD.source_event_id, '') IS NOT COALESCE(NEW.source_event_id, '')
           OR COALESCE(OLD.message_id, '') IS NOT COALESCE(NEW.message_id, '')
           OR COALESCE(OLD.is_sidechain, 0) IS NOT COALESCE(NEW.is_sidechain, 0)
           OR COALESCE(OLD.fast, 0) IS NOT COALESCE(NEW.fast, 0)
           OR COALESCE(OLD.turn_id, '') IS NOT COALESCE(NEW.turn_id, '')
           OR COALESCE(OLD.gen_ms, 0) IS NOT COALESCE(NEW.gen_ms, 0)
           OR COALESCE(OLD.gen_basis, '') IS NOT COALESCE(NEW.gen_basis, '') )
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq)
    VALUES ('token_usage', NEW.id, (SELECT rev FROM org_push_rev WHERE k = 1));
END;

-- A project's identity columns ride EVERY session row of that project (the
-- push joins sessions to projects), so a project that learns its remote /
-- upstream / root commit later changes the wire shape of sessions already
-- shipped. Re-queue them.
CREATE TRIGGER org_push_change_projects
AFTER UPDATE OF
    root_path, root_path_hash, git_remote, git_remote_hash,
    git_upstream_remote, git_upstream_remote_hash, git_remote_owner_hash, git_upstream_owner_hash,
    root_commit_hash, content_fingerprint_hash
ON projects
WHEN CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_sessions') AS INTEGER) IS NOT NULL
 AND ( COALESCE(OLD.root_path, '') IS NOT COALESCE(NEW.root_path, '')
           OR COALESCE(OLD.root_path_hash, '') IS NOT COALESCE(NEW.root_path_hash, '')
           OR COALESCE(OLD.git_remote, '') IS NOT COALESCE(NEW.git_remote, '')
           OR COALESCE(OLD.git_remote_hash, '') IS NOT COALESCE(NEW.git_remote_hash, '')
           OR COALESCE(OLD.git_upstream_remote, '') IS NOT COALESCE(NEW.git_upstream_remote, '')
           OR COALESCE(OLD.git_upstream_remote_hash, '') IS NOT COALESCE(NEW.git_upstream_remote_hash, '')
           OR COALESCE(OLD.git_remote_owner_hash, '') IS NOT COALESCE(NEW.git_remote_owner_hash, '')
           OR COALESCE(OLD.git_upstream_owner_hash, '') IS NOT COALESCE(NEW.git_upstream_owner_hash, '')
           OR COALESCE(OLD.root_commit_hash, '') IS NOT COALESCE(NEW.root_commit_hash, '')
           OR COALESCE(OLD.content_fingerprint_hash, '') IS NOT COALESCE(NEW.content_fingerprint_hash, '') )
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq)
    SELECT 'sessions', s.rowid, (SELECT rev FROM org_push_rev WHERE k = 1)
      FROM sessions s
     WHERE s.project_id = NEW.id
       AND s.rowid > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_sessions') AS INTEGER);
END;

-- A token_usage row's project fields come from its SESSION's project (the
-- push joins token_usage -> sessions -> projects), so a session moved to a
-- different project changes the wire shape of that session's token rows too.
CREATE TRIGGER org_push_change_session_tokens
AFTER UPDATE OF project_id ON sessions
WHEN OLD.project_id IS NOT NEW.project_id
 AND CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_token_usage') AS INTEGER) IS NOT NULL
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq)
    SELECT 'token_usage', tu.id, (SELECT rev FROM org_push_rev WHERE k = 1)
      FROM token_usage tu
     WHERE tu.session_id = NEW.id
       AND tu.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_token_usage') AS INTEGER);
END;

