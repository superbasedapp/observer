-- 142_org_push_changes_upsert.sql - the org push re-send triggers queue with
-- an UPSERT, not INSERT OR REPLACE (lane R2-TRIG, 2026-09-28, defect D3; no
-- server pair, no wire change, no new table).
--
-- WHY. Migrations 140 and 141 queued a re-send with
--     INSERT OR REPLACE INTO org_push_changes (tbl, row_id, seq) ...
-- intending "replace the queued row with the newer seq". SQLite does not
-- honour a conflict clause inside a trigger body when the statement that
-- FIRED the trigger has its own conflict handling: the outer statement's
-- algorithm is used instead (https://sqlite.org/lang_createtrigger.html). An
-- UPSERT's DO UPDATE half runs as an UPDATE with ABORT, so when the outer
-- statement is an `INSERT ... ON CONFLICT DO UPDATE` (store.UpsertSession,
-- store.UpsertProject, the action upsert in store.InsertActions, the
-- token_usage MAX-upgrade in store.InsertTokenEvents) and the row is ALREADY
-- queued, the trigger's insert failed
--     UNIQUE constraint failed: org_push_changes.tbl, org_push_changes.row_id
-- and the whole ingest transaction rolled back, again and again, until the
-- next push drained the queue (up to 900 s; a live node logged 438 failed
-- ingests in 8 minutes). Only ENROLLED nodes were hit - the triggers are
-- gated on the org_push_floor_<table> schema_meta key. The opposite outer
-- clauses were silently wrong too: under an outer `INSERT OR IGNORE` /
-- `UPDATE OR IGNORE` the queue insert was IGNORED, leaving the queued row at
-- its OLDER seq, so a batch in flight could acknowledge (seq <= its rev) a
-- change it never read and the change was never re-sent.
--
-- HOW. Every trigger that writes org_push_changes is dropped and re-created
-- with the SAME name, the SAME event (AFTER UPDATE OF <same column list> /
-- AFTER INSERT), the SAME WHEN clause and the SAME statements; only the
-- queue insert changes, to
--     INSERT INTO org_push_changes (tbl, row_id, seq) ...
--     ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq;
-- An UPSERT clause is NOT overridden by the outer statement's conflict
-- algorithm, so the queue row always ends at the latest change's seq,
-- whatever fired it (a plain UPDATE, an UPSERT, UPDATE OR IGNORE/REPLACE,
-- INSERT OR IGNORE). seq = excluded.seq is exactly the old REPLACE semantics:
-- org_push_rev only ever grows, so the incoming seq is always the newest.
--
-- NOT rewritten: the 141 tombstone triggers (org_push_delete_* /
-- org_push_identity_*). They use a plain INSERT into org_push_deletions keyed
-- by seq = the freshly bumped org_push_rev value, which is unique by
-- construction, so no conflict algorithm (inner or outer) ever applies.
--
-- Migrations 140 / 141 are never edited (already applied on live nodes); a
-- DB at 141 upgrades here in the migration transaction, and a queue row
-- already present keeps its seq until its row changes again. The guard test
-- internal/db/triggers_guard_test.go fails if any trigger body (latest
-- definition across all migrations) uses a statement conflict clause again,
-- and if any trigger the migrations define is missing after a fresh open - a
-- later table-rebuilding migration (CREATE new / copy / DROP old / RENAME)
-- silently drops every trigger on the dropped table, so such a migration must
-- re-create them.

-- Migration 140's trigger, unchanged but for the queue UPSERT.
DROP TRIGGER IF EXISTS org_push_change_sessions;
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
    INSERT INTO org_push_changes (tbl, row_id, seq)
    VALUES ('sessions', NEW.rowid, (SELECT rev FROM org_push_rev WHERE k = 1))
    ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq;
END;

-- Migration 140's trigger, unchanged but for the queue UPSERT.
DROP TRIGGER IF EXISTS org_push_change_actions;
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
    INSERT INTO org_push_changes (tbl, row_id, seq)
    VALUES ('actions', NEW.id, (SELECT rev FROM org_push_rev WHERE k = 1))
    ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq;
END;

-- Migration 140's trigger, unchanged but for the queue UPSERT.
DROP TRIGGER IF EXISTS org_push_change_api_turns;
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
    INSERT INTO org_push_changes (tbl, row_id, seq)
    VALUES ('api_turns', NEW.id, (SELECT rev FROM org_push_rev WHERE k = 1))
    ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq;
END;

-- Migration 140's trigger, unchanged but for the queue UPSERT.
DROP TRIGGER IF EXISTS org_push_change_token_usage;
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
    INSERT INTO org_push_changes (tbl, row_id, seq)
    VALUES ('token_usage', NEW.id, (SELECT rev FROM org_push_rev WHERE k = 1))
    ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq;
END;

-- Migration 140's trigger, unchanged but for the queue UPSERT.
DROP TRIGGER IF EXISTS org_push_change_projects;
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
    INSERT INTO org_push_changes (tbl, row_id, seq)
    SELECT 'sessions', s.rowid, (SELECT rev FROM org_push_rev WHERE k = 1)
      FROM sessions s
     WHERE s.project_id = NEW.id
       AND s.rowid > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_sessions') AS INTEGER)
    ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq;
END;

-- Migration 140's trigger, unchanged but for the queue UPSERT.
DROP TRIGGER IF EXISTS org_push_change_session_tokens;
CREATE TRIGGER org_push_change_session_tokens
AFTER UPDATE OF project_id ON sessions
WHEN OLD.project_id IS NOT NEW.project_id
 AND CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_token_usage') AS INTEGER) IS NOT NULL
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_changes (tbl, row_id, seq)
    SELECT 'token_usage', tu.id, (SELECT rev FROM org_push_rev WHERE k = 1)
      FROM token_usage tu
     WHERE tu.session_id = NEW.id
       AND tu.id > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_token_usage') AS INTEGER)
    ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq;
END;

-- Migration 141's reused-rowid insert trigger, unchanged but for the queue
-- UPSERT.
DROP TRIGGER IF EXISTS org_push_insert_sessions;
CREATE TRIGGER org_push_insert_sessions
AFTER INSERT ON sessions
WHEN NEW.rowid <= CAST((SELECT value FROM schema_meta WHERE key = 'org_push_cursor_sessions') AS INTEGER)
 AND NEW.rowid > CAST((SELECT value FROM schema_meta WHERE key = 'org_push_floor_sessions') AS INTEGER)
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_changes (tbl, row_id, seq)
    VALUES ('sessions', NEW.rowid, (SELECT rev FROM org_push_rev WHERE k = 1))
    ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq;
END;
