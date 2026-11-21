-- 240_session_execution_location.sql - where a session ran and its
-- cross-rail vendor reference (cloud-agents arc, lane CA-A1; decisions CA-D1
-- and CA-D2 of docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md;
-- paired with server migration 300 / pg 0170).
--
--   execution_location - where the session's agent ran: one of the closed
--                        models.Execution* kinds ('local', 'vendor_cloud',
--                        'customer_worker'). A dimension of its own, NOT a
--                        Surface kind: surface stays "where the human
--                        interacts". NULL = unknown, never a defaulted
--                        'local'.
--   vendor_session_ref - the vendor's SECOND native session reference used to
--                        join one session across capture rails (a Claude Code
--                        `cse_...` id, a `ccr.session.id`, a GitHub
--                        `agent_session_id`). The vendor's primary native id
--                        is sessions.id itself (CA-D2). Opaque id, never
--                        content; grammar orgcontract.ValidVendorSessionRef.
--
-- One writer: internal/store/cloudsessions.go::SetSessionExecution
-- (FIRST-WINS-UNLESS-EMPTY per column, the SetSessionSurface shape);
-- UpsertSession never touches either column. Nullable, no backfill: every
-- existing session stays unknown. Both columns ship on the org wire as
-- METADATA (orgcontract.SessionRow, omitempty), the surface /
-- parent_thread_id posture.
--
-- The partial index serves the cross-rail join (Store.SessionIDByVendorRef):
-- almost every row is NULL, so only stamped rows are indexed.
--
-- RE-SEND. Migrations 140/142/162 queue a session for re-push when one of a
-- fixed column list changes. Both new columns must be on that list or a stamp
-- landed after the row first shipped would never reach the org. The trigger
-- is dropped and re-created with the SAME name, the SAME WHEN shape and the
-- migration-142 UPSERT queue insert; only the two columns join the column
-- list and the change predicate (internal/db/triggers_guard_test.go checks the
-- latest definition).
--
-- Numbered 240, the first number of the cloud-agents arc's reservation
-- (node 240-249, CA-D14; reservedMigrationRanges in
-- tests/invariant/migrations_pin_test.go). The plans orchestrator confirms the
-- reservation before the first merge into the combined line
-- (docs/migration-numbering.md).
ALTER TABLE sessions ADD COLUMN execution_location TEXT;
ALTER TABLE sessions ADD COLUMN vendor_session_ref TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_vendor_session_ref
    ON sessions (vendor_session_ref)
    WHERE vendor_session_ref IS NOT NULL;

DROP TRIGGER IF EXISTS org_push_change_sessions;
CREATE TRIGGER org_push_change_sessions
AFTER UPDATE OF
    project_id, tool, model, git_branch, started_at,
    ended_at, total_actions, workspace_hash, workspace, is_worktree,
    surface, surface_host, tool_version, parent_thread_id, tool_version_last,
    execution_location, vendor_session_ref
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
           OR COALESCE(OLD.parent_thread_id, '') IS NOT COALESCE(NEW.parent_thread_id, '')
           OR COALESCE(OLD.tool_version_last, '') IS NOT COALESCE(NEW.tool_version_last, '')
           OR COALESCE(OLD.execution_location, '') IS NOT COALESCE(NEW.execution_location, '')
           OR COALESCE(OLD.vendor_session_ref, '') IS NOT COALESCE(NEW.vendor_session_ref, '') )
BEGIN
    UPDATE org_push_rev SET rev = rev + 1 WHERE k = 1;
    INSERT INTO org_push_changes (tbl, row_id, seq)
    VALUES ('sessions', NEW.rowid, (SELECT rev FROM org_push_rev WHERE k = 1))
    ON CONFLICT (tbl, row_id) DO UPDATE SET seq = excluded.seq;
END;
