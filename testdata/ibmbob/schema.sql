-- IBM Bob Shell (bobshell 2.0.6) bob.db DDL for the two tables the
-- ibmbob adapter reads. Copied verbatim from `sqlite3 bob.db .schema`
-- (DDL only, zero data) on 2026-10-21; the store had applied migrations
-- 001_initial .. 011_key_value_store. The columns after `lock_lease_until`
-- were added by later ALTER TABLE migrations, which is why SQLite prints
-- them on the closing line.
CREATE TABLE tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    parent_id TEXT REFERENCES tasks(id),
    title TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    first_message TEXT,
    directory TEXT NOT NULL,
    version TEXT,
    git_sha TEXT,
    git_branch TEXT,
    env TEXT,
    costs TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    time_archived INTEGER,
    locked_by TEXT,
    lock_lease_until INTEGER
, approval_config TEXT, message_queue TEXT, task_type TEXT NOT NULL DEFAULT 'normal' CHECK (task_type IN ('normal', 'subtask', 'subagent')), last_error TEXT, is_pinned INTEGER NOT NULL DEFAULT 0);
CREATE INDEX idx_tasks_project ON tasks(project_id);
CREATE INDEX idx_tasks_updated ON tasks(updated_at DESC, id DESC);
CREATE INDEX idx_tasks_parent ON tasks(parent_id);
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX idx_messages_task ON messages(task_id, created_at);
