-- 135_skill_history.sql - Skills history on the Projects page (S10-SKILLS,
-- docs/projects-page.md "Skills: versions across commits and sessions").
--
-- Three independent facts per (session, skill), never merged:
--
--   1. OBSERVED  - a Claude Code hook snapshot hashed every SKILL.md at
--                  SessionStart (startup/resume/clear/compact) and the
--                  invoked SKILL.md at PostToolUse(Skill). Written ONLY by
--                  internal/store/skillsnap.go, called ONLY from the hook
--                  seam (cmd/observer/hook_skillsnap.go).
--   2. HEAD AT SESSION START - the git REFLOG (the only local record of when
--                  HEAD pointed where) plus the SKILL.md blob id in that
--                  commit's tree (`git ls-tree`). Written ONLY by
--                  internal/store/skillgit.go, called ONLY from the commit
--                  scanner's after-scan step (internal/skillscan).
--   3. INVOKED   - read from actions (skill_invoke), joined by tool_use_id to
--                  the PostToolUse snapshot. No new table.
--
-- The commit TIMELINE reuses project_commit_files (migration 127); the tree
-- memo below only adds the blob id per (sha, path), an immutable fact.
--
-- PRIVACY: every table here is NODE-LOCAL. None is ever selected by
-- internal/store/orgpush.go::SelectUnpushedSince; all seven names are in the
-- forbidden-name sentinel (tests/invariant/privacy_test.go) with a seeded
-- behavioral test. No free text is stored: no file bodies, no reflog
-- messages (%gs is classified into an allow-listed kind token and dropped),
-- no commit subjects (the UI joins project_commits for the already-scrubbed
-- subject). `name` is the skill's identifier (frontmatter name or dir).
--
-- Timestamps are FIXED-WIDTH UTC `2006-01-02T15:04:05.000000000Z` so a TEXT
-- comparison orders correctly; readers still compare in Go.

-- Content-addressed member sets: identical snapshots (the common case - the
-- same skills at every session start) share one set.
CREATE TABLE IF NOT EXISTS skill_snapshot_members (
    set_hash     TEXT NOT NULL,
    scope        TEXT NOT NULL,              -- project | user
    rel_path     TEXT NOT NULL,              -- forward slashes; real on-disk case
    dir_key      TEXT NOT NULL,              -- case-folded skill directory
    name         TEXT NOT NULL DEFAULT '',
    state        TEXT NOT NULL,              -- present | unreadable
    content_hash TEXT NOT NULL DEFAULT '',   -- sha256 of the bytes
    blob_oid     TEXT NOT NULL DEFAULT '',   -- git blob id of the bytes
    blob_oid_lf  TEXT NOT NULL DEFAULT '',   -- git blob id of the LF-normalised bytes (CRLF bodies only)
    size_bytes   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (set_hash, scope, rel_path)
);

CREATE TABLE IF NOT EXISTS session_skill_snapshots (
    id            INTEGER PRIMARY KEY,
    session_id    TEXT NOT NULL,
    tool          TEXT NOT NULL,
    event         TEXT NOT NULL,             -- session_start | skill_invoke
    source        TEXT NOT NULL DEFAULT '',  -- startup|resume|clear|compact (session_start)
    tool_use_id   TEXT NOT NULL DEFAULT '',  -- skill_invoke: joins actions.source_event_id
    invoked_name  TEXT NOT NULL DEFAULT '',
    observed_at   TEXT NOT NULL,
    project_root  TEXT NOT NULL DEFAULT '',  -- display only; the join is session_id
    set_hash      TEXT NOT NULL,
    complete      INTEGER NOT NULL DEFAULT 1,  -- 0 = budget/file cap hit: a missing member is UNKNOWN, not absent
    home_resolved INTEGER NOT NULL DEFAULT 1,  -- 0 = the tool's home .claude could not be resolved
    UNIQUE (session_id, event, tool_use_id, observed_at)
);
CREATE INDEX IF NOT EXISTS idx_session_skill_snapshots_session ON session_skill_snapshots(session_id);
CREATE INDEX IF NOT EXISTS idx_session_skill_snapshots_tool_use ON session_skill_snapshots(tool_use_id);

-- Persisted HEAD reflog (our copy outlives the reflog's own expiry once captured).
CREATE TABLE IF NOT EXISTS project_head_moves (
    project_id INTEGER NOT NULL REFERENCES projects(id),
    moved_at   TEXT NOT NULL,
    sha        TEXT NOT NULL,
    kind       TEXT NOT NULL,                -- allow-listed token (commitlog.ReflogKind)
    -- seq orders entries that share one reflog second (--date=unix has
    -- 1-second resolution; a rebase writes several in one second): larger
    -- is newer. Assigned from the reflog's own output order at capture,
    -- above every stored seq, so it only ever breaks ties WITHIN a second.
    seq        INTEGER NOT NULL DEFAULT 0,
    UNIQUE (project_id, moved_at, sha)
);
CREATE INDEX IF NOT EXISTS idx_project_head_moves_project_time ON project_head_moves(project_id, moved_at, seq);

-- Tree memo: which commits have had their skill paths listed. Immutable per
-- sha; reachability stays owned by project_commits.
CREATE TABLE IF NOT EXISTS project_skill_trees (
    project_id  INTEGER NOT NULL REFERENCES projects(id),
    sha         TEXT NOT NULL,
    state       TEXT NOT NULL,               -- ok | missing
    resolved_at TEXT NOT NULL,
    PRIMARY KEY (project_id, sha)
);

CREATE TABLE IF NOT EXISTS project_skill_tree_files (
    project_id INTEGER NOT NULL REFERENCES projects(id),
    sha        TEXT NOT NULL,
    rel_path   TEXT NOT NULL,
    mode       TEXT NOT NULL,
    blob_oid   TEXT NOT NULL,
    PRIMARY KEY (project_id, sha, rel_path)
);

-- Current working-tree state of the skill paths, from the status porcelain
-- (the VCS's own answer; replaced whole on each pass). A path absent here
-- is clean.
CREATE TABLE IF NOT EXISTS project_skill_worktree (
    project_id INTEGER NOT NULL REFERENCES projects(id),
    rel_path   TEXT NOT NULL,
    state      TEXT NOT NULL,
    PRIMARY KEY (project_id, rel_path)
);

CREATE TABLE IF NOT EXISTS project_skill_scan (
    project_id           INTEGER PRIMARY KEY REFERENCES projects(id),
    last_scan_at         TEXT NOT NULL DEFAULT '',
    head_sha             TEXT NOT NULL DEFAULT '',
    reflog_since         TEXT NOT NULL DEFAULT '',
    -- Repository probes, refreshed every 24 h (probed_at). ignorecase and
    -- shallow are tri-state: 1 true, 0 false, -1 unknown (the probe failed
    -- and no earlier answer exists); object_format '' = unknown.
    probed_at            TEXT NOT NULL DEFAULT '',
    ignorecase           INTEGER NOT NULL DEFAULT -1,
    object_format        TEXT NOT NULL DEFAULT '',
    shallow              INTEGER NOT NULL DEFAULT -1,
    last_error           TEXT NOT NULL DEFAULT '',
    consecutive_failures INTEGER NOT NULL DEFAULT 0
);
