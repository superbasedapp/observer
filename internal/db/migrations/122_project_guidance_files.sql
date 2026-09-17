-- Project guidance files: the AI-guidance documents (CLAUDE.md, AGENTS.md,
-- .cursor/rules/*.mdc, skills, sub-agents, slash commands, and the JSON
-- configs that point at more of them) each tool sees for a project.
--
-- NODE-LOCAL. This table is never on the org-push wire: it names private
-- project paths and the operator's own home-scope files, the same posture as
-- codeintel_* and project_patterns. Pinned at the source level by
-- tests/invariant/privacy_test.go's forbidden-name sentinel, so the table name
-- can never appear in internal/store/orgpush.go.
--
-- Rows are TOMBSTONED (present = 0), never deleted: a guidance file that
-- disappeared is a fact about the project worth keeping, and first_seen would
-- otherwise be lost on every transient scan miss.
--
-- The unique key is (project_root, tool, scope, rel_path), not path alone:
-- one AGENTS.md is read by fifteen harnesses and each of them is a separate
-- row, because the question the feature answers is "what guidance does THIS
-- tool see".
--
-- Bodies are never stored — only the path, a name, a capped description, the
-- size and the sha256 of the bytes (CLAUDE.md "Don'ts").
CREATE TABLE IF NOT EXISTS project_guidance_files (
    id               INTEGER PRIMARY KEY,
    project_root     TEXT NOT NULL,
    tool             TEXT NOT NULL,
    kind             TEXT NOT NULL,
    scope            TEXT NOT NULL,
    rel_path         TEXT NOT NULL,
    abs_path         TEXT NOT NULL,
    name             TEXT NOT NULL DEFAULT '',
    description      TEXT NOT NULL DEFAULT '',
    size_bytes       INTEGER NOT NULL DEFAULT 0,
    content_hash     TEXT NOT NULL DEFAULT '',
    modified_at      TEXT NOT NULL DEFAULT '',
    frontmatter_json TEXT NOT NULL DEFAULT '{}',
    present          INTEGER NOT NULL DEFAULT 1,
    first_seen       TEXT NOT NULL,
    last_scanned     TEXT NOT NULL,
    parse_error      TEXT NOT NULL DEFAULT '',
    UNIQUE (project_root, tool, scope, rel_path)
);

-- The panel's primary read: one project, grouped by tool then kind.
CREATE INDEX IF NOT EXISTS idx_guidance_project_tool_kind
    ON project_guidance_files (project_root, tool, kind);

-- The wave-2 join: "which files in this project are called <name>".
CREATE INDEX IF NOT EXISTS idx_guidance_project_name
    ON project_guidance_files (project_root, name);
