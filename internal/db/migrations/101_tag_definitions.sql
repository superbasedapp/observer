-- 101_tag_definitions.sql — user-authored definitions for the session
-- tag vocabulary (session_tags, migration 075). A tag itself is just a
-- string; this table lets the operator attach an optional human-readable
-- explanation ("what does 'compression-regression-2026' mean?") plus an
-- optional grouping category, without inventing a second tag namespace.
--
-- ONE OWNER: internal/store/tagdefinitions.go is the only writer/reader seam
-- (CLAUDE.md module-boundary rule #4), a sibling of
-- internal/store/sessiontags.go which owns session_tags/session_annotations.
--
-- No FK to session_tags: a definition can be authored before any session
-- carries the tag (defining the vocabulary ahead of first use), and a tag
-- with zero remaining assignments (DeleteTag/RenameTag having emptied it)
-- keeps its definition rather than losing it to an implicit cascade.
--
-- NODE-LOCAL: never pushed. Tag names and definitions are the same privacy
-- class as sessions.git_branch (gated off the org wire 2026-07-02, security
-- review M2) — they encode client names, codenames and ticket ids. This
-- table's name is pinned in tests/invariant/privacy_test.go's
-- forbiddenCacheTables sentinel alongside session_tags/session_annotations.
-- No paired orgserver migration exists, by design.

CREATE TABLE IF NOT EXISTS tag_definitions (
    tag        TEXT PRIMARY KEY,                       -- normalized tag (store.NormalizeTag)
    definition TEXT NOT NULL DEFAULT '',                -- human-readable explanation, '' = none
    category   TEXT NOT NULL DEFAULT '',                -- optional grouping label, '' = none
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
