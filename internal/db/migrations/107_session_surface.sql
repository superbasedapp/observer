-- 107_session_surface.sql — capture-surface attribution on sessions.
--
-- Every flagship AI tool stamps WHICH client produced a session on disk
-- (Claude Code `entrypoint` = cli / claude-vscode / claude-desktop /
-- sdk-*; Codex `session_meta.originator` + `source` = codex_cli /
-- codex_vscode / "Codex Desktop" × cli / vscode / exec; Cline `source`
-- = cli / vscode / jetbrains / neovim / desktop / ...; Cursor by store
-- shape) and until this migration Observer read none of it, so the
-- dashboard could not split IDE vs terminal vs desktop spend for any
-- tool (docs/audits/ide-session-tracking-audit-2026-09-02.md IDE-05).
--
--   surface       — the normalized KIND: cli | ide | desktop | sdk | web
--                   (models.Surface* constants; closed vocabulary)
--   surface_host  — the concrete host token refining the kind:
--                   vscode | cursor | jetbrains | neovim | kiro |
--                   claude-desktop | codex-desktop | codex-exec | ...
--
-- Each adapter resolves its vendor token through a TABLE at its own
-- boundary (CLAUDE.md #3/#5); nothing downstream switches on tool name.
--
-- Both columns are NODE-LOCAL: they are NEVER selected by the org-push
-- seam (internal/store/orgpush.go::SelectUnpushedSince) and are pinned
-- out of the wire by tests/invariant/privacy_test.go. Written ONLY
-- through Store.SetSessionSurface (not UpsertSession), COALESCE-
-- preserving, so a re-parse never clears a captured value.
--
-- Nullable, no backfill: existing rows keep NULL (= "unknown", the
-- honest zero) until the owning transcript is re-scanned
-- (`observer scan --force`).

ALTER TABLE sessions ADD COLUMN surface TEXT;
ALTER TABLE sessions ADD COLUMN surface_host TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_surface ON sessions(surface);
