-- 102_project_identity_v2.sql — Project Identity Resolver v2, node-side
-- capture columns (docs/plans/project-identity-resolver-v2-plan-2026-09-06.md
-- §3.1 / W1).
--
-- WHAT THIS IS. The 2026-08-21 Team Project Identity Mapping arc gave every
-- git-backed session a normalized `origin` remote (projects.git_remote +
-- git_remote_hash). Resolver v2 widens that single signal into the full
-- identity bundle an org server needs to fold N differently-named local
-- folders onto ONE canonical project with zero developer action:
--
--   * the `upstream` remote (fork -> enterprise repo resolution),
--   * per-remote OWNER hashes, sha256("host/owner"), so an org can declare
--     its enterprise owner prefixes without the server ever seeing a URL,
--   * the repository's ROOT COMMIT (`git rev-list --max-parents=0 HEAD`,
--     smallest sha when a repo has several roots) — stable across clones,
--     forks and renames, and the only signal that can fold a remote-less
--     clone,
--   * a coarse CONTENT FINGERPRINT (manifest module names + top-level dir
--     names) for `.git`-less copies — suggestion-only, never auto-folded,
--   * the monorepo WORKSPACE (session cwd's nearest manifest dir relative to
--     the git root) as a sub-dimension of the project, not a second key,
--   * the worktree bit, so a linked worktree is visibly the same repo.
--
-- ONE OWNER. internal/store/projectidentity.go owns every column added here
-- (CLAUDE.md module-boundary rule #4); UpsertProject/UpsertSession call into
-- it. The values themselves are produced by internal/git.ResolveIdentity —
-- a pure package except for the single injected root-commit exec.
--
-- PRIVACY. Everything here is NODE-LOCAL storage. What reaches an org server
-- is decided in the ONE push seam (internal/store/orgpush.go::
-- SelectUnpushedSince) and follows the standing invariant exactly:
--   * hash columns (git_upstream_remote_hash, git_remote_owner_hash,
--     git_upstream_owner_hash, root_commit_hash, content_fingerprint_hash,
--     workspace_hash) ship ALWAYS — they are unsalted sha256, joinable across
--     nodes, and disclose nothing a raw value would not;
--   * raw columns (git_upstream_remote, workspace) ship ONLY under
--     ShareOptions.shipsRawContent(), stripped in Go per row exactly like
--     git_remote / project_root are today, and pinned by
--     tests/invariant/privacy_test.go's sentinel set;
--   * root_commit_sha and content_fingerprint are the RAW pre-image inputs
--     and NEVER ship in any share mode — only their hashes do. They exist
--     locally so the hash can be recomputed without re-running git.
-- No remote server toggle exists or is added.
--
-- root_commit_checked_at is the retry fence for the one exec: a huge repo
-- whose `git rev-list` times out (or a machine with no git binary) records
-- the attempt instant and is retried at most every 7 days, instead of paying
-- the timeout on every process start.
--
-- Paired server migration: internal/orgserver/db/migrations/121_* (the
-- sessions columns) — the wire fields are additive and omitempty, so older
-- agents that never set them keep resolving by remote alone.

ALTER TABLE projects ADD COLUMN git_upstream_remote      TEXT;
ALTER TABLE projects ADD COLUMN git_upstream_remote_hash TEXT;
ALTER TABLE projects ADD COLUMN git_remote_owner_hash    TEXT;
ALTER TABLE projects ADD COLUMN git_upstream_owner_hash  TEXT;
ALTER TABLE projects ADD COLUMN root_commit_sha          TEXT;
ALTER TABLE projects ADD COLUMN root_commit_hash         TEXT;
ALTER TABLE projects ADD COLUMN root_commit_checked_at   TEXT;
ALTER TABLE projects ADD COLUMN content_fingerprint      TEXT;
ALTER TABLE projects ADD COLUMN content_fingerprint_hash TEXT;

-- Per-SESSION, not per-project: the workspace is the cwd's position inside
-- the repo (Alice in platform/services/payments, Bob in platform) and the
-- worktree bit describes how THIS session's cwd reached the root. The
-- project root stays the main repo either way.
ALTER TABLE sessions ADD COLUMN workspace      TEXT;
ALTER TABLE sessions ADD COLUMN workspace_hash TEXT;
ALTER TABLE sessions ADD COLUMN is_worktree    INTEGER;

CREATE INDEX IF NOT EXISTS idx_projects_root_commit_hash
    ON projects(root_commit_hash);
