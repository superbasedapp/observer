-- 001_archive_codeintel.sql — cold storage for Bucket A of the corpus
-- archival arc (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md
-- §2.1, §3.1). These tables live in ~/.observer/archive.db, NOT in the hot
-- observer.db.
--
-- NODE-LOCAL, and more strongly so than the hot codeintel_* tables: this file
-- is opened by exactly one package (internal/archivestore) through its own
-- *sql.DB, and internal/store/orgpush.go has no code path that could reach a
-- second database handle. The archive_* names are additionally pinned in
-- tests/invariant/privacy_test.go's forbidden-name sentinel so naming one
-- inside the push seam fails at the SOURCE level.
--
-- Three schema decisions, each deliberate:
--
-- 1. ROW IDS ARE PRESERVED. `id` mirrors the hot rowid rather than being
--    re-issued. codeintel_nodes/edges/sites/embeddings/minhash all reference
--    file ids and node ids; a re-numbered cold copy would rehydrate into a
--    silently disconnected graph.
--
-- 2. NO FOREIGN KEYS between these tables. The hot schema's ON DELETE CASCADE
--    is exactly what made CodeIntelDeleteProject pathological (see its doc
--    comment: the cascade seeks children by BARE file_id while every index is
--    project-leading, so it full-scans once per deleted file — 20+ minutes on
--    a ~40k-file project). Cold storage gets no benefit from the cascade: every
--    write and every delete here is already scoped by `project` in one
--    statement. Referential integrity is guaranteed by the mover copying whole
--    projects atomically, not by the engine.
--
-- 3. NO FTS MIRROR. codeintel_fts is a DERIVED index over codeintel_nodes,
--    rebuilt per project by store.CodeIntelBuildDerived. Round-tripping it
--    through cold storage would double the archived bytes of the largest
--    bucket to store something a rehydrate regenerates anyway (design §3.1).
--
-- archived_at (unix seconds) is the one added column, so the archive file can
-- answer its own aggregate storage questions (design §4.4) without joining
-- back to the hot DB's marker table.

CREATE TABLE IF NOT EXISTS archive_codeintel_files (
    id           INTEGER PRIMARY KEY,      -- preserved hot codeintel_files.id
    project      TEXT NOT NULL,
    path         TEXT NOT NULL,
    lang         TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    mtime        INTEGER NOT NULL DEFAULT 0,
    indexed_at   INTEGER NOT NULL DEFAULT 0,
    parser       TEXT NOT NULL DEFAULT '', -- backend that produced the rows
    status       TEXT NOT NULL DEFAULT '',
    archived_at  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_archive_codeintel_files_project
    ON archive_codeintel_files(project, path);

CREATE TABLE IF NOT EXISTS archive_codeintel_nodes (
    id          INTEGER PRIMARY KEY,       -- preserved hot codeintel_nodes.id
    project     TEXT NOT NULL,
    file_id     INTEGER NOT NULL,
    kind        TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL DEFAULT '',
    fqn         TEXT NOT NULL DEFAULT '',
    lang        TEXT NOT NULL DEFAULT '',
    start_line  INTEGER NOT NULL DEFAULT 0,
    end_line    INTEGER NOT NULL DEFAULT 0,
    start_byte  INTEGER NOT NULL DEFAULT 0,
    end_byte    INTEGER NOT NULL DEFAULT 0,
    signature   TEXT NOT NULL DEFAULT '',  -- declaration-line excerpt, never a body
    sig_hash    TEXT NOT NULL DEFAULT '',
    archived_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_archive_codeintel_nodes_project
    ON archive_codeintel_nodes(project, file_id, start_line);

CREATE TABLE IF NOT EXISTS archive_codeintel_edges (
    id               INTEGER PRIMARY KEY,  -- preserved hot codeintel_edges.id
    project          TEXT NOT NULL,
    file_id          INTEGER NOT NULL,
    src_id           INTEGER NOT NULL DEFAULT 0,
    dst_id           INTEGER NOT NULL DEFAULT 0,
    kind             TEXT NOT NULL DEFAULT '',
    confidence       REAL NOT NULL DEFAULT 1.0,
    resolver_backend TEXT NOT NULL DEFAULT '',
    archived_at      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_archive_codeintel_edges_project
    ON archive_codeintel_edges(project, file_id);

CREATE TABLE IF NOT EXISTS archive_codeintel_sites (
    id               INTEGER PRIMARY KEY,  -- preserved hot codeintel_sites.id
    project          TEXT NOT NULL,
    edge_id          INTEGER NOT NULL,
    file_id          INTEGER NOT NULL,
    start_line       INTEGER NOT NULL DEFAULT 0,
    start_byte       INTEGER NOT NULL DEFAULT 0,
    raw_text         TEXT NOT NULL DEFAULT '',
    target_name      TEXT NOT NULL DEFAULT '',
    resolver_backend TEXT NOT NULL DEFAULT '',
    confidence       REAL NOT NULL DEFAULT 1.0,
    recv_type        TEXT NOT NULL DEFAULT '',
    archived_at      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_archive_codeintel_sites_project
    ON archive_codeintel_sites(project, file_id);

CREATE TABLE IF NOT EXISTS archive_codeintel_embeddings (
    node_id     INTEGER PRIMARY KEY,       -- preserved hot codeintel_nodes.id
    project     TEXT NOT NULL DEFAULT '',
    dim         INTEGER NOT NULL DEFAULT 0,
    vec         BLOB NOT NULL,
    archived_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_archive_codeintel_embeddings_project
    ON archive_codeintel_embeddings(project);

-- (node_id, band) is the natural key: the hot table stores one row per node
-- per LSH band. Declaring it PRIMARY KEY here is what makes a re-copy after a
-- crash an idempotent upsert rather than a silent duplication — the hot table
-- has no such constraint, so this is a genuine strengthening, not a mirror.
CREATE TABLE IF NOT EXISTS archive_codeintel_minhash (
    node_id     INTEGER NOT NULL,
    project     TEXT NOT NULL DEFAULT '',
    band        INTEGER NOT NULL,
    hash        INTEGER NOT NULL,
    archived_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (node_id, band)
);
CREATE INDEX IF NOT EXISTS idx_archive_codeintel_minhash_project
    ON archive_codeintel_minhash(project);
