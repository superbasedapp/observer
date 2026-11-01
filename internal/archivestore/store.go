package archivestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/archive"
	"github.com/marmutapp/superbased-observer/internal/archivestore/migrations"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/migplan"
	"github.com/marmutapp/superbased-observer/internal/migplan/sqliteledger"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"

	_ "modernc.org/sqlite" // pure-Go sqlite driver registration (no CGO).
)

// hardHeapLimitBytes is the conservative process-global PRAGMA
// hard_heap_limit applied alongside temp_store=MEMORY on the DSN. It matches
// internal/db's and internal/edge/wal's 1 GiB so every SQLite file this binary
// opens carries the same backstop: a runaway archive operation fails fast
// instead of exhausting host RAM.
const hardHeapLimitBytes = int64(1) << 30 // 1 GiB

// maxOpenConns bounds the archive pool. The archive is touched by one
// background retention pass and (from P2 on) by scoped rehydrate reads, so it
// needs far fewer connections than the hot DB — and every extra connection is
// another candidate temp-file holder, the P0-B failure mode.
const maxOpenConns = 4

// Options configures Open.
type Options struct {
	// Path is the archive database file. ":memory:" is for tests only.
	Path string
	// BusyTimeout is the SQLite busy_timeout pragma; defaults to 30s.
	BusyTimeout time.Duration
	// Now is the injectable clock used to stamp archived_at; defaults to
	// time.Now().UTC(). Tests pin it so stamped rows are deterministic.
	Now func() time.Time
}

// Store is the cold-storage seam. It implements [archive.ProjectSink], so the
// hot-side exporter can stream a project straight into it without either side
// knowing the other's schema.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

var _ archive.ProjectSink = (*Store)(nil)

// Open opens (or creates) archive.db, pins the durability and memory pragmas
// on the DSN so EVERY pooled connection carries them (a post-open PRAGMA
// reaches only the one connection database/sql happens to hand ExecContext —
// the P0-B root cause), applies this package's own migration lineage, and
// returns a Store safe for concurrent use.
//
// It deliberately does NOT run a PRAGMA quick_check: that reads and checksums
// every page, so its cost scales with the archive rather than with the work
// the caller came to do — the same reason internal/db.Open made the probe
// opt-in.
func Open(ctx context.Context, opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, errors.New("archivestore.Open: Path is required")
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	busy := opts.BusyTimeout
	if busy <= 0 {
		busy = 30 * time.Second
	}

	dsn := opts.Path
	if opts.Path != ":memory:" {
		dsn = fmt.Sprintf(
			"file:%s?_pragma=busy_timeout(%d)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)&_pragma=hard_heap_limit(%d)&_txlock=immediate",
			sqlitedsn.Escape(opts.Path), busy.Milliseconds(), hardHeapLimitBytes,
		)
	}

	database, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("archivestore.Open: sql.Open: %w", err)
	}
	database.SetMaxOpenConns(maxOpenConns)
	database.SetConnMaxIdleTime(5 * time.Minute)
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("archivestore.Open: ping: %w", err)
	}
	if opts.Path != ":memory:" {
		if _, err := database.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
			_ = database.Close()
			return nil, fmt.Errorf("archivestore.Open: journal_mode: %w", err)
		}
		// SR27-A4: archive.db holds archived captured content; keep it (and
		// its WAL sidecars) owner-only. Best-effort, like the hot DB.
		_ = db.RestrictFileMode(opts.Path)
	}
	if err := runMigrations(ctx, database); err != nil {
		_ = database.Close()
		return nil, err
	}
	return &Store{db: database, now: nowFn}, nil
}

// Close checkpoints the WAL sidecar into the main file and closes the pool, so
// a reopen (or a backup of the file alone) sees a self-contained database.
func (s *Store) Close() error {
	var checkpointErr error
	if _, err := s.db.ExecContext(context.Background(), "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		checkpointErr = fmt.Errorf("archivestore.Close: wal_checkpoint: %w", err)
	}
	var closeErr error
	if err := s.db.Close(); err != nil {
		closeErr = fmt.Errorf("archivestore.Close: %w", err)
	}
	return errors.Join(checkpointErr, closeErr)
}

// DB exposes the underlying handle for diagnostics only. Callers must not run
// schema or write statements through it — every write goes through the typed
// seam above so this package stays the one owner of the archive_* tables.
func (s *Store) DB() *sql.DB { return s.db }

// --- write side: archive.ProjectSink ---------------------------------

// All writers use INSERT OR REPLACE keyed on the preserved hot row id. That is
// what makes the copy half of copy-then-delete idempotent: a process that
// crashes mid-copy and re-runs re-writes the same rows onto themselves rather
// than duplicating them or failing on a conflict.

// WriteFiles upserts a batch of archived codeintel_files rows.
func (s *Store) WriteFiles(ctx context.Context, rows []archive.FileRow) error {
	return s.batch(ctx, "WriteFiles", len(rows),
		`INSERT OR REPLACE INTO archive_codeintel_files
		   (id, project, path, lang, content_hash, mtime, indexed_at, parser, status, archived_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		func(stmt *sql.Stmt, at int64) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.ID, r.Project, r.Path, r.Lang,
					r.ContentHash, r.Mtime, r.IndexedAt, r.Parser, r.Status, at); err != nil {
					return err
				}
			}
			return nil
		})
}

// WriteNodes upserts a batch of archived codeintel_nodes rows.
func (s *Store) WriteNodes(ctx context.Context, rows []archive.NodeRow) error {
	return s.batch(ctx, "WriteNodes", len(rows),
		`INSERT OR REPLACE INTO archive_codeintel_nodes
		   (id, project, file_id, kind, name, fqn, lang, start_line, end_line,
		    start_byte, end_byte, signature, sig_hash, archived_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		func(stmt *sql.Stmt, at int64) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.ID, r.Project, r.FileID, r.Kind, r.Name,
					r.FQN, r.Lang, r.StartLine, r.EndLine, r.StartByte, r.EndByte,
					r.Signature, r.SigHash, at); err != nil {
					return err
				}
			}
			return nil
		})
}

// WriteEdges upserts a batch of archived codeintel_edges rows.
func (s *Store) WriteEdges(ctx context.Context, rows []archive.EdgeRow) error {
	return s.batch(ctx, "WriteEdges", len(rows),
		`INSERT OR REPLACE INTO archive_codeintel_edges
		   (id, project, file_id, src_id, dst_id, kind, confidence, resolver_backend, archived_at)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		func(stmt *sql.Stmt, at int64) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.ID, r.Project, r.FileID, r.SrcID, r.DstID,
					r.Kind, r.Confidence, r.ResolverBackend, at); err != nil {
					return err
				}
			}
			return nil
		})
}

// WriteSites upserts a batch of archived codeintel_sites rows.
func (s *Store) WriteSites(ctx context.Context, rows []archive.SiteRow) error {
	return s.batch(ctx, "WriteSites", len(rows),
		`INSERT OR REPLACE INTO archive_codeintel_sites
		   (id, project, edge_id, file_id, start_line, start_byte, raw_text,
		    target_name, resolver_backend, confidence, recv_type, archived_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
		func(stmt *sql.Stmt, at int64) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.ID, r.Project, r.EdgeID, r.FileID,
					r.StartLine, r.StartByte, r.RawText, r.TargetName, r.ResolverBackend,
					r.Confidence, r.RecvType, at); err != nil {
					return err
				}
			}
			return nil
		})
}

// WriteEmbeddings upserts a batch of archived codeintel_embeddings rows.
func (s *Store) WriteEmbeddings(ctx context.Context, rows []archive.EmbeddingRow) error {
	return s.batch(ctx, "WriteEmbeddings", len(rows),
		`INSERT OR REPLACE INTO archive_codeintel_embeddings
		   (node_id, project, dim, vec, archived_at)
		 VALUES (?,?,?,?,?)`,
		func(stmt *sql.Stmt, at int64) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.NodeID, r.Project, r.Dim, r.Vec, at); err != nil {
					return err
				}
			}
			return nil
		})
}

// WriteMinhash upserts a batch of archived codeintel_minhash rows.
func (s *Store) WriteMinhash(ctx context.Context, rows []archive.MinhashRow) error {
	return s.batch(ctx, "WriteMinhash", len(rows),
		`INSERT OR REPLACE INTO archive_codeintel_minhash
		   (node_id, project, band, hash, archived_at)
		 VALUES (?,?,?,?,?)`,
		func(stmt *sql.Stmt, at int64) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.NodeID, r.Project, r.Band, r.Hash, at); err != nil {
					return err
				}
			}
			return nil
		})
}

// batch runs one prepared statement over a batch inside a single transaction.
func (s *Store) batch(ctx context.Context, method string, n int, query string, exec func(*sql.Stmt, int64) error) error {
	if n == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("archivestore.%s: begin: %w", method, err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("archivestore.%s: prepare: %w", method, err)
	}
	defer func() { _ = stmt.Close() }()
	if err := exec(stmt, s.now().Unix()); err != nil {
		return fmt.Errorf("archivestore.%s: exec: %w", method, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("archivestore.%s: commit: %w", method, err)
	}
	return nil
}

// --- delete side -----------------------------------------------------

// codeIntelTables is the archive-side fan-out for one project, child-to-parent.
// Table-driven so adding a table is one row rather than another statement in a
// hand-maintained sequence (CLAUDE.md §5).
var codeIntelTables = []string{
	"archive_codeintel_minhash",
	"archive_codeintel_embeddings",
	"archive_codeintel_sites",
	"archive_codeintel_edges",
	"archive_codeintel_nodes",
	"archive_codeintel_files",
}

// DeleteCodeIntelProject removes every archived row for a project, in one
// transaction. It serves two callers with the same shape:
//
//   - the mover's PRE-CLEAR, which drops any partial copy left by a crashed
//     earlier attempt before re-copying. This is not a "delete-first"
//     violation: the hot rows are still intact at that moment, and clearing
//     first is what makes the subsequent verification exact — an upsert alone
//     would leave orphaned rows behind if the hot project shrank between the
//     crashed attempt and the retry, and the read-back digest would then
//     legitimately disagree with the hot digest forever.
//   - (from P3 on) the cold-storage expiry sweep.
func (s *Store) DeleteCodeIntelProject(ctx context.Context, project string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("archivestore.DeleteCodeIntelProject: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, table := range codeIntelTables {
		//nolint:gosec // table comes from the package-local codeIntelTables list, never from input.
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE project = ?`, project); err != nil {
			return fmt.Errorf("archivestore.DeleteCodeIntelProject: %s: %w", table, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("archivestore.DeleteCodeIntelProject: commit: %w", err)
	}
	return nil
}

// --- read side -------------------------------------------------------

// StreamCodeIntelProject reads every archived row for a project back OUT of
// the archive file and pushes it through sink in parent-first order.
//
// This is the read half of verification: the mover streams the cold copy
// through a digest sink and compares it against the hot digest. Digesting what
// the writer believed it wrote would verify the writer's memory rather than
// the durable copy, so this genuinely re-reads.
//
// It is also the rehydrate read path P2 will use unchanged — replay is the
// same stream pointed at a different sink.
func (s *Store) StreamCodeIntelProject(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	if batchRows <= 0 {
		batchRows = archive.DefaultBatchRows
	}
	if err := s.streamFiles(ctx, project, batchRows, sink); err != nil {
		return err
	}
	if err := s.streamNodes(ctx, project, batchRows, sink); err != nil {
		return err
	}
	if err := s.streamEdges(ctx, project, batchRows, sink); err != nil {
		return err
	}
	if err := s.streamSites(ctx, project, batchRows, sink); err != nil {
		return err
	}
	if err := s.streamEmbeddings(ctx, project, batchRows, sink); err != nil {
		return err
	}
	return s.streamMinhash(ctx, project, batchRows, sink)
}

// CodeIntelProjectDigest is the archive-side digest of one project: the
// fingerprint [archive.Verify] compares against the hot side before any hot
// row is deleted.
func (s *Store) CodeIntelProjectDigest(ctx context.Context, project string, batchRows int) (archive.ProjectDigest, error) {
	sink := archive.NewDigestSink()
	if err := s.StreamCodeIntelProject(ctx, project, batchRows, sink); err != nil {
		return archive.ProjectDigest{}, err
	}
	return sink.Digest(), nil
}

// CodeIntelProjectParsers reports the DISTINCT parser backends that produced
// the archived rows for a project.
//
// It is the cheap pre-check the rehydrate path runs BEFORE it touches the hot
// database: a codeintel row encodes the parser that produced it
// (memory:feedback_db_rows_encode_parser_version), so a cold copy written by a
// backend the current build no longer produces is stale in a way no amount of
// faithful copying fixes — replaying it would restore a graph that disagrees
// with what a fresh index of the same repo yields. The caller supplies the
// acceptance predicate; this package only reports the facts.
//
// One indexed scan over the (small) archive file's file rows — never the node
// rows, and never the hot database.
func (s *Store) CodeIntelProjectParsers(ctx context.Context, project string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT parser FROM archive_codeintel_files WHERE project = ? ORDER BY parser`, project)
	if err != nil {
		return nil, fmt.Errorf("archivestore.CodeIntelProjectParsers: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("archivestore.CodeIntelProjectParsers: scan: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archivestore.CodeIntelProjectParsers: %w", err)
	}
	return out, nil
}

func (s *Store) streamFiles(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project, path, lang, content_hash, mtime, indexed_at, parser, status
		   FROM archive_codeintel_files WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: files: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.FileRow, 0, batchRows)
	for rows.Next() {
		var r archive.FileRow
		if err := rows.Scan(&r.ID, &r.Project, &r.Path, &r.Lang, &r.ContentHash,
			&r.Mtime, &r.IndexedAt, &r.Parser, &r.Status); err != nil {
			return fmt.Errorf("archivestore.StreamCodeIntelProject: files scan: %w", err)
		}
		buf = append(buf, r)
		if len(buf) >= batchRows {
			if err := sink.WriteFiles(ctx, buf); err != nil {
				return err
			}
			buf = buf[:0]
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: files rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteFiles(ctx, buf)
	}
	return nil
}

func (s *Store) streamNodes(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project, file_id, kind, name, fqn, lang, start_line, end_line,
		        start_byte, end_byte, signature, sig_hash
		   FROM archive_codeintel_nodes WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.NodeRow, 0, batchRows)
	for rows.Next() {
		var r archive.NodeRow
		if err := rows.Scan(&r.ID, &r.Project, &r.FileID, &r.Kind, &r.Name, &r.FQN, &r.Lang,
			&r.StartLine, &r.EndLine, &r.StartByte, &r.EndByte, &r.Signature, &r.SigHash); err != nil {
			return fmt.Errorf("archivestore.StreamCodeIntelProject: nodes scan: %w", err)
		}
		buf = append(buf, r)
		if len(buf) >= batchRows {
			if err := sink.WriteNodes(ctx, buf); err != nil {
				return err
			}
			buf = buf[:0]
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: nodes rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteNodes(ctx, buf)
	}
	return nil
}

func (s *Store) streamEdges(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project, file_id, src_id, dst_id, kind, confidence, resolver_backend
		   FROM archive_codeintel_edges WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: edges: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.EdgeRow, 0, batchRows)
	for rows.Next() {
		var r archive.EdgeRow
		if err := rows.Scan(&r.ID, &r.Project, &r.FileID, &r.SrcID, &r.DstID,
			&r.Kind, &r.Confidence, &r.ResolverBackend); err != nil {
			return fmt.Errorf("archivestore.StreamCodeIntelProject: edges scan: %w", err)
		}
		buf = append(buf, r)
		if len(buf) >= batchRows {
			if err := sink.WriteEdges(ctx, buf); err != nil {
				return err
			}
			buf = buf[:0]
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: edges rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteEdges(ctx, buf)
	}
	return nil
}

func (s *Store) streamSites(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project, edge_id, file_id, start_line, start_byte, raw_text,
		        target_name, resolver_backend, confidence, recv_type
		   FROM archive_codeintel_sites WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: sites: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.SiteRow, 0, batchRows)
	for rows.Next() {
		var r archive.SiteRow
		if err := rows.Scan(&r.ID, &r.Project, &r.EdgeID, &r.FileID, &r.StartLine, &r.StartByte,
			&r.RawText, &r.TargetName, &r.ResolverBackend, &r.Confidence, &r.RecvType); err != nil {
			return fmt.Errorf("archivestore.StreamCodeIntelProject: sites scan: %w", err)
		}
		buf = append(buf, r)
		if len(buf) >= batchRows {
			if err := sink.WriteSites(ctx, buf); err != nil {
				return err
			}
			buf = buf[:0]
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: sites rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteSites(ctx, buf)
	}
	return nil
}

func (s *Store) streamEmbeddings(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT node_id, project, dim, vec
		   FROM archive_codeintel_embeddings WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: embeddings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.EmbeddingRow, 0, batchRows)
	for rows.Next() {
		var r archive.EmbeddingRow
		if err := rows.Scan(&r.NodeID, &r.Project, &r.Dim, &r.Vec); err != nil {
			return fmt.Errorf("archivestore.StreamCodeIntelProject: embeddings scan: %w", err)
		}
		buf = append(buf, r)
		if len(buf) >= batchRows {
			if err := sink.WriteEmbeddings(ctx, buf); err != nil {
				return err
			}
			buf = buf[:0]
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: embeddings rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteEmbeddings(ctx, buf)
	}
	return nil
}

func (s *Store) streamMinhash(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT node_id, project, band, hash
		   FROM archive_codeintel_minhash WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: minhash: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.MinhashRow, 0, batchRows)
	for rows.Next() {
		var r archive.MinhashRow
		if err := rows.Scan(&r.NodeID, &r.Project, &r.Band, &r.Hash); err != nil {
			return fmt.Errorf("archivestore.StreamCodeIntelProject: minhash scan: %w", err)
		}
		buf = append(buf, r)
		if len(buf) >= batchRows {
			if err := sink.WriteMinhash(ctx, buf); err != nil {
				return err
			}
			buf = buf[:0]
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("archivestore.StreamCodeIntelProject: minhash rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteMinhash(ctx, buf)
	}
	return nil
}

// --- migrations ------------------------------------------------------

// runMigrations applies this package's lineage inside one BEGIN IMMEDIATE
// transaction on a pinned connection — the same concurrency contract as the
// agent, org-server and edge-WAL runners, over this package's OWN embed.FS and
// schema_meta.
func runMigrations(ctx context.Context, db *sql.DB) error {
	return runMigrationsFrom(ctx, db, migrations.Files, lateSteps)
}

// lateSteps is the closed table of this lineage's migrations known to have
// landed on a parallel line under a number below a step another line already
// shipped in a build (migplan.LateStep). It is EMPTY: no step of this lineage
// interleaves today.
//
// A database that has a ledger never needs a row: its missing step simply has
// no per-step record and runs. Add a row only when a PRE-LEDGER database (one
// last migrated by a binary older than T-979) may already hold a version
// record above the step without having run it. Name a column the step adds,
// so the probe adopts the step where it really ran and runs it where it did
// not, and add a test that stages such a database. See
// docs/migration-numbering.md.
var lateSteps = []migplan.LateStep{}

// runMigrationsFrom is the runner over an explicit lineage and late-step
// table, so tests can drive it with synthetic lineages.
//
// "Pending" is per step (internal/migplan, T-979): every embedded step
// without a migration:<n> record in schema_meta runs in ascending order,
// including one numbered below the highest applied version, so a step that
// landed late from a parallel line is never skipped. The 'version' record
// still holds the highest applied step. A database written before the ledger
// existed has its steps up to 'version' adopted (recorded without running),
// the old behaviour, unless lateSteps lists one. The whole pass, steps and
// bookkeeping, is one transaction: a failing step rolls everything back.
func runMigrationsFrom(ctx context.Context, db *sql.DB, source fs.FS, late []migplan.LateStep) error {
	entries, err := readMigrationEntries(source)
	if err != nil {
		return err
	}
	embedded := make([]int, 0, len(entries))
	byVersion := make(map[int]migrationEntry, len(entries))
	for _, e := range entries {
		embedded = append(embedded, e.version)
		byVersion[e.version] = e
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_meta (
		key TEXT PRIMARY KEY, value TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("archivestore.runMigrations: bootstrap schema_meta: %w", err)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("archivestore.runMigrations: acquire connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("archivestore.runMigrations: acquire migration lock: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()

	plan, err := sqliteledger.Plan(ctx, conn, embedded, late)
	if err != nil {
		return fmt.Errorf("archivestore.runMigrations: %w", err)
	}
	if err := sqliteledger.Apply(ctx, conn, plan, func(version int) error {
		e := byVersion[version]
		body, readErr := fs.ReadFile(source, e.filename)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", e.filename, readErr)
		}
		if _, err := conn.ExecContext(ctx, string(body)); err != nil {
			return fmt.Errorf("exec %s: %w", e.filename, err)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("archivestore.runMigrations: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("archivestore.runMigrations: commit: %w", err)
	}
	committed = true
	return nil
}

type migrationEntry struct {
	version  int
	filename string
}

// readMigrationEntries lists source's NNN_name.sql files, ascending.
func readMigrationEntries(source fs.FS) ([]migrationEntry, error) {
	dirEntries, err := fs.ReadDir(source, ".")
	if err != nil {
		return nil, fmt.Errorf("archivestore.readMigrationEntries: %w", err)
	}
	var entries []migrationEntry
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		name := de.Name()
		if filepath.Ext(name) != ".sql" {
			continue
		}
		prefix := strings.SplitN(name, "_", 2)[0]
		v, err := strconv.Atoi(prefix)
		if err != nil {
			return nil, fmt.Errorf("archivestore.readMigrationEntries: unparseable migration %q: %w", name, err)
		}
		entries = append(entries, migrationEntry{version: v, filename: name})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].version < entries[j].version })
	return entries, nil
}
