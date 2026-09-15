package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// This file is the HOT-side seam of the corpus archival arc
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md). It owns
// three things:
//
//   - reading a project's codeintel_* rows OUT of the hot database in bounded
//     batches, as plain internal/archive row values;
//   - the codeintel_archived_projects marker table (migration 092);
//   - the ONE transaction that deletes an archived project's hot rows and
//     writes its marker.
//
// The archive file itself is owned by internal/archivestore and is never
// opened from here — internal/archivesvc composes the two. That separation is
// what keeps the archive off hot query plans (design §3.1) and keeps
// orgpush.go's single-database assumption true.

// ErrArchiveProjectChanged aborts an archive move because the project was
// re-indexed between the copy and the hot delete. It wraps
// [archive.ErrProjectChanged] so the composer in internal/archivesvc can
// recognise the outcome without importing this package.
//
// This is the race the watermark guard exists to close. The mover reads the
// hot rows, copies them, verifies them, and only then deletes — but an index
// pass running concurrently could have written NEW rows in that window, and
// those rows were never copied. Deleting them would be silent data loss on a
// bucket the operator believes is fully recoverable. The delete therefore
// re-checks the shape it was selected on, inside its own transaction, and
// refuses if it moved. The project simply stays hot and is re-offered next
// pass.
var ErrArchiveProjectChanged = fmt.Errorf("store: %w", archive.ErrProjectChanged)

// CodeIntelStaleProjects returns the projects whose most recent index pass is
// older than retentionDays, with the watermark that made each eligible.
//
// This is the SAME indexed, O(distinct projects) staleness query
// CodeIntelPruneStaleProjects has always used — factored out so the delete
// sweep and the archive sweep share one definition of "stale" rather than
// drifting apart. Its conservatism is preserved verbatim:
//
//   - retentionDays ≤ 0 disables the sweep entirely (returns nil, nil).
//   - MAX(indexed_at) = 0 means "never successfully indexed", not "indexed
//     long ago", and is never eligible.
//   - An actively indexed project carries a fresh watermark and is untouched.
func (s *Store) CodeIntelStaleProjects(ctx context.Context, retentionDays int) ([]archive.Candidate, error) {
	if retentionDays <= 0 {
		return nil, nil
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()
	rows, err := s.db.QueryContext(ctx,
		`SELECT project, MAX(indexed_at) FROM codeintel_files
		 GROUP BY project
		 HAVING MAX(indexed_at) > 0 AND MAX(indexed_at) < ?
		 ORDER BY project`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("store.CodeIntelStaleProjects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []archive.Candidate
	for rows.Next() {
		var c archive.Candidate
		if err := rows.Scan(&c.Project, &c.Watermark); err != nil {
			return nil, fmt.Errorf("store.CodeIntelStaleProjects: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.CodeIntelStaleProjects: %w", err)
	}
	return out, nil
}

// CodeIntelProjectShape reports the (watermark, file count) pair the archive
// move guards on. Exposed so the mover can capture the shape immediately
// before it starts copying, rather than trusting a candidate list that may be
// several projects old by the time this one's turn arrives.
func (s *Store) CodeIntelProjectShape(ctx context.Context, project string) (watermark, files int64, err error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(indexed_at), 0), COUNT(*) FROM codeintel_files WHERE project = ?`, project)
	if err := row.Scan(&watermark, &files); err != nil {
		return 0, 0, fmt.Errorf("store.CodeIntelProjectShape: %w", err)
	}
	return watermark, files, nil
}

// CodeIntelExportProject streams every codeintel_* row for a project into
// sink, in bounded batches, parent-first (files, nodes, edges, sites,
// embeddings, minhash).
//
// codeintel_fts is deliberately NOT exported: it is a derived FTS index over
// codeintel_nodes, rebuilt per project by CodeIntelBuildDerived, so archiving
// it would double the cold bytes of the largest bucket to store something a
// rehydrate regenerates (design §3.1).
//
// The batching is what keeps this bounded by the PROJECT rather than by the
// corpus — no step of an archive move ever materializes more than batchRows
// rows at a time, however large the project.
func (s *Store) CodeIntelExportProject(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	if batchRows <= 0 {
		batchRows = archive.DefaultBatchRows
	}
	if err := s.exportFiles(ctx, project, batchRows, sink); err != nil {
		return err
	}
	if err := s.exportNodes(ctx, project, batchRows, sink); err != nil {
		return err
	}
	if err := s.exportEdges(ctx, project, batchRows, sink); err != nil {
		return err
	}
	if err := s.exportSites(ctx, project, batchRows, sink); err != nil {
		return err
	}
	if err := s.exportEmbeddings(ctx, project, batchRows, sink); err != nil {
		return err
	}
	return s.exportMinhash(ctx, project, batchRows, sink)
}

// CodeIntelProjectDigest is the hot-side fingerprint of a project, computed by
// streaming the SAME exporter the copy uses through a digest sink.
//
// Reusing the exporter is deliberate: a digest computed by a second, parallel
// set of aggregate queries would verify those queries, not the rows the copy
// actually read. Callers that are about to copy should prefer
// [archive.NewTeeSink] and get the hot digest from the copy pass itself —
// this method exists for callers that only want the fingerprint.
func (s *Store) CodeIntelProjectDigest(ctx context.Context, project string, batchRows int) (archive.ProjectDigest, error) {
	sink := archive.NewDigestSink()
	if err := s.CodeIntelExportProject(ctx, project, batchRows, sink); err != nil {
		return archive.ProjectDigest{}, err
	}
	return sink.Digest(), nil
}

// CodeIntelArchiveComplete finishes one archive move: it re-checks the
// project's shape, deletes its hot codeintel_* rows, and writes the
// codeintel_archived_projects marker — ALL IN ONE TRANSACTION.
//
// The single transaction is the crash-safety property. The states a crash can
// leave behind are:
//
//   - copied, not deleted → the next pass re-copies (idempotent upsert) and
//     deletes. No loss.
//   - deleted AND marked → done; the project is no longer stale-eligible.
//
// There is deliberately no third state where the rows are gone but the marker
// is missing, which would make an archived project indistinguishable from a
// never-indexed one — the exact dishonesty the marker exists to prevent.
//
// It must be called ONLY after the cold copy has been read back and verified
// ([archive.Verify]). It does not verify anything itself; it is the last,
// irreversible step and assumes its caller earned the right to take it.
func (s *Store) CodeIntelArchiveComplete(ctx context.Context, c archive.Completion) error {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("store.CodeIntelArchiveComplete: conn: %w", err)
	}
	defer func() { _ = conn.Close() }()
	// Same foreign_keys pinning as CodeIntelDeleteProject — without it the
	// (redundant) cascade re-scans and the delete goes O(files × rows).
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		return fmt.Errorf("store.CodeIntelArchiveComplete: disable fk: %w", err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), `PRAGMA foreign_keys=ON`) }()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.CodeIntelArchiveComplete: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var watermark, files int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(indexed_at), 0), COUNT(*) FROM codeintel_files WHERE project = ?`,
		c.Project).Scan(&watermark, &files); err != nil {
		return fmt.Errorf("store.CodeIntelArchiveComplete: re-check shape: %w", err)
	}
	if watermark != c.ExpectedWatermark || files != c.ExpectedFiles {
		return fmt.Errorf("%w: %s (watermark %d->%d, files %d->%d)",
			ErrArchiveProjectChanged, c.Project,
			c.ExpectedWatermark, watermark, c.ExpectedFiles, files)
	}

	if err := codeIntelDeleteProjectTx(ctx, tx, c.Project); err != nil {
		return fmt.Errorf("store.CodeIntelArchiveComplete: delete: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO codeintel_archived_projects
		   (project, archived_at, last_indexed_at, rows_archived)
		 VALUES (?,?,?,?)
		 ON CONFLICT(project) DO UPDATE SET
		   archived_at     = excluded.archived_at,
		   last_indexed_at = excluded.last_indexed_at,
		   rows_archived   = excluded.rows_archived`,
		c.Project, c.ArchivedAt, c.ExpectedWatermark, c.RowsArchived); err != nil {
		return fmt.Errorf("store.CodeIntelArchiveComplete: marker: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.CodeIntelArchiveComplete: commit: %w", err)
	}
	return nil
}

// CodeIntelArchivedProject reports the marker row for a project, if it has
// one. A single indexed primary-key lookup — the common-path check that never
// opens the archive file.
func (s *Store) CodeIntelArchivedProject(ctx context.Context, project string) (archive.Marker, bool, error) {
	var a archive.Marker
	err := s.db.QueryRowContext(ctx,
		`SELECT project, archived_at, last_indexed_at, rows_archived
		   FROM codeintel_archived_projects WHERE project = ?`, project).
		Scan(&a.Project, &a.ArchivedAt, &a.LastIndexedAt, &a.RowsArchived)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return archive.Marker{}, false, nil
	case err != nil:
		return archive.Marker{}, false, fmt.Errorf("store.CodeIntelArchivedProject: %w", err)
	}
	return a, true, nil
}

// CodeIntelArchivedProjects lists every archived project, most recently
// archived first.
//
// This is the AGGREGATE surface (design §4.4), deliberately distinct from the
// per-project marker lookup the query paths use: no scoped read may enumerate
// "all archived things". It is answered entirely from the hot marker table —
// one row per archived project — so it never joins across the two databases and
// never opens the archive file.
func (s *Store) CodeIntelArchivedProjects(ctx context.Context, limit int) ([]archive.Marker, error) {
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT project, archived_at, last_indexed_at, rows_archived
		   FROM codeintel_archived_projects ORDER BY archived_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("store.CodeIntelArchivedProjects: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []archive.Marker
	for rows.Next() {
		var m archive.Marker
		if err := rows.Scan(&m.Project, &m.ArchivedAt, &m.LastIndexedAt, &m.RowsArchived); err != nil {
			return nil, fmt.Errorf("store.CodeIntelArchivedProjects: scan: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.CodeIntelArchivedProjects: %w", err)
	}
	return out, nil
}

// ArchivedSummary is the AGGREGATE answer to "what is in cold storage" — the
// P5.1 storage surface (design §4.4).
//
// It is a separate seam from the marker LISTERS above, not a fold over them,
// and the difference matters: those cap their result (500 projects, 100 day
// windows) because they exist to render a table, so summing what they return
// would silently under-report a large archive. An aggregate surface that
// quietly stops counting is worse than no surface. These are indexed
// COUNT/SUM queries over the small marker tables, so they cost the same
// whatever the archive holds.
type ArchivedSummary struct {
	CodeIntelProjects int64
	CodeIntelRows     int64
	ProcessWindows    int64
	ProcessRows       int64
}

// ArchivedSummary reports the aggregate cold-storage totals from the HOT-side
// marker tables alone. It never opens the archive file and never joins across
// the two databases (design §4.4).
func (s *Store) ArchivedSummary(ctx context.Context) (ArchivedSummary, error) {
	var out ArchivedSummary
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(SUM(rows_archived), 0) FROM codeintel_archived_projects`,
	).Scan(&out.CodeIntelProjects, &out.CodeIntelRows); err != nil {
		return out, fmt.Errorf("store.ArchivedSummary: codeintel: %w", err)
	}
	if err := s.db.QueryRowContext(
		ctx,
		`SELECT COUNT(*), COALESCE(SUM(runs + events + bodies), 0) FROM process_archived_windows`,
	).Scan(&out.ProcessWindows, &out.ProcessRows); err != nil {
		return out, fmt.Errorf("store.ArchivedSummary: process: %w", err)
	}
	return out, nil
}

// CodeIntelClearArchivedProject removes a project's marker. Called on a
// successful rehydrate (P2) so an archived-then-restored project stops
// claiming it is archived; also the escape hatch if an operator re-indexes an
// archived project by hand.
func (s *Store) CodeIntelClearArchivedProject(ctx context.Context, project string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM codeintel_archived_projects WHERE project = ?`, project); err != nil {
		return fmt.Errorf("store.CodeIntelClearArchivedProject: %w", err)
	}
	return nil
}

// --- per-table exporters ---------------------------------------------

func (s *Store) exportFiles(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project, path, lang, content_hash, mtime, indexed_at, parser, status
		   FROM codeintel_files WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("store.CodeIntelExportProject: files: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.FileRow, 0, batchRows)
	for rows.Next() {
		var r archive.FileRow
		if err := rows.Scan(&r.ID, &r.Project, &r.Path, &r.Lang, &r.ContentHash,
			&r.Mtime, &r.IndexedAt, &r.Parser, &r.Status); err != nil {
			return fmt.Errorf("store.CodeIntelExportProject: files scan: %w", err)
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
		return fmt.Errorf("store.CodeIntelExportProject: files rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteFiles(ctx, buf)
	}
	return nil
}

func (s *Store) exportNodes(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project, file_id, kind, name, fqn, lang, start_line, end_line,
		        start_byte, end_byte, signature, sig_hash
		   FROM codeintel_nodes WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("store.CodeIntelExportProject: nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.NodeRow, 0, batchRows)
	for rows.Next() {
		var r archive.NodeRow
		if err := rows.Scan(&r.ID, &r.Project, &r.FileID, &r.Kind, &r.Name, &r.FQN, &r.Lang,
			&r.StartLine, &r.EndLine, &r.StartByte, &r.EndByte, &r.Signature, &r.SigHash); err != nil {
			return fmt.Errorf("store.CodeIntelExportProject: nodes scan: %w", err)
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
		return fmt.Errorf("store.CodeIntelExportProject: nodes rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteNodes(ctx, buf)
	}
	return nil
}

func (s *Store) exportEdges(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project, file_id, src_id, dst_id, kind, confidence, resolver_backend
		   FROM codeintel_edges WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("store.CodeIntelExportProject: edges: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.EdgeRow, 0, batchRows)
	for rows.Next() {
		var r archive.EdgeRow
		if err := rows.Scan(&r.ID, &r.Project, &r.FileID, &r.SrcID, &r.DstID,
			&r.Kind, &r.Confidence, &r.ResolverBackend); err != nil {
			return fmt.Errorf("store.CodeIntelExportProject: edges scan: %w", err)
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
		return fmt.Errorf("store.CodeIntelExportProject: edges rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteEdges(ctx, buf)
	}
	return nil
}

func (s *Store) exportSites(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, project, edge_id, file_id, start_line, start_byte, raw_text,
		        target_name, resolver_backend, confidence, recv_type
		   FROM codeintel_sites WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("store.CodeIntelExportProject: sites: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.SiteRow, 0, batchRows)
	for rows.Next() {
		var r archive.SiteRow
		if err := rows.Scan(&r.ID, &r.Project, &r.EdgeID, &r.FileID, &r.StartLine, &r.StartByte,
			&r.RawText, &r.TargetName, &r.ResolverBackend, &r.Confidence, &r.RecvType); err != nil {
			return fmt.Errorf("store.CodeIntelExportProject: sites scan: %w", err)
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
		return fmt.Errorf("store.CodeIntelExportProject: sites rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteSites(ctx, buf)
	}
	return nil
}

func (s *Store) exportEmbeddings(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT node_id, project, dim, vec
		   FROM codeintel_embeddings WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("store.CodeIntelExportProject: embeddings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.EmbeddingRow, 0, batchRows)
	for rows.Next() {
		var r archive.EmbeddingRow
		if err := rows.Scan(&r.NodeID, &r.Project, &r.Dim, &r.Vec); err != nil {
			return fmt.Errorf("store.CodeIntelExportProject: embeddings scan: %w", err)
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
		return fmt.Errorf("store.CodeIntelExportProject: embeddings rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteEmbeddings(ctx, buf)
	}
	return nil
}

func (s *Store) exportMinhash(ctx context.Context, project string, batchRows int, sink archive.ProjectSink) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT node_id, project, band, hash
		   FROM codeintel_minhash WHERE project = ?`, project)
	if err != nil {
		return fmt.Errorf("store.CodeIntelExportProject: minhash: %w", err)
	}
	defer func() { _ = rows.Close() }()
	buf := make([]archive.MinhashRow, 0, batchRows)
	for rows.Next() {
		var r archive.MinhashRow
		if err := rows.Scan(&r.NodeID, &r.Project, &r.Band, &r.Hash); err != nil {
			return fmt.Errorf("store.CodeIntelExportProject: minhash scan: %w", err)
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
		return fmt.Errorf("store.CodeIntelExportProject: minhash rows: %w", err)
	}
	if len(buf) > 0 {
		return sink.WriteMinhash(ctx, buf)
	}
	return nil
}
