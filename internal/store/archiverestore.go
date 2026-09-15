package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/archive"
)

// This file is the REHYDRATE half of the hot-side archival seam (P2 of
// docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §9). Its
// sibling archive.go moves a project OUT; this one brings it back.
//
// The two halves are deliberately symmetric. Archiving reads the hot tables
// through an exporter, writes the cold copy, re-reads the cold copy, and
// verifies before deleting. Rehydrating reads the cold copy through the SAME
// streaming reader, writes the hot tables, re-reads the hot tables through the
// SAME exporter, and verifies before clearing the marker. Both directions run
// through archive.Verify — there is exactly one verification primitive in this
// arc, and neither direction gets a weaker one.

// codeIntelImportSink writes archived rows BACK into the hot codeintel_*
// tables, preserving the row ids they carried when they were archived.
//
// Preserving ids is not a nicety. codeintel_nodes references codeintel_files
// by id; codeintel_edges/sites reference both; codeintel_embeddings and
// codeintel_minhash are keyed by node id. A restore that let SQLite re-issue
// ids would produce a hot index whose every symbol resolves and whose every
// EDGE POINTS AT THE WRONG SYMBOL — a corruption that answers queries
// confidently and wrongly, which is worse than answering nothing.
//
// Each batch is one transaction. A crash therefore leaves a partial hot copy
// with the marker still set, and the next rehydrate pre-clears and replays —
// the same re-runnability contract the outbound mover has.
type codeIntelImportSink struct {
	s       *Store
	project string
}

var _ archive.ProjectSink = (*codeIntelImportSink)(nil)

// CodeIntelImportSink returns the [archive.ProjectSink] that replays an
// archived project into the hot tables.
//
// Callers MUST clear the project's hot rows first (see
// [Store.CodeIntelDeleteProject]). codeintel_minhash has no unique constraint
// in the hot schema — unlike its archive-side mirror, which declares
// (node_id, band) PRIMARY KEY precisely so the cold copy is upsert-safe — so
// replaying onto a non-empty hot project would silently DUPLICATE minhash
// bands rather than overwrite them, and the near-clone detector would then
// see the same symbol twice in every band it occupies.
func (s *Store) CodeIntelImportSink(project string) archive.ProjectSink {
	return &codeIntelImportSink{s: s, project: project}
}

func (k *codeIntelImportSink) WriteFiles(ctx context.Context, rows []archive.FileRow) error {
	return k.batch(ctx, "files", len(rows),
		`INSERT OR REPLACE INTO codeintel_files
		   (id, project, path, lang, content_hash, mtime, indexed_at, parser, status)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		func(stmt *sql.Stmt) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.ID, r.Project, r.Path, r.Lang,
					r.ContentHash, r.Mtime, r.IndexedAt, r.Parser, r.Status); err != nil {
					return err
				}
			}
			return nil
		})
}

func (k *codeIntelImportSink) WriteNodes(ctx context.Context, rows []archive.NodeRow) error {
	return k.batch(ctx, "nodes", len(rows),
		`INSERT OR REPLACE INTO codeintel_nodes
		   (id, project, file_id, kind, name, fqn, lang, start_line, end_line,
		    start_byte, end_byte, signature, sig_hash)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		func(stmt *sql.Stmt) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.ID, r.Project, r.FileID, r.Kind, r.Name,
					r.FQN, r.Lang, r.StartLine, r.EndLine, r.StartByte, r.EndByte,
					r.Signature, r.SigHash); err != nil {
					return err
				}
			}
			return nil
		})
}

func (k *codeIntelImportSink) WriteEdges(ctx context.Context, rows []archive.EdgeRow) error {
	return k.batch(ctx, "edges", len(rows),
		`INSERT OR REPLACE INTO codeintel_edges
		   (id, project, file_id, src_id, dst_id, kind, confidence, resolver_backend)
		 VALUES (?,?,?,?,?,?,?,?)`,
		func(stmt *sql.Stmt) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.ID, r.Project, r.FileID, r.SrcID,
					r.DstID, r.Kind, r.Confidence, r.ResolverBackend); err != nil {
					return err
				}
			}
			return nil
		})
}

func (k *codeIntelImportSink) WriteSites(ctx context.Context, rows []archive.SiteRow) error {
	return k.batch(ctx, "sites", len(rows),
		`INSERT OR REPLACE INTO codeintel_sites
		   (id, project, edge_id, file_id, start_line, start_byte, raw_text,
		    target_name, resolver_backend, confidence, recv_type)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		func(stmt *sql.Stmt) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.ID, r.Project, r.EdgeID, r.FileID,
					r.StartLine, r.StartByte, r.RawText, r.TargetName, r.ResolverBackend,
					r.Confidence, r.RecvType); err != nil {
					return err
				}
			}
			return nil
		})
}

func (k *codeIntelImportSink) WriteEmbeddings(ctx context.Context, rows []archive.EmbeddingRow) error {
	return k.batch(ctx, "embeddings", len(rows),
		`INSERT OR REPLACE INTO codeintel_embeddings (node_id, project, dim, vec)
		 VALUES (?,?,?,?)`,
		func(stmt *sql.Stmt) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.NodeID, r.Project, r.Dim, r.Vec); err != nil {
					return err
				}
			}
			return nil
		})
}

func (k *codeIntelImportSink) WriteMinhash(ctx context.Context, rows []archive.MinhashRow) error {
	return k.batch(ctx, "minhash", len(rows),
		`INSERT INTO codeintel_minhash (node_id, project, band, hash) VALUES (?,?,?,?)`,
		func(stmt *sql.Stmt) error {
			for _, r := range rows {
				if _, err := stmt.ExecContext(ctx, r.NodeID, r.Project, r.Band, r.Hash); err != nil {
					return err
				}
			}
			return nil
		})
}

// batch runs one prepared statement over one batch inside one transaction.
func (k *codeIntelImportSink) batch(ctx context.Context, table string, n int, query string, exec func(*sql.Stmt) error) error {
	if n == 0 {
		return nil
	}
	tx, err := k.s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.CodeIntelImportSink(%s): begin: %w", table, err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("store.CodeIntelImportSink(%s): prepare: %w", table, err)
	}
	defer func() { _ = stmt.Close() }()
	if err := exec(stmt); err != nil {
		return fmt.Errorf("store.CodeIntelImportSink(%s): exec: %w", table, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.CodeIntelImportSink(%s): commit: %w", table, err)
	}
	return nil
}
