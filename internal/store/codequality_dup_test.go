//go:build !sbo_omit_codeintel

package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codequality"
)

// seedCodeIntelNode inserts one file (once per path) and one node with its
// twelve band buckets: shared bands [0, n) take hash base+band.
func seedCodeIntelNode(t *testing.T, db *sql.DB, project, path, kind, name string, start, end int, base int64, n int) int64 {
	t.Helper()
	ctx := context.Background()
	var fileID int64
	if err := db.QueryRowContext(ctx, `SELECT id FROM codeintel_files WHERE project = ? AND path = ?`, project, path).Scan(&fileID); err != nil {
		res, err := db.ExecContext(ctx,
			`INSERT INTO codeintel_files(project, path, lang, status, indexed_at) VALUES(?, ?, 'go', 'indexed', 1730000000)`, project, path)
		if err != nil {
			t.Fatal(err)
		}
		fileID, _ = res.LastInsertId()
	}
	res, err := db.ExecContext(ctx,
		`INSERT INTO codeintel_nodes(project, file_id, kind, name, start_line, end_line) VALUES(?, ?, ?, ?, ?, ?)`,
		project, fileID, kind, name, start, end)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	for band := 0; band < codequality.TotalBands; band++ {
		h := id*1000 + int64(band)
		if band < n {
			h = base + int64(band)
		}
		if _, err := db.ExecContext(ctx, `INSERT INTO codeintel_minhash(node_id, project, band, hash) VALUES(?, ?, ?, ?)`, id, project, band, h); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func TestLoadCodeQualityDuplication(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	const root = "/repo/dup"
	seedCodeIntelNode(t, db, root, root+"/a.go", "function", "Alpha", 1, 12, 500, 12)
	seedCodeIntelNode(t, db, root, root+"/b.go", "function", "Beta", 3, 14, 500, 12)
	seedCodeIntelNode(t, db, root, root+"/b.go", "function", "tiny", 20, 22, 500, 12) // under the line floor
	seedCodeIntelNode(t, db, root, root+"/c.go", "class", "Gamma", 1, 40, 500, 12)    // not a function
	seedCodeIntelNode(t, db, "/other", "/other/x.go", "function", "Other", 1, 30, 500, 12)

	in, err := s.LoadCodeQualityDuplication(ctx, []string{"", root, root})
	if err != nil {
		t.Fatal(err)
	}
	if in.Index.Key != root || in.Index.IndexedFiles != 3 || in.Index.LastIndexedAt.IsZero() || in.Index.Archived || in.Index.NotInBuild {
		t.Fatalf("index = %+v", in.Index)
	}
	if len(in.Symbols) != 2 || len(in.Buckets) != 2*codequality.TotalBands {
		t.Fatalf("symbols=%d buckets=%d", len(in.Symbols), len(in.Buckets))
	}
	res := codequality.MeasureDuplication(true, true, in)
	if res.State != codequality.StateMeasured || res.ClonedSymbols != 2 || res.Groups != 1 {
		t.Fatalf("duplication = %+v", res)
	}

	none, err := s.LoadCodeQualityDuplication(ctx, []string{"/not/indexed"})
	if err != nil {
		t.Fatal(err)
	}
	if none.Index.IndexedFiles != 0 || none.Index.Archived || len(none.Symbols) != 0 {
		t.Fatalf("unindexed = %+v", none)
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO codeintel_archived_projects(project, archived_at) VALUES('/repo/cold', 1730000000)`); err != nil {
		t.Fatal(err)
	}
	cold, err := s.LoadCodeQualityDuplication(ctx, []string{"/repo/cold"})
	if err != nil {
		t.Fatal(err)
	}
	if !cold.Index.Archived {
		t.Fatalf("archived = %+v", cold.Index)
	}
}
