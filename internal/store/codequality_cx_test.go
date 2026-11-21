//go:build !sbo_omit_codeintel

package store

import (
	"context"
	"database/sql"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codequality"
)

// seedCxFile inserts one indexed file and returns its id.
func seedCxFile(t *testing.T, db *sql.DB, project, path, lang, parser string, version int) int64 {
	t.Helper()
	res, err := db.ExecContext(context.Background(),
		`INSERT INTO codeintel_files(project, path, lang, parser, status, indexed_at, extract_version)
		 VALUES(?, ?, ?, ?, 'indexed', 1730000000, ?)`, project, path, lang, parser, version)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

// seedCxNode inserts one node; complexity 0 is stored as NULL.
func seedCxNode(t *testing.T, db *sql.DB, project string, fileID int64, kind, name, lang string, start, cx int) {
	t.Helper()
	var c any
	if cx > 0 {
		c = cx
	}
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO codeintel_nodes(project, file_id, kind, name, lang, start_line, end_line, complexity) VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		project, fileID, kind, name, lang, start, start+10, c); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCodeQualityComplexity(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	const root = "/repo/cx"
	v := codeintel.ExtractVersion
	a := seedCxFile(t, db, root, root+"/a.go", "go", "goast", v)
	b := seedCxFile(t, db, root, root+"/b.py", "python", "treesitter:python", v)
	seedCxFile(t, db, root, root+"/c.py", "python", "treesitter:python", 0) // indexed before counting
	h := seedCxFile(t, db, root, root+"/d.go", "go", "heuristic", v)        // heuristic span: no counter
	seedCxFile(t, db, root, root+"/e.xyz", "xyz", "treesitter:xyz", v)      // no rule table
	seedCxNode(t, db, root, a, "function", "Small", "go", 1, 2)
	seedCxNode(t, db, root, a, "method", "Big", "go", 20, 14)
	seedCxNode(t, db, root, a, "class", "T", "go", 40, 0)
	seedCxNode(t, db, root, b, "function", "py", "python", 1, 5)
	seedCxNode(t, db, root, h, "function", "Heur", "go", 1, 0)
	other := seedCxFile(t, db, "/other", "/other/x.go", "go", "goast", v)
	seedCxNode(t, db, "/other", other, "function", "Elsewhere", "go", 1, 50)

	in, err := s.LoadCodeQualityComplexity(ctx, []string{"", root})
	if err != nil {
		t.Fatal(err)
	}
	if in.Index.Key != root || in.Index.IndexedFiles != 5 {
		t.Fatalf("index = %+v", in.Index)
	}
	if len(in.Values) != 3 {
		t.Fatalf("values = %+v", in.Values)
	}
	if len(in.Top) != 3 || in.Top[0].Name != "Big" || in.Top[0].File != root+"/a.go" || in.Top[0].Complexity != 14 || in.Top[0].Kind != "method" {
		t.Fatalf("top = %+v", in.Top)
	}
	res := codequality.MeasureComplexity(true, true, in)
	if res.State != codequality.StateMeasured || res.Functions != 3 || res.Over != 1 || res.Max != 14 {
		t.Fatalf("complexity = %+v", res)
	}
	if res.CountedFiles != 2 || res.PendingFiles != 1 || res.UncountedFiles != 2 {
		t.Fatalf("files counted %d pending %d uncounted %d (%v)", res.CountedFiles, res.PendingFiles, res.UncountedFiles, res.UncountedLangs)
	}

	none, err := s.LoadCodeQualityComplexity(ctx, []string{"/not/indexed"})
	if err != nil {
		t.Fatal(err)
	}
	if none.Index.IndexedFiles != 0 || len(none.Values) != 0 || len(none.Files) != 0 {
		t.Fatalf("unindexed = %+v", none)
	}
}

// TestCodeIntelSaveFileComplexityAndVersion pins the codeintel write side
// of migration 215: a counted node stores its figure, an uncounted one
// NULL (never 0), and the file row carries the extraction version the
// indexer's freshness check reads back.
func TestCodeIntelSaveFileComplexityAndVersion(t *testing.T) {
	t.Parallel()
	s, db := newTestStore(t)
	ctx := context.Background()
	const root = "/repo/save"
	if err := s.CodeIntelSaveFile(ctx, codeintel.FileResult{
		Project: root, Path: root + "/a.go", Lang: "go", Parser: "goast", ContentHash: "h",
		Nodes: []codeintel.Node{
			{Kind: "function", Name: "F", StartLine: 1, EndLine: 9, StartByte: 0, EndByte: 90, Complexity: 4},
			{Kind: "class", Name: "T", StartLine: 10, EndLine: 12, StartByte: 91, EndByte: 120},
		},
		ExtractVersion: codeintel.ExtractVersion,
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := db.QueryContext(ctx, `SELECT name, complexity FROM codeintel_nodes WHERE project = ? ORDER BY start_line`, root)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]sql.NullInt64{}
	for rows.Next() {
		var name string
		var c sql.NullInt64
		if err := rows.Scan(&name, &c); err != nil {
			t.Fatal(err)
		}
		got[name] = c
	}
	if c := got["F"]; !c.Valid || c.Int64 != 4 {
		t.Errorf("F complexity %+v, want 4", c)
	}
	if c := got["T"]; c.Valid {
		t.Errorf("T complexity %+v, want NULL", c)
	}
	st, ok, err := s.CodeIntelFileState(ctx, root, root+"/a.go")
	if err != nil || !ok || st.ExtractVersion != codeintel.ExtractVersion {
		t.Fatalf("file state %+v %v %v", st, ok, err)
	}
}
