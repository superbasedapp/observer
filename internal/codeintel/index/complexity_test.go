//go:build !sbo_omit_codeintel

package index_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codeintel/index"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse/goast"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestIndexProject_ComplexityVersion pins the extraction-version rule: a
// pass without complexity stores no figure; turning counting on re-parses
// the unchanged file once and stores its figure; turning it off again
// re-parses nothing (the requirement is monotone).
func TestIndexProject_ComplexityVersion(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	st := store.New(database)
	reg := parse.NewRegistry()
	reg.Register(goast.New())

	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.go"), "package a\n\nfunc Run(x int) int {\n\tif x > 0 && x < 9 {\n\t\treturn 1\n\t}\n\treturn 0\n}\n")
	figure := func() sql.NullInt64 {
		t.Helper()
		var c sql.NullInt64
		if err := database.QueryRowContext(ctx, `SELECT complexity FROM codeintel_nodes WHERE name = 'Run'`).Scan(&c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	pass := func(count bool) index.Report {
		t.Helper()
		rep, err := index.New(index.Options{Store: st, Registry: reg, CountComplexity: count}).IndexProject(ctx, root, true)
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}

	steps := []struct {
		name        string
		count       bool
		wantIndexed int
		wantFigure  int64 // 0 = NULL
	}{
		{"first pass without counting", false, 1, 0},
		{"unchanged, still without", false, 0, 0},
		{"counting on re-parses once", true, 1, 3},
		{"unchanged with counting", true, 0, 3},
		{"counting off re-parses nothing", false, 0, 3},
	}
	for _, s := range steps {
		rep := pass(s.count)
		if rep.Indexed != s.wantIndexed {
			t.Fatalf("%s: indexed %d, want %d (%+v)", s.name, rep.Indexed, s.wantIndexed, rep)
		}
		c := figure()
		if (s.wantFigure == 0) == c.Valid || (c.Valid && c.Int64 != s.wantFigure) {
			t.Fatalf("%s: figure %+v, want %d", s.name, c, s.wantFigure)
		}
	}
}
