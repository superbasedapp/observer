//go:build !sbo_omit_codeintel

package store

import (
	"context"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
)

// TestCodeIntelProjectImports pins the read the import-level reachability
// tier uses: distinct (file, specifier) pairs of one project and language,
// ordered, capped (Truncated), with the language's file counts.
func TestCodeIntelProjectImports(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	save := func(project, path string, lang codeintel.Language, imports ...string) {
		t.Helper()
		res := codeintel.FileResult{Project: project, Path: path, Lang: lang, Parser: "goast", ContentHash: path}
		for i, imp := range imports {
			res.Imports = append(res.Imports, codeintel.Import{Path: imp, StartLine: i + 1, RawText: `"` + imp + `"`})
		}
		if err := s.CodeIntelSaveFile(ctx, res); err != nil {
			t.Fatalf("save %s: %v", path, err)
		}
	}
	save("/p", "/p/a.go", "go", "fmt", "golang.org/x/net/html", "fmt")
	save("/p", "/p/a_test.go", "go", "testing")
	save("/p", "/p/b.py", "python", "yaml")
	save("/q", "/q/c.go", "go", "os")
	if _, err := database.ExecContext(ctx, `INSERT INTO codeintel_files(project, path, lang, status) VALUES('/p', '/p/pending.go', 'go', 'pending')`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		project string
		lang    string
		limit   int
		want    CodeIntelImports
	}{
		{
			name: "one project and language, distinct and ordered", project: "/p", lang: "go",
			want: CodeIntelImports{Files: 3, Indexed: 2, Sites: []CodeIntelImportSite{
				{File: "/p/a.go", Spec: "fmt"}, {File: "/p/a.go", Spec: "golang.org/x/net/html"}, {File: "/p/a_test.go", Spec: "testing"},
			}},
		},
		{
			name: "capped", project: "/p", lang: "go", limit: 2,
			want: CodeIntelImports{Files: 3, Indexed: 2, Truncated: true, Sites: []CodeIntelImportSite{
				{File: "/p/a.go", Spec: "fmt"}, {File: "/p/a.go", Spec: "golang.org/x/net/html"},
			}},
		},
		{name: "a project the index does not hold", project: "/none", lang: "go", want: CodeIntelImports{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.CodeIntelProjectImports(ctx, tc.project, tc.lang, tc.limit)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestCodeIntelProjectCalls pins the read of the approximate Rust call
// level: CALLS sites of one project and language whose callee name is
// asked for, with their excerpt, distinct, ordered and capped.
func TestCodeIntelProjectCalls(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	save := func(project, path string, lang codeintel.Language, calls ...codeintel.CallSite) {
		t.Helper()
		res := codeintel.FileResult{Project: project, Path: path, Lang: lang, Parser: "treesitter", ContentHash: path}
		res.Calls = calls
		if err := s.CodeIntelSaveFile(ctx, res); err != nil {
			t.Fatalf("save %s: %v", path, err)
		}
	}
	call := func(name, text string, line int) codeintel.CallSite {
		return codeintel.CallSite{Name: name, RawText: text, StartLine: line, Enclosing: -1}
	}
	save("/p", "/p/src/a.rs", "rust", call("insert_many", "v.insert_many(0, it)", 3), call("push", "v.push(1)", 4),
		call("insert_many", "v.insert_many(0, it)", 9))
	save("/p", "/p/src/b.rs", "rust", call("insert_many", "smallvec::SmallVec::insert_many(&mut v, 0, it)", 2))
	save("/p", "/p/x.py", "python", call("insert_many", "x.insert_many()", 1))
	save("/q", "/q/src/c.rs", "rust", call("insert_many", "v.insert_many()", 1))

	cases := []struct {
		name  string
		names []string
		limit int
		want  CodeIntelCalls
	}{
		{name: "the asked names of one project and language", names: []string{"insert_many"}, want: CodeIntelCalls{Sites: []CodeIntelCallSite{
			{File: "/p/src/a.rs", Name: "insert_many", Text: "v.insert_many(0, it)"},
			{File: "/p/src/b.rs", Name: "insert_many", Text: "smallvec::SmallVec::insert_many(&mut v, 0, it)"},
		}}},
		{name: "capped", names: []string{"insert_many", "push"}, limit: 2, want: CodeIntelCalls{Truncated: true, Sites: []CodeIntelCallSite{
			{File: "/p/src/a.rs", Name: "insert_many", Text: "v.insert_many(0, it)"},
			{File: "/p/src/a.rs", Name: "push", Text: "v.push(1)"},
		}}},
		{name: "no names", names: nil, want: CodeIntelCalls{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := s.CodeIntelProjectCalls(ctx, "/p", "rust", tc.names, tc.limit)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
