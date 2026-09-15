package store

import (
	"context"
	"testing"
)

// TestCodeIntelHasDerived pins the cheap probe the index-on-start change
// gate leans on: it must tell "derived rows built" from "nodes exist but
// nothing was derived" (a build that never ran / was interrupted), and it
// must report satisfied for a project with nothing to derive.
func TestCodeIntelHasDerived(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()

	seedNode := func(project string) int64 {
		t.Helper()
		rf, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_files(project, path, lang, status) VALUES(?, ?, 'go', 'indexed')`,
			project, project+"/a.go")
		if err != nil {
			t.Fatalf("seed file: %v", err)
		}
		fid, _ := rf.LastInsertId()
		rn, err := database.ExecContext(ctx,
			`INSERT INTO codeintel_nodes(project, file_id, kind, name, fqn, lang, signature)
			 VALUES(?, ?, 'function', 'Foo', 'pkg.Foo', 'go', 'func Foo()')`,
			project, fid)
		if err != nil {
			t.Fatalf("seed node: %v", err)
		}
		nid, _ := rn.LastInsertId()
		return nid
	}

	cases := []struct {
		name    string
		project string
		setup   func(project string)
		want    bool
	}{
		{
			name:    "unknown project has nothing to derive",
			project: "/p/empty",
			setup:   func(string) {},
			want:    true,
		},
		{
			name:    "nodes present but never derived",
			project: "/p/interrupted",
			setup:   func(p string) { seedNode(p) },
			want:    false,
		},
		{
			name:    "nodes present and derived",
			project: "/p/built",
			setup: func(p string) {
				seedNode(p)
				if err := s.CodeIntelBuildDerived(ctx, p); err != nil {
					t.Fatalf("CodeIntelBuildDerived: %v", err)
				}
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup(tc.project)
			got, err := s.CodeIntelHasDerived(ctx, tc.project)
			if err != nil {
				t.Fatalf("CodeIntelHasDerived: %v", err)
			}
			if got != tc.want {
				t.Errorf("CodeIntelHasDerived(%q) = %v, want %v", tc.project, got, tc.want)
			}
		})
	}

	// Cross-project isolation: a built project must not make an
	// unbuilt sibling look derived.
	if got, _ := s.CodeIntelHasDerived(ctx, "/p/interrupted"); got {
		t.Error("a sibling project's derived rows satisfied the probe")
	}
}
