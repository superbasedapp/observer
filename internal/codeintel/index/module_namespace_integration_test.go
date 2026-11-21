//go:build !sbo_omit_codeintel

package index_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/index"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestModuleScopedResolution_NamespaceDisambiguates pins the namespace row
// of the TS/Python module-import model on REAL parser output: the caller's
// own file AND the imported module both define the same name, and the call
// goes through the namespace import (`relay.forward(x)`). The tree-sitter
// call excerpt must keep the `relay.` qualifier so the scoped pass sees a
// namespace call and binds the imported module's definition at 0.9; with the
// qualifier dropped the call looks bare and same-file locality picks the
// caller's own `forward` (spike XF-0, case T2). The existing `ui.render()`
// test cannot catch this: `render` has a single definition, so name matching
// alone already gets it right.
func TestModuleScopedResolution_NamespaceDisambiguates(t *testing.T) {
	cases := []struct {
		name       string
		files      map[string]string
		calleeFile string // the file whose definition the call must bind
		ownFile    string // the caller's file, which also defines the name
		callee     string
		caller     string
		rawText    string // the persisted call-site excerpt
	}{
		{
			name: "typescript",
			files: map[string]string{
				"relay.ts": "export function forward(x: number): number { return x + 1 }\n",
				"routes.ts": `import * as relay from './relay'

export function forward(x: number): number { return x * 2 }

export function handle(x: number): number {
	return relay.forward(x)
}
`,
			},
			calleeFile: "relay.ts", ownFile: "routes.ts",
			callee: "forward", caller: "handle", rawText: "relay.forward(x)",
		},
		{
			name: "python",
			files: map[string]string{
				"db_util.py": "def run(q):\n    return q\n",
				"main.py": `import db_util


def run(q):
    return None


def handle(q):
    return db_util.run(q)
`,
			},
			calleeFile: "db_util.py", ownFile: "main.py",
			callee: "run", caller: "handle", rawText: "db_util.run(q)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
			if err != nil {
				t.Fatalf("db.Open: %v", err)
			}
			defer database.Close()
			st := store.New(database)

			root := t.TempDir()
			for name, body := range tc.files {
				mustWrite(t, filepath.Join(root, name), body)
			}
			ix := index.New(index.Options{Store: st, Registry: index.DefaultRegistry()})
			if _, err := ix.IndexProject(ctx, root, true); err != nil {
				t.Fatalf("IndexProject: %v", err)
			}
			eng := codeintel.NewEngine(st)

			imported := symID(t, ctx, eng, filepath.Join(root, tc.calleeFile), tc.callee)
			own := symID(t, ctx, eng, filepath.Join(root, tc.ownFile), tc.callee)

			if !hasCaller(t, ctx, eng, imported, tc.caller) {
				t.Errorf("%s %s: %s not bound as caller (namespace binding did not fire)", tc.calleeFile, tc.callee, tc.caller)
			}
			if hasCaller(t, ctx, eng, own, tc.caller) {
				t.Errorf("%s %s: %s wrongly bound as caller (namespace call fell back to same-file locality)", tc.ownFile, tc.callee, tc.caller)
			}

			// The site keeps the qualifier in raw_text, target_name stays the
			// bare name, and the edge carries the namespace row's 0.9.
			var raw, target string
			var conf float64
			err = database.QueryRowContext(ctx, `
				SELECT s.raw_text, s.target_name, e.confidence
				  FROM codeintel_sites s JOIN codeintel_edges e ON e.id = s.edge_id
				 WHERE e.kind = 'CALLS' AND e.dst_id = ?`, imported).Scan(&raw, &target, &conf)
			if errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("no CALLS edge into %s %s", tc.calleeFile, tc.callee)
			} else if err != nil {
				t.Fatalf("query site: %v", err)
			}
			if raw != tc.rawText {
				t.Errorf("raw_text = %q, want %q (qualifier must survive)", raw, tc.rawText)
			}
			if target != tc.callee {
				t.Errorf("target_name = %q, want bare %q", target, tc.callee)
			}
			if conf != 0.9 {
				t.Errorf("confidence = %v, want 0.9 (namespace row)", conf)
			}
		})
	}
}
