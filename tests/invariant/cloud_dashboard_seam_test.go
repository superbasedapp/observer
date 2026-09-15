package invariant

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FF1 source-ownership invariant: the node-local cloud_* tables have ONE SQL
// owner — internal/store (the cloudlocal.go seam). The dashboard handler package
// (internal/intelligence/dashboard) reads cloud state ONLY through that seam's
// exported methods (st.CloudReceiptCounts, st.ListSendableCloudOutbox, ...); it
// must never grow its own SQL against a cloud_* table.
//
// The store-seam regression (TestCloudDashboardReadSeam) proves the seam methods
// return the right data, but a green seam test does not stop someone from
// reintroducing a direct `SELECT ... FROM cloud_results` in the handler and
// leaving the seam test untouched — that is the silent schema/privacy drift
// vector Sol flagged. This sentinel is the structural floor: a cloud_* table name
// in a dashboard-package SQL string literal fails the build.
//
// Scanning string LITERALS (not raw bytes) via the AST keeps it precise:
// dashboard/cloud.go legitimately documents the tables in COMMENTS ("cloud_*
// tables are NODE-LOCAL"), and the API routes are "/api/cloud/..." (slash, no
// underscore) — neither is a `cloud_`-prefixed string literal, so only real SQL
// against a table name trips it.
func TestDashboardHasNoDirectCloudTableSQL(t *testing.T) {
	dir := filepath.Join("..", "..", "internal", "intelligence", "dashboard")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("dashboard package not found at %s: %v", dir, err)
	}

	// The full closed set of node-local cloud_* table names (agent migration
	// 097). Any of these appearing as a substring of a dashboard string literal
	// is a direct-SQL reintroduction.
	cloudTables := []string{
		"cloud_consent_receipts",
		"cloud_outbox",
		"cloud_results",
		"cloud_result_overrides",
		"cloud_session_map",
		"cloud_project_map",
	}

	var scanned int
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		scanned++
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", path, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			bl, ok := n.(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING {
				return true
			}
			for _, tbl := range cloudTables {
				if strings.Contains(bl.Value, tbl) {
					t.Errorf("dashboard source %s names cloud table %q in a string literal (%s) — "+
						"cloud_* SQL belongs only in internal/store; read through the seam methods instead",
						path, tbl, bl.Value)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk dashboard package: %v", err)
	}
	if scanned == 0 {
		t.Fatal("scanned 0 dashboard source files — the discovery glob broke")
	}
}
