package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// reportsCostTools is the grounded set of tools whose adapter stores the
// tool's own stated cost in token_usage.estimated_cost_usd (TokenTier.
// ReportsCost). Each was read at its stamping site on 2026-09-29: command-code
// ("provider-reported costUsd" - Command Code bills its own gateway), opencode
// and kilo-code-cli (per-message msg.cost), cline-cli (per-message
// metrics.cost), hermes (actual billed cost, else Hermes' own estimate), pi and
// prime-agent (usage.cost.total), crush and goose (the store's cumulative
// session cost), aider (the "Cost: $x message" chat-history clause), junie
// (modelUsage cost), mistral-code (meta.json session_cost), freebuff (desktop
// metrics costUsd). docs/new-adapter-checklist.md files these as
// "provider-reported cost" rows.
var reportsCostTools = []string{
	"aider", "cline-cli", "command-code", "crush", "freebuff", "goose", "hermes",
	"junie", "kilo-code-cli", "mistral-code", "opencode", "pi", "prime-agent",
}

// reportsCostPackages is the set of internal/adapter packages whose
// non-test source assigns EstimatedCostUSD. It must move together with
// reportsCostTools: a new adapter that starts storing a cost fails here until
// its registry row is flagged (or deliberately not).
var reportsCostPackages = []string{
	"aider", "clinecli", "commandcode", "crush", "freebuff", "goose", "hermes",
	"junie", "kilocode", "mistralcode", "opencode", "pi", "primeagent",
}

func TestReportsCostSetIsPinned(t *testing.T) {
	var got []string
	for _, c := range Capabilities() {
		if c.TokenTier.ReportsCost {
			got = append(got, c.Tool)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(reportsCostTools, ",") {
		t.Fatalf("TokenTier.ReportsCost rows = %v, want %v (ground the new row at its adapter's stamping site, then update reportsCostTools)", got, reportsCostTools)
	}
}

// TestReportsCostPackagesPinned scans every adapter package for a non-test
// assignment to an EstimatedCostUSD field (a composite-literal key or an
// assignment target). The zero value of ReportsCost claims "this adapter never
// stores a cost of its own"; this scan is what keeps that claim true.
func TestReportsCostPackagesPinned(t *testing.T) {
	root := filepath.Join("..", "adapter")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}
	var got []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if packageAssignsCost(t, filepath.Join(root, e.Name())) {
			got = append(got, e.Name())
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(reportsCostPackages, ",") {
		t.Fatalf("adapter packages assigning EstimatedCostUSD = %v, want %v (flag the tool's TokenTier.ReportsCost, then update both pinned sets)", got, reportsCostPackages)
	}
}

func packageAssignsCost(t *testing.T, dir string) bool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		found := false
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.KeyValueExpr:
				if id, ok := x.Key.(*ast.Ident); ok && id.Name == "EstimatedCostUSD" {
					found = true
				}
			case *ast.AssignStmt:
				for _, lhs := range x.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "EstimatedCostUSD" {
						found = true
					}
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}
