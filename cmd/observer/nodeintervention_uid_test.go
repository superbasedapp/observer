package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNodeInterventionAuthorityUIDIsAValidInput: the uid every caller passes
// to the node intervention authority is one it accepts on every OS. On
// Windows os.Getuid() is -1, which refused every managed-budget launch there
// (Windows 11 Pro live run, PT-02).
func TestNodeInterventionAuthorityUIDIsAValidInput(t *testing.T) {
	if uid := nodeInterventionAuthorityUID(); uid < 0 {
		t.Fatalf("nodeInterventionAuthorityUID() = %d: the node intervention authority refuses a negative uid", uid)
	}
}

// TestNodeInterventionAuthorityCallersUseTheUIDHelper (R-160): no caller of
// nodeInterventionAuthority passes os.Getuid() directly (the posture report
// and the control line did, so both read "unverifiable" on Windows). A
// caller holding a scanned process's uid passes that uid instead.
func TestNodeInterventionAuthorityCallersUseTheUIDHelper(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	helper := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "nodeInterventionAuthority(") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "nodeInterventionAuthority" || len(call.Args) < 3 {
				return true
			}
			uid, ok := call.Args[2].(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := uid.Fun.(type) {
			case *ast.Ident:
				if fn.Name == "nodeInterventionAuthorityUID" {
					helper++
				}
			case *ast.SelectorExpr:
				if x, ok := fn.X.(*ast.Ident); ok && x.Name == "os" && fn.Sel.Name == "Getuid" {
					t.Errorf("%s: nodeInterventionAuthority is passed os.Getuid(), which is -1 on Windows; use nodeInterventionAuthorityUID()", f)
				}
			}
			return true
		})
	}
	if helper < 3 {
		t.Fatalf("%d nodeInterventionAuthority calls pass nodeInterventionAuthorityUID(), want the launch, posture and control-line callers", helper)
	}
}
