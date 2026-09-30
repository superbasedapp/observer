// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package cost

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md rule
// 1, doc3 §11.12b "ONE package map"): internal/mcpintel/cost is pure logic.
// It must not reach a database, the network, the filesystem watcher, a store
// or the MCP gateway packages that call it (the callers import cost, never
// the reverse).
func TestNoForbiddenImports(t *testing.T) {
	const module = "github.com/marmutapp/superbased-observer/"
	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
		module + "internal/store",
		module + "internal/db",
		module + "internal/orgserver",
		module + "internal/mcpgw",
		module + "internal/intelligence/discover",
	}
	fset := token.NewFileSet()
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, f := range matches {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, imp := range af.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if p == bad || strings.HasPrefix(p, bad+"/") {
					t.Errorf("%s imports forbidden %q - internal/mcpintel/cost must stay pure", f, p)
				}
			}
		}
	}
}
