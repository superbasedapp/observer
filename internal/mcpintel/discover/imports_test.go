// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package discover

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md rule
// 1, doc3 §11.12b "ONE package map"): internal/mcpintel/discover is pure
// logic. It must not import database/sql, net/http or fsnotify, nor reach a
// store / the SQL-importing internal/intelligence/discover.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"github.com/fsnotify/fsnotify",
		"github.com/marmutapp/superbased-observer/internal/store",
		"github.com/marmutapp/superbased-observer/internal/intelligence/discover",
		"github.com/marmutapp/superbased-observer/internal/orgserver/controlstore",
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
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if path == bad {
					t.Errorf("%s imports forbidden %q - internal/mcpintel/discover must stay pure", f, bad)
				}
			}
		}
	}
}
