// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package record

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// TestRecordImportsStayAtTheStoreSeam pins the package's boundary: it is a
// store seam over database/sql and nothing more - no HTTP, no fsnotify, and
// never internal/store (which imports THIS package to compose the wire; the
// reverse import would be a cycle and a second owner of the push seam).
func TestRecordImportsStayAtTheStoreSeam(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"net/http", "github.com/fsnotify/fsnotify", "/internal/store", "/internal/orgclient", "/internal/orgserver", "/internal/proxy"}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if strings.Contains(p, bad) {
					t.Errorf("%s imports %q - the record store seam must stay free of %s", e.Name(), p, bad)
				}
			}
		}
	}
}
