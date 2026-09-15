package telemetrylog

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoNonStdlibImports pins the module-boundary discipline (CLAUDE.md §1 /
// plan §4.1): internal/telemetrylog is the PURE contract. Its non-test files
// must import nothing but the Go standard library — no database/sql, no
// net/http, no fsnotify, and crucially no broker client (nats.go). The adapters
// (memlog, natslog) and the conformance suite (logtest) hold every dependency;
// this package holds only types, interfaces, errors and pure helpers.
func TestNoNonStdlibImports(t *testing.T) {
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
			if isNonStdlib(path) {
				t.Errorf("%s imports non-stdlib %q — internal/telemetrylog must stay pure", f, path)
			}
		}
	}
}

// isNonStdlib reports whether an import path is outside the standard library.
// The standard library is identified structurally: its first path segment
// contains no dot (stdlib packages are "context", "crypto/sha256", ...; every
// third-party path begins with a dotted host like "github.com/...").
func isNonStdlib(path string) bool {
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	return strings.Contains(first, ".")
}
