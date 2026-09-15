package cloudcontract

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the purity discipline as an EXACT CLOSED ALLOWLIST
// (plan §6 CI-P1 / Sol SB7 / FF6, CLAUDE.md §1): internal/cloudcontract may
// import ONLY the named stdlib packages it actually uses, plus exactly
// golang.org/x/text/unicode/norm (a pure NFC library; Go's stdlib has no Unicode
// normalization) and internal/dataauthority (itself pure). Any import outside
// this closed set — a third-party HTTP/filesystem/telemetry package, a new
// internal package, or an unlisted stdlib package — fails the gate. This encodes
// the x/text exception the earlier "forbidden-list-only" pin left implicit, and
// makes process/filesystem/network dependencies structurally impossible.
func TestNoForbiddenImports(t *testing.T) {
	// The closed allowlist. Adding an import here is a deliberate, reviewable act
	// (the whole point of an exact pin): a new stdlib dependency must be named,
	// and no third-party/internal dependency may be added without an explicit
	// architecture decision.
	allowed := map[string]bool{
		// stdlib actually used by the production files.
		"bytes":         true,
		"crypto/sha256": true,
		"encoding/hex":  true,
		"encoding/json": true,
		"fmt":           true,
		"html":          true,
		"net/url":       true,
		"strings":       true,
		"time":          true,
		"unicode/utf8":  true,
		// The two non-stdlib exceptions, both pure and non-I/O.
		"golang.org/x/text/unicode/norm":                                  true,
		"github.com/marmutapp/superbased-observer/internal/dataauthority": true,
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
			if !allowed[path] {
				t.Errorf("%s imports %q — not in the cloudcontract closed allowlist (stdlib named set + x/text/unicode/norm + internal/dataauthority only). Adding a dependency here requires an explicit architecture decision.", f, path)
			}
		}
	}
}
