package update

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoForbiddenImports pins the module-boundary discipline (CLAUDE.md
// §1): internal/update is pure data + logic. It must not import
// database/sql, net/http, net, os/exec or fsnotify.
//
// The internal/announce rationale applies verbatim and then some. There,
// an http import would be the first symptom of re-inventing the
// rejected phone-home rail. Here the stakes are higher on both axes:
//
//   - net/http or net: ruling R8 says the org server the node is
//     already enrolled with is the ONLY host a node contacts for an
//     update. A transport import in the package that DECIDES what to
//     download would be the first symptom of a node reaching GitHub, a
//     CDN or npm — which would also falsify the "no network calls in
//     the observer/watcher" claim in CLAUDE.md and the egress
//     disclosure in `observer privacy`.
//   - os/exec: this package decides whether to swap a binary. Executing
//     one from here would put process control inside the decision
//     layer, where it could not be tested without running it. The
//     --version probe, the fork-exec handshake and any dpkg/rpm
//     ownership query live in cmd/observer and reach this package
//     through injected seams (PathProbe).
//   - database/sql: update_state and update_events are owned by
//     internal/store (W3), one writer, one seam.
func TestNoForbiddenImports(t *testing.T) {
	forbidden := []string{
		"database/sql",
		"net/http",
		"net",
		"os/exec",
		"github.com/fsnotify/fsnotify",
	}
	fset := token.NewFileSet()
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no Go files found — the pin would pass vacuously")
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
					t.Errorf("%s imports forbidden %q — internal/update must stay pure (no transport, no storage, no process control)", f, bad)
				}
			}
		}
	}
}
