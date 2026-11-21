package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins internal/policy PURE (CLAUDE.md Module
// Boundaries, guard spec section 17.1): no I/O, ZERO observer packages, and
// no path/filepath, so the same Event yields the same Verdict on every OS.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"os",
			"os/exec",
			"io",
			"io/ioutil",
			"path/filepath",
			"net/http",
			"database/sql",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		// The one allowed Observer import is the stdlib-only IP classifier, so
		// host classification (metadata, private ranges) has one owner shared
		// with internal/netpolicy's dial policy and can never fork.
		Except: []string{"github.com/marmutapp/superbased-observer/internal/ipclass"},
		Reason: "module boundary section 17.1",
	})
}

// TestNoToolIdentityBranching enforces guard spec §17.3: no logic in
// this package may branch on tool/client identity. Event.Tool exists
// for reporting only; client differences resolve into Capabilities
// and Dialect at the boundary. The scan rejects equality comparisons
// and switches on anything named *tool/*Tool in non-test source.
func TestNoToolIdentityBranching(t *testing.T) {
	t.Parallel()

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`\b[Tt]ool\s*[!=]=`),
		regexp.MustCompile(`switch\s+[\w.]*\.?Tool\b`),
	}
	for _, path := range nonTestSourceFiles(t) {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, re := range patterns {
			if loc := re.Find(src); loc != nil {
				t.Errorf("%s: tool-identity branching %q (spec §17.3 — resolve differences into Capabilities at the boundary)",
					filepath.Base(path), string(loc))
			}
		}
	}
}

// nonTestSourceFiles lists the package's non-test .go files.
func nonTestSourceFiles(t *testing.T) []string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(cwd, "*.go"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	var out []string
	for _, m := range matches {
		if !strings.HasSuffix(m, "_test.go") {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		t.Fatal("no non-test source files found")
	}
	return out
}
