package secfinding

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPureImports pins the package pure (CLAUDE.md module rule 1): no
// database, HTTP, fsnotify, exec or file system access.
func TestPureImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"os", "os/exec", "io/ioutil", "path/filepath", "net", "net/http", "database/sql", "github.com/fsnotify/fsnotify"},
		Reason:    "security pillar plan section 4.2: a pure package",
	})
}

// TestContractCompiles is the compile-only check of the finding model.
func TestContractCompiles(t *testing.T) {
	t.Parallel()
	f := Finding{Category: "secret", Severity: "high", Confidence: "high", Scope: "pre_write", Baseline: "new", Status: "open"}
	if f.Location.RelPath != "" || f.Commit.Landed {
		t.Fatal("a zero finding has no location and no commit")
	}
}
