package secposture

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestHookPathImports pins the package to what the hook path may load
// (section 4.3, SECP-3): the standard library, internal/fsatomic,
// internal/guardposture (itself stdlib plus fsatomic), the pure
// internal/policy and the pure decision table internal/secposture/gatetable;
// no database, HTTP, fsnotify or exec.
func TestHookPathImports(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"github.com/marmutapp/superbased-observer/internal/fsatomic":     true,
		"github.com/marmutapp/superbased-observer/internal/guardposture": true,
		"github.com/marmutapp/superbased-observer/internal/policy":       true,
		// The decision table's own pure package (lane SEC-P4): policy only.
		"github.com/marmutapp/superbased-observer/internal/secposture/gatetable": true,
	}
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"os/exec", "net", "net/http", "database/sql", "github.com/fsnotify/fsnotify"},
		Custom: func(_, p string) string {
			if strings.HasPrefix(p, "github.com/marmutapp/superbased-observer/") && !allowed[p] {
				return "the sidecar reader is stdlib-only plus fsatomic, guardposture, policy and its pure gatetable"
			}
			return ""
		},
		Reason: "security pillar plan section 4.3: read on the hook path",
	})
}

// TestFileContractCompiles is the compile-only check of the file shape.
func TestFileContractCompiles(t *testing.T) {
	t.Parallel()
	f := File{Schema: SchemaVersion, Counts: []Count{{N: 1}}}
	if f.Schema != 1 || MaxFileBytes != 16<<10 || MaxBlocking != 256 {
		t.Fatal("the posture file contract changed")
	}
}
