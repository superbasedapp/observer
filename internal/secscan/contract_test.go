package secscan

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

// TestContractCompiles is the compile-only check of the driver contract.
func TestContractCompiles(t *testing.T) {
	t.Parallel()
	var _ Driver = nil
	if len(Kinds()) != 5 {
		t.Fatalf("Kinds() = %v, want the five kinds of section 4.4", Kinds())
	}
	_ = Result{Coverage: Coverage{Outcome: OutcomeNotScanned}}
}
