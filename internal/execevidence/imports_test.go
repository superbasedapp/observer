package execevidence

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports_Bounded pins the envelope pure and in core: the
// standard library and the neutral vocabulary leaf only, so both optional
// modules can use it without importing each other.
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden:  []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		StdlibOnly: true,
		Allowed:    []string{"github.com/marmutapp/superbased-observer/internal/sandboxvocab"},
		Reason:     "the evidence envelope is a pure core leaf",
	})
}
