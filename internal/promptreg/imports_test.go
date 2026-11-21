package promptreg

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the registry core pure (CLAUDE.md "Module
// Boundaries" rule 1): no SQL, HTTP or file watching, and never internal/obs,
// so the org store and the machine's obs store can both import it without
// crossing the obs boundary. It imports nothing from this repository.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden:         []string{"database/sql", "net/http", "net", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		ForbiddenTrees:    []string{"github.com/marmutapp/superbased-observer/internal/obs"},
		ForbiddenPrefixes: []string{"github.com/marmutapp/superbased-observer/"},
		Reason:            "internal/promptreg is the pure prompt registry core",
	})
}
