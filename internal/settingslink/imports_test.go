package settingslink

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the package pure: no database, HTTP, file
// system, process or watcher imports.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "os", "os/exec", "github.com/fsnotify/fsnotify"},
		Reason:    "internal/settingslink must stay pure",
	})
}
