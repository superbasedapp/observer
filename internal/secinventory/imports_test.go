package secinventory

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the package free of process execution, SQL,
// HTTP and file watching; it reads the project tree through os only.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"os/exec",
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
		},
		Reason: "keep internal/secinventory free of exec, SQL, HTTP and watchers",
	})
}
