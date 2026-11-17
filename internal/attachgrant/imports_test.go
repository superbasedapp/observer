package attachgrant

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the package pure: no SQL, no network, no file
// watching, no process exec, and neither server tree (the cloud mints and the
// org server verifies through this package, never through each other).
func TestNoForbiddenImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net", "net/http", "os", "os/exec", "github.com/fsnotify/fsnotify",
		},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/cloudserver",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
		},
		Reason: "internal/attachgrant is the pure attach grant contract",
	})
}
