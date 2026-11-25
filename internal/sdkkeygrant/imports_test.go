package sdkkeygrant

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the package pure: no SQL, no network, no file
// watching, no process exec, no file reads, and neither server tree (the
// cloud signs and the tenant host verifies through this package, never
// through each other).
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
		Reason: "internal/sdkkeygrant is the pure SDK key grant contract",
	})
}
