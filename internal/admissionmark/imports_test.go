package admissionmark

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPurity pins the package pure (no SQL, HTTP, fsnotify or exec) and
// outside the obs reverse-import boundary: both the node obs store and the
// org rollup import it, so it may import neither.
func TestPurity(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"os/exec",
			"github.com/marmutapp/superbased-observer/internal/obs",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
		},
		Reason: "admissionmark is pure and shared by the node obs store and the org rollup",
	})
}
