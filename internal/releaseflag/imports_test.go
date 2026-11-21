package releaseflag

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins the package pure: no SQL, HTTP, fsnotify or os.
func TestNoForbiddenImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{
			"database/sql",
			"net/http",
			"github.com/fsnotify/fsnotify",
			"os",
		},
		Reason: "internal/releaseflag is pure; the clock and changed set are injected",
	})
}
