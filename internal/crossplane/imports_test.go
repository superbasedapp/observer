package crossplane

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports keeps the cross-plane core pure (CLAUDE.md module
// boundary rule 1): no SQL, HTTP, file watching or exec, and none of the
// stores or the machine's obs tree it is called from.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify", "os/exec"},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/obs",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/orgserver",
		},
		Reason: "internal/crossplane is the pure link rule, series and regression window; the org rollup and the machine's route load the rows",
	})
}
