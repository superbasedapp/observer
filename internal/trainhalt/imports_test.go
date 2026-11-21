package trainhalt

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins internal/trainhalt pure (CLAUDE.md module
// boundaries, rule 1): roll.sh fetches the signals and observer-org train
// judge reads them; this package only decides.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"os/exec",
			"github.com/fsnotify/fsnotify",
		},
		ForbiddenTrees: []string{"github.com/marmutapp/superbased-observer/internal/orgserver"},
		Reason:         "internal/trainhalt must stay pure",
	})
}
