package alertspec

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestNoForbiddenImports pins alertspec purity (CLAUDE.md rule 1): the shared
// alert dialect holds no I/O; each evaluator posts to Slack at its own boundary.
func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify", "github.com/marmutapp/superbased-observer/internal/config"},
		Reason:    "internal/alertspec must stay pure",
	})
}
