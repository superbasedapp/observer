package costseries

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestPackageImports pins costseries to the cost engine seam: no HTTP, no
// filesystem watching, no subprocess. database/sql is allowed only so the
// *sql.DB can be handed to cost.Engine.Summary, which owns every query.
func TestPackageImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		ForbiddenTrees: []string{"net/http", "github.com/fsnotify/fsnotify", "os/exec"},
		Reason:         "costseries composes the cost engine; it serves no HTTP and runs no process",
	})
}
