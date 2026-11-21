package connectflow

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins connectflow as a pure core.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"os",
			"os/exec",
			"github.com/jackc/pgx/v5",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/api",
		},
		ForbiddenTrees: []string{"net/http"},
		Reason:         "connectflow is the pure connect-flow core; SQL lives in store, HTTP in api",
	})
}
