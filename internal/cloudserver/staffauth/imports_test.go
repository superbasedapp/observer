package staffauth

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins staffauth as the pure staff console core: no SQL,
// no HTTP, no sockets, no file system and no store or api import.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os",
			"os/exec",
			"syscall",
			"github.com/jackc/pgx/v5",
			"github.com/jackc/pgx/v5/pgxpool",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/api",
		},
		ForbiddenTrees: []string{"net/http"},
		Reason:         "staffauth is the pure staff console core; SQL lives in store, HTTP in api",
	})
}
