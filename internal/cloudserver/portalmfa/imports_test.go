package portalmfa

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins portalmfa as a pure core.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"os",
			"os/exec",
			"github.com/jackc/pgx/v5",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/api",
		},
		ForbiddenTrees: []string{"net/http", "github.com/go-webauthn/webauthn"},
		Reason:         "portalmfa is the pure portal second-factor core; SQL lives in store, HTTP in api",
	})
}
