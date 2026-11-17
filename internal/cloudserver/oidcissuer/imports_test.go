package oidcissuer

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins oidcissuer as a pure core (design m6.0 section 6:
// "oidcissuer ... pure cores import no database/sql, net/http"): no SQL, no
// HTTP, no sockets, no file system, no store, and no test support.
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
			"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest",
		},
		ForbiddenTrees: []string{"net/http"},
		Reason:         "oidcissuer is the pure issuer core; I/O lives in store, signerd and oidchttp",
	})
}
