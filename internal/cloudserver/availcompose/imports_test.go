package availcompose

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins availcompose as pure logic: no SQL, no HTTP, no
// signer, never the org server or the store.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"crypto/tls",
			"os",
			"os/exec",
			"github.com/jackc/pgx/v5",
			"github.com/jackc/pgx/v5/pgxpool",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/api",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd",
		},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/orgserver",
		},
		Reason: "availcompose is the pure input-to-envelope composer; I/O belongs to the store, the worker and the API",
	})
}
