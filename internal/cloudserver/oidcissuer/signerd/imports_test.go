package signerd

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins the signer process to its job: a socket, a key
// file and the pure claim rules. No HTTP, no database, no store: the signer
// holds the private key and nothing else.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"github.com/jackc/pgx/v5",
			"github.com/jackc/pgx/v5/pgxpool",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/api",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidchttp",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest",
		},
		ForbiddenTrees: []string{"net/http"},
		Reason:         "the signer holds the key and talks only over its unix socket",
	})
}
