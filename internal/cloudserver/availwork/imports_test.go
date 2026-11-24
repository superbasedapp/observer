package availwork

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins availwork as composition over injected seams: no
// SQL driver (the store owns every statement), no HTTP (the sender is
// injected), no signer socket package, never the org server.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net",
			"net/http",
			"crypto/tls",
			"github.com/jackc/pgx/v5",
			"github.com/jackc/pgx/v5/pgxpool",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/api",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg",
		},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/orgserver",
		},
		Reason: "availwork composes the composer, the signer seam, the transport seam and the store seam only",
	})
}
