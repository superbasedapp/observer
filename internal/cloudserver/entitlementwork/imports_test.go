package entitlementwork

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins entitlementwork as composition over injected
// seams: no SQL driver (the store owns every statement), no HTTP (the
// dispatcher sends), no signer socket package (the signer is injected) and
// never the org server.
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
			"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg",
		},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/orgserver",
			"github.com/marmutapp/superbased-observer/internal/cloudclient",
			"github.com/marmutapp/superbased-observer/internal/cloudcred",
		},
		Reason: "entitlementwork composes the catalog, the signer seam and the store seam only",
	})
}
