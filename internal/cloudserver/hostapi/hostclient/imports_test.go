package hostclient

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins hostclient as the I/O composition of the host-API
// client: it may use net/http and the store seam, but never SQL directly
// (the store owns every statement), never the org server (the host side is
// reached over the wire only), never the console API, and never a cloud
// network or credential package of the personal plane.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"github.com/jackc/pgx/v5",
			"github.com/jackc/pgx/v5/pgxpool",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/api",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg",
		},
		ForbiddenTrees: []string{
			"github.com/marmutapp/superbased-observer/internal/orgserver",
			"github.com/marmutapp/superbased-observer/internal/cloudclient",
			"github.com/marmutapp/superbased-observer/internal/cloudcred",
		},
		Reason: "hostclient composes the pure hostapi core with the transport and the store seam only",
	})
}
