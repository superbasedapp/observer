package oidchttp

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins oidchttp as an HTTP adapter over the pure core: no
// SQL, no store (the api package resolves the session and wires the store
// behind oidcissuer.Store), no sockets of its own, no test support.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"github.com/jackc/pgx/v5",
			"github.com/jackc/pgx/v5/pgxpool",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/api",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/oidctest",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer/signerd",
		},
		Reason: "oidchttp translates HTTP to the pure oidcissuer core and nothing else",
	})
}
