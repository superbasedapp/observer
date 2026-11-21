package oidctest

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

// TestBoundaryImports pins the test-support package to the pure issuer core:
// no SQL, no HTTP, no store.
func TestBoundaryImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql",
			"net/http",
			"github.com/jackc/pgx/v5",
			"github.com/marmutapp/superbased-observer/internal/cloudserver/store",
		},
		Reason: "oidctest is an in-memory stand-in for the store",
	})
}
