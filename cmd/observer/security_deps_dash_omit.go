//go:build sbo_omit_security || sbo_omit_security_deps

package main

import (
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// packageChecksDash has no seam without the security.deps component: the
// dashboard route answers 404.
func packageChecksDash(string, *sql.DB) *dashapi.PackageChecks { return nil }
