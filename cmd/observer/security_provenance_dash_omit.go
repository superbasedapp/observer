//go:build sbo_omit_security

package main

import (
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// provenanceDash: no AI change records without the security module.
func provenanceDash(string, *sql.DB) *dashapi.Provenance { return nil }
