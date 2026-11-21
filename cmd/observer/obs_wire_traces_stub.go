package main

import (
	"context"
	"database/sql"

	"github.com/marmutapp/superbased-observer/internal/explorerview"
)

// The no_obs build of `observer obs traces` (obs_wire_traces.go): obs is
// compiled out, so every read refuses with errObsCompiledOut.

func obsTracesListCLI(_ context.Context, _ *sql.DB, _ obsTraceQuery) ([]obsTraceLine, int, error) {
	return nil, 0, errObsCompiledOut
}

func obsTraceShowCLI(_ context.Context, _ *sql.DB, _ string) (obsTraceShown, bool, error) {
	return obsTraceShown{}, false, errObsCompiledOut
}

func obsViewsCLI(_ context.Context, _ *sql.DB, _, _ string, _ explorerview.View) (any, error) {
	return nil, errObsCompiledOut
}
