//go:build sbo_omit_terminals

package main

import (
	"database/sql"
	"log/slog"
)

// liveRunSourceFor returns nil: a build without terminals has no sandboxed
// run to ask about.
func liveRunSourceFor(terminalLiveCounter, *sql.DB, *slog.Logger) liveRunSource { return nil }
