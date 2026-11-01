package main

import (
	"database/sql"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// dashboardComponents builds the component service the dashboard's
// Settings > Components page and route guard use (modular packaging P1,
// lane MP-DASH): newComponentsService, the constructor `observer components`
// runs, so the page and the CLI share one teardown, one purge store and one
// audit path. A service that cannot be built leaves the dashboard unwired
// (every route answers as before, the page says it is unavailable); it
// returns a nil interface, never an interface holding a nil pointer.
func dashboardComponents(configPath string, database *sql.DB) dashapi.ComponentsService {
	svc, err := newComponentsService(configPath, database)
	if err != nil {
		slog.Default().Warn("dashboard: components service unavailable", "err", err)
		return nil
	}
	return withLiveRunHold(svc) // live sandboxed runs hold a sandbox deactivation (SBX-UPD-1)
}
