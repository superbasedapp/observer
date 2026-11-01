package main

import "github.com/marmutapp/superbased-observer/internal/dashapi"

// sandbox_gates_routes.go is the one seam the dashboard routes of lane
// GATES-SBX's sandbox pieces (re-adoption and checkpoints, credential
// injection) are mounted through: each piece's own build-tagged file
// appends its route func from init, so a build or a node without the piece
// mounts none. Every route is Local and answers 404 while its component is
// not selected.
var gatesSandboxRouteFuncs []func(configPath string) []dashapi.ExtraRoute

// gatesSandboxDashboardRoutes returns the registered routes.
func gatesSandboxDashboardRoutes(configPath string) []dashapi.ExtraRoute {
	var out []dashapi.ExtraRoute
	for _, f := range gatesSandboxRouteFuncs {
		out = append(out, f(configPath)...)
	}
	return out
}
