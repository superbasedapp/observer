//go:build sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/dashapi"

// terminal_sandbox_hosted_omit.go: a build without the sandbox module has no
// hosted rows, so the Hosted sandboxes panel has no routes.
func hostedDashboardRoutes(string) []dashapi.ExtraRoute { return nil }
