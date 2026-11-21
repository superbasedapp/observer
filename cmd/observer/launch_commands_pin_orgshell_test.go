//go:build !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

// launch_commands_pin_orgshell_test.go adds the org-hosted sandbox row's
// launch command to TestEveryLaunchCommandAsks (fold audit H1, lane FX5),
// under the build tags that compile the command, so an omit-tag build that
// drops it does not read the row as stale.
func init() {
	// Resuming a held org sandbox box starts the agent in it through the
	// tool's launcher verb (sandbox_orgshell_hold.go).
	launchCommandSamples["sandbox org-shell resume"] = "sandbox org-shell resume run-1 --tool claude-code"
}
