//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

// sandbox_cli_console.go decides whether a sandboxed CLI launch runs its
// backend's host helper on a pseudo console of the launcher's own (Windows
// 11 Pro run 3 RERUN2, D1). The mxc-process box writes to the standard
// handles wxc-exec inherits; from a classic console window those were the
// window's handles, MXC gave the box a console of its own with no window,
// and nothing the tool printed reached the user. A dashboard terminal does
// not have the problem: the daemon runs the launcher on a pseudo console
// (internal/termsession), whose handles the box inherits. So a CLI launch
// on a console window takes the same shape: the launcher spawns the helper
// through the dashboard's own spawner (termsession.NewOSSpawner) and pumps
// the pseudo console to and from the real console
// (sandbox_cli_console_windows.go). The helper reads sandboxConsoleHostedEnv
// to name the route in the run's inner log.

// sandboxConsoleHostedEnv tells the host helper it runs on the launcher's
// pseudo console ("1").
const sandboxConsoleHostedEnv = "OBSERVER_SANDBOX_CONSOLE_HOSTED"

// sandboxCLIConsoleFacts are what the choice is made on.
type sandboxCLIConsoleFacts struct {
	// DriverHosts: the backend's driver asks for it
	// (sandboxDriverReg.cliConsoleHost).
	DriverHosts bool
	// DaemonChild: the launch runs in a daemon-owned terminal, already on
	// the daemon's pseudo console.
	DaemonChild bool
	// StdoutConsole: the launcher's stdout is a console window.
	StdoutConsole bool
	// PseudoConsole: this OS can create a pseudo console here.
	PseudoConsole bool
}

// sandboxCLIConsoleRows is the decision table, walked top-down; the first
// match wins.
var sandboxCLIConsoleRows = []struct {
	match func(sandboxCLIConsoleFacts) bool
	host  bool
}{
	{func(f sandboxCLIConsoleFacts) bool { return !f.DriverHosts }, false},
	{func(f sandboxCLIConsoleFacts) bool { return f.DaemonChild }, false},
	{func(f sandboxCLIConsoleFacts) bool { return !f.StdoutConsole }, false},
	{func(f sandboxCLIConsoleFacts) bool { return !f.PseudoConsole }, false},
	{func(sandboxCLIConsoleFacts) bool { return true }, true},
}

// sandboxCLIHostConsole reports whether the launch runs its helper on the
// launcher's own pseudo console.
func sandboxCLIHostConsole(f sandboxCLIConsoleFacts) bool {
	for _, r := range sandboxCLIConsoleRows {
		if r.match(f) {
			return r.host
		}
	}
	return false
}
