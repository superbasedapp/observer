//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

// terminal_sandbox_mxc_console.go is the console a mxc-process box writes to
// (Windows 11 Pro run 3 RERUN2, D1). A box started from a classic console
// window (a CLI launch: `observer claude --observer-sandbox mxc-process` in
// Windows Terminal or PowerShell) got a console of its own with no window:
// its conhost was a child of the box's first process (the in-box observer
// MXC starts), GetConsoleWindow answered 0 there and nothing the tool
// printed reached the user. Measured on the laptop (Windows 11 26200): the
// box writes to the standard handles wxc-exec inherited, never to a console
// window of its own. A box under a pseudo console the launcher runs on (a
// dashboard terminal, where the daemon hosts the launcher in one) shares
// it, and its output reaches the page; a pseudo console given to wxc-exec
// by attribute, from a helper not attached to it, did not carry the box's
// output (114 bytes, all the pseudo console's own). So a CLI launch on a
// console window takes the dashboard's shape: the launcher runs the helper
// on a pseudo console of its own (internal/termsession's spawner, the
// dashboard's ConPTY code; sandbox_cli_console_windows.go), copies its
// output to the real console, keystrokes back and the size across, and the
// helper passes its console handles to wxc-exec as the dashboard's does.

// mxcConsoleRoute is how the box's console reaches the user.
type mxcConsoleRoute string

const (
	// mxcConsoleDaemonPTY: a dashboard terminal; the daemon's pseudo
	// console, which the box shares, is already the user's screen.
	mxcConsoleDaemonPTY mxcConsoleRoute = "daemon pseudo console"
	// mxcConsoleHostPTY: a CLI launch on a console window; the launcher's
	// own pseudo console (sandboxConsoleHostedEnv), pumped to that window.
	mxcConsoleHostPTY mxcConsoleRoute = "host pseudo console"
	// mxcConsoleRedirected: the helper's stdout is a file or a pipe (a
	// script, the kit's receipts); the handles go to wxc-exec as they are.
	mxcConsoleRedirected mxcConsoleRoute = "redirected handles"
	// mxcConsoleClassic: a console window the launcher did not host (a
	// Windows without CreatePseudoConsole, or the helper started by hand);
	// the box keeps the console Windows gives it, which shows nothing.
	mxcConsoleClassic mxcConsoleRoute = "classic console (not hosted on a pseudo console; the box's output is not shown)"
)

// mxcConsoleFacts are what the route is decided on.
type mxcConsoleFacts struct {
	// DaemonChild: the helper runs in a daemon-owned terminal
	// (OBSERVER_DAEMON_CHILD).
	DaemonChild bool
	// Hosted: the launcher runs the helper on its own pseudo console
	// (sandboxConsoleHostedEnv).
	Hosted bool
	// StdoutConsole: the helper's stdout is a console.
	StdoutConsole bool
}

// mxcConsoleRows is the route table, walked top-down; the first match wins.
var mxcConsoleRows = []struct {
	match func(mxcConsoleFacts) bool
	route mxcConsoleRoute
}{
	{func(f mxcConsoleFacts) bool { return f.DaemonChild }, mxcConsoleDaemonPTY},
	{func(f mxcConsoleFacts) bool { return !f.StdoutConsole }, mxcConsoleRedirected},
	{func(f mxcConsoleFacts) bool { return f.Hosted }, mxcConsoleHostPTY},
	{func(mxcConsoleFacts) bool { return true }, mxcConsoleClassic},
}

// mxcConsoleRouteFor is the route for f.
func mxcConsoleRouteFor(f mxcConsoleFacts) mxcConsoleRoute {
	for _, r := range mxcConsoleRows {
		if r.match(f) {
			return r.route
		}
	}
	return mxcConsoleClassic
}
