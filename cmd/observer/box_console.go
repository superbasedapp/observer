package main

// mxcConsoleEnv names, inside the box, the console route the helper chose,
// for the inner log's terminal row.
const mxcConsoleEnv = "OBSERVER_SANDBOX_CONSOLE"

// boxConsoleNote is the inner log's console field for a process in the box:
// the route the helper named and what this process's console is (a window
// that is shown, one that is hidden, or none), so a run whose screen stayed
// blank says why without a probe (RERUN2 D1).
func boxConsoleNote(getenv func(string) string, window string) string {
	route := getenv(mxcConsoleEnv)
	if route == "" {
		route = "not named by the helper"
	}
	return "; console: " + route + ", console window " + window
}
