//go:build !windows && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"os"
)

// sandboxCLIConsoleFactsHere: only Windows hosts a launch's helper on a
// pseudo console of the launcher's own.
func sandboxCLIConsoleFactsHere(driverHosts bool) sandboxCLIConsoleFacts {
	return sandboxCLIConsoleFacts{DriverHosts: driverHosts}
}

// runSandboxCLIOnHostConsole is never chosen off Windows.
func runSandboxCLIOnHostConsole([]string, []string, string, <-chan os.Signal, bool) (int, error) {
	return 0, errors.New("a host pseudo console is a Windows launch shape")
}
