//go:build linux && !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"
	"strconv"
)

// landlockEnvSocketDir names the run's socket dir to the hook client in the
// box (the box shares the host's /tmp, so the box record cannot sit at the
// fixed guest path); honoured only with the sandbox marker. The same
// spelling as the Seatbelt driver's. Read only on Linux
// (terminal_sandbox_landlock_linux.go), so it lives in a Linux file (WINFIX4
// lint: unused on Windows).
const landlockEnvSocketDir = "OBSERVER_SANDBOX_SOCK_DIR"

// landlockExecGate reads the optional `--block-fd <n>` the host helper's
// start gate puts first (sandboxGatedHelpers); -1 without it. Called only on
// Linux, so it lives in a Linux file (WINFIX4 lint: unused on Windows).
func landlockExecGate(args []string) (int, []string, error) {
	if len(args) == 0 || args[0] != "--block-fd" {
		return -1, args, nil
	}
	if len(args) < 2 {
		return -1, nil, errLandlockUsage
	}
	fd, err := strconv.Atoi(args[1])
	if err != nil || fd < 3 {
		return -1, nil, fmt.Errorf("the start gate descriptor %q is not a descriptor above stdio", args[1])
	}
	return fd, args[2:], nil
}
