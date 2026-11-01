//go:build sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// terminal_sandbox_cli_omit.go stands in for the sandbox module's two
// daemon and CLI seams in a build without it (any of the three omit tags):
// the posture seam binds nothing, and a `--observer-sandbox` launch is refused with
// the build reason rather than passed to the tool or run unsandboxed.

// bindSandboxCapability binds nothing: without the Sandboxes and VMs module
// the sandbox posture aggregate is never composed.
func bindSandboxCapability(context.Context, *store.Store, bool, dashapi.SandboxProber) {}

// sandboxCLIDispatch refuses `observer <tool> --observer-sandbox <profile>`.
func sandboxCLIDispatch(args []string) (int, bool) {
	if len(args) < 2 {
		return 0, false
	}
	if _, ok := integration.ToolForLaunchSubcommand(args[1]); !ok {
		return 0, false
	}
	for _, a := range args[2:] {
		if a == "--" {
			return 0, false
		}
		if a == "--observer-sandbox" || strings.HasPrefix(a, "--observer-sandbox=") {
			fmt.Fprintf(os.Stderr, "observer %s --observer-sandbox: the Sandboxes and VMs component (terminals.sandbox) is not in this build; %s.\n",
				args[1], components.DistrosHaving("terminals.sandbox"))
			return 3, true
		}
	}
	return 0, false
}

// sandboxModuleActive is false: the Sandboxes and VMs module is not in this
// build.
func sandboxModuleActive(componentstate.Snapshot) bool { return false }

// sandboxLauncherHelp adds nothing to a launcher's --help in a build without
// the sandbox module (a --observer-sandbox launch is refused here).
func sandboxLauncherHelp() string { return "" }
