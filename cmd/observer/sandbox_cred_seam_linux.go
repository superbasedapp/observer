//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"net/http"
)

// sandbox_cred_seam_linux.go holds the hosted host helper's credential
// hooks. The helper runs only on Linux (terminal_sandbox_hosted_host.go,
// terminal_sandbox_hosted_proxystamp.go), so the hooks live in a Linux file
// (WINFIX4 lint: unused on Windows). nil unless the credentials files are
// compiled (sandbox_cred_hooks_linux.go sets them from init).

// hostedCredSetupHook runs in the hosted host helper before the box is
// created: it mints the run's sentinel (home_relay) or sets up the vendor's
// broker rule (provider_injected), and refuses a custody it cannot serve.
var hostedCredSetupHook func(ctx context.Context, plan hostedPlanFile) error

// hostedCredTeardownHook undoes the setup when the run ends.
var hostedCredTeardownHook func(plan hostedPlanFile)

// hostedCredEnvHook puts the run's sentinel in the tool's key variable of
// the box's environment.
var hostedCredEnvHook func(plan hostedPlanFile, env map[string]string)

// hostedCredStampHook stamps the run's relay token on a relayed model
// request on the home side (any value the box sent is replaced).
var hostedCredStampHook func(h http.Header, runID string)
