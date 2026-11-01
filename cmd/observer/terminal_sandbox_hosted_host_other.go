//go:build !linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

// terminal_sandbox_hosted_host_other.go: the hosted rows run their host
// services (the per-run socket dir, the capture relay, the model proxy
// forward) on a Linux or WSL2 daemon only; elsewhere the probe refuses at
// its platform row and this helper is never started.
func runHostedHost([]string) int { return sandboxHelperUnsupported() }

// hostedHelperAlive: no helper runs on this platform.
var hostedHelperAlive = func(string) bool { return false }

// hostedStopHelper: no helper runs on this platform.
var hostedStopHelper = func(string) error { return nil }
