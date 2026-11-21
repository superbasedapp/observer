//go:build sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/config"

// sandboxEgressHostCheckSeam is nil in a build without the sandbox: the
// refusal advisor offers nothing.
func sandboxEgressHostCheckSeam() func(config.TerminalSandboxConfig, string) string { return nil }

// sandboxProviderHostSeam is nil in a build without the sandbox.
func sandboxProviderHostSeam() func(config.Config, string) bool { return nil }

// bindSandboxLiveProviderHosts is a no-op in a build without the sandbox
// (lane FU8): there is no provider block to feed.
func bindSandboxLiveProviderHosts(any) {}
