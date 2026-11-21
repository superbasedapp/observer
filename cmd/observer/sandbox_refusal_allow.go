//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandboxEgressHostCheckSeam is the dashboard refusal advisor's host check
// (OpenShell lane N5, Options.SandboxEgressHostCheck): the gateway rule that
// refuses host under ts, or "" when the gateway lets it through. It is the
// gateway's own list builder (agentEgressRules), so the advisor and the
// gateway can never disagree about a host. A list that does not parse
// refuses every host (the gateway is refused at launch then too).
func sandboxEgressHostCheckSeam() func(config.TerminalSandboxConfig, string) string {
	return func(ts config.TerminalSandboxConfig, host string) string {
		rules, err := agentEgressRules(ts)
		if err != nil {
			return "host-list-invalid"
		}
		return rules.Check(host)
	}
}

// sandboxProviderHostSeam is the dashboard refusal advisor's provider check
// (Options.SandboxProviderHost, audit finding N5-A1): whether host is in the
// set the gateway's provider block refuses. The block is
// sandboxnet.NewProviderBlock(sandboxProviderHosts(full.Proxy)), whose name
// rule is sandboxvocab.MatchesProvider over sandboxvocab.ModelProviderHosts()
// plus those hosts; this asks the same functions over the same inputs.
// The gateway checks the host list first, so a provider host missing from
// the list is stored as an allow-list miss and must not be offered.
func sandboxProviderHostSeam() func(config.Config, string) bool {
	return func(full config.Config, host string) bool {
		return sandboxvocab.MatchesProvider(host, append(sandboxvocab.ModelProviderHosts(), sandboxProviderHosts(full.Proxy)...))
	}
}
