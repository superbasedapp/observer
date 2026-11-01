//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// terminal_sandbox_egresshosts.go is the agent-run host allow-list (lane
// LEFT-SBX, [terminal.sandbox].egress_allow_hosts): under a tier with the
// egress gateway, a run whose list is set reaches only those hosts (and the
// model proxy). It is one rule for every row that runs the gateway in a host
// helper (the Linux helper of bwrap, process_lite and the oci rows, the macOS
// helper of Seatbelt and Apple container, the MXC helper): each helper reads
// the list from the daemon config its run record names (ConfigPath, the
// file every launch path loads, governance pins applied by config.Load), so
// no driver threads it through its own plan and a row cannot forget it.

// agentEgressRules is the gateway's host list for a [terminal.sandbox]
// block: nil (the tier's own behaviour) with no list, the parsed list, or
// the deny-all list when an org pin left none in common
// (PinnedNoEgressHost).
func agentEgressRules(ts config.TerminalSandboxConfig) (*sandboxnet.HostRules, error) {
	if ts.PinnedNoEgressHost != "" {
		return sandboxnet.DenyAllHosts(), nil
	}
	if len(ts.EgressAllowHosts) == 0 {
		return nil, nil
	}
	rules, err := sandboxnet.ParseHostRules(ts.EgressAllowHosts)
	if err != nil {
		return nil, fmt.Errorf("[terminal.sandbox].egress_allow_hosts: %w", err)
	}
	return rules, nil
}

// sandboxAgentEgressLoad loads the config at path (a variable for tests).
var sandboxAgentEgressLoad = func(path string) (config.Config, error) {
	return config.Load(config.LoadOptions{GlobalPath: path})
}

// sandboxAgentEgressRules is the host list of run runID's gateway, read from
// the daemon config its run record under observerDir names. A run with no
// relay (no record) keeps the tier's own behaviour, as before the list. A
// record that cannot be read, or a config that does not load, refuses the
// gateway (fail closed: the list could be set).
func sandboxAgentEgressRules(observerDir, runID string) (*sandboxnet.HostRules, error) {
	if observerDir == "" || runID == "" {
		return nil, nil
	}
	rec, err := sandboxrelayd.ReadRun(observerDir, runID)
	if err != nil {
		return nil, fmt.Errorf("read the run record for the egress host list: %w", err)
	}
	if rec.ConfigPath == "" {
		return nil, nil
	}
	cfg, err := sandboxAgentEgressLoad(rec.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("load the config for the egress host list: %w", err)
	}
	return agentEgressRules(cfg.Terminal.Sandbox)
}
