package config

import (
	"strings"

	"github.com/BurntSushi/toml"
)

// TerminalLaunchKeys records which agent keys of [terminal.launch] this
// node actually set, as opposed to the shipped defaults (allow_fresh_agent
// false, empty lists). A launch that predates the policy and must keep its
// behaviour on a node that never configured it (Agent Arena, ruling P-203)
// applies only the keys set here. A key counts as set when a merged TOML
// file defines it, when its OBSERVER_* environment override is non-empty,
// or when a verified governance pin replaced it (GovernanceOutcome.Applied).
type TerminalLaunchKeys struct {
	AllowFreshAgent     bool
	AllowedTools        bool
	AllowedProjectRoots bool
}

// terminalLaunchKeyRows maps each agent key to its flag, the one table both
// the file, env and pin readers walk.
var terminalLaunchKeyRows = []struct {
	key  string
	flag func(*TerminalLaunchKeys) *bool
}{
	{"allow_fresh_agent", func(k *TerminalLaunchKeys) *bool { return &k.AllowFreshAgent }},
	{"allowed_tools", func(k *TerminalLaunchKeys) *bool { return &k.AllowedTools }},
	{"allowed_project_roots", func(k *TerminalLaunchKeys) *bool { return &k.AllowedProjectRoots }},
}

// terminalLaunchKeysOf reads which agent keys the merged files (metas) or
// the environment set.
func terminalLaunchKeysOf(metas []toml.MetaData, env func(string) string) TerminalLaunchKeys {
	var k TerminalLaunchKeys
	for _, row := range terminalLaunchKeyRows {
		for _, m := range metas {
			if m.IsDefined("terminal", "launch", row.key) {
				*row.flag(&k) = true
			}
		}
		if env != nil && strings.TrimSpace(env("OBSERVER_TERMINAL_LAUNCH_"+strings.ToUpper(row.key))) != "" {
			*row.flag(&k) = true
		}
	}
	return k
}

// withPinned marks every agent key a verified governance pin set (applied
// is GovernanceOutcome.Applied, dotted keys).
func (k TerminalLaunchKeys) withPinned(applied []string) TerminalLaunchKeys {
	for _, row := range terminalLaunchKeyRows {
		for _, a := range applied {
			if a == "terminal.launch."+row.key {
				*row.flag(&k) = true
			}
		}
	}
	return k
}
