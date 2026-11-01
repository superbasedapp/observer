package main

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// security_switches.go is the settings contract's rule switches (security
// pillar plan section 6.5, lane sec-c3): a [security.*] on/off key that
// removes one of the pillar's rules from the composed pack. It sits beside
// the pack composition at the two places guard is built (the daemon's
// guardwire and the hook), so the hook and the daemon judge with the same
// set. Removing a rule only narrows what is judged: no switch relaxes
// another rule, and a removed rule's [[override]] becomes the usual
// load issue for an unloaded S-7xx rule.

// securityRuleSwitch is one row: the rule and whether its switch keeps it.
type securityRuleSwitch struct {
	rule string
	on   func(config.SecurityConfig) bool
}

// securityRuleSwitches is the table, one row per switched rule.
var securityRuleSwitches = []securityRuleSwitch{
	// "Secret check before writes": S-721 judges a write's proposed
	// content in the hook; the post-write seam and the commit gate still
	// cover a file written while it is off.
	{rule: "S-721", on: func(s config.SecurityConfig) bool { return s.Secrets.WriteCheck }},
}

// securityRulesWithSwitches drops the pack rules whose switch is off.
func securityRulesWithSwitches(sec config.SecurityConfig, rules []policy.Rule) []policy.Rule {
	off := map[string]bool{}
	for _, sw := range securityRuleSwitches {
		if !sw.on(sec) {
			off[sw.rule] = true
		}
	}
	if len(off) == 0 {
		return rules
	}
	out := make([]policy.Rule, 0, len(rules))
	for _, r := range rules {
		if !off[r.ID] {
			out = append(out, r)
		}
	}
	return out
}
