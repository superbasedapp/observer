//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_hosted_net.go is the cmd seam of the hosted internet
// tier's private-range deny (decision SBXD-7): it reads the person's
// effective [terminal.sandbox.hosted] allow_private_ranges for one vendor and
// hands it to the pure table (sandboxremote.PrivateRangeDeny), whose answer
// the consent facts bind, the plan carries to the create and the notes
// describe. Nothing here decides the posture itself.

// hostedPrivateRangesAllowed is the effective allow_private_ranges for v:
// its provider table's own override when set, else the shared value.
func hostedPrivateRangesAllowed(v sandboxremote.Vendor, cfg config.TerminalSandboxHostedConfig) bool {
	return cfg.PrivateRangesAllowed(hostedVendorConfig(cfg, v.ID))
}

// hostedRangeDeny is what a launch of v on tier asks the vendor to deny.
func hostedRangeDeny(v sandboxremote.Vendor, cfg config.TerminalSandboxHostedConfig, tier vocab.Tier) sandboxremote.RangeDeny {
	return sandboxremote.PrivateRangeDeny(v, tier, hostedPrivateRangesAllowed(v, cfg))
}

// hostedPrivateRangesFact is the consent fact the deny binds on tier.
func hostedPrivateRangesFact(v sandboxremote.Vendor, cfg config.TerminalSandboxHostedConfig, tier vocab.Tier) string {
	return hostedRangeDeny(v, cfg, tier).Posture.ConsentValue()
}
