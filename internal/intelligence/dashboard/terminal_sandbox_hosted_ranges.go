package dashboard

import (
	"fmt"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// terminal_sandbox_hosted_ranges.go is the dashboard shape of the hosted
// internet tier's private-range deny (decision SBXD-7):
// [terminal.sandbox.hosted].allow_private_ranges and each provider table's
// optional override, edited by web/src/components/sandboxHosted/. It is one
// self-contained block of the hosted payload: a client that sends none of it
// keeps the saved values.

// The per-provider override values the panel sends.
const (
	privateRangeFollow = "follow"
	privateRangeAllow  = "allow"
	privateRangeDeny   = "deny"
)

// hostedPrivateRangesPayload is the block. AllowPrivateRanges and Overrides
// are pointers so a client that predates them keeps the saved values;
// DenyCapable is read-only (the provider tables whose vendor takes deny
// rules, so the panel offers an override only there).
type hostedPrivateRangesPayload struct {
	AllowPrivateRanges *bool `json:"allow_private_ranges,omitempty"`
	// Overrides maps a provider table name (e2b, docker, vercel) to follow,
	// allow or deny.
	Overrides   *map[string]string `json:"private_range_overrides,omitempty"`
	DenyCapable []string           `json:"private_range_deny_capable,omitempty"`
}

// hostedRangeTables are the provider tables an override can name.
var hostedRangeTables = []string{"e2b", "modal", "vercel", "docker", "instabox", "daytona"}

// hostedPrivateRangesToPayload reads the block from the config.
func hostedPrivateRangesToPayload(c config.TerminalSandboxHostedConfig) hostedPrivateRangesPayload {
	allow := c.AllowPrivateRanges
	overrides := map[string]string{}
	for _, name := range config.HostedPrivateRangeDenyProviders {
		overrides[name] = privateRangeFollow
		if t := c.ProviderTable(name); t != nil {
			if p := t.AllowPrivateRanges; p != nil {
				overrides[name] = map[bool]string{true: privateRangeAllow, false: privateRangeDeny}[*p]
			}
		}
	}
	return hostedPrivateRangesPayload{AllowPrivateRanges: &allow, Overrides: &overrides, DenyCapable: slices.Clone(config.HostedPrivateRangeDenyProviders)}
}

// hostedBlockFor is the hosted block a PUT validates with: the defaults for
// a client that predates the block (the save keeps the file's own), else the
// normalized payload with this block's fields applied.
func hostedBlockFor(h *terminalSandboxHostedPayload) (config.TerminalSandboxHostedConfig, error) {
	if h == nil {
		return config.Default().Terminal.Sandbox.Hosted, nil
	}
	out := normalizedSandboxHostedConfig(h)
	if err := applyHostedPrivateRanges(&out, h.hostedPrivateRangesPayload); err != nil {
		return config.TerminalSandboxHostedConfig{}, err
	}
	return out, nil
}

// applyHostedPrivateRanges writes what the block sent onto next (the
// normalized hosted config); an unknown table or value is a request error.
// What it leaves unsent is restored from the saved config by
// keepHostedPrivateRanges.
func applyHostedPrivateRanges(next *config.TerminalSandboxHostedConfig, b hostedPrivateRangesPayload) error {
	if b.AllowPrivateRanges != nil {
		next.AllowPrivateRanges = *b.AllowPrivateRanges
	}
	if b.Overrides == nil {
		return nil
	}
	for name, v := range *b.Overrides {
		t := next.ProviderTable(name)
		if t == nil {
			return fmt.Errorf("terminal.sandbox.hosted.%s is not a hosted provider table", name)
		}
		switch v {
		case privateRangeFollow:
			t.AllowPrivateRanges = nil
		case privateRangeAllow, privateRangeDeny:
			on := v == privateRangeAllow
			t.AllowPrivateRanges = &on
		default:
			return fmt.Errorf("terminal.sandbox.hosted.%s.allow_private_ranges override %q not in {follow, allow, deny}", name, v)
		}
	}
	return nil
}

// keepHostedPrivateRanges restores the saved shared value and overrides a
// PUT body did not send (the provider tables are rebuilt from the payload,
// which carries no override of its own).
func keepHostedPrivateRanges(next *config.TerminalSandboxHostedConfig, sent hostedPrivateRangesPayload, saved config.TerminalSandboxHostedConfig) {
	if sent.AllowPrivateRanges == nil {
		next.AllowPrivateRanges = saved.AllowPrivateRanges
	}
	for _, name := range hostedRangeTables {
		if sent.Overrides != nil {
			if _, ok := (*sent.Overrides)[name]; ok {
				continue
			}
		}
		next.ProviderTable(name).AllowPrivateRanges = saved.ProviderTable(name).AllowPrivateRanges
	}
}
