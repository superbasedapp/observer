package dashboard

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// terminal_sandbox_config_copies.go is the Settings save's part for two keys
// of the sandbox decisions (lane COPIES), kept in its own embedded blocks so
// the payload's other fields stay untouched:
//
//   - [terminal.sandbox].returned_copy_retention_days (SBXD-2), edited on
//     the Sandbox isolation card beside workspace_retention_days;
//   - [terminal.sandbox.hosted].diff_against (the smaller item "diff against
//     the box's baseline"), edited on the Hosted sandboxes panel.
//
// Both are pointers, so a client that predates them (and so omits them)
// keeps the saved values instead of resetting them on every save.

// terminalSandboxCopiesPayload is embedded in terminalSandboxConfigPayload.
type terminalSandboxCopiesPayload struct {
	ReturnedCopyRetentionDays *int `json:"returned_copy_retention_days,omitempty"`
}

// copiesPayloadFor is the block's read shape.
func copiesPayloadFor(c config.TerminalSandboxConfig) terminalSandboxCopiesPayload {
	days := c.ReturnedCopyRetentionDays
	return terminalSandboxCopiesPayload{ReturnedCopyRetentionDays: &days}
}

// applyTo sets the sent keys on next (normalizedSandboxConfig, before the
// validation).
func (p terminalSandboxCopiesPayload) applyTo(next *config.TerminalSandboxConfig) {
	if p.ReturnedCopyRetentionDays != nil {
		next.ReturnedCopyRetentionDays = *p.ReturnedCopyRetentionDays
	}
}

// keepUnsent puts the saved value back for a key the body left out.
func (p terminalSandboxCopiesPayload) keepUnsent(next *config.TerminalSandboxConfig, saved config.TerminalSandboxConfig) {
	if p.ReturnedCopyRetentionDays == nil {
		next.ReturnedCopyRetentionDays = saved.ReturnedCopyRetentionDays
	}
}

// terminalSandboxHostedDiffPayload is embedded in
// terminalSandboxHostedPayload.
type terminalSandboxHostedDiffPayload struct {
	DiffAgainst *string `json:"diff_against,omitempty"`
}

// hostedDiffPayloadFor is the block's read shape ("" reads as baseline, its
// meaning).
func hostedDiffPayloadFor(c config.TerminalSandboxHostedConfig) terminalSandboxHostedDiffPayload {
	v := c.DiffAgainst
	if v == "" {
		v = config.HostedDiffAgainstBaseline
	}
	return terminalSandboxHostedDiffPayload{DiffAgainst: &v}
}

// applyTo sets the sent key on out (normalizedSandboxHostedConfig).
func (p terminalSandboxHostedDiffPayload) applyTo(out *config.TerminalSandboxHostedConfig) {
	if p.DiffAgainst != nil {
		out.DiffAgainst = strings.TrimSpace(*p.DiffAgainst)
	}
}

// keepUnsent puts the saved value back when the body left it out
// (keepHostedOnPut).
func (p terminalSandboxHostedDiffPayload) keepUnsent(next *config.TerminalSandboxHostedConfig, saved config.TerminalSandboxHostedConfig) {
	if p.DiffAgainst == nil {
		next.DiffAgainst = saved.DiffAgainst
	}
}
