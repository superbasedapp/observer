package dashboard

import (
	"github.com/marmutapp/superbased-observer/internal/config"
)

// terminal_sandbox_config_hostedupload.go is the Hosted sandboxes panel's
// editor for the two [terminal.sandbox.hosted] keys of decision SBXD-8
// (uploading a folder that is not a git repository): upload_non_git and
// upload_ignore. The payload is embedded in terminalSandboxHostedPayload, so
// its keys sit in the hosted block beside their siblings; both are pointers
// so a client that predates them (and so omits them) keeps the saved
// values. The whole block is checked by the one config validation on save
// (validateTerminalSandboxHosted).

// terminalSandboxHostedUploadPayload carries the two keys.
type terminalSandboxHostedUploadPayload struct {
	UploadNonGit *bool     `json:"upload_non_git,omitempty"`
	UploadIgnore *[]string `json:"upload_ignore,omitempty"`
}

// hostedUploadToPayload is the GET side.
func hostedUploadToPayload(c config.TerminalSandboxHostedConfig) terminalSandboxHostedUploadPayload {
	nonGit := c.UploadNonGit
	ignore := append([]string{}, c.UploadIgnore...)
	return terminalSandboxHostedUploadPayload{UploadNonGit: &nonGit, UploadIgnore: &ignore}
}

// normalizedHostedUpload applies a PUT body's keys to out (an absent key
// takes the shipped default here; keepHostedUploadOnPut then puts the saved
// value back).
func normalizedHostedUpload(out *config.TerminalSandboxHostedConfig, p terminalSandboxHostedUploadPayload) {
	def := config.Default().Terminal.Sandbox.Hosted
	out.UploadNonGit, out.UploadIgnore = def.UploadNonGit, def.UploadIgnore
	if p.UploadNonGit != nil {
		out.UploadNonGit = *p.UploadNonGit
	}
	if p.UploadIgnore != nil {
		out.UploadIgnore = cleanStringList(*p.UploadIgnore)
	}
}

// keepHostedUploadOnPut keeps the saved values of the keys a PUT body left
// out.
func keepHostedUploadOnPut(next *config.TerminalSandboxHostedConfig, body terminalSandboxHostedUploadPayload, saved config.TerminalSandboxHostedConfig) {
	if body.UploadNonGit == nil {
		next.UploadNonGit = saved.UploadNonGit
	}
	if body.UploadIgnore == nil {
		next.UploadIgnore = saved.UploadIgnore
	}
}
