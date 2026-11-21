package dashapi

import (
	"context"
	"errors"
)

// ErrSetupInput marks a setup request whose input is malformed (an extension
// id that is not 32 a-p characters); the route answers it 400, not 409.
var ErrSetupInput = errors.New("invalid setup input")

// SetupExtras groups the three Settings controls that used to exist only as
// CLI verbs (dashboard CLI parity, lane L2): the Claude Code status line, the
// start-at-login service and the browser-capture native-messaging host. cmd
// wires one SetupExtras over the same code the CLI runs; a nil field is the
// honest not-wired state of that control (501), and a nil *SetupExtras wires
// none of them.
type SetupExtras struct {
	Statusline StatuslineSetup
	LoginStart LoginStartService
	Browser    BrowserCaptureSetup
}

// SetupAction names what a setup control does. The closed vocabulary shared
// by the three controls.
type SetupAction string

// The closed SetupAction vocabulary.
const (
	// SetupInstall writes the control's integration.
	SetupInstall SetupAction = "install"
	// SetupRemove removes what Observer wrote, byte-exactly.
	SetupRemove SetupAction = "remove"
)

// SetupOutcome is the shared result of a setup control's preview or apply.
type SetupOutcome struct {
	Action SetupAction `json:"action"`
	// DryRun is true for a preview: nothing was written.
	DryRun bool `json:"dry_run"`
	// Changed is true when the action wrote (or, in a preview, would write)
	// something.
	Changed bool `json:"changed"`
	// Refused is true when the action did not run because of the machine's
	// state (a foreign entry, an existing unit); Reason says why in words
	// that read the same in the dashboard and the CLI.
	Refused bool   `json:"refused,omitempty"`
	Reason  string `json:"reason,omitempty"`
	// Path is the file or entry the action targets.
	Path string `json:"path,omitempty"`
	// Lines are the exact changes, one per line, as the CLI prints them.
	Lines []string `json:"lines"`
}

// StatuslineState is where Claude Code's statusLine entry stands.
type StatuslineState string

// The closed StatuslineState vocabulary.
const (
	// StatuslineAbsent: no statusLine entry in Claude Code's settings.
	StatuslineAbsent StatuslineState = "absent"
	// StatuslineInstalled: Observer's entry, current.
	StatuslineInstalled StatuslineState = "installed"
	// StatuslineStale: Observer's entry pointing at another binary path.
	StatuslineStale StatuslineState = "stale"
	// StatuslineForeign: a statusLine entry Observer did not write.
	StatuslineForeign StatuslineState = "foreign"
)

// StatuslineStatus is GET /api/setup/statusline's answer.
type StatuslineStatus struct {
	// Supported is false when this daemon cannot write Claude Code's
	// settings (no Claude Code home on this OS); Reason says why.
	Supported  bool            `json:"supported"`
	Reason     string          `json:"reason,omitempty"`
	ConfigPath string          `json:"config_path,omitempty"`
	State      StatuslineState `json:"state"`
	// Command is the command Observer would write ("<binary> statusline").
	Command string `json:"command,omitempty"`
}

// StatuslineSetup is the dashboard's seam onto the Claude Code status line
// writer (`observer init --statusline`). Opt-in only; never implied by any
// other setup and never written by `observer start`.
type StatuslineSetup interface {
	Status(ctx context.Context) (StatuslineStatus, error)
	// Apply installs or removes the entry. dryRun previews it; force
	// replaces a statusLine entry Observer did not write.
	Apply(ctx context.Context, action SetupAction, dryRun, force bool) (SetupOutcome, error)
}

// LoginStartStatus is GET /api/setup/login-start's answer.
type LoginStartStatus struct {
	// Supported is false when this host has no per-user start-at-login
	// mechanism this daemon can write; Reason says why.
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	// Manager is the capability that starts the daemon at login:
	// "systemd-user", "launchd" or "windows-run".
	Manager      string `json:"manager,omitempty"`
	ManagerLabel string `json:"manager_label,omitempty"`
	// Installed is true when Observer's entry exists (a unit file, a
	// LaunchAgent plist, a Run value).
	Installed bool `json:"installed"`
	// Enabled is true when the manager will start it at login.
	Enabled bool `json:"enabled"`
	// Running is true when the manager reports the service itself running.
	Running bool `json:"running"`
	// Path is the unit file, plist or registry value the control owns.
	Path string `json:"path,omitempty"`
	// Command is the daemon command line the entry runs, when installed.
	Command string `json:"command,omitempty"`
}

// LoginStartService is the dashboard's seam onto the user-level
// start-at-login install (`observer service install` / `uninstall` on Linux
// and macOS, `observer setup autostart` on Windows). It never starts, stops
// or restarts the daemon, and never overwrites an existing entry.
type LoginStartService interface {
	Status(ctx context.Context) (LoginStartStatus, error)
	// Apply installs or removes the entry. dryRun previews it.
	Apply(ctx context.Context, action SetupAction, dryRun bool) (SetupOutcome, error)
}

// BrowserExtensionCandidate is one SuperBased extension a local browser has
// loaded unpacked.
type BrowserExtensionCandidate struct {
	Browser string `json:"browser"`
	Profile string `json:"profile"`
	ID      string `json:"id"`
}

// BrowserCaptureStatus is GET /api/setup/browser's answer.
type BrowserCaptureStatus struct {
	// Supported is false when this build carries no browser-capture rail.
	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"`
	// HostFiles are the native-messaging files Observer wrote that exist now.
	HostFiles []string `json:"host_files"`
	// Installed is len(HostFiles) > 0.
	Installed bool `json:"installed"`
	// Candidates are extensions found loaded unpacked in local browsers.
	Candidates []BrowserExtensionCandidate `json:"candidates"`
}

// BrowserCaptureSetup is the dashboard's seam onto the browser-capture
// native-messaging host install (`observer init --browser`).
type BrowserCaptureSetup interface {
	Status(ctx context.Context) (BrowserCaptureStatus, error)
	// Apply installs the host (extensionID "" keeps the placeholder the CLI
	// writes). dryRun previews it. Removal stays on Settings > Components.
	Apply(ctx context.Context, extensionID string, dryRun bool) (SetupOutcome, error)
}
