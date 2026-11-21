package dashapi

import (
	"context"
	"errors"
	"time"
)

// ToolInstallRecord is the wire shape of one dashboard-install record.
type ToolInstallRecord struct {
	ID int64 `json:"id"`
	// Tool is the AI tool's name, or the prerequisite id of a sandbox
	// setup record (SubjectKind sandbox).
	Tool    string `json:"tool"`
	Channel string `json:"channel"`
	// SubjectKind is whose record this is: "tool" (an AI tool's guided
	// install, the default and what every tool route lists) or "sandbox" (a
	// sandbox setup step, agent migration 222). "" reads as tool.
	SubjectKind string `json:"subject_kind,omitempty"`
	// Backend is the sandbox backend a sandbox record was set up for.
	Backend string `json:"backend,omitempty"`
	// Source is where a pinned download came from (vendor_release,
	// org_mirror, from_file).
	Source string `json:"source,omitempty"`
	// Digest is the sha256 of a placed file.
	Digest string `json:"digest,omitempty"`
	// PlacedPath is the file Observer placed (a pinned download).
	PlacedPath string `json:"placed_path,omitempty"`
	// Elevated: the step ran under sudo or UAC.
	Elevated bool `json:"elevated,omitempty"`
	// Package is the identity the channel installed ("" for a vendor script).
	Package string `json:"package,omitempty"`
	// Command is the install command as it was shown to the operator.
	Command string `json:"command"`
	// Status is internal/toolinstall's closed lifecycle vocabulary.
	Status      string     `json:"status"`
	ExitCode    *int       `json:"exit_code,omitempty"`
	InstalledAt time.Time  `json:"installed_at"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
	// ResolvedBin is where the tool's binary resolved after the last
	// install/uninstall settled ("" = not found).
	ResolvedBin string `json:"resolved_bin,omitempty"`
	// CanUninstall: this record may start an uninstall now (its status allows
	// it, its channel has a defined uninstall command, and the guided-install
	// kill-switch is on).
	CanUninstall bool `json:"can_uninstall"`
	// UninstallCommand is the exact command an uninstall would run (display
	// form), set whenever the channel has one.
	UninstallCommand string `json:"uninstall_command,omitempty"`
	// UninstallGuidance is the honest copy for a channel with no defined
	// uninstall (a vendor script): set instead of UninstallCommand.
	UninstallGuidance string `json:"uninstall_guidance,omitempty"`
	// CanForget: the record may be dropped from these surfaces.
	CanForget bool `json:"can_forget"`
	// UninstalledAt / UninstallExitCode describe the last uninstall run.
	UninstallStartedAt *time.Time `json:"uninstall_started_at,omitempty"`
	UninstalledAt      *time.Time `json:"uninstalled_at,omitempty"`
	UninstallExitCode  *int       `json:"uninstall_exit_code,omitempty"`
	// TerminalHandle is the live PTY an in-flight install / uninstall runs in
	// ("" when none in this daemon tracks it), so the dashboard can open it.
	TerminalHandle string `json:"terminal_handle,omitempty"`
	// MaybeWaitingForInput: still in flight after
	// toolinstall.InputWaitAfter, so the installer may be sitting at a
	// prompt in its terminal (T-034j). A hint to open the terminal.
	MaybeWaitingForInput bool `json:"maybe_waiting_for_input,omitempty"`
}

// ToolUninstallStarted is what a successful uninstall spawn returns.
type ToolUninstallStarted struct {
	RecordID int64  `json:"record_id"`
	Handle   string `json:"handle"`
	Tool     string `json:"tool"`
	Command  string `json:"command"`
	Package  string `json:"package,omitempty"`
}

// ToolInstallLedger is the seam onto the node's dashboard-install record.
type ToolInstallLedger interface {
	// RecordInstall records an install the dashboard just spawned (handle is
	// its setup PTY) and tracks its exit. argv/display are the server-derived
	// command that was executed.
	RecordInstall(ctx context.Context, tool, handle string, argv []string, display string) error
	// Lookup returns the latest record for tool (ok=false: none).
	Lookup(ctx context.Context, tool string) (ToolInstallRecord, bool, error)
	// List returns the latest record per tool, newest first.
	List(ctx context.Context) ([]ToolInstallRecord, error)
	// Uninstall claims recordID (which must be tool's latest record and in an
	// uninstallable status), derives the uninstall argv from the recorded
	// install, spawns it through spawn, and tracks its exit. A spawn error is
	// returned unwrapped-compatible (errors.Is works) after the claim is
	// reverted.
	Uninstall(ctx context.Context, tool string, recordID int64, spawn func(argv []string) (string, error)) (ToolUninstallStarted, error)
	// Forget hides recordID (tool's latest record) from every surface.
	Forget(ctx context.Context, tool string, recordID int64) error
}

// Ledger errors the handlers map to statuses.
var (
	// ErrToolInstallNotFound: no record for the tool (404).
	ErrToolInstallNotFound = errors.New("no dashboard install is recorded for this tool")
	// ErrToolInstallStale: the record id is not the tool's latest record, or
	// its status no longer allows the action (409 - re-check and retry).
	ErrToolInstallStale = errors.New("the install record changed since this page loaded; re-check and try again")
	// ErrToolUninstallUnsupported: the record's channel has no defined
	// uninstall command (409, with the honest guidance).
	ErrToolUninstallUnsupported = errors.New("this install has no defined uninstall command")
)
