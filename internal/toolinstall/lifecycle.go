package toolinstall

import "time"

// Status is the closed lifecycle vocabulary of one recorded dashboard install
// (tool_installs.status).
type Status string

// The statuses.
const (
	// StatusInstalling: the install PTY was spawned; its exit is not yet seen.
	StatusInstalling Status = "installing"
	// StatusInstalled: the install command exited 0 and the tool's binary
	// resolves afterwards.
	StatusInstalled Status = "installed"
	// StatusInstalledNotFound: the install command exited 0 but the tool's
	// binary does NOT resolve afterwards (T-034j): it may have landed off
	// PATH or in another environment, or the installer stopped early while
	// still exiting 0. It is not reported as installed; it MAY have put
	// something on disk, so an uninstall stays on offer.
	StatusInstalledNotFound Status = "installed_not_found"
	// StatusInstallFailed: the install command exited non-zero. Nothing is
	// known to have been installed, so no uninstall is offered.
	StatusInstallFailed Status = "install_failed"
	// StatusInstallInterrupted: the daemon that spawned the install is gone
	// and never saw it exit. It MAY have installed something.
	StatusInstallInterrupted Status = "install_interrupted"
	// StatusUninstalling: the uninstall PTY was spawned; its exit is not yet
	// seen.
	StatusUninstalling Status = "uninstalling"
	// StatusUninstalled: the uninstall command exited 0.
	StatusUninstalled Status = "uninstalled"
	// StatusUninstallFailed: the uninstall command exited non-zero; the
	// package may still be there, so the uninstall stays on offer.
	StatusUninstallFailed Status = "uninstall_failed"
	// StatusUninstallInterrupted: the daemon that spawned the uninstall is
	// gone and never saw it exit.
	StatusUninstallInterrupted Status = "uninstall_interrupted"
)

// Event is something that happens to a record.
type Event string

// The events.
const (
	// EventExitOK: the tracked PTY exited 0 (for an install: and the binary
	// resolves afterwards).
	EventExitOK Event = "exit_ok"
	// EventExitOKNoBinary: an install PTY exited 0 but the tool's binary does
	// not resolve afterwards.
	EventExitOKNoBinary Event = "exit_ok_no_binary"
	// EventExitFail: the tracked PTY exited non-zero (or was killed).
	EventExitFail Event = "exit_fail"
	// EventOrphaned: the record is in flight but no live process in this
	// daemon tracks it (the daemon that spawned it restarted).
	EventOrphaned Event = "orphaned"
	// EventUninstallStart: the operator confirmed an uninstall.
	EventUninstallStart Event = "uninstall_start"
)

// transitions is THE lifecycle table: (from, event) -> to. A pair absent from
// the table is refused. One test row per entry (lifecycle_test.go).
var transitions = map[Status]map[Event]Status{
	StatusInstalling: {
		EventExitOK:         StatusInstalled,
		EventExitOKNoBinary: StatusInstalledNotFound,
		EventExitFail:       StatusInstallFailed,
		EventOrphaned:       StatusInstallInterrupted,
	},
	StatusUninstalling: {
		EventExitOK:   StatusUninstalled,
		EventExitFail: StatusUninstallFailed,
		EventOrphaned: StatusUninstallInterrupted,
	},
	StatusInstalled:            {EventUninstallStart: StatusUninstalling},
	StatusInstalledNotFound:    {EventUninstallStart: StatusUninstalling},
	StatusInstallInterrupted:   {EventUninstallStart: StatusUninstalling},
	StatusUninstallFailed:      {EventUninstallStart: StatusUninstalling},
	StatusUninstallInterrupted: {EventUninstallStart: StatusUninstalling},
}

// Next returns the status a record moves to on ev, or ok=false when the
// transition is not allowed from `from`.
func Next(from Status, ev Event) (Status, bool) {
	to, ok := transitions[from][ev]
	return to, ok
}

// InFlight reports whether a status is waiting on a live PTY.
func InFlight(s Status) bool {
	_, ok := transitions[s][EventOrphaned]
	return ok
}

// Uninstallable reports whether a record in status s may START an uninstall
// (the dashboard installed — or may have installed — something that is still
// there). The channel decides separately whether a command exists.
func Uninstallable(s Status) bool {
	_, ok := Next(s, EventUninstallStart)
	return ok
}

// UninstallableFrom lists every status an uninstall may start from — the
// compare-and-set guard the store applies so two confirms cannot both claim
// one record.
func UninstallableFrom() []Status {
	var out []Status
	for s, evs := range transitions {
		if _, ok := evs[EventUninstallStart]; ok {
			out = append(out, s)
		}
	}
	return out
}

// Forgettable reports whether the operator may drop the record (hide it):
// any settled status, never one a live PTY is still writing.
func Forgettable(s Status) bool {
	return s != "" && !InFlight(s) && validStatus[s]
}

// ForgettableFrom lists every status Forget accepts.
func ForgettableFrom() []Status {
	var out []Status
	for s := range validStatus {
		if Forgettable(s) {
			out = append(out, s)
		}
	}
	return out
}

var validStatus = map[Status]bool{
	StatusInstalling:           true,
	StatusInstalled:            true,
	StatusInstalledNotFound:    true,
	StatusInstallFailed:        true,
	StatusInstallInterrupted:   true,
	StatusUninstalling:         true,
	StatusUninstalled:          true,
	StatusUninstallFailed:      true,
	StatusUninstallInterrupted: true,
}

// ExitEvent maps a PTY exit code to its lifecycle event.
func ExitEvent(code int) Event {
	if code == 0 {
		return EventExitOK
	}
	return EventExitFail
}

// InstallExitEvent maps an INSTALL PTY's exit code plus whether the tool's
// binary resolves afterwards to its lifecycle event (T-034j): exit 0 with no
// binary is its own outcome, never "installed".
func InstallExitEvent(code int, binaryResolves bool) Event {
	switch {
	case code != 0:
		return EventExitFail
	case binaryResolves:
		return EventExitOK
	default:
		return EventExitOKNoBinary
	}
}

// InputWaitAfter is how long an install may run before the dashboard says it
// may be waiting for input (a vendor installer that stops at a prompt keeps
// its PTY open and its record "installing" forever). Most guided installs
// finish well inside it; a slow one is only told to look at its terminal.
const InputWaitAfter = 90 * time.Second

// MaybeWaitingForInput reports whether a record should be shown as possibly
// waiting for input in its terminal: still installing (or uninstalling)
// after InputWaitAfter. It is a hint to open the terminal, not a verdict.
func MaybeWaitingForInput(s Status, phaseStart, now time.Time) bool {
	return InFlight(s) && !phaseStart.IsZero() && now.Sub(phaseStart) >= InputWaitAfter
}
