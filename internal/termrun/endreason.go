package termrun

import "strconv"

// endreason.go is the vocabulary of why a terminal run ended (Windows 11 Pro
// run 4, N3): terminal_run.end_reason (node migration 072, an existing
// column; no migration) is recorded with the exit code, and every reason has
// one named line the CLI prints and the dashboard shows. The store is the one
// writer of the column and holds the same strings as store.EndReason*
// (pinned by TestEndReasonVocabularyMatchesStore in cmd/observer); this
// package owns the classification and the lines, so the daemon, the CLI and
// their tests share them.
const (
	// EndChildExit: the tool exited on its own (any code).
	EndChildExit = "child_exit"
	// EndConsoleClosed: the console window the run lived in was closed (a
	// CLI launch: the window's X, a log off or a shutdown; or the tool's own
	// STATUS_CONTROL_C_EXIT exit, 0xC000013A).
	EndConsoleClosed = "console_closed"
	// EndDashboardStop: the dashboard's Stop & close ended the run.
	EndDashboardStop = "dashboard_stop"
	// EndStoppedOutside: something outside Observer stopped the process
	// (exit code 0xFFFFFFFF, -1: Stop-Process, taskkill /F, or a POSIX
	// signal such as kill).
	EndStoppedOutside = "stopped_outside"
	// EndProcessGone: the daemon found a sandboxed CLI launch's helper gone
	// with its row still running; nobody saw the exit, so the code is NULL.
	EndProcessGone = "process_gone"
	// EndDaemonShutdown: the Observer daemon stopped while the run was live.
	EndDaemonShutdown = "daemon_shutdown"
	// EndResumed: a newer run resumed this one.
	EndResumed = "resumed"
	// EndOrgFloorHooksDrifted: the organization's full-capture floor ended
	// the run because its hooks drifted.
	EndOrgFloorHooksDrifted = "org_floor_require_full_capture_hooks_drifted"
)

// endLines are the named lines, one per reason.
var endLines = map[string]string{
	EndChildExit:            "the tool exited",
	EndConsoleClosed:        "the console window was closed",
	EndDashboardStop:        "stopped from the dashboard (Stop & close)",
	EndStoppedOutside:       "stopped from outside (for example Stop-Process, taskkill /F or a kill signal)",
	EndProcessGone:          "the run's process is gone (ended outside Observer); its exit code is not known",
	EndDaemonShutdown:       "the Observer daemon stopped",
	EndResumed:              "resumed in a newer run",
	EndOrgFloorHooksDrifted: "ended by the organization's full-capture floor (the run's hooks drifted)",
}

// KnownEndReason reports whether reason is in the vocabulary.
func KnownEndReason(reason string) bool {
	_, ok := endLines[reason]
	return ok
}

// EndLine is the named line for a run's end: "the run ended: the console
// window was closed (exit code 3221225786)". exitCode nil leaves the code
// out; an unknown reason says only that the run ended.
func EndLine(reason string, exitCode *int) string {
	s := "the run ended"
	if l, ok := endLines[reason]; ok {
		s += ": " + l
	}
	if exitCode != nil {
		s += " (exit code " + strconv.Itoa(*exitCode) + ")"
	}
	return s
}

// exitShapes classifies an exit by its code alone, for an end nobody
// announced (no Stop & close, no closed window seen): the first row that
// matches wins.
var exitShapes = []struct {
	match  func(code int) bool
	reason string
}{
	// 0xC000013A STATUS_CONTROL_C_EXIT: the console was closed or Ctrl+C or
	// Ctrl+Break ended it.
	{func(c int) bool { return uint32(c) == 0xC000013A }, EndConsoleClosed}, //nolint:gosec // G115: an exit code's NTSTATUS bits
	// 0xFFFFFFFF (-1): TerminateProcess from outside (Stop-Process,
	// taskkill /F), or a POSIX process ended by a signal.
	{func(c int) bool { return c == -1 || uint32(c) == 0xFFFFFFFF }, EndStoppedOutside}, //nolint:gosec // G115: an exit code's NTSTATUS bits
}

// EndReasonForExit is the reason an exit code alone gives: console_closed,
// stopped_outside, else child_exit.
func EndReasonForExit(code int) string {
	for _, r := range exitShapes {
		if r.match(code) {
			return r.reason
		}
	}
	return EndChildExit
}
