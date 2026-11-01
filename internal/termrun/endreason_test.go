package termrun

import "testing"

// TestEndReasonForExit pins the code-only classification (Windows 11 Pro
// run 4, N3), one row per shape.
func TestEndReasonForExit(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		code int
		want string
	}{
		{0, EndChildExit},
		{1, EndChildExit},
		{7, EndChildExit},
		{3221225786, EndConsoleClosed},  // 0xC000013A as GetExitCodeProcess reports it
		{-1073741510, EndConsoleClosed}, // the same NTSTATUS as a signed 32-bit code
		{4294967295, EndStoppedOutside}, // 0xFFFFFFFF
		{-1, EndStoppedOutside},
	} {
		if got := EndReasonForExit(c.code); got != c.want {
			t.Errorf("EndReasonForExit(%d) = %q, want %q", c.code, got, c.want)
		}
	}
}

// TestEndLineNamesEveryReason: every reason has its own named line, and the
// line carries the exit code when one was seen.
func TestEndLineNamesEveryReason(t *testing.T) {
	t.Parallel()
	one := 1
	want := map[string]string{
		EndChildExit:            "the run ended: the tool exited (exit code 1)",
		EndConsoleClosed:        "the run ended: the console window was closed (exit code 1)",
		EndDashboardStop:        "the run ended: stopped from the dashboard (Stop & close) (exit code 1)",
		EndStoppedOutside:       "the run ended: stopped from outside (for example Stop-Process, taskkill /F or a kill signal) (exit code 1)",
		EndProcessGone:          "the run ended: the run's process is gone (ended outside Observer); its exit code is not known (exit code 1)",
		EndDaemonShutdown:       "the run ended: the Observer daemon stopped (exit code 1)",
		EndResumed:              "the run ended: resumed in a newer run (exit code 1)",
		EndOrgFloorHooksDrifted: "the run ended: ended by the organization's full-capture floor (the run's hooks drifted) (exit code 1)",
	}
	seen := map[string]bool{}
	for r, w := range want {
		if !KnownEndReason(r) {
			t.Errorf("%q is not known", r)
		}
		got := EndLine(r, &one)
		if got != w {
			t.Errorf("EndLine(%q) = %q, want %q", r, got, w)
		}
		if seen[got] {
			t.Errorf("two reasons share the line %q", got)
		}
		seen[got] = true
	}
	if len(endLines) != len(want) {
		t.Errorf("%d lines, %d pinned", len(endLines), len(want))
	}
	if got := EndLine(EndProcessGone, nil); got != "the run ended: the run's process is gone (ended outside Observer); its exit code is not known" {
		t.Errorf("no code: %q", got)
	}
	if got := EndLine("something-new", nil); got != "the run ended" || KnownEndReason("something-new") {
		t.Errorf("unknown reason: %q", got)
	}
}
