package main

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestDaemonCredentialView (WINNODE2 item 1b(b)): push-status, org status
// and the dashboard report what each RUNNING daemon itself saw of its
// credential. A report from an earlier daemon that had the same pid is not
// taken for the running one's, and a push-log row older than every running
// daemon is named as an earlier daemon's.
func TestDaemonCredentialView(t *testing.T) {
	start := time.Date(2026, 10, 28, 13, 0, 0, 0, time.UTC)
	locks := []diag.LockInfo{{PID: 4242, StartedAt: start}}
	stale := store.OrgDaemonCredentialReport{PID: 4242, StartedAt: start.Add(-time.Hour).Format(time.RFC3339), Enrolled: true, Backend: "file", At: "x"}
	stuck := store.OrgDaemonCredentialReport{PID: 4242, StartedAt: start.Add(time.Second).Format(time.RFC3339), Enrolled: false, Backend: "keychain", Reason: "this process cannot read the org credential (bearer) from its credential store", At: "2026-10-28T13:00:05Z"}

	cases := []struct {
		name      string
		reports   []store.OrgDaemonCredentialReport
		wantLine  string
		wantStuck int
		wantWarn  bool
	}{
		{"no report yet", nil, "has not reported its credential yet", 0, false},
		{"an earlier daemon's report is ignored", []store.OrgDaemonCredentialReport{stale}, "has not reported its credential yet", 0, false},
		{"running daemon cannot read the credential", []store.OrgDaemonCredentialReport{stale, stuck}, "NOT enrolled from its own view", 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Readers get the reports by pid; a stale one first.
			dcs := liveDaemonCredentials(locks, tc.reports)
			lines := daemonCredentialLines(dcs)
			if len(lines) != 1 || !strings.Contains(lines[0], tc.wantLine) {
				t.Fatalf("lines = %q, want %q", lines, tc.wantLine)
			}
			if got := notEnrolledDaemons(dcs); got != tc.wantStuck {
				t.Fatalf("notEnrolledDaemons = %d, want %d", got, tc.wantStuck)
			}
			if w := daemonCredentialWarning(dcs); (w != "") != tc.wantWarn {
				t.Fatalf("warning = %q, want set=%v", w, tc.wantWarn)
			}
		})
	}

	dcs := liveDaemonCredentials(locks, nil)
	if !lastPushBeforeDaemons(&store.PushLogEntry{PushedAt: "2026-10-28 11:58:00"}, dcs) {
		t.Fatal("a push before the running daemon started is not named as an earlier daemon's")
	}
	if lastPushBeforeDaemons(&store.PushLogEntry{PushedAt: "2026-10-28 13:02:00"}, dcs) {
		t.Fatal("the running daemon's own push was named as an earlier daemon's")
	}
}
