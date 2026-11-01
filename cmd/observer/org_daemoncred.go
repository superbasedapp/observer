package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// bindDaemonCredential is the daemon's half of WINNODE2 issue 1b. It
// persists every change of what the daemon sees of its own credential at
// each push cycle, so `observer org push-status`, `observer org status` and
// the dashboard's enrolment page say when the RUNNING daemon cannot push
// instead of showing a healthy loop. The credential itself is never moved
// (WINNODE2 merge ruling): a file-stored one stays readable by every logon
// context.
func bindDaemonCredential(c *orgclient.Client, st *store.Store) {
	if c == nil || st == nil {
		return
	}
	pid, started := os.Getpid(), time.Now().UTC().Format(time.RFC3339)
	c.SetCredentialSink(func(v orgclient.CredentialState) {
		_ = st.SaveOrgDaemonCredentialReport(context.Background(), store.OrgDaemonCredentialReport{
			PID: pid, StartedAt: started, Enrolled: v.Enrolled, Backend: v.Backend, Reason: v.Reason,
			At: time.Now().UTC().Format(time.RFC3339),
		})
	})
}

// daemonCredential is one live daemon's credential view, as read back.
type daemonCredential struct {
	lock diag.LockInfo
	// report is nil when the daemon has not run a push cycle yet (or is an
	// older build that does not report).
	report *store.OrgDaemonCredentialReport
}

// reportStartSlack absorbs the gap between a daemon writing its lock and
// binding its credential sink; a report older than that predates the daemon
// (an earlier daemon that had the same pid).
const reportStartSlack = 5 * time.Second

// liveDaemonCredentials pairs each live daemon lock with that daemon's own
// report.
func liveDaemonCredentials(locks []diag.LockInfo, reports []store.OrgDaemonCredentialReport) []daemonCredential {
	out := make([]daemonCredential, 0, len(locks))
	for _, l := range locks {
		dc := daemonCredential{lock: l}
		for i := range reports {
			r := reports[i]
			if r.PID != l.PID {
				continue
			}
			if t, err := time.Parse(time.RFC3339, r.StartedAt); err == nil && !l.StartedAt.IsZero() && t.Before(l.StartedAt.Add(-reportStartSlack)) {
				continue
			}
			dc.report = &r
			break
		}
		out = append(out, dc)
	}
	return out
}

// loadLiveDaemonCredentials reads the live daemons in dbDir and their
// reports.
func loadLiveDaemonCredentials(ctx context.Context, dbDir string, st *store.Store) []daemonCredential {
	locks, _ := diag.LiveLocks(dbDir)
	reports, _ := st.LoadOrgDaemonCredentialReports(ctx)
	return liveDaemonCredentials(locks, reports)
}

// notEnrolledDaemons is how many live daemons reported, at their last push
// cycle, that they could not read the org credential.
func notEnrolledDaemons(dcs []daemonCredential) int {
	n := 0
	for _, d := range dcs {
		if d.report != nil && !d.report.Enrolled {
			n++
		}
	}
	return n
}

// daemonCredentialFix is the one remedy sentence for a daemon that cannot
// read the org credential.
const daemonCredentialFix = "Enrol from the same sign-in the daemon runs in (on Windows, the developer's desktop sign-in is the clean path), or restart the daemon from the session that enrolled." //nolint:gosec // G101: an operator sentence, not a credential

// daemonCredentialLines renders one line per live daemon for push-status
// and org status: what that daemon itself last saw.
func daemonCredentialLines(dcs []daemonCredential) []string {
	var lines []string
	for _, d := range dcs {
		who := fmt.Sprintf("Daemon pid %d (started %s)", d.lock.PID, d.lock.StartedAt.Local().Format("2006-01-02 15:04 MST"))
		switch {
		case d.report == nil:
			lines = append(lines, who+": has not reported its credential yet (no push cycle since it started, or an older build)")
		case d.report.Enrolled:
			lines = append(lines, fmt.Sprintf("%s: enrolled, reads its credential from the %s store", who, credentialStoreName(d.report.Backend)))
		default:
			lines = append(lines, fmt.Sprintf("%s: NOT enrolled from its own view - %s (%s store, since %s). It cannot push; captured rows wait until it can. %s",
				who, d.report.Reason, credentialStoreName(d.report.Backend), d.report.At, daemonCredentialFix))
		}
	}
	return lines
}

// credentialStoreName is a backend name in plain words.
func credentialStoreName(backend string) string {
	switch backend {
	case "keychain":
		return "OS keychain"
	case "file":
		return "0600 file"
	case "":
		return "unknown"
	}
	return backend
}

// daemonCredentialWarning is the dashboard enrolment page's sentence when a
// live daemon reports it cannot read the org credential, "" otherwise.
func daemonCredentialWarning(dcs []daemonCredential) string {
	var reasons []string
	for _, d := range dcs {
		if d.report != nil && !d.report.Enrolled {
			reasons = append(reasons, fmt.Sprintf("the daemon (pid %d) cannot read the organization credential: %s", d.lock.PID, d.report.Reason))
		}
	}
	if len(reasons) == 0 {
		return ""
	}
	return "Not pushing: " + strings.Join(reasons, "; ") + ". Captured activity waits until it can. " + daemonCredentialFix
}

// lastPushBeforeDaemons reports whether the last push-log row predates every
// live daemon, so "Last attempt" is from an earlier daemon.
func lastPushBeforeDaemons(lastPush *store.PushLogEntry, dcs []daemonCredential) bool {
	if lastPush == nil || len(dcs) == 0 {
		return false
	}
	t, ok := parsePushStamp(lastPush.PushedAt)
	if !ok {
		return false
	}
	for _, d := range dcs {
		if d.lock.StartedAt.IsZero() || !t.Before(d.lock.StartedAt) {
			return false
		}
	}
	return true
}

// parsePushStamp reads an org_push_log timestamp (SQLite datetime UTC, or
// RFC 3339).
func parsePushStamp(s string) (time.Time, bool) {
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", s, time.UTC); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}
