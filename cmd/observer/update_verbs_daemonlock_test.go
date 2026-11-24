//go:build !sbo_omit_org_update

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
)

// TestLiveDaemonForSkipsSelfAndEmpty pins the two "no daemon" answers of
// liveDaemonFor that need no second process: an empty database path, and a
// lock this very process wrote (a CLI never refuses because of itself).
func TestLiveDaemonForSkipsSelfAndEmpty(t *testing.T) {
	if _, ok := liveDaemonFor(""); ok {
		t.Fatal("an empty database path must answer no daemon")
	}
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	if _, err := diag.WriteLock(dir, diag.LockInfo{PID: os.Getpid(), StartedAt: time.Now().UTC(), DBPath: dbPath}); err != nil {
		t.Fatal(err)
	}
	if _, ok := liveDaemonFor(dbPath); ok {
		t.Fatal("this process's own lock must not count as a running daemon")
	}
}

// TestUpdateUnderDaemonRefusalNamesCauseAndFix pins REVIEW-4 P4-09: the
// refusal names the daemon, the cause and a fix, offers the daemon's own
// update loop only for an apply, and never offers it for a rollback.
func TestUpdateUnderDaemonRefusalNamesCauseAndFix(t *testing.T) {
	lock := diag.LockInfo{PID: 4242}
	db := filepath.Join(t.TempDir(), "observer.db")
	for _, tc := range []struct {
		rollback bool
		want     []string
		notWant  []string
	}{
		{false, []string{"observer update apply refused", "pid 4242", "swap the binary", "[update].auto_apply", "observer service stop", "observer-4242.lock"}, nil},
		{true, []string{"observer update rollback refused", "pid 4242", "database snapshot", "observer service stop"}, []string{"auto_apply"}},
	} {
		msg := updateUnderDaemonRefusal(lock, db, "127.0.0.1:8081", tc.rollback)
		for _, w := range tc.want {
			if !strings.Contains(msg, w) {
				t.Errorf("rollback=%v: refusal lacks %q:\n%s", tc.rollback, w, msg)
			}
		}
		for _, nw := range tc.notWant {
			if strings.Contains(msg, nw) {
				t.Errorf("rollback=%v: refusal must not offer %q:\n%s", tc.rollback, nw, msg)
			}
		}
	}
}
