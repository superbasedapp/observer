//go:build !sbo_omit_security && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// TestLeftSecHostedMarkerAfterRecord (audit F7): a hosted saved diff or kept
// diff error whose record write fails is not marked handled, so the next
// tick retries it; once the write succeeds it is marked.
func TestLeftSecHostedMarkerAfterRecord(t *testing.T) {
	step, database := boxTestStep(t, nil)
	obs, secDir, root := t.TempDir(), t.TempDir(), t.TempDir()
	returns := filepath.Join(hostedStateDir(obs), "returns")
	if err := os.MkdirAll(returns, 0o700); err != nil {
		t.Fatal(err)
	}
	diff := "diff --git a/cfg.py b/cfg.py\nnew file mode 100644\n--- /dev/null\n+++ b/cfg.py\n@@ -0,0 +1 @@\n+" + strings.TrimSuffix(secretLine, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(returns, "HOSTEDA.diff"), []byte(diff), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hostedWithState(obs, true, func() error {
		return hostedKeepDiffErrorLocked(obs, sandboxremote.Record{RunID: "HOSTEDB", Provider: "e2b", DiffError: "the box has no git"}, time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	projectOf := func(context.Context, string) string { return root }
	marked := func(id string) bool {
		_, err := os.Stat(filepath.Join(secDir, hostedReturnsMarkerDir, id))
		return err == nil
	}
	ctx := context.Background()
	if _, err := database.Exec(`CREATE TRIGGER leftsec_fail_runs BEFORE INSERT ON sec_scan_runs BEGIN SELECT RAISE(ABORT, 'test write failure'); END`); err != nil {
		t.Fatal(err)
	}
	securityScanHostedReturns(ctx, step, secDir, obs, projectOf)
	if marked("HOSTEDA") || marked("HOSTEDB") {
		t.Fatal("a run was marked handled although its record write failed")
	}
	if _, err := database.Exec(`DROP TRIGGER leftsec_fail_runs`); err != nil {
		t.Fatal(err)
	}
	securityScanHostedReturns(ctx, step, secDir, obs, projectOf)
	if !marked("HOSTEDA") || !marked("HOSTEDB") {
		t.Fatal("the retried runs were not marked after their records were written")
	}
	if n := boxCountRows(t, database, `SELECT COUNT(*) FROM sec_findings WHERE run_id = 'HOSTEDA'`); n == 0 {
		t.Fatal("the retried diff recorded no finding")
	}
}
