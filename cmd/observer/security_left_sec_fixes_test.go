//go:build !sbo_omit_security

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secpostwrite"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestLeftSecWorktreeMissKeepsSighting (audit F1): an out-of-tree worktree
// sighting whose checkout is no longer listed closes as deleted only once
// the repository's worktree admin entries read whole without its key. A
// checkout off disk (not yet pruned) and an unreadable gitdir keep the
// blocking secret open.
func TestLeftSecWorktreeMissKeepsSighting(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	n := newGate2Node(t)
	gitInitMain(t, n.root)
	n.write(t, "README", "x\n")
	gitRun(t, n.root, "add", "README")
	gitRun(t, n.root, "commit", "-qm", "first")
	wt := filepath.Join(t.TempDir(), "wt")
	if r, err := filepath.EvalSymlinks(filepath.Dir(wt)); err == nil {
		wt = filepath.Join(r, "wt")
	}
	gitRun(t, n.root, "worktree", "add", "-q", "-b", "feature", wt)
	if err := os.MkdirAll(filepath.Join(wt, "pkg"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wt, "pkg", "a.go"), []byte(secretLine), 0o600); err != nil {
		t.Fatal(err)
	}
	pw, ok := store.PostWriteFor(n.root, "pkg/a.go", filePathInput(filepath.Join(wt, "pkg", "a.go")))
	if !ok || pw.Checkout != wt {
		t.Fatalf("the out-of-tree write was not placed under its checkout: %+v %v", pw, ok)
	}
	pw.SessionID, pw.ActionID = "s", 1
	ctx := context.Background()
	n.q.Submit(securityPostWriteFor(ctx, n.st, pw))
	n.q.Drain(ctx)
	opened := n.only(t, "secret.aws_access_key")
	if opened.Status != policy.FindingStatusOpen {
		t.Fatalf("finding %s, want open", opened.Status)
	}
	// Audit F3: the lane's finding exports as SARIF GitHub keeps (P-115).
	data, err := sarif.Encode([]secfinding.Finding{opened}, sarif.ToolInfo{Name: "SuperBased Observer", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if p := sarif.LocationProblems(data); len(p) != 0 {
		t.Fatalf("the worktree finding fails the location rule: %v", p)
	}
	if !strings.Contains(string(data), `"uri": "`+sarif.WorktreeURIPrefix+"/") || !strings.Contains(string(data), sarif.PropWorktree) {
		t.Fatalf("the worktree finding's SARIF location: %s", data)
	}
	// The rescan of a sighting whose checkout is not listed (what
	// securityRescanWrite builds then).
	unlisted := secpostwrite.Write{ProjectRoot: n.root, Path: pw.Path}
	rescan := func(shape string, wantOpen bool) {
		t.Helper()
		n.q.Submit(unlisted)
		n.q.Drain(ctx)
		f := n.only(t, "secret.aws_access_key")
		if open := f.Status == policy.FindingStatusOpen; open != wantOpen {
			t.Fatalf("%s: finding %s, want open=%v", shape, f.Status, wantOpen)
		}
	}
	// Off disk, git has not pruned it: unknown, never closed.
	if err := os.RemoveAll(wt); err != nil {
		t.Fatal(err)
	}
	rescan("checkout off disk", true)
	gitRun(t, n.root, "worktree", "prune")
	// An admin entry whose gitdir cannot be read: partial, kept open.
	odd := filepath.Join(n.root, ".git", "worktrees", "odd")
	if err := os.MkdirAll(filepath.Join(odd, "gitdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	rescan("unreadable gitdir", true)
	if err := os.RemoveAll(odd); err != nil {
		t.Fatal(err)
	}
	// A whole listing with no entry for the key: the worktree is gone.
	rescan("whole listing without the key", false)
}

// TestLeftSecManagedRefusesReflogCaps (audit F2): a managed node refuses
// both reflog caps the way it refuses the 64 KiB post-write cap (no cap
// applies, the history check keeps the S-792 deny) and status names each
// refusal; an individual node keeps the caps it chose.
func TestLeftSecManagedRefusesReflogCaps(t *testing.T) {
	local := config.DefaultSecurityConfig()
	local.Scanning.ReflogHoldMaxAgeDays, local.Scanning.ReflogHoldMaxEntries = 30, 100
	securityReflogBase.Store(&local)
	t.Cleanup(func() { securityReflogBase.Store(nil) })

	withSecurityScanningNode(t, true, local, "security.secrets")
	eff := securityFloorsApplied(local)
	if eff.Scanning.ReflogHoldMaxAgeDays != 0 || eff.Scanning.ReflogHoldMaxEntries != 0 {
		t.Fatalf("a managed node kept the reflog caps: %+v", eff.Scanning)
	}
	if age, entries := securityReflogCapsNow(); age != 0 || entries != 0 {
		t.Fatalf("the history check on a managed node reads caps %v %d, want none", age, entries)
	}
	lines := strings.Join(securityNodeSettingLines(local, eff, true), "\n")
	for _, k := range []string{
		"security.scanning.reflog_hold_max_age_days: 30 (default 0); refused on a managed node (it turns the push hold into an ask), 0 applies",
		"security.scanning.reflog_hold_max_entries: 100 (default 0); refused on a managed node (it turns the push hold into an ask), 0 applies",
	} {
		if !strings.Contains(lines, k) {
			t.Errorf("status does not say %q:\n%s", k, lines)
		}
	}

	withSecurityScanningNode(t, false, local, "security.secrets")
	if age, entries := securityReflogCapsNow(); age != 30*24*time.Hour || entries != 100 {
		t.Fatalf("an individual node's caps in force %v %d, want 30d 100", age, entries)
	}
	if got := strings.Join(securityNodeSettingLines(local, securityFloorsApplied(local), false), "\n"); strings.Contains(got, "refused") {
		t.Fatalf("an individual node's status says refused:\n%s", got)
	}
}

// TestLeftSecReflogListingCapRun (audit F6): a history answer left unknown
// by the reflog listing cap records one unknown run naming the cap (once
// per commit, not once per pass) and changes no hold.
func TestLeftSecReflogListingCapRun(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "obs.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	c := store.SecFindingCommit{ProjectRootHash: "ph-listing", CommitSHA: strings.Repeat("ab", 20)}
	v := secquickscan.HistoryVerdict{State: secquickscan.HistoryUnknown, Reason: secquickscan.HistoryReasonReflogListingCap}
	for i := 0; i < 2; i++ {
		if n, err := applyHistory(ctx, st, c, v, time.Now()); err != nil || n != 0 {
			t.Fatalf("pass %d: %d %v", i, n, err)
		}
	}
	var runs int
	var cov string
	if err := database.QueryRow(`SELECT COUNT(*), COALESCE(MAX(coverage_json), '') FROM sec_scan_runs WHERE project_root_hash = ? AND driver = ?`, c.ProjectRootHash, securityReflogCapDriver).Scan(&runs, &cov); err != nil {
		t.Fatal(err)
	}
	if runs != 1 || !strings.Contains(cov, secquickscan.HistoryReasonReflogListingCap) || !strings.Contains(cov, string(secscan.OutcomeUnknown)) {
		t.Fatalf("runs %d coverage %s, want one unknown run naming the listing cap", runs, cov)
	}
	// Any other unknown answer records nothing.
	other := store.SecFindingCommit{ProjectRootHash: "ph-listing", CommitSHA: strings.Repeat("cd", 20)}
	if _, err := applyHistory(ctx, st, other, secquickscan.HistoryVerdict{State: secquickscan.HistoryUnknown}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM sec_scan_runs WHERE project_root_hash = ?`, c.ProjectRootHash).Scan(&runs); err != nil || runs != 1 {
		t.Fatalf("a plain unknown recorded a run: %d %v", runs, err)
	}
}
