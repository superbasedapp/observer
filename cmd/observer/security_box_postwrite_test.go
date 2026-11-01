//go:build !sbo_omit_security && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secpostwrite"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// boxRunsFixture points the process's run-record index at a fresh observer
// directory and restores it afterwards.
func boxRunsFixture(t *testing.T) string {
	t.Helper()
	obs := t.TempDir()
	prev := securityCopyRuns
	securityCopyRuns = &copyRunIndex{observerDir: func() string { return obs }}
	t.Cleanup(func() { securityCopyRuns = prev })
	return obs
}

// writeBoxRun writes a run record (and, when stack is set, its stored
// terminal run with that isolation stack, bound to the record).
func writeBoxRun(t *testing.T, st *store.Store, obs, id, workspace, copyPath string, copied bool, stack []string) {
	t.Helper()
	rec := sandboxrelayd.RunRecord{RunID: id, Tool: "codex", ProjectRoot: workspace, WorkspaceDir: workspace, Roots: []string{workspace}}
	if copied {
		rec.Delivery, rec.CopyHostPath = sandboxrelayd.DeliveryCopy, copyPath
	}
	rec, err := sandboxrelayd.NewRunRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	if stack != nil {
		if err := st.InsertTerminalRun(context.Background(), store.TerminalRun{RunID: "T" + id, Tool: "codex", Kind: "fresh", Isolation: store.TerminalRunIsolation{Stack: stack}}); err != nil {
			t.Fatal(err)
		}
		if err := sandboxrelayd.BindTerminalRun(obs, id, "T"+id); err != nil {
			t.Fatal(err)
		}
	}
}

// todaysWrite is the Write the feed submitted before lane sec-box.
func todaysWrite(w store.PostWrite) secpostwrite.Write {
	return secpostwrite.Write{SessionID: w.SessionID, ActionID: w.ActionID, ProjectRoot: w.ProjectRoot, Path: w.Path}
}

// TestSecurityPostWriteForRows: one case per row of the security plan's
// 4.8 table on the post-write feed (live, a copy the host can see, a copy
// only inside a box), plus a session tied to no run, which is exactly
// today's Write (golden), as is a clone-local copy recorded under its own
// root.
func TestSecurityPostWriteForRows(t *testing.T) {
	st, _ := openTestStore(t)
	obs := boxRunsFixture(t)
	base := t.TempDir()
	if r, err := filepath.EvalSymlinks(base); err == nil {
		base = r
	}
	dir := func(name string) string {
		p := filepath.Join(base, name)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	live, clone, recorded, hostCopy, remote, unknown := dir("live"), dir("clone"), dir("recorded"), dir("hostcopy"), dir("remote"), dir("unknown")
	writeBoxRun(t, st, obs, "RUNLIVE00001", live, "", false, []string{"bwrap"})
	writeBoxRun(t, st, obs, "RUNCLONE0001", clone, clone, true, []string{"oci-runc"})
	writeBoxRun(t, st, obs, "RUNHOSTC0001", recorded, hostCopy, true, []string{"oci-runc"})
	writeBoxRun(t, st, obs, "RUNREMOTE001", remote, remote, true, []string{"e2b"})
	writeBoxRun(t, st, obs, "RUNUNKNOWN01", unknown, unknown, true, nil)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		root string
		want func(store.PostWrite) secpostwrite.Write
	}{
		{"no run (golden)", dir("plain"), todaysWrite},
		{"live delivery", live, todaysWrite},
		{"clone-local copy recorded under its own root", clone, todaysWrite},
		{"copy the host can see, elsewhere", recorded, func(w store.PostWrite) secpostwrite.Write {
			out := todaysWrite(w)
			out.CopyWorkspace, out.WorkspaceRoot = true, hostCopy
			return out
		}},
		{"copy only inside a box", remote, func(w store.PostWrite) secpostwrite.Write {
			out := todaysWrite(w)
			out.CopyWorkspace = true
			return out
		}},
		{"copy whose backend is not known", unknown, func(w store.PostWrite) secpostwrite.Write {
			out := todaysWrite(w)
			out.CopyWorkspace = true
			return out
		}},
	} {
		w := store.PostWrite{SessionID: "s", ActionID: 9, ProjectRoot: tc.root, Path: "cfg.py"}
		if got, want := securityPostWriteFor(ctx, st, w), tc.want(w); got != want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, want)
		}
	}
	// Without the sandbox module's lookup the feed is today's, whatever
	// the records say.
	prev := securityCopyWorkspace
	securityCopyWorkspace = nil
	defer func() { securityCopyWorkspace = prev }()
	w := store.PostWrite{SessionID: "s", ActionID: 9, ProjectRoot: remote, Path: "cfg.py"}
	if got := securityPostWriteFor(ctx, st, w); got != todaysWrite(w) {
		t.Errorf("no lookup: %+v", got)
	}
}

// TestSecurityPostWriteInCopyWorkspace: a write in a copy the host can see
// is read under the copy root (its secret becomes a finding on the
// recorded project, closing nothing), a symlink there is refused, and a
// write in a copy only inside a box is a not_scanned copy_workspace run,
// never clean.
func TestSecurityPostWriteInCopyWorkspace(t *testing.T) {
	st, database := openTestStore(t)
	obs := boxRunsFixture(t)
	base := t.TempDir()
	if r, err := filepath.EvalSymlinks(base); err == nil {
		base = r
	}
	recorded, hostCopy, remote := filepath.Join(base, "recorded"), filepath.Join(base, "hostcopy"), filepath.Join(base, "remote")
	for _, d := range []string{recorded, hostCopy, remote} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := []byte("k = \"" + fakeSecretAWSKeyID + "\"\n")
	if err := os.WriteFile(filepath.Join(hostCopy, "cfg.py"), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	// The recorded root's own file is clean: had the scan read it, nothing
	// would be found.
	if err := os.WriteFile(filepath.Join(recorded, "cfg.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.py")
	if err := os.WriteFile(outside, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := testSymlink(t, outside, filepath.Join(hostCopy, "link.py")); err != nil {
		t.Skip("no symlinks here")
	}
	writeBoxRun(t, st, obs, "RUNHOSTC0001", recorded, hostCopy, true, []string{"oci-runc"})
	writeBoxRun(t, st, obs, "RUNREMOTE001", remote, remote, true, []string{"e2b"})
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	q := &secpostwrite.Queue{Scanner: secdetect.Scanner{Identify: func(typ, _ string) string { return "id-" + typ }}}
	var results []secpostwrite.Result
	q.Sink = func(_ context.Context, r secpostwrite.Result) { results = append(results, r) }
	for _, w := range []store.PostWrite{
		{SessionID: "s", ActionID: 1, ProjectRoot: recorded, Path: "cfg.py"},
		{SessionID: "s", ActionID: 2, ProjectRoot: recorded, Path: "link.py"},
		{SessionID: "s", ActionID: 3, ProjectRoot: remote, Path: "cfg.py"},
	} {
		q.Submit(securityPostWriteFor(ctx, st, w))
	}
	q.Drain(ctx)
	if len(results) != 3 {
		t.Fatalf("results %+v", results)
	}
	if results[1].NotScanned != secpostwrite.NotScannedRefused || results[2].NotScanned != secpostwrite.NotScannedCopyWorkspace {
		t.Fatalf("symlink %q, in-box %q", results[1].NotScanned, results[2].NotScanned)
	}
	for _, r := range results {
		recordPostWrite(ctx, st, r, logger)
	}
	var rel string
	if err := database.QueryRow(`SELECT rel_path FROM sec_findings WHERE project_root_hash = ? AND status = 'open'`, secposture.ProjectRootHash(recorded)).Scan(&rel); err != nil || rel != "cfg.py" {
		t.Fatalf("the copy's secret is not a finding: %q %v", rel, err)
	}
	var outcome, cov string
	if err := database.QueryRow(`SELECT outcome, coverage_json FROM sec_scan_runs WHERE project_root_hash = ?`, secposture.ProjectRootHash(remote)).Scan(&outcome, &cov); err != nil {
		t.Fatalf("no run for the in-box write: %v", err)
	}
	if outcome != "not_scanned" || !strings.Contains(cov, "copy_workspace") {
		t.Fatalf("in-box run %s %s", outcome, cov)
	}
}

// TestSecurityQuickScanRootRows: the quick-scan column of the 4.8 table.
// On the host path and for a live run the request is today's (the
// project root); a relayed commit in a copy the host can see is scanned
// in the copy; a copy only inside a box, or one the records do not place,
// makes the plan opaque (unknown, never clean).
func TestSecurityQuickScanRootRows(t *testing.T) {
	st, _ := openTestStore(t)
	obs := boxRunsFixture(t)
	prevStore := securityHookStore
	securityHookStore = func() *store.Store { return st }
	t.Cleanup(func() { securityHookStore = prevStore })
	base := t.TempDir()
	if r, err := filepath.EvalSymlinks(base); err == nil {
		base = r
	}
	clone, remote, orphan := filepath.Join(base, "clone"), filepath.Join(base, "remote"), filepath.Join(base, "orphan")
	writeBoxRun(t, st, obs, "RUNCLONE0001", clone, clone, true, []string{"oci-runc"})
	writeBoxRun(t, st, obs, "RUNREMOTE001", remote, remote, true, []string{"e2b"})
	pe := &policy.Event{Kind: policy.KindShellExec, Target: "git commit -m wip"}
	for _, tc := range []struct {
		name       string
		ch         *hookctx.Channel
		root       string
		wantRoot   string
		wantOpaque bool
	}{
		{"host path", nil, base, base, false},
		{"live run", &hookctx.Channel{Delivery: hookctx.DeliveryLive, ProjectRoot: base}, base, base, false},
		{"copy the host can see", &hookctx.Channel{Delivery: hookctx.DeliveryCopy, CopyHostPath: clone}, clone, clone, false},
		{"copy only inside a box", &hookctx.Channel{Delivery: hookctx.DeliveryCopy, CopyHostPath: remote}, remote, "", true},
		{"copy the records do not place", &hookctx.Channel{Delivery: hookctx.DeliveryCopy, CopyHostPath: orphan}, orphan, "", true},
	} {
		if tc.ch != nil {
			hookctx.SetProcess(hookctx.Daemon(context.Background(), hookctx.Request{}, *tc.ch, hookctx.DaemonProviders{}))
		} else {
			hookctx.SetProcess(nil)
		}
		plan := securityQuickScanPlanFor(pe, tc.root, nil)
		hookctx.SetProcess(nil)
		if plan.opaque != tc.wantOpaque {
			t.Errorf("%s: opaque %v", tc.name, plan.opaque)
			continue
		}
		if !tc.wantOpaque && (len(plan.reqs) != 1 || plan.reqs[0].ProjectRoot != tc.wantRoot) {
			t.Errorf("%s: requests %+v", tc.name, plan.reqs)
		}
	}
}
