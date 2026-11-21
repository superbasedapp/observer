//go:build !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

// fakeExitTable is a stand-in for termsession.Manager.ExitStatus.
type fakeExitTable struct {
	mu     sync.Mutex
	exited map[string]int
	gone   map[string]bool
}

func (f *fakeExitTable) status(handle string) (bool, int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gone[handle] {
		return false, 0, false
	}
	code, ok := f.exited[handle]
	return ok, code, true
}

func newTestLedger(t *testing.T, plan dashboardInstallPlan) (*toolInstallLedger, *store.Store, *fakeExitTable, *string) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	l := newToolInstallLedger(st, nil)
	l.now = func() time.Time { return time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC) }
	l.bootAt = time.Date(2026, 10, 2, 8, 0, 0, 0, time.UTC)
	l.planFor = func(string) (dashboardInstallPlan, bool) { return plan, plan.Channel != "" }
	bin := "/home/u/.local/bin/codex"
	l.resolveBin = func(string) string { return bin }
	l.lookArgv0 = nil
	ex := &fakeExitTable{exited: map[string]int{}, gone: map[string]bool{}}
	l.setExitStatus(ex.status)
	return l, st, ex, &bin
}

var npmCodexPlan = dashboardInstallPlan{
	Argv:    []string{"npm", "install", "--global", "--prefix", "/home/u/.local", "@openai/codex"},
	Display: "npm install --global --prefix /home/u/.local @openai/codex",
	Channel: "npm",
}

// TestToolInstallLedgerRoundTrip: install -> exit 0 -> installed (with the
// post-install resolution) -> uninstall (argv DERIVED from the recorded
// install, prefix kept) -> exit 0 -> uninstalled (resolution re-checked) ->
// forget.
func TestToolInstallLedgerRoundTrip(t *testing.T) {
	ctx := context.Background()
	l, st, _, bin := newTestLedger(t, npmCodexPlan)

	if err := l.RecordInstall(ctx, "codex", "h-install", npmCodexPlan.Argv, npmCodexPlan.Display); err != nil {
		t.Fatal(err)
	}
	rec, ok, err := l.Lookup(ctx, "codex")
	if err != nil || !ok || rec.Status != "installing" || rec.CanUninstall || rec.CanForget {
		t.Fatalf("while installing: %+v ok=%v err=%v", rec, ok, err)
	}
	if rec.Package != "@openai/codex" || rec.UninstallCommand != "npm uninstall --global --prefix /home/u/.local @openai/codex" {
		t.Fatalf("record = %+v", rec)
	}
	l.observeExit("some-other-handle", 0) // ignored
	l.observeExit("h-install", 0)
	l.observeExit("h-install", 1) // exactly once: the second exit is a no-op
	rec, _, _ = l.Lookup(ctx, "codex")
	if rec.Status != "installed" || !rec.CanUninstall || !rec.CanForget || rec.ResolvedBin != "/home/u/.local/bin/codex" || rec.ExitCode == nil || *rec.ExitCode != 0 {
		t.Fatalf("after install exit: %+v", rec)
	}

	var spawned []string
	started, err := l.Uninstall(ctx, "codex", rec.ID, func(argv []string) (string, error) {
		spawned = argv
		return "h-uninstall", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"npm", "uninstall", "--global", "--prefix", "/home/u/.local", "@openai/codex"}
	if !reflect.DeepEqual(spawned, want) {
		t.Fatalf("spawned %q, want %q", spawned, want)
	}
	if started.Handle != "h-uninstall" || started.Package != "@openai/codex" || started.RecordID != rec.ID {
		t.Fatalf("started = %+v", started)
	}
	// A second confirm while the first runs is refused.
	if _, err := l.Uninstall(ctx, "codex", rec.ID, func([]string) (string, error) { return "x", nil }); !errors.Is(err, dashapi.ErrToolInstallStale) {
		t.Fatalf("double uninstall: %v", err)
	}
	*bin = "" // the binary is gone after the uninstall
	l.observeExit("h-uninstall", 0)
	rec, _, _ = l.Lookup(ctx, "codex")
	if rec.Status != "uninstalled" || rec.CanUninstall || rec.ResolvedBin != "" || rec.UninstalledAt == nil || rec.UninstallExitCode == nil {
		t.Fatalf("after uninstall exit: %+v", rec)
	}
	row, _, _ := st.GetToolInstall(ctx, rec.ID)
	if !reflect.DeepEqual(row.UninstallArgv, want) {
		t.Errorf("stored uninstall argv = %q", row.UninstallArgv)
	}
	if err := l.Forget(ctx, "codex", rec.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := l.Lookup(ctx, "codex"); ok {
		t.Fatal("forgotten record must disappear")
	}
}

// TestToolInstallLedgerEdges covers the honest refusals and the races.
func TestToolInstallLedgerEdges(t *testing.T) {
	ctx := context.Background()

	t.Run("pre-registration exit is reconciled", func(t *testing.T) {
		l, _, ex, _ := newTestLedger(t, npmCodexPlan)
		ex.exited["h1"] = 2 // the PTY exited before RecordInstall ran
		if err := l.RecordInstall(ctx, "codex", "h1", npmCodexPlan.Argv, npmCodexPlan.Display); err != nil {
			t.Fatal(err)
		}
		rec, _, _ := l.Lookup(ctx, "codex")
		if rec.Status != "install_failed" || rec.CanUninstall || !rec.CanForget {
			t.Fatalf("got %+v", rec)
		}
	})

	t.Run("reaped handle settles as interrupted", func(t *testing.T) {
		l, _, ex, _ := newTestLedger(t, npmCodexPlan)
		ex.gone["h1"] = true
		_ = l.RecordInstall(ctx, "codex", "h1", npmCodexPlan.Argv, npmCodexPlan.Display)
		rec, _, _ := l.Lookup(ctx, "codex")
		if rec.Status != "install_interrupted" || !rec.CanUninstall {
			t.Fatalf("got %+v", rec)
		}
	})

	t.Run("previous daemon's in-flight row is orphaned on read", func(t *testing.T) {
		l, st, _, _ := newTestLedger(t, npmCodexPlan)
		before := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC) // a previous daemon's run
		id, _ := st.InsertToolInstall(ctx, store.ToolInstallRow{Tool: "codex", Channel: "npm", Argv: npmCodexPlan.Argv, Display: npmCodexPlan.Display, Status: "installed", StartedAt: before})
		if _, ok, err := st.ClaimToolUninstall(ctx, id, []string{"installed"}, "uninstalling", []string{"npm"}, "npm", before); !ok || err != nil {
			t.Fatalf("claim: %v", err)
		}
		recs, err := l.List(ctx)
		if err != nil || len(recs) != 1 || recs[0].ID != id || recs[0].Status != "uninstall_interrupted" || !recs[0].CanUninstall {
			t.Fatalf("got %+v err=%v", recs, err)
		}
	})

	t.Run("a row this process just inserted is never swept as an orphan", func(t *testing.T) {
		// Regression (live round trip 2026-10-02): a /api/terminal/installs
		// poll landing between RecordInstall's INSERT and its track() call
		// flipped the brand-new row to install_interrupted, and the real
		// exit then lost its compare-and-set.
		l, st, _, _ := newTestLedger(t, npmCodexPlan)
		id, _ := st.InsertToolInstall(ctx, store.ToolInstallRow{Tool: "codex", Channel: "npm", Argv: npmCodexPlan.Argv, Display: npmCodexPlan.Display, Status: "installing", StartedAt: l.now()})
		rec, _, _ := l.Lookup(ctx, "codex")
		if rec.ID != id || rec.Status != "installing" {
			t.Fatalf("got %+v", rec)
		}
		l.track("h-late", pendingToolInstallOp{id: id, tool: "codex", from: toolinstall.StatusInstalling})
		l.observeExit("h-late", 0)
		if rec, _, _ = l.Lookup(ctx, "codex"); rec.Status != "installed" {
			t.Fatalf("the real exit must still settle the row: %+v", rec)
		}
	})

	t.Run("vendor script: no uninstall, guidance, forget allowed", func(t *testing.T) {
		script := dashboardInstallPlan{Argv: []string{"bash", "-lc", "curl -fsSL https://claude.ai/install.sh | bash"}, Display: "curl -fsSL https://claude.ai/install.sh | bash", Channel: "script"}
		l, _, _, _ := newTestLedger(t, script)
		_ = l.RecordInstall(ctx, "claude-code", "h1", script.Argv, script.Display)
		l.observeExit("h1", 0)
		rec, _, _ := l.Lookup(ctx, "claude-code")
		if rec.Status != "installed" || rec.CanUninstall || rec.UninstallCommand != "" || rec.UninstallGuidance != toolinstall.NoDefinedUninstallGuidance || !rec.CanForget {
			t.Fatalf("got %+v", rec)
		}
		called := false
		_, err := l.Uninstall(ctx, "claude-code", rec.ID, func([]string) (string, error) { called = true; return "x", nil })
		if !errors.Is(err, dashapi.ErrToolUninstallUnsupported) || called {
			t.Fatalf("script uninstall: err=%v spawned=%v", err, called)
		}
		if err := l.Forget(ctx, "claude-code", rec.ID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("unknown tool and stale record id", func(t *testing.T) {
		l, _, _, _ := newTestLedger(t, npmCodexPlan)
		if _, err := l.Uninstall(ctx, "codex", 1, nil); !errors.Is(err, dashapi.ErrToolInstallNotFound) {
			t.Fatalf("no record: %v", err)
		}
		_ = l.RecordInstall(ctx, "codex", "h1", npmCodexPlan.Argv, npmCodexPlan.Display)
		l.observeExit("h1", 0)
		rec, _, _ := l.Lookup(ctx, "codex")
		if _, err := l.Uninstall(ctx, "codex", rec.ID+100, nil); !errors.Is(err, dashapi.ErrToolInstallStale) {
			t.Fatalf("stale id: %v", err)
		}
		if err := l.Forget(ctx, "codex", rec.ID+100); !errors.Is(err, dashapi.ErrToolInstallStale) {
			t.Fatalf("stale forget: %v", err)
		}
	})

	t.Run("spawn failure reverts the claim", func(t *testing.T) {
		l, _, _, _ := newTestLedger(t, npmCodexPlan)
		_ = l.RecordInstall(ctx, "codex", "h1", npmCodexPlan.Argv, npmCodexPlan.Display)
		l.observeExit("h1", 0)
		rec, _, _ := l.Lookup(ctx, "codex")
		boom := errors.New("setup in flight")
		if _, err := l.Uninstall(ctx, "codex", rec.ID, func([]string) (string, error) { return "", boom }); !errors.Is(err, boom) {
			t.Fatalf("err = %v", err)
		}
		rec, _, _ = l.Lookup(ctx, "codex")
		if rec.Status != "installed" || !rec.CanUninstall {
			t.Fatalf("after revert: %+v", rec)
		}
	})

	t.Run("failed uninstall stays retryable", func(t *testing.T) {
		l, _, _, _ := newTestLedger(t, npmCodexPlan)
		_ = l.RecordInstall(ctx, "codex", "h1", npmCodexPlan.Argv, npmCodexPlan.Display)
		l.observeExit("h1", 0)
		rec, _, _ := l.Lookup(ctx, "codex")
		_, _ = l.Uninstall(ctx, "codex", rec.ID, func([]string) (string, error) { return "h2", nil })
		l.observeExit("h2", 1)
		rec, _, _ = l.Lookup(ctx, "codex")
		if rec.Status != "uninstall_failed" || !rec.CanUninstall {
			t.Fatalf("got %+v", rec)
		}
	})

	t.Run("no plan: record refused", func(t *testing.T) {
		l, _, _, _ := newTestLedger(t, dashboardInstallPlan{})
		if err := l.RecordInstall(ctx, "codex", "h1", npmCodexPlan.Argv, npmCodexPlan.Display); err == nil {
			t.Fatal("want an error without a plan")
		}
	})

	t.Run("nil ledger is inert", func(t *testing.T) {
		var l *toolInstallLedger
		l.observeExit("h", 0)
		l.setExitStatus(nil)
		if newToolInstallLedgerFor(nil, nil) != nil {
			t.Fatal("no DB must mean no ledger")
		}
	})
}

// TestToolInstallLedgerLiveProgram: a recorded absolute program that no longer
// exists is re-resolved by base name, else falls back to the bare name.
func TestToolInstallLedgerLiveProgram(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "npm")
	if err := os.WriteFile(live, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	l := &toolInstallLedger{}
	if got := l.liveProgram(live); got != live {
		t.Errorf("existing program: %q", got)
	}
	if got := l.liveProgram("npm"); got != "npm" {
		t.Errorf("bare program: %q", got)
	}
	gone := filepath.Join(dir, "old", "npm")
	if got := l.liveProgram(gone); got != "npm" {
		t.Errorf("missing program without lookup: %q", got)
	}
	l.lookArgv0 = func(name string) (string, bool) {
		if name == "npm" {
			return live, true
		}
		return "", false
	}
	if got := l.liveProgram(gone); got != live {
		t.Errorf("missing program re-resolved: %q", got)
	}
	if !strings.HasSuffix(live, "npm") {
		t.Fatal("sanity")
	}
}

// TestToolInstallLedgerExitZeroWithoutBinary: an installer that exits 0 but
// leaves no resolvable binary is recorded installed_not_found, never
// installed, keeps the uninstall on offer and does not fire the post-install
// hook (T-034j).
func TestToolInstallLedgerExitZeroWithoutBinary(t *testing.T) {
	ctx := context.Background()
	l, _, _, bin := newTestLedger(t, npmCodexPlan)
	*bin = ""
	fired := false
	l.setOnInstalled(func(string) { fired = true })
	if err := l.RecordInstall(ctx, "codex", "h-install", npmCodexPlan.Argv, npmCodexPlan.Display); err != nil {
		t.Fatal(err)
	}
	l.observeExit("h-install", 0)
	rec, _, _ := l.Lookup(ctx, "codex")
	if rec.Status != string(toolinstall.StatusInstalledNotFound) || rec.ResolvedBin != "" || !rec.CanUninstall || !rec.CanForget || fired {
		t.Fatalf("exit 0 without a binary: %+v fired=%v", rec, fired)
	}
}

// TestToolInstallLedgerWaitingForInput: a live install past
// toolinstall.InputWaitAfter is flagged as possibly waiting for input and
// carries its terminal handle; a settled one carries neither (T-034j).
func TestToolInstallLedgerWaitingForInput(t *testing.T) {
	ctx := context.Background()
	l, _, _, _ := newTestLedger(t, npmCodexPlan)
	start := l.now()
	if err := l.RecordInstall(ctx, "codex", "h-install", npmCodexPlan.Argv, npmCodexPlan.Display); err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return start.Add(30 * time.Second) }
	rec, _, _ := l.Lookup(ctx, "codex")
	if rec.MaybeWaitingForInput || rec.TerminalHandle != "h-install" {
		t.Fatalf("young install: %+v", rec)
	}
	l.now = func() time.Time { return start.Add(toolinstall.InputWaitAfter + time.Second) }
	recs, err := l.List(ctx)
	if err != nil || len(recs) != 1 || !recs[0].MaybeWaitingForInput || recs[0].TerminalHandle != "h-install" {
		t.Fatalf("stalled install: %+v %v", recs, err)
	}
	l.observeExit("h-install", 0)
	rec, _, _ = l.Lookup(ctx, "codex")
	if rec.MaybeWaitingForInput || rec.TerminalHandle != "" {
		t.Fatalf("settled install still flagged: %+v", rec)
	}
}

// ---- sandbox setup records (subject_kind sandbox) --------------------------

// aptBwrapArgv is the argv toolinstall builds for bubblewrap on apt.
func aptBwrapArgv(t *testing.T) []string {
	t.Helper()
	pm, ok := toolinstall.PackageManagerByName("apt")
	if !ok {
		t.Fatal("no apt row")
	}
	_, argv, ok := toolinstall.InstallArgvFor(pm, []string{"bubblewrap"})
	if !ok {
		t.Fatal("no apt argv")
	}
	return argv
}

// TestSandboxLedgerSettlesWithTheVerify: a sandbox step settles from its
// prerequisite's own Detect (verify), never the tool binary, and never calls
// the post-install tool hook; a tool record's behaviour is unchanged.
func TestSandboxLedgerSettlesWithTheVerify(t *testing.T) {
	cases := []struct {
		name   string
		code   int
		found  string
		status toolinstall.Status
	}{
		{"exit 0 and detected", 0, "/usr/bin/bwrap", toolinstall.StatusInstalled},
		{"exit 0 but not detected", 0, "", toolinstall.StatusInstalledNotFound},
		{"exit 1", 1, "/usr/bin/bwrap", toolinstall.StatusInstallFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, st, _, _ := newTestLedger(t, npmCodexPlan)
			toolBinCalls, hookCalls := 0, 0
			l.resolveBin = func(string) string { toolBinCalls++; return "/x" }
			l.setOnInstalled(func(string) { hookCalls++ })
			argv := aptBwrapArgv(t)
			id, err := l.RecordSandboxInstall(context.Background(), sandboxInstallRecord{
				Name: "bwrap", Backend: "bwrap", Channel: "apt", Argv: argv, Display: toolinstall.DisplayArgv(argv), Elevated: true,
			}, "h-1", func(bool) string { return tc.found })
			if err != nil {
				t.Fatal(err)
			}
			l.observeExit("h-1", tc.code)
			row, ok, err := st.GetInstallRecord(context.Background(), store.SubjectSandbox, id)
			if err != nil || !ok {
				t.Fatalf("row: %v %v", ok, err)
			}
			if row.Status != string(tc.status) || row.Backend != "bwrap" || !row.Elevated || row.Package != "bubblewrap" {
				t.Fatalf("row = %+v", row)
			}
			if toolBinCalls != 0 || hookCalls != 0 {
				t.Fatalf("a sandbox record touched the tool path: resolveBin %d hook %d", toolBinCalls, hookCalls)
			}
			// The tool routes never see it.
			if recs, _ := l.List(context.Background()); len(recs) != 0 {
				t.Fatalf("tool List shows a sandbox record: %+v", recs)
			}
		})
	}
}

// TestSandboxLedgerOpsSettleFromTheOp: an op-driven record (a download)
// settles from the op's outcome with its digest and placed path.
func TestSandboxLedgerOpsSettleFromTheOp(t *testing.T) {
	l, st, _, _ := newTestLedger(t, npmCodexPlan)
	ctx := context.Background()
	rec := sandboxInstallRecord{Name: "cloud-hypervisor", Backend: "cloud-hypervisor", Channel: "pinned_download", Argv: []string{"pinned_download", "cloud-hypervisor", "v54"}, Display: "download", Source: "vendor_release"}
	id, err := l.BeginSandboxOp(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	// While the op runs, the orphan sweep never takes it.
	rows, _ := l.SandboxRecords(ctx)
	if len(rows) != 1 || rows[0].Status != string(toolinstall.StatusInstalling) {
		t.Fatalf("in flight = %+v", rows)
	}
	got, err := l.FinishSandboxOp(ctx, id, sandboxOpOutcome{Digest: "abc", PlacedPath: "/home/u/.observer/tools/cloud-hypervisor"}, func() string { return "/home/u/.observer/tools/cloud-hypervisor" })
	if err != nil || got != toolinstall.StatusInstalled {
		t.Fatalf("finish = %v %v", got, err)
	}
	row, _, _ := st.GetInstallRecord(ctx, store.SubjectSandbox, id)
	if row.Digest != "abc" || row.PlacedPath == "" || row.Source != "vendor_release" {
		t.Fatalf("row = %+v", row)
	}
	id2, _ := l.BeginSandboxOp(ctx, rec)
	if got, _ := l.FinishSandboxOp(ctx, id2, sandboxOpOutcome{Err: errors.New("sha256 mismatch")}, nil); got != toolinstall.StatusInstallFailed {
		t.Fatalf("failed op = %v", got)
	}
}

// TestSandboxLedgerReconcilesOrphans: an in-flight sandbox record a previous
// daemon left is settled as interrupted on the next read.
func TestSandboxLedgerReconcilesOrphans(t *testing.T) {
	l, st, _, _ := newTestLedger(t, npmCodexPlan)
	ctx := context.Background()
	id, err := st.InsertToolInstall(ctx, store.ToolInstallRow{
		SubjectKind: store.SubjectSandbox, Tool: "bwrap", Channel: "apt", Argv: aptBwrapArgv(t),
		Status: string(toolinstall.StatusInstalling), StartedAt: l.bootAt.Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := l.SandboxRecords(ctx)
	if err != nil || len(rows) != 1 || rows[0].ID != id || rows[0].Status != string(toolinstall.StatusInstallInterrupted) {
		t.Fatalf("rows = %+v %v", rows, err)
	}
}

// TestSandboxLedgerUninstallDerivesTheArgv: the undo of a package step runs
// toolinstall.PlanUninstall over the recorded argv (sudo kept, remove not
// purge) and settles on exit.
func TestSandboxLedgerUninstallDerivesTheArgv(t *testing.T) {
	l, st, _, _ := newTestLedger(t, npmCodexPlan)
	ctx := context.Background()
	argv := aptBwrapArgv(t)
	id, err := l.RecordSandboxInstall(ctx, sandboxInstallRecord{Name: "bwrap", Backend: "bwrap", Channel: "apt", Argv: argv, Display: "x", Elevated: true}, "h-1", func(bool) string { return "/usr/bin/bwrap" })
	if err != nil {
		t.Fatal(err)
	}
	l.observeExit("h-1", 0)
	want, err := toolinstall.PlanUninstall("apt", argv)
	if err != nil {
		t.Fatal(err)
	}
	var spawned []string
	started, err := l.UninstallSandbox(ctx, "bwrap", id, func(a []string) (string, error) { spawned = a; return "h-2", nil })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(spawned, want.Argv) || spawned[0] != "sudo" || started.Handle != "h-2" {
		t.Fatalf("spawned %v, want %v", spawned, want.Argv)
	}
	for _, a := range spawned {
		if a == "purge" || a == "autoremove" {
			t.Fatalf("uninstall argv %v purges", spawned)
		}
	}
	l.observeExit("h-2", 0)
	row, _, _ := st.GetInstallRecord(ctx, store.SubjectSandbox, id)
	if row.Status != string(toolinstall.StatusUninstalled) {
		t.Fatalf("status = %s", row.Status)
	}
	// A tool route can never act on it.
	if _, err := l.Uninstall(ctx, "bwrap", id, func([]string) (string, error) { return "", nil }); !errors.Is(err, dashapi.ErrToolInstallNotFound) {
		t.Fatalf("tool Uninstall on a sandbox record = %v", err)
	}
}

// TestSandboxLedgerForegroundAndUndone: the CLI's foreground settle and an
// in-process undo.
func TestSandboxLedgerForegroundAndUndone(t *testing.T) {
	l, st, _, _ := newTestLedger(t, npmCodexPlan)
	ctx := context.Background()
	id, err := l.SettleSandboxForeground(ctx, sandboxInstallRecord{Name: "component:bwrap", Backend: "bwrap", Channel: "component_select", Argv: []string{"components", "add", "x"}, Display: "x"}, 0, func(bool) string { return "x" })
	if err != nil {
		t.Fatal(err)
	}
	row, _, _ := st.GetInstallRecord(ctx, store.SubjectSandbox, id)
	if row.Status != string(toolinstall.StatusInstalled) {
		t.Fatalf("foreground = %s", row.Status)
	}
	if err := l.MarkSandboxUndone(ctx, "component:bwrap", id, "observer components remove x", nil); err != nil {
		t.Fatal(err)
	}
	row, _, _ = st.GetInstallRecord(ctx, store.SubjectSandbox, id)
	if row.Status != string(toolinstall.StatusUninstalled) {
		t.Fatalf("undone = %s", row.Status)
	}
	if err := l.MarkSandboxUndone(ctx, "component:bwrap", id, "again", nil); err == nil {
		t.Fatal("a second undo of a settled record was accepted")
	}
}
