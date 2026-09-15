//go:build linux

package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// This fixture supplies native usage without a proxy or Observer launcher.
// The child is a disposable copied sleep executable, never a real adapter.
type nodeInterventionFixtureAdapter struct {
	name string
	root string
}

func (a nodeInterventionFixtureAdapter) Name() string {
	if a.name == "" {
		return "muse"
	}
	return a.name
}
func (a nodeInterventionFixtureAdapter) WatchPaths() []string { return []string{a.root} }
func (a nodeInterventionFixtureAdapter) IsSessionFile(path string) bool {
	return strings.HasSuffix(path, ".fixture")
}

func (a nodeInterventionFixtureAdapter) ParseSessionFile(ctx context.Context, path string, _ int64) (adapter.ParseResult, error) {
	if err := ctx.Err(); err != nil {
		return adapter.ParseResult{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return adapter.ParseResult{}, err
	}
	var tokens []models.TokenEvent
	if err := json.Unmarshal(raw, &tokens); err != nil {
		return adapter.ParseResult{}, err
	}
	return adapter.ParseResult{TokenEvents: tokens, NewOffset: int64(len(raw))}, nil
}

func TestNodeInterventionDirectProcessStopsFromNativeSpend(t *testing.T) {
	_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.UserID = "fixture-member" })
	// Start the control deadline after fixture schema setup. Race-instrumented
	// SQLite migrations are not part of the process-intervention latency.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("budget identity: active=%v err=%v", active, err)
	}
	durable, err := st.LoadOrgBudget(ctx)
	if err != nil || !durable.Witness.Valid() {
		t.Fatalf("durable budget witness: %+v err=%v", durable.Witness, err)
	}
	pricing, err := st.LoadOrgPricing(ctx)
	if err != nil || !pricing.Witness.Valid() {
		t.Fatalf("durable pricing witness: %+v err=%v", pricing.Witness, err)
	}
	pricingWitness := guard.BudgetDocumentWitness{
		Known: pricing.Witness.Known, Present: pricing.Witness.Present, SHA256: pricing.Witness.SHA256,
	}
	root := t.TempDir()
	launcher := filepath.Join(root, "muse")
	native := filepath.Join(root, "muse-bin-1.2.3")
	bytes, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(native, bytes, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest, err := intervention.BuildInstallManifest(ctx, []intervention.InstalledCandidate{{Tool: "muse", LauncherPath: launcher}})
	if err != nil {
		t.Fatal(err)
	}
	row, ok := manifest.Surface("muse/cli")
	if !ok || len(row.Targets) != 1 {
		t.Fatalf("fixture manifest: %+v", row)
	}
	start := func(path string) *exec.Cmd {
		t.Helper()
		// Ordinary shell launch; no Observer wrapper/proxy or session seed.
		cmd := exec.Command("/bin/sh", "-c", "exec \"$1\" 60", "fixture-shell", path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			id, e := intervention.Inspect(ctx, cmd.Process.Pid)
			if e == nil && (path != native || id.Executable == row.Targets[0].Executable.Identity) {
				return cmd
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("fixture did not reach native executable")
		return nil
	}
	target := start(native)
	sibling := start("/bin/sleep")
	registry := adapter.NewRegistry()
	registry.Register(nodeInterventionFixtureAdapter{root: root})
	capture := watcher.New(st, registry, watcher.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	source := filepath.Join(root, "usage.fixture")
	var events []models.TokenEvent
	addUsage := func(id string, usd float64) {
		t.Helper()
		events = append(events, models.TokenEvent{SessionID: "fixture-session", SourceEventID: id, SourceFile: source, ProjectRoot: root, Timestamp: time.Now().UTC(), Tool: "muse", Model: "fixture-priced-model", InputTokens: int64(usd * 1000), EstimatedCostUSD: 0.001, Source: "jsonl", Reliability: "approximate"})
		raw, e := json.Marshal(events)
		if e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(source, raw, 0o600); e != nil {
			t.Fatal(e)
		}
	}
	cfg := config.Default()
	cfg.Guard.Enabled, cfg.Guard.Mode = true, "enforce"
	gd, err := guard.New(guard.Options{Config: cfg.Guard, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := gd.ApplyOrgBudgetWithWitness(config.GuardBudgetConfig{DailyUSD: 0.35, Hard: true}, nil, false, policy.BudgetProtection{DailyUSD: true}, identity.Binding, guardBudgetDocumentWitness(durable.Witness)); err != nil {
		t.Fatal(err)
	}
	gd.SetBudgetAccountingLookup(func(sid string, accounting guard.BudgetAccountingContext) (guard.BudgetSnapshot, bool) {
		now := time.Now().UTC()
		day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		spend, e := st.GuardBudgetSpendPriced(ctx, sid, day, day.Add(-7*24*time.Hour), day.AddDate(0, -1, 0), func(_ string, _ time.Time, split store.PushTokenSplit) (float64, string, bool) {
			return float64(split.Input) / 1000, "exact", true
		}, store.GuardBudgetReadOptions{Managed: accounting.Managed})
		return guard.BudgetSnapshot{
			DailyUSD: spend.DailyUSD, USDUnavailable: policy.BudgetUnavailableWindows{Daily: spend.UnpricedWindows.Daily},
			PricingDocumentWitness: pricingWitness,
			AccountingEvidence:     &guard.BudgetAccountingEvidence{Fence: func(_ context.Context, action func() error) error { return action() }},
		}, e == nil
	})
	opts := intervention.ScanOptions{TargetUID: os.Getuid(), ControllerPID: os.Getpid()}
	cycle := func() []intervention.Outcome {
		t.Helper()
		_, out, e := reconcileNodeIntervention(ctx, st, cfg, gd, capture, manifest, opts)
		if e != nil {
			t.Fatal(e)
		}
		return out
	}
	addUsage("first", 0.25)
	if out := cycle(); len(out) != 1 || out[0].Status != "allowed" {
		t.Fatalf("under-cap native process: %+v", out)
	}
	addUsage("second", 0.10)
	if out := cycle(); len(out) != 1 || !out[0].Stopped || out[0].RuleID != "B-602" {
		t.Fatalf("native exhaustion did not stop: %+v", out)
	}
	if _, err := intervention.Inspect(ctx, sibling.Process.Pid); err != nil {
		t.Fatalf("unrelated sibling affected: %v", err)
	}
	_ = target.Wait()
	second := start(native)
	if out := cycle(); len(out) != 1 || !out[0].Stopped {
		t.Fatalf("new direct launch escaped exhausted cap: %+v", out)
	}
	_ = second.Wait()
	if err := gd.ApplyOrgBudget(config.GuardBudgetConfig{}, nil, false, policy.BudgetProtection{}, identity.Binding); err != nil {
		t.Fatal(err)
	}
	_ = start(native)
	if out := cycle(); len(out) != 1 || out[0].Status != "allowed" {
		t.Fatalf("removed cap did not recover: %+v", out)
	}
}

// TestNodeInterventionScopesAccountingFailureToItsOwnTool pins R1/R2/R3 of the
// accounting-readiness correction (2026-09-14) end to end on real processes:
//
//   - a governed tool with no store at all runs under an unexhausted cap (the
//     catch-22 fix: it was stopped before it could write the source that would
//     have made it "ready");
//   - one tool's broken source stops only that tool's processes, in the same
//     cycle in which the other tool's processes are allowed.
func TestNodeInterventionScopesAccountingFailureToItsOwnTool(t *testing.T) {
	_, dbPath := writeManagedBudgetLaunchFixture(t, true, "enforce")
	rewriteBudgetLaunchEnrolment(t, dbPath, func(e *store.Enrolment) { e.UserID = "fixture-member" })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	st := store.New(database)
	identity, active, err := orgclient.CurrentBudgetIdentity(ctx, st)
	if err != nil || !active {
		t.Fatalf("budget identity: active=%v err=%v", active, err)
	}
	durable, err := st.LoadOrgBudget(ctx)
	if err != nil || !durable.Witness.Valid() {
		t.Fatalf("durable budget witness: %+v err=%v", durable.Witness, err)
	}
	pricing, err := st.LoadOrgPricing(ctx)
	if err != nil || !pricing.Witness.Valid() {
		t.Fatalf("durable pricing witness: %+v err=%v", pricing.Witness, err)
	}
	pricingWitness := guard.BudgetDocumentWitness{
		Known: pricing.Witness.Known, Present: pricing.Witness.Present, SHA256: pricing.Witness.SHA256,
	}

	install := t.TempDir()
	sleepBytes, err := os.ReadFile("/bin/sleep")
	if err != nil {
		t.Fatal(err)
	}
	// muse binds through its declared versioned-sibling worker; opencode binds
	// its native launcher directly. Two different binding shapes, two tools.
	museLauncher := filepath.Join(install, "muse")
	museNative := filepath.Join(install, "muse-bin-1.2.3")
	opencodeNative := filepath.Join(install, "opencode")
	if err := os.WriteFile(museLauncher, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{museNative, opencodeNative} {
		if err := os.WriteFile(path, sleepBytes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := intervention.BuildInstallManifest(ctx, []intervention.InstalledCandidate{
		{Tool: "muse", LauncherPath: museLauncher},
		{Tool: "opencode", LauncherPath: opencodeNative},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets := map[string]string{"muse/cli": museNative, "opencode/cli": opencodeNative}
	for id, path := range targets {
		row, ok := manifest.Surface(id)
		if !ok || len(row.Targets) != 1 || row.Targets[0].Executable.Path != path {
			t.Fatalf("fixture manifest for %s: %+v", id, row)
		}
	}
	start := func(surfaceID string) *exec.Cmd {
		t.Helper()
		path := targets[surfaceID]
		row, _ := manifest.Surface(surfaceID)
		cmd := exec.Command("/bin/sh", "-c", "exec \"$1\" 60", "fixture-shell", path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			id, e := intervention.Inspect(ctx, cmd.Process.Pid)
			if e == nil && id.Executable == row.Targets[0].Executable.Identity {
				return cmd
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("%s fixture did not reach its native executable", surfaceID)
		return nil
	}

	// muse has a store directory with no session file yet; opencode has no
	// store at all. Both are "this tool has captured nothing", which is
	// measured zero spend for that tool.
	museRoot := t.TempDir()
	opencodeRoot := filepath.Join(t.TempDir(), "absent")
	registry := adapter.NewRegistry()
	registry.Register(nodeInterventionFixtureAdapter{name: "muse", root: museRoot})
	registry.Register(nodeInterventionFixtureAdapter{name: "opencode", root: opencodeRoot})
	capture := watcher.New(st, registry, watcher.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})

	cfg := config.Default()
	cfg.Guard.Enabled, cfg.Guard.Mode = true, "enforce"
	gd, err := guard.New(guard.Options{Config: cfg.Guard, Home: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if err := gd.ApplyOrgBudgetWithWitness(config.GuardBudgetConfig{DailyUSD: 1, Hard: true}, nil, false,
		policy.BudgetProtection{DailyUSD: true}, identity.Binding, guardBudgetDocumentWitness(durable.Witness)); err != nil {
		t.Fatal(err)
	}
	gd.SetBudgetAccountingLookup(func(sid string, accounting guard.BudgetAccountingContext) (guard.BudgetSnapshot, bool) {
		now := time.Now().UTC()
		day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
		spend, e := st.GuardBudgetSpendPriced(ctx, sid, day, day.Add(-7*24*time.Hour), day.AddDate(0, -1, 0),
			func(_ string, _ time.Time, split store.PushTokenSplit) (float64, string, bool) {
				return float64(split.Input) / 1000, "exact", true
			}, store.GuardBudgetReadOptions{Managed: accounting.Managed})
		return guard.BudgetSnapshot{
			DailyUSD: spend.DailyUSD,
			USDUnavailable: policy.BudgetUnavailableWindows{
				Session: spend.UnpricedWindows.Session, Daily: spend.UnpricedWindows.Daily,
				Weekly: spend.UnpricedWindows.Weekly, Monthly: spend.UnpricedWindows.Monthly,
			},
			PricingDocumentWitness: pricingWitness,
			AccountingEvidence:     &guard.BudgetAccountingEvidence{Fence: func(_ context.Context, action func() error) error { return action() }},
		}, e == nil
	})

	opts := intervention.ScanOptions{TargetUID: os.Getuid(), ControllerPID: os.Getpid()}
	cycle := func() (nodeInterventionStatus, map[string]intervention.Outcome) {
		t.Helper()
		status, out, e := reconcileNodeIntervention(ctx, st, cfg, gd, capture, manifest, opts)
		if e != nil {
			t.Fatal(e)
		}
		bySurface := make(map[string]intervention.Outcome, len(out))
		for _, o := range out {
			bySurface[o.Workload.SurfaceID] = o
		}
		return status, bySurface
	}

	// Neither tool has written a store yet. That is measured zero spend for
	// both, not unknown spend, so both freshly launched processes survive.
	museProc := start("muse/cli")
	opencodeProc := start("opencode/cli")
	status, outcomes := cycle()
	if len(outcomes) != 2 {
		t.Fatalf("bound workloads = %+v, want both surfaces", outcomes)
	}
	for id, outcome := range outcomes {
		if outcome.Status != "allowed" || outcome.Stopped {
			t.Fatalf("%s stopped before it could write a source: %+v", id, outcome)
		}
	}
	for tool, wantReason := range map[string]string{
		"muse":     watcher.BudgetCaptureReasonNoFiles,
		"opencode": watcher.BudgetCaptureReasonMissingRoot,
	} {
		if row, ok := status.Capture[tool]; !ok || !row.Ready || row.Reason != wantReason {
			t.Fatalf("capture report for %s = %+v present=%v, want ready %s", tool, row, ok, wantReason)
		}
	}

	// Break ONLY muse's source, and break it STRUCTURALLY: a session-file
	// symlink whose target escapes the adapter's watch roots is never opened,
	// so nothing on this node can read muse's spend. The fixture used to be a
	// failing parser, but a parse error against the tail a RUNNING tool is
	// writing is merely delayed since the 2026-09-15 ruling and must no longer
	// stop anything; a structural reason keeps this test pinning the
	// fail-closed path it was written for. opencode's accounting is untouched,
	// so its process must keep running under the same unexhausted cap - in the
	// same cycle that stops muse.
	escaped := filepath.Join(t.TempDir(), "escaped.fixture")
	if err := os.WriteFile(escaped, []byte("[]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(escaped, filepath.Join(museRoot, "broken.fixture")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	status, outcomes = cycle()
	muse, opencode := outcomes["muse/cli"], outcomes["opencode/cli"]
	if !muse.Stopped || muse.RuleID != "B-602" {
		t.Fatalf("broken muse source did not stop muse: %+v", muse)
	}
	if !strings.Contains(muse.Reason, "accounting source unavailable for muse: unsafe_symlink") {
		t.Fatalf("muse stop reason = %q, want it to name its own broken source", muse.Reason)
	}
	if opencode.Status != "allowed" || opencode.Stopped {
		t.Fatalf("healthy tool stopped by another tool's broken source: %+v", opencode)
	}
	if row := status.Capture["muse"]; row.Ready || row.Delayed ||
		row.Reason != watcher.BudgetCaptureReasonUnsafeSymlink {
		t.Fatalf("capture report for muse = %+v", row)
	}
	if row := status.Capture["opencode"]; !row.Ready {
		t.Fatalf("capture report for opencode = %+v", row)
	}
	if _, err := intervention.Inspect(ctx, opencodeProc.Process.Pid); err != nil {
		t.Fatalf("healthy tool process was signalled: %v", err)
	}
	_ = museProc.Wait()
}
