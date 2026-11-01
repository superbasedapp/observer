//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// TestRelayCloneOriginReadsManagedMeta (P-032): a recorded root inside a
// managed clone maps to the project its meta.json names; a remote clone,
// a root outside the managed tree, a linked meta.json and a relative origin
// map to nothing.
func TestRelayCloneOriginReadsManagedMeta(t *testing.T) {
	managed := t.TempDir()
	project := t.TempDir()
	write := func(id string, m workspace.Meta) string {
		t.Helper()
		ws := filepath.Join(managed, id, "repo")
		if err := os.MkdirAll(ws, 0o700); err != nil {
			t.Fatal(err)
		}
		b, err := workspace.MarshalMeta(m)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(managed, id, "meta.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		return ws
	}
	local := write("a", workspace.Meta{Source: workspace.SourceCloneLocal, Origin: project, RunID: "a", CreatedAt: time.Now()})
	remote := write("b", workspace.Meta{Source: workspace.SourceCloneRemote, Origin: "https://example.com/r.git", RunID: "b"})
	relative := write("c", workspace.Meta{Source: workspace.SourceCloneLocal, Origin: "proj", RunID: "c"})
	linked := filepath.Join(managed, "d", "repo")
	if err := os.MkdirAll(linked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := testSymlink(t, filepath.Join(managed, "a", "meta.json"), filepath.Join(managed, "d", "meta.json")); err != nil {
		t.Fatal(err)
	}
	origin := relayCloneOrigin(managed)
	for _, tc := range []struct {
		name, root, want string
	}{
		{"a local clone", local, project},
		{"a directory inside a local clone", filepath.Join(local, "sub"), project},
		{"a remote clone", remote, ""},
		{"a relative origin", relative, ""},
		{"a linked meta.json", linked, ""},
		{"outside the managed tree", project, ""},
		{"the managed root itself", managed, ""},
	} {
		if got := origin(tc.root); got != tc.want {
			t.Errorf("%s: origin %q, want %q", tc.name, got, tc.want)
		}
	}
	if relayCloneOrigin("") != nil {
		t.Error("no managed root must recognise no clone")
	}
}

// TestRelayLegacyRefusalMatchesTheBoxAnswer (lane sbx-p2c): a box running
// an earlier binary gets, for a refusal, the same exit code and output a
// current box gives its tool: a gate event blocks, a capture-only one is
// dropped with exit 0, a launch gate is refused.
func TestRelayLegacyRefusalMatchesTheBoxAnswer(t *testing.T) {
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		req := sandboxrelay.HookRequest{V: sandboxrelay.LegacyHookVersion, Kind: sandboxrelay.KindHook, Args: []string{"claude-code", event}}
		got := relayLegacyRefusal(req, sandboxrelay.RefusedPath)
		var stdout, stderr bytes.Buffer
		want := relayRefused("claude-code", canonicalHookEvent("claude-code", event), relayRequestGated(req), sandboxrelay.RefusedPath, &stdout, &stderr)
		if got.Exit != want || !bytes.Equal(got.Stdout, stdout.Bytes()) || !bytes.Equal(got.Stderr, stderr.Bytes()) {
			t.Errorf("%s: legacy answer %d %q %q, box answer %d %q %q", event, got.Exit, got.Stdout, got.Stderr, want, stdout.Bytes(), stderr.Bytes())
		}
		if relayRequestGated(req) && got.Exit == 0 && len(got.Stdout) == 0 {
			t.Errorf("%s: a gate event's legacy refusal does not block", event)
		}
	}
	if got := relayLegacyRefusal(sandboxrelay.HookRequest{Kind: sandboxrelay.KindLaunchGate, Args: []string{"claude-code"}}, sandboxrelay.RefusedRate); got.Exit == 0 {
		t.Error("a launch gate's legacy refusal allowed the launch")
	}
}

// TestRelayHealthReachesTheRunEvidence (P-032, milestone 2a): a lowered
// relay run marks its stored terminal run capture_degraded with the causes
// and the missed heartbeats, reseals the evidence digest so it still
// recomputes from the row, and shows on the live run pill.
func TestRelayHealthReachesTheRunEvidence(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "health.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	run := termrun.Run{RunID: "term-h", Tool: "claude-code", Kind: termrun.KindFresh, Isolation: termrun.Isolation{
		Class: "process", Stack: []string{"bwrap"}, EgressTier: "internet", CaptureLevel: "full",
		CaptureRule: "C6", CaptureOrigin: "sandboxed", Verification: "live", KeyCustody: "host_bound",
	}}
	if err := (termRunRecorder{st: st}).RecordRun(ctx, run); err != nil {
		t.Fatal(err)
	}
	before := runIsolationRecord(run).EvidenceDigest
	lower := func(ctx context.Context, id string, h store.TerminalRunCaptureHealth) error {
		_, err := st.LowerTerminalRunCapture(ctx, id, h, resealRunEvidence)
		return err
	}
	on := relayOnHealth(lower, nil)
	on(sandboxrelayd.RunRecord{RunID: "relay-h", TerminalRunID: "term-h"},
		sandboxrelayd.Health{Causes: []sandboxrelayd.DegradedCause{sandboxrelayd.CauseHooksDrifted, sandboxrelayd.CauseHeartbeatMissed}, MissedHeartbeats: 4})
	h, ok, err := st.LoadTerminalRunCaptureHealth(ctx, "term-h")
	if err != nil || !ok || h.Causes != "hooks_drifted,heartbeat_missed" || h.MissedHeartbeats != 4 {
		t.Fatalf("stored health %+v %v %v", h, ok, err)
	}
	rows, err := st.SelectTerminalRunRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var row *orgcontract.TerminalRunRow
	for i := range rows {
		if rows[i].RunID == "term-h" {
			row = &rows[i]
		}
	}
	if row == nil || !row.CaptureDegraded || row.EvidenceDigest == "" || row.EvidenceDigest == before {
		t.Fatalf("the stored row was not lowered and resealed: %+v", row)
	}
	lowered := runIsolationRecord(run)
	lowered.CaptureDegraded = true
	if !recomputeFromRecord("term-h", lowered).Verify(row.EvidenceDigest) {
		t.Fatal("the resealed digest does not recompute from the lowered row")
	}
	pill := launchIsolationFor(run.Isolation)
	relayPillHealth(pill, "term-h")
	if !pill.CaptureDegraded || !slices.Equal(pill.CaptureCauses, []string{"hooks_drifted", "heartbeat_missed"}) {
		t.Fatalf("pill %+v", pill)
	}
	other := launchIsolationFor(run.Isolation)
	relayPillHealth(other, "term-other")
	if other.CaptureDegraded {
		t.Fatal("another run's pill shows this run's health")
	}
}

// TestRelayHookProbeSeesAReplacedHookFile (sandbox plan P2 acceptance, "a
// hook file replaced mid-run marks the run hooks_drifted"): the helper's
// probe reads the registration the daemon wrote from the host side; once
// the tool's hook file is replaced by one without Observer's hooks, the
// drift rule fires.
func TestRelayHookProbeSeesAReplacedHookFile(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(home, ".observer", "config.toml")
	opts := hookRegistrationOptions(binary, cfgPath)
	opts.DryRun = false
	reg, err := hook.NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("claude-code"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}
	probe := relayHookProbe(sandboxrelayd.RunRecord{Tool: "claude-code", ConfigPath: cfgPath})
	if probe == nil {
		t.Fatal("no probe for a hook-capable tool")
	}
	base, err := probe()
	if err != nil || len(base.Events) == 0 {
		t.Fatalf("the launch's registration: %+v %v", base, err)
	}
	if again, _ := probe(); func() bool { d, _ := sandboxrelayd.HookDrift(base, again); return d }() {
		t.Fatal("an untouched registration drifted")
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{"hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	now, err := probe()
	if err != nil {
		t.Fatal(err)
	}
	if drifted, rule := sandboxrelayd.HookDrift(base, now); !drifted {
		t.Fatalf("a replaced hook file did not drift (%+v -> %+v)", base, now)
	} else if rule == "" {
		t.Fatal("no rule named")
	}
	if relayHookProbe(sandboxrelayd.RunRecord{Tool: "no-such-tool"}) != nil {
		t.Fatal("a probe for a tool with no hook mechanism")
	}
}

// TestRelayHookProbeSeesAProjectHooksSwitch (sandbox plan P2 audit finding
// 1): a box that turns the hooks off through a project-scope settings file
// in its workspace, leaving the user-level registration untouched, still
// marks the run hooks_drifted.
func TestRelayHookProbeSeesAProjectHooksSwitch(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(home, ".observer", "config.toml")
	opts := hookRegistrationOptions(binary, cfgPath)
	opts.DryRun = false
	reg, err := hook.NewRegistry(opts)
	if err != nil {
		t.Fatal(err)
	}
	if res := reg.Register("claude-code"); res.Error != nil {
		t.Fatalf("register: %v", res.Error)
	}
	ws := t.TempDir()
	probe := relayHookProbe(sandboxrelayd.RunRecord{Tool: "claude-code", ConfigPath: cfgPath, WorkspaceDir: ws, Roots: []string{ws}})
	base, err := probe()
	if err != nil || len(base.Events) == 0 || len(base.Disabled) != 0 {
		t.Fatalf("the launch's registration: %+v %v", base, err)
	}
	if err := os.MkdirAll(filepath.Join(ws, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".claude", "settings.local.json"), []byte(`{"disableAllHooks": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	now, err := probe()
	if err != nil {
		t.Fatal(err)
	}
	if len(now.Events) != len(base.Events) {
		t.Fatalf("the user-level registration changed: %+v -> %+v", base, now)
	}
	if drifted, rule := sandboxrelayd.HookDrift(base, now); !drifted || rule == "" {
		t.Fatalf("a project hooks switch did not drift (%+v -> %+v)", base, now)
	}
	other := relayHookProbe(sandboxrelayd.RunRecord{Tool: "codex", ConfigPath: cfgPath, WorkspaceDir: ws, Roots: []string{ws}})
	if other != nil {
		if r, err := other(); err == nil && len(r.Disabled) != 0 {
			t.Fatalf("a Claude Code switch counted for codex: %v", r.Disabled)
		}
	}
}
