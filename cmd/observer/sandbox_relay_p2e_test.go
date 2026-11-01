//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// TestRelayEndsUnderFullCaptureTable (SBX-P2E, sandbox plan 13.12 A10): one
// row per cause; only hook drift ends a run, and only while the org's
// require_full_capture floor is in force.
func TestRelayEndsUnderFullCaptureTable(t *testing.T) {
	cases := []struct {
		name  string
		cause sandboxrelayd.DegradedCause
		full  bool
		want  sandboxrelayd.DegradedCause
	}{
		{"drift under the floor", sandboxrelayd.CauseHooksDrifted, true, sandboxrelayd.CauseHooksDrifted},
		{"drift with no floor", sandboxrelayd.CauseHooksDrifted, false, ""},
		{"refused under the floor", sandboxrelayd.CauseRefused, true, ""},
		{"replayed under the floor", sandboxrelayd.CauseReplayed, true, ""},
		{"dropped under the floor", sandboxrelayd.CauseDropped, true, ""},
		{"rate limited under the floor", sandboxrelayd.CauseRateLimited, true, ""},
		{"heartbeat missed under the floor", sandboxrelayd.CauseHeartbeatMissed, true, ""},
	}
	for _, tc := range cases {
		h := sandboxrelayd.Health{Causes: []sandboxrelayd.DegradedCause{tc.cause}}
		if got := relayEndsUnderFullCapture(h, tc.full); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

// TestRelayFloorEnderEndsADriftedRunOnce: under require_full_capture a
// drifted run is ended through the daemon's teardown, once however many
// later health changes arrive; with the floor withdrawn nothing is ended;
// after the run ends its entry goes.
func TestRelayFloorEnderEndsADriftedRunOnce(t *testing.T) {
	full := true
	prev := relayRequireFullCapture
	relayRequireFullCapture = func() bool { return full }
	t.Cleanup(func() { relayRequireFullCapture = prev })

	var ended []string
	step := relayFloorEnder(func(id, reason, notice string) bool {
		if reason != store.EndReasonOrgFloorHooksDrifted || !strings.Contains(notice, `"Require full capture"`) || !strings.Contains(notice, "drifted") {
			t.Errorf("end reason %q, notice %q: want the org floor and the drift named", reason, notice)
		}
		ended = append(ended, id)
		return true
	}, nil)
	run := sandboxrelayd.RunRecord{RunID: "relay-1", TerminalRunID: "term-1"}
	drift := sandboxrelayd.Health{Causes: []sandboxrelayd.DegradedCause{sandboxrelayd.CauseHooksDrifted}}

	step(run, sandboxrelayd.Health{Causes: []sandboxrelayd.DegradedCause{sandboxrelayd.CauseRefused}})
	if len(ended) != 0 {
		t.Fatalf("a refusal ended the run: %v", ended)
	}
	step(run, drift)
	step(run, drift)
	if len(ended) != 1 || ended[0] != "term-1" {
		t.Fatalf("ended %v, want term-1 once", ended)
	}
	relayOnRunEnd(run)
	if _, ok := relayEndedByFloor.Load(run.RunID); ok {
		t.Fatal("the ended run's entry stayed after the run ended")
	}

	full = false
	other := sandboxrelayd.RunRecord{RunID: "relay-2", TerminalRunID: "term-2"}
	step(other, drift)
	if len(ended) != 1 {
		t.Fatalf("a drifted run ended with no floor in force: %v", ended)
	}
	relayOnRunEnd(other)
}

// TestRelayHealthStepsRecordBeforeEnding: the stored row is lowered (the
// record of why) before the run is ended.
func TestRelayHealthStepsRecordBeforeEnding(t *testing.T) {
	var order []string
	steps := relayHealthSteps(
		func(sandboxrelayd.RunRecord, sandboxrelayd.Health) { order = append(order, "record") },
		func(sandboxrelayd.RunRecord, sandboxrelayd.Health) { order = append(order, "end") },
	)
	steps(sandboxrelayd.RunRecord{}, sandboxrelayd.Health{})
	if len(order) != 2 || order[0] != "record" || order[1] != "end" {
		t.Fatalf("order %v", order)
	}
}

// TestIsolationFloorRefusalNamesTheMissingSandbox (SBX-P2E, plan 11.5): an
// isolation floor in force on a machine that cannot run a sandbox refuses
// an unsandboxed terminal naming both the floor and why the machine cannot
// sandbox; a machine that can keeps the retry reason.
func TestIsolationFloorRefusalNamesTheMissingSandbox(t *testing.T) {
	publishFloorsForTest(t, `{"min_isolation":"process"}`, true)
	prev := sandboxCannotRunHere
	t.Cleanup(func() { sandboxCannotRunHere = prev })

	sandboxCannotRunHere = func() string { return "this platform (macos) has no sandbox backend in this build" }
	ok, why := isolationFloorsAllowUnsandboxed()
	if ok || !strings.Contains(why, `"Minimum isolation"`) || !strings.Contains(why, "no sandbox backend in this build") {
		t.Fatalf("cannot sandbox: %v %q", ok, why)
	}
	sandboxCannotRunHere = func() string { return "" }
	if ok, why := isolationFloorsAllowUnsandboxed(); ok || !strings.Contains(why, "retry with sandbox enabled") {
		t.Fatalf("can sandbox: %v %q", ok, why)
	}
}

// TestSandboxRefusalReasonsAreTheWireSet (SBX-P2E): every reason the node's
// composition can give is one the push wire carries (orgcontract's closed
// list, which ingest clamps to), and every managed field's key is a wire key.
func TestSandboxRefusalReasonsAreTheWireSet(t *testing.T) {
	node := []string{
		sandboxRefusedPinned, sandboxRefusedNotAbsolute, sandboxRefusedBadCharacter, sandboxRefusedDotDot,
		sandboxRefusedLeadingDash, sandboxRefusedWholeRoot, sandboxRefusedObserverDir, sandboxRefusedCIDRNotAllowable,
		sandboxRefusedSensitive, sandboxRefusedPinnedEnabled,
	}
	if strings.Join(node, ",") != strings.Join(orgcontract.SandboxNodeRefusalReasons, ",") {
		t.Fatalf("node reasons %v, wire %v", node, orgcontract.SandboxNodeRefusalReasons)
	}
	var keys []string
	for _, f := range sandboxManagedFields {
		keys = append(keys, strings.TrimPrefix(f.key, sandboxPinPrefix))
	}
	if strings.Join(keys, ",") != strings.Join(orgcontract.SandboxManagedKeys, ",") {
		t.Fatalf("node keys %v, wire %v", keys, orgcontract.SandboxManagedKeys)
	}
}

// TestSandboxManagedRefusedRowsForThePush: the node's refusals reach the
// wire without their prefix, clamped; with no managed body in force the
// push carries none (an individual node does no work).
func TestSandboxManagedRefusedRowsForThePush(t *testing.T) {
	rows := sandboxManagedRefusedRows([]SandboxManagedRefusedKey{
		{Key: "terminal.sandbox.extra_rw_binds", Reason: sandboxRefusedSensitive},
		{Key: "terminal.sandbox.backends", Reason: sandboxRefusedPinned},
	})
	if len(rows) != 2 || rows[0].Key != "extra_rw_binds" || rows[1].Reason != "pinned_by_org" {
		t.Fatalf("rows %+v", rows)
	}
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{})
	if got := sandboxManagedRefusedForPush(t.Context()); got != nil {
		t.Fatalf("no body in force, but the push carries %+v", got)
	}
}

// TestSandboxManagedViewShowsEffectiveValues (SBX-P2E, P1c audit F10): the
// Card's organization view lists each key the in-force body sets with the
// EFFECTIVE value (mask_paths the union with the developer's own) and each
// key it refused with its reason; with no body in force it lists nothing.
// The push carries the same refusals.
func TestSandboxManagedViewShowsEffectiveValues(t *testing.T) {
	t.Cleanup(func() { processSandboxManaged.observe(orgclient.ManagedPullOutcome{}) })
	cfg := config.Default()
	cfg.Terminal.Sandbox.MaskPaths = []string{"/mine"}
	if m, r := sandboxManagedView(cfg); m != nil || r != nil {
		t.Fatalf("no body in force: %v %v", m, r)
	}
	body := []byte(`{"schema":"sbo-sandbox-managed-v1","prep_timeout_seconds":600,"mask_paths":["/org"],"node":{"extra_rw_binds":["/home/alice/.config/gh"]}}`)
	processSandboxManaged.observe(orgclient.ManagedPullOutcome{Rail: "sandbox", InForce: true, Version: 2, ExpiresAt: time.Now().Add(time.Hour).Unix(), Body: body})
	managed, refused := sandboxManagedView(cfg)
	got := map[string]string{}
	for _, v := range managed {
		got[v.Key] = v.Value
	}
	if runtime.GOOS == "windows" {
		// A managed body's paths are POSIX by contract
		// (orgcontract.validManagedPath). A Windows node cannot apply them,
		// so it refuses each path key not_absolute and the org sees that the
		// key did not apply; the rest of the body applies (ruling of the
		// Windows 11 Pro rerun 2026-10-25, D5 group 4).
		reasons := map[string]string{}
		for _, r := range refused {
			reasons[r.Key] = r.Value
		}
		if got["prep_timeout_seconds"] != "600" || got["mask_paths"] != "" ||
			reasons["mask_paths"] != sandboxRefusedNotAbsolute || reasons["extra_rw_binds"] != sandboxRefusedNotAbsolute {
			t.Fatalf("managed %+v refused %+v", managed, refused)
		}
		return
	}
	if got["prep_timeout_seconds"] != "600" || got["mask_paths"] != "/mine, /org" {
		t.Fatalf("managed %+v", managed)
	}
	if len(refused) != 1 || refused[0].Key != "extra_rw_binds" || refused[0].Value != sandboxRefusedSensitive {
		t.Fatalf("refused %+v", refused)
	}
}

// TestTerminalRunEnderBeforeTheServiceExists: a health delivery that
// arrives before the terminal service is built ends nothing and reports so.
func TestTerminalRunEnderBeforeTheServiceExists(t *testing.T) {
	var ref atomic.Pointer[termsvc.Service]
	if terminalRunEnder(&ref, nil, nil, nil)("run-1", store.EndReasonOrgFloorHooksDrifted, "") {
		t.Fatal("no service yet, but a run was reported ended")
	}
}
