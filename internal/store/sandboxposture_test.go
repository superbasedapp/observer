package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSandboxPostureComposition: the posture aggregate ships only under the
// terminal_detail tier AND only while the sandbox module binds its
// capability seam; it counts runs per day by the closed enums, leaves out
// runs that recorded no evidence, and carries no tool, run id or hash.
func TestSandboxPostureComposition(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i, iso := range []TerminalRunIsolation{
		{Class: "process", Stack: []string{"bwrap"}, CaptureLevel: "full", CaptureOrigin: "sandboxed", Verification: "live", KeyCustody: "host_bound"},
		{Class: "process", Stack: []string{"bwrap"}, CaptureLevel: "full", CaptureOrigin: "sandboxed", Verification: "live", KeyCustody: "host_bound"},
		{Class: "none", CaptureOrigin: "local"},
		{},
	} {
		if err := s.InsertTerminalRun(ctx, TerminalRun{
			RunID: "run-" + string(rune('a'+i)), Tool: "secret-tool-name", Kind: "fresh",
			ProjectRootHash: "deadbeefcafe", LaunchedAt: now, Isolation: iso,
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.SelectSandboxPostureRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows %+v, want two buckets (the evidence-less run left out)", rows)
	}
	for _, r := range rows {
		if r.IsolationClass == "process" && r.Runs != 2 {
			t.Fatalf("process bucket %+v, want 2 runs", r)
		}
	}
	b, _ := json.Marshal(rows)
	for _, leak := range []string{"secret-tool-name", "run-a", "deadbeefcafe", "bwrap"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("posture rows carry %q: %s", leak, b)
		}
	}

	// Module inactive (no provider): nothing composes.
	if days, capRow, err := s.composeSandboxPosture(ctx, nil, "org", "dev@example.test"); err != nil || days != nil || capRow != nil {
		t.Fatalf("an unbound seam composed %v %v %v", days, capRow, err)
	}
	s.SetSandboxCapabilityProvider(func() (orgcontract.SandboxCapabilityRow, bool) {
		return orgcontract.SandboxCapabilityRow{Backends: []string{"bwrap"}, MaxClass: "process", FullCapture: true}, true
	})
	off, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org", "dev@example.test", ShareOptions{}, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if off.SandboxPosture != nil || off.SandboxCapability != nil {
		t.Fatalf("posture shipped without the terminal_detail tier: %+v", off.SandboxPosture)
	}
	on, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org", "dev@example.test", ShareOptions{TerminalDetail: true}, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(on.SandboxPosture) != 2 || on.SandboxCapability == nil || on.SandboxCapability.MaxClass != "process" {
		t.Fatalf("posture under terminal_detail: %+v %+v", on.SandboxPosture, on.SandboxCapability)
	}
	s.SetSandboxCapabilityProvider(nil)
	again, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org", "dev@example.test", ShareOptions{TerminalDetail: true}, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if again.SandboxPosture != nil || again.SandboxCapability != nil {
		t.Fatal("posture shipped after the module unbound its seam")
	}
}

// TestSandboxPostureSeccompSplit (lane FU4, tracker F-002): runs of one
// bucket that recorded different seccomp states stay ONE bucket with the
// sum in Runs and the states as counts; a run with no recorded state, or a
// value outside the closed vocabulary, counts only in Runs; and the value is
// stored and read back per run (migration 232).
func TestSandboxPostureSeccompSplit(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	base := TerminalRunIsolation{Class: "process", Stack: []string{"bwrap"}, CaptureLevel: "full", CaptureOrigin: "sandboxed", Verification: "live", KeyCustody: "host_bound"}
	for i, sc := range []string{"observer_default", "observer_default", "off", "", "not-a-state"} {
		iso := base
		iso.Seccomp = sc
		if err := s.InsertTerminalRun(ctx, TerminalRun{RunID: "sc-" + string(rune('a'+i)), Tool: "t", Kind: "fresh", LaunchedAt: now, Isolation: iso}); err != nil {
			t.Fatal(err)
		}
	}
	if v, ok, err := s.LoadTerminalRunSeccomp(ctx, "sc-a"); err != nil || !ok || v != "observer_default" {
		t.Fatalf("LoadTerminalRunSeccomp = %q %v %v", v, ok, err)
	}
	if _, ok, err := s.LoadTerminalRunSeccomp(ctx, "missing"); err != nil || ok {
		t.Fatalf("a missing run: %v %v", ok, err)
	}
	rows, err := s.SelectSandboxPostureRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Runs != 5 {
		t.Fatalf("rows %+v, want one bucket of five runs", rows)
	}
	want := map[string]int64{"observer_default": 2, "off": 1}
	if got := rows[0].Seccomp; len(got) != len(want) || got["observer_default"] != 2 || got["off"] != 1 {
		t.Fatalf("split %v, want %v", got, want)
	}
}
