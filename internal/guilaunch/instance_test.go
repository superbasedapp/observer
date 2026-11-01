package guilaunch

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// running is an InstanceRunning probe answering want and counting its calls.
func running(want bool, calls *int) func(string) bool {
	return func(string) bool {
		*calls++
		return want
	}
}

// TestComposeInstanceRunning pins IDE-2 (ledger AP-043): a single-instance
// app that is already running receives the launch over IPC and keeps its
// own environment, so the wrap is NOT applied and the note says to close it
// first. macOS `open -a` reuses a running app whatever the row says. A
// multi-instance app never asks the probe; a probe that cannot tell (nil or
// false) keeps the old verdict and its cold-start caveat.
func TestComposeInstanceRunning(t *testing.T) {
	t.Parallel()
	const proxy = "http://127.0.0.1:8820"
	cold := specExe()
	cold.Wrap.ColdStartOnly = true
	bundle := specExe()
	bundle.DarwinApp = "Editor"

	tests := []struct {
		name        string
		spec        integration.GUILaunchSpec
		in          Inputs
		probe       *bool // nil: no probe
		wantApplied bool
		wantReason  WrapReason
		wantCalls   int
		wantNote    string
		noteLacks   string
	}{
		{
			name: "single-instance app running: wrap not applied", spec: cold,
			in: Inputs{GOOS: "windows", Bin: `C:\Apps\Code.exe`, ProxyURL: proxy}, probe: ptr(true),
			wantReason: WrapReasonInstanceRunning, wantCalls: 1,
			wantNote: "close all windows first", noteLacks: "cold-start only",
		},
		{
			name: "single-instance app not running: applied with the caveat", spec: cold,
			in: Inputs{GOOS: "windows", Bin: `C:\Apps\Code.exe`, ProxyURL: proxy}, probe: ptr(false),
			wantApplied: true, wantReason: WrapReasonNone, wantCalls: 1, wantNote: "cold-start only",
		},
		{
			name: "no probe: unchanged verdict", spec: cold,
			in:          Inputs{GOOS: "linux", Bin: "/opt/editor/editor", ProxyURL: proxy},
			wantApplied: true, wantReason: WrapReasonNone, wantNote: "cold-start only",
		},
		{
			name: "macOS open -a reuses a running app", spec: bundle,
			in: Inputs{GOOS: "darwin", Bin: "/Applications/Editor.app", ProxyURL: proxy}, probe: ptr(true),
			wantReason: WrapReasonInstanceRunning, wantCalls: 1, wantNote: "close all windows first",
		},
		{
			name: "multi-instance app never asks the probe", spec: specExe(),
			in: Inputs{GOOS: "linux", Bin: "/opt/editor/editor", ProxyURL: proxy}, probe: ptr(true),
			wantApplied: true, wantReason: WrapReasonNone,
		},
		{
			name: "interop is decided before the probe runs", spec: cold,
			in: Inputs{GOOS: "linux", Bin: "/mnt/c/Apps/Code.exe", ProxyURL: proxy, ViaInterop: true}, probe: ptr(true),
			wantReason: WrapReasonInteropEnvNotPropagated,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			in := tc.in
			if tc.probe != nil {
				in.InstanceRunning = running(*tc.probe, &calls)
			}
			plan, err := Compose(tc.spec, in)
			if err != nil {
				t.Fatalf("Compose: %v", err)
			}
			if plan.WrapApplied != tc.wantApplied || plan.WrapReason != tc.wantReason {
				t.Fatalf("applied %v reason %q; want %v %q (note %q)", plan.WrapApplied, plan.WrapReason, tc.wantApplied, tc.wantReason, plan.WrapNote)
			}
			if !plan.WrapApplied && len(plan.Env) != 0 {
				t.Fatalf("an unapplied wrap carries env %q", plan.Env)
			}
			if calls != tc.wantCalls {
				t.Fatalf("probe called %d times, want %d", calls, tc.wantCalls)
			}
			if tc.wantNote != "" && !strings.Contains(plan.WrapNote, tc.wantNote) {
				t.Fatalf("note %q lacks %q", plan.WrapNote, tc.wantNote)
			}
			if tc.noteLacks != "" && strings.Contains(plan.WrapNote, tc.noteLacks) {
				t.Fatalf("note %q repeats %q", plan.WrapNote, tc.noteLacks)
			}
		})
	}
}

func ptr(b bool) *bool { return &b }
