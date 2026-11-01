package termsvc

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestLaunchFreshAppliesTheNativeSwitchFromTheEvidence (lane SBX-P3D): the
// agent's per-run switch rides ExtraArgs exactly when the run's evidence
// says Observer changed its sandbox, after the model's own flags; a state
// without a usable switch refuses before a run is minted.
func TestLaunchFreshAppliesTheNativeSwitchFromTheEvidence(t *testing.T) {
	cases := []struct {
		name  string
		tool  string
		state vocab.NativeSandboxState
		model string
		want  string
		err   bool
	}{
		{"disabled by observer", "codex", vocab.NativeDisabledByObserver, "", "-- --sandbox danger-full-access", false},
		{"after the model flag", "codex", vocab.NativeDisabledByObserver, "gpt-5.5", "--model gpt-5.5 -- --sandbox danger-full-access", false},
		{"kept: nothing", "codex", "", "", "", false},
		{"not applicable: nothing", "goose", vocab.NativeNotApplicable, "", "", false},
		{"a global-setting row is refused", "droid", vocab.NativeDisabledByObserver, "", "", true},
	}
	for _, tc := range cases {
		root := t.TempDir()
		rec := newFakeRecorder()
		l := &fakeLauncher{handle: "H"}
		sb := &fakeSandboxer{result: PrepareResult{Dir: root, WrapArgv: []string{"bwrap", "--"}, Isolation: termrun.Isolation{Class: "process", NativeSandboxState: string(tc.state)}}}
		svc := New(Options{
			Policy:   Policy{AllowFresh: true, AllowedTools: []string{tc.tool}, AllowedProjectRoots: []string{root}},
			Recorder: rec, Launcher: l, Sandboxer: sb,
		})
		_, err := svc.LaunchFresh(context.Background(), FreshRequest{Tool: tc.tool, Subcommand: tc.tool, Sandbox: true, ProjectRoot: root, Model: tc.model})
		if tc.err {
			if !errors.Is(err, integration.ErrNoNativeSwitch) || l.calls != 0 || rec.recordCalls != 0 {
				t.Errorf("%s: err %v, spawned %d, recorded %d", tc.name, err, l.calls, rec.recordCalls)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := strings.Join(l.lastReq.ExtraArgs, " "); got != tc.want {
			t.Errorf("%s: ExtraArgs %q, want %q", tc.name, got, tc.want)
		}
	}
}
