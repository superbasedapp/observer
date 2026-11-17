package termsvc

import (
	"context"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// TestLaunchFreshRecordsIsolationEvidence: a sandboxed launch records the
// Sandboxer's isolation evidence on the run (sandbox plan v2 section 8.4);
// an unsandboxed fresh launch records only what is true of it (class none,
// captured on the host).
func TestLaunchFreshRecordsIsolationEvidence(t *testing.T) {
	root := t.TempDir()
	want := termrun.Isolation{Class: "process", Stack: []string{"bwrap"}, EgressTier: "internet", CaptureLevel: "full", CaptureRule: "C6", CaptureOrigin: "sandboxed"}
	for _, tc := range []struct {
		name    string
		sandbox bool
		want    termrun.Isolation
	}{
		{"sandboxed", true, want},
		{"unsandboxed", false, termrun.Isolation{Class: "none", CaptureOrigin: "local"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := newFakeRecorder()
			sb := &fakeSandboxer{result: PrepareResult{WrapArgv: []string{"bwrap", "--"}, Isolation: want}}
			sb.result.Dir, _ = ValidateProjectRoot(root, []string{root})
			svc := New(Options{
				Policy:    Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{root}},
				Recorder:  rec,
				Launcher:  &fakeLauncher{handle: "H"},
				Sandboxer: sb,
			})
			if _, err := svc.LaunchFresh(context.Background(), FreshRequest{
				Tool: "claude-code", Subcommand: "claude", Sandbox: tc.sandbox, ProjectRoot: root, WorkspaceSource: "live",
			}); err != nil {
				t.Fatalf("LaunchFresh: %v", err)
			}
			got := rec.runs[0].Isolation
			if got.Class != tc.want.Class || got.CaptureOrigin != tc.want.CaptureOrigin || got.CaptureLevel != tc.want.CaptureLevel ||
				strings.Join(got.Stack, ",") != strings.Join(tc.want.Stack, ",") || got.CaptureRule != tc.want.CaptureRule {
				t.Fatalf("recorded %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestLaunchFreshReportsTheBackendThatBuiltTheBox: the launch result names the
// backend the Sandboxer built, the outermost layer of its isolation stack, so a
// caller that records "in a sandbox" can say which one (an Automatic request is
// resolved only by the Sandboxer). A launch that was not sandboxed names none,
// and neither does a stack that is empty: the isolation class is not a backend.
func TestLaunchFreshReportsTheBackendThatBuiltTheBox(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name    string
		sandbox bool
		iso     termrun.Isolation
		want    string
	}{
		{"one layer", true, termrun.Isolation{Class: "process", Stack: []string{"bwrap"}}, "bwrap"},
		{"the outermost of two layers", true, termrun.Isolation{Class: "vm", Stack: []string{"lima", "bwrap"}}, "lima"},
		{"an empty stack names none, the class does not stand in", true, termrun.Isolation{Class: "process"}, ""},
		{"an empty first layer names none", true, termrun.Isolation{Class: "process", Stack: []string{""}}, ""},
		{"not sandboxed", false, termrun.Isolation{Class: "process", Stack: []string{"bwrap"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sb := &fakeSandboxer{result: PrepareResult{WrapArgv: []string{"x", "--"}, Isolation: tc.iso}}
			sb.result.Dir, _ = ValidateProjectRoot(root, []string{root})
			svc := New(Options{
				Policy:    Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{root}},
				Recorder:  newFakeRecorder(),
				Launcher:  &fakeLauncher{handle: "H"},
				Sandboxer: sb,
			})
			res, err := svc.LaunchFresh(context.Background(), FreshRequest{
				Tool: "claude-code", Subcommand: "claude", Sandbox: tc.sandbox, ProjectRoot: root, WorkspaceSource: "live",
			})
			if err != nil {
				t.Fatalf("LaunchFresh: %v", err)
			}
			if res.Backend != tc.want {
				t.Errorf("Backend = %q, want %q", res.Backend, tc.want)
			}
		})
	}
}
