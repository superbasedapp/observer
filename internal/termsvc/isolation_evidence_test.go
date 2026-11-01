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
