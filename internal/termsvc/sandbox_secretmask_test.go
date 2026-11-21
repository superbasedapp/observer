package termsvc

import (
	"context"
	"testing"
)

// TestLaunchFreshPassesTheSecretMaskRequestToTheSandboxer pins the opt-in
// workspace secret mask across the termsvc seam: FreshRequest's flag reaches
// the Sandboxer's PrepareRequest unchanged, and the default (false) stays
// false, so a launch that never asks for the mask is exactly what it was.
func TestLaunchFreshPassesTheSecretMaskRequestToTheSandboxer(t *testing.T) {
	cases := []struct {
		name string
		mask bool
	}{
		{"default off", false},
		{"asked for", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			projectRoot := t.TempDir()
			validated, err := ValidateProjectRoot(projectRoot, []string{projectRoot})
			if err != nil {
				t.Fatalf("ValidateProjectRoot: %v", err)
			}
			sb := &fakeSandboxer{result: PrepareResult{Dir: validated}}
			svc := New(Options{
				Policy:    Policy{AllowFresh: true, AllowedTools: []string{"claude-code"}, AllowedProjectRoots: []string{projectRoot}},
				Recorder:  newFakeRecorder(),
				Launcher:  &fakeLauncher{handle: "HM"},
				Sandboxer: sb,
			})
			if _, err := svc.LaunchFresh(context.Background(), FreshRequest{
				Tool: "claude-code", Subcommand: "claude", Sandbox: true,
				ProjectRoot: projectRoot, WorkspaceSource: "live", MaskWorkspaceSecrets: tc.mask,
			}); err != nil {
				t.Fatalf("LaunchFresh: %v", err)
			}
			if sb.calls != 1 {
				t.Fatalf("Sandboxer.Prepare called %d times, want 1", sb.calls)
			}
			if sb.lastReq.MaskWorkspaceSecrets != tc.mask {
				t.Fatalf("PrepareRequest.MaskWorkspaceSecrets = %v, want %v", sb.lastReq.MaskWorkspaceSecrets, tc.mask)
			}
		})
	}
}
