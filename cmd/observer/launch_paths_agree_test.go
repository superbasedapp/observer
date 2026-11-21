//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentlaunch"
	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// TestForegroundAndDetachedLaunchesAgree pins discovery section 7 "Two
// launch paths" (lane cli-2; fixes-1, audit M3). It drives the real
// foreground entry, runSandboxCLI (`observer claude --observer-sandbox
// <profile>`), over a real config and runtime with only the probe and the
// launch step injected, and the daemon's `observer launch --sandbox
// <profile>` (launch control) over the same probe. Each case must refuse on
// both or launch on both, and the foreground launch must use the backend
// agentlaunch.Choose decided. Deleting the foreground path's Normalize call
// fails the control-character case, and deleting its Choose call fails the
// tool-row case: no other check on that path refuses them.
func TestForegroundAndDetachedLaunchesAgree(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "o.db")) + "\"\n" +
		"[components]\ndistro = \"developer\"\nadd = [\"terminals.sandbox\"]\n[terminal.sandbox]\nenabled = true\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(dir, "proj")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		profile string
		cwd     string
		probe   func(*dashapi.SandboxAvailability)
		// wantBackend is the backend the foreground launch must run with;
		// "" means both paths refuse.
		wantBackend string
		wantCode    string
	}{
		{name: "auto takes the selection's non-beta pick", profile: "auto", wantBackend: "bwrap"},
		{name: "explicit available row", profile: "bwrap", wantBackend: "bwrap"},
		{name: "explicit beta row when named", profile: "oci-runc", wantBackend: "oci-runc"},
		{name: "explicit unavailable row", profile: "bwrap", probe: func(p *dashapi.SandboxAvailability) {
			p.Backends[0].Available, p.Backends[0].Reason = false, "bwrap is not installed"
		}, wantCode: agentlaunch.CodeSandboxUnavailable},
		{name: "auto with only a beta row", profile: "auto", probe: func(p *dashapi.SandboxAvailability) {
			p.Backends[0].Available = false
		}, wantCode: agentlaunch.CodeSandboxUnavailable},
		// Only Choose refuses this one on the foreground path (row C6).
		{name: "tool without a sandbox row", profile: "auto", probe: func(p *dashapi.SandboxAvailability) {
			p.Tools["claude-code"] = dashapi.SandboxToolAvail{Reason: "no grounded state row"}
		}, wantCode: agentlaunch.CodeSandboxUnavailable},
		// Only Normalize refuses this one on the foreground path (row V3).
		{name: "a launch directory with a control character", profile: "auto", cwd: "/work/a\x01b", wantCode: agentlaunch.CodeInvalid},
	}
	oldProbe, oldStart, oldDir := sandboxCLIProbe, sandboxCLIStart, cliLaunchDir
	t.Cleanup(func() { sandboxCLIProbe, sandboxCLIStart, cliLaunchDir = oldProbe, oldStart, oldDir })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := liveProbe()
			probe.Backend = "bwrap" // the selection's pick for auto
			if tc.probe != nil {
				tc.probe(&probe)
			}
			cwd := project
			if tc.cwd != "" {
				cwd = tc.cwd
			}
			cliLaunchDir = func() (string, error) { return cwd, nil }
			sandboxCLIProbe = func(context.Context, *sandboxRuntime) dashapi.SandboxAvailability { return probe }
			started := ""
			sandboxCLIStart = func(_ context.Context, l sandboxCLILaunch) int {
				started = l.backend
				if l.cwd != cwd || l.req.Tool != "claude-code" {
					t.Errorf("launch step got cwd %q tool %q", l.cwd, l.req.Tool)
				}
				return 0
			}
			var stderr bytes.Buffer
			code := runSandboxCLI(context.Background(), sandboxCLIRequest{Verb: "claude", Tool: "claude-code", Profile: tc.profile, ConfigPath: cfgPath}, &stderr)

			// The daemon's launch control over the same probe.
			f := newFakeTermsvc()
			f.probe = probe
			_, dErr := f.control(true).LaunchDetached(context.Background(), attachsock.LaunchSpec{Tool: "claude", Project: cwd, Sandbox: tc.profile})

			if tc.wantBackend != "" {
				if code != 0 || started != tc.wantBackend {
					t.Fatalf("foreground: exit %d, launched with %q, want %q (stderr %q)", code, started, tc.wantBackend, stderr.String())
				}
				if dErr != nil {
					t.Fatalf("the paths disagree: the daemon refused %v", dErr)
				}
				return
			}
			if started != "" {
				t.Fatalf("foreground launched with %q; want a refusal (stderr %q)", started, stderr.String())
			}
			want := sandboxCLIUnavailable
			if tc.wantCode == agentlaunch.CodeInvalid {
				want = sandboxCLIUsage
			}
			if code != want {
				t.Fatalf("foreground: exit %d, want %d (stderr %q)", code, want, stderr.String())
			}
			if dErr == nil || codeOf(t, dErr) != tc.wantCode {
				t.Fatalf("daemon: %v, want code %q", dErr, tc.wantCode)
			}
		})
	}
}
