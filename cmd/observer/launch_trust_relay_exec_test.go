//go:build linux && !sbo_omit_security && !sbo_omit_security_trust && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestRelayExecutorLaunchGateWiring (lane SEC-TRUST4 items 1d and 2e): for
// a launch_gate request the executor starts its child in relayChildDir (the
// box's directory under the run's roots, else the workspace) and hands it a
// channel record whose trust accept root is the copy run's source project
// from the run record, never the box's cwd. The child here is a script that
// prints its working directory and then the record.
func TestRelayExecutorLaunchGateWiring(t *testing.T) {
	dir := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	bin := filepath.Join(dir, "pwd-channel")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\npwd\nexec cat <&3\n"), 0o700); err != nil { //nolint:gosec // G306: an executable test script
		t.Fatal(err)
	}
	mk := func(parts ...string) string {
		p := filepath.Join(append([]string{dir}, parts...)...)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	project, clone, cloneSub, outside := mk("project"), mk("clone"), mk("clone", "sub"), mk("outside")
	copyRun := sandboxrelayd.RunRecord{
		RunID: "c", Tool: "claude-code", ProjectRoot: project, WorkspaceDir: clone,
		Roots: []string{clone}, Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: clone,
	}
	liveRun := sandboxrelayd.RunRecord{
		RunID: "l", Tool: "claude-code", ProjectRoot: project, WorkspaceDir: project,
		Roots: []string{project}, Delivery: sandboxrelayd.DeliveryLive,
	}
	for _, tc := range []struct {
		name               string
		run                sandboxrelayd.RunRecord
		cwd                string
		wantDir, wantTrust string
	}{
		{"clone, cwd inside", copyRun, cloneSub, cloneSub, project},
		{"clone, cwd outside the roots", copyRun, outside, clone, project},
		{"live", liveRun, project, project, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := relayExecutor(filepath.Join(dir, "config.toml"), bin)(context.Background(), tc.run, sandboxrelay.HookRequest{
				Kind: sandboxrelay.KindLaunchGate, Args: []string{"claude-code"}, Cwd: tc.cwd,
			})
			if err != nil {
				t.Fatal(err)
			}
			pwd, body, _ := strings.Cut(string(resp.Stdout), "\n")
			if pwd != tc.wantDir {
				t.Errorf("child ran in %q, want %q", pwd, tc.wantDir)
			}
			var rec relayChildRecord
			if err := json.Unmarshal([]byte(body), &rec); err != nil {
				t.Fatalf("record %q: %v", body, err)
			}
			if rec.TrustAcceptRoot != tc.wantTrust {
				t.Errorf("trust accept root %q, want %q", rec.TrustAcceptRoot, tc.wantTrust)
			}
		})
	}
}
