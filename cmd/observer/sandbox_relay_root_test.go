//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestRelayExecutorChildRecordCarriesRunRoot pins audit finding 1 of lane
// sbx-p2b: the channel record relayExecutor hands its child names the
// run record's root, never the box's working directory. A live run keys
// on the run's project root; a copy run (a clone) keys on its own
// workspace, whose index the quick scan reads, never on the original
// project. The child here is a script that echoes the record it was
// handed on the channel descriptor.
func TestRelayExecutorChildRecordCarriesRunRoot(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "echo-channel")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexec cat <&3\n"), 0o700); err != nil { //nolint:gosec // G306: an executable test script
		t.Fatal(err)
	}
	mk := func(parts ...string) string {
		p := filepath.Join(append([]string{dir}, parts...)...)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		return p
	}
	project, clone := mk("project"), mk("clone")
	projectSub, cloneSub := mk("project", "sub"), mk("clone", "sub")
	for _, tc := range []struct {
		name string
		run  sandboxrelayd.RunRecord
		cwd  string
		want string
	}{
		{
			name: "live",
			run:  sandboxrelayd.RunRecord{RunID: "run-live", Tool: "codex", ProjectRoot: project, WorkspaceDir: project, Roots: []string{project}, Delivery: sandboxrelayd.DeliveryLive},
			cwd:  projectSub, want: project,
		},
		{
			name: "clone",
			run: sandboxrelayd.RunRecord{
				RunID: "run-copy", Tool: "codex", ProjectRoot: project, WorkspaceDir: clone, Roots: []string{clone},
				Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: clone,
			},
			cwd: cloneSub, want: clone,
		},
		{
			name: "no project root",
			run:  sandboxrelayd.RunRecord{RunID: "run-bare", Tool: "codex", WorkspaceDir: project, Roots: []string{project}, Delivery: sandboxrelayd.DeliveryLive},
			cwd:  projectSub, want: project,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := relayExecutor("", bin)(context.Background(), tc.run, sandboxrelay.HookRequest{
				Kind: sandboxrelay.KindHook, Args: []string{"codex", "PreToolUse"}, Cwd: tc.cwd,
			})
			if err != nil {
				t.Fatal(err)
			}
			var got relayChildRecord
			if err := json.Unmarshal(resp.Stdout, &got); err != nil {
				t.Fatalf("child record %q: %v", resp.Stdout, err)
			}
			if got.ProjectRoot != tc.want {
				t.Errorf("child record project root %q, want %q", got.ProjectRoot, tc.want)
			}
			if got.ProjectRoot == got.Cwd {
				t.Errorf("child record project root is the payload's cwd %q", got.Cwd)
			}
			if got.Cwd != tc.cwd || got.RunID != tc.run.RunID || got.Delivery != string(tc.run.Delivery) {
				t.Errorf("child record %+v does not carry the run and request", got)
			}
		})
	}
}
