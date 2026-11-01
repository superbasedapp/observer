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

// TestBoxLaunchGateSendsAnAbsoluteExecutable: the evidence an in-box
// launcher sends the relay gate names its binary absolutely whatever the
// launcher put there. The microVM row's second live run: `observer claude
// --claude-path ./agent.sh --observer-sandbox cloud-hypervisor` booted, then
// the gate refused "the launch evidence is refused: executable" (the claude
// launcher sets the evidence itself, not through launch.go), so the tool
// never ran.
func TestBoxLaunchGateSendsAnAbsoluteExecutable(t *testing.T) {
	ws, sock := relayShortDir(t), relayShortDir(t)
	if err := os.Chmod(sock, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ws, "agent.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	run, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run-exe", Tool: "claude-code", ProjectRoot: ws, WorkspaceDir: ws, Roots: []string{ws}})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteBoxRecord(sock, run); err != nil {
		t.Fatal(err)
	}
	prevPath, prevTrip := boxRecordPath, boxRoundTrip
	t.Cleanup(func() { boxRecordPath, boxRoundTrip = prevPath, prevTrip })
	boxRecordPath = filepath.Join(sock, sandboxrelayd.BoxRecordName)
	var sent []byte
	boxRoundTrip = func(_ context.Context, _ sandboxrelayd.BoxRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
		sent = req.Stdin
		return sandboxrelay.HookResponse{}, nil
	}
	t.Chdir(ws)
	for _, bin := range []string{"./agent.sh", "agent.sh/../agent.sh", filepath.Join(ws, "agent.sh")} {
		sent = nil
		err, boxed := boxLaunchGate("claude-code", budgetLaunchEvidence{Executable: bin, Arguments: []string{"--x"}})
		if !boxed || err != nil {
			t.Fatalf("%s: boxed %v, %v", bin, boxed, err)
		}
		var raw budgetLaunchEvidence
		if err := json.Unmarshal(sent, &raw); err != nil {
			t.Fatalf("%s: the sent evidence: %v (%q)", bin, err, sent)
		}
		got, err := boxLaunchEvidence(raw)
		if err != nil {
			t.Fatalf("%s: the relay gate refuses the sent evidence %q: %v", bin, raw.Executable, err)
		}
		if got.Executable != filepath.Join(ws, "agent.sh") || len(got.Arguments) != 1 {
			t.Fatalf("%s: sent executable %q args %q", bin, got.Executable, got.Arguments)
		}
	}
}
