//go:build !sbo_omit_terminals_sandbox_landlock && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/promptjudgeipc"
)

// TestSandboxHidesThePromptJudgeEndpoint pins M1 (adm-2 fixes-1): the org
// prompt judge's ask endpoint is in the hidden-secrets table every overlay
// driver applies (bwrap, OCI, Apple container, MXC, Seatbelt), and in the
// Landlock row's daemon-socket set the box must be refused connecting to.
func TestSandboxHidesThePromptJudgeEndpoint(t *testing.T) {
	hidden := false
	for _, pp := range sandboxObserverSecrets {
		if pp.Rel == promptjudgeipc.DirName && pp.Dir {
			hidden = true
		}
	}
	if !hidden {
		t.Fatalf("sandboxObserverSecrets lacks the %q directory", promptjudgeipc.DirName)
	}
	dir := t.TempDir()
	ep, err := promptjudgeipc.EndpointInDir(dir)
	if err != nil || !filepath.IsAbs(ep) {
		t.Skipf("no on-disk prompt judge endpoint on this platform (%q, %v)", ep, err)
	}
	for _, s := range landlockDaemonSockets(dir, "") {
		if s == filepath.Clean(ep) {
			return
		}
	}
	t.Fatalf("landlockDaemonSockets(%q) lacks the prompt judge endpoint %q", dir, ep)
}
