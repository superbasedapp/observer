//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_mxc_cli_test.go covers the CLI path `observer claude
// --observer-sandbox mxc-process` (lane SBX-UPD, the P6 audit's untested
// path) through the driver's fakes: the parsed request and the argv and
// plan file a launch runs (any host), and the whole CLI path's refusal of
// a missing MXC bundle (terminal_sandbox_mxc_cli_windows_test.go, which
// needs a Windows host for the selection).

// TestMXCCLIParsesTheProfile: the flag picks the mxc-process row, the
// rest of the launcher's arguments (its binary path flag included) are
// kept, and the binary path is what the plan grants read-only.
func TestMXCCLIParsesTheProfile(t *testing.T) {
	req, ok, err := parseSandboxCLI([]string{"observer", "claude", "--observer-sandbox", "mxc-process", "--claude-path", `C:\tools\claude.exe`, "--", "-p", "hi"})
	if err != nil || !ok || req.Tool != "claude-code" || req.Profile != "mxc-process" {
		t.Fatalf("parse = %+v ok=%v err=%v", req, ok, err)
	}
	if strings.Join(req.Rest, " ") != `--claude-path C:\tools\claude.exe -- -p hi` {
		t.Fatalf("rest = %q", req.Rest)
	}
	if b, err := sandboxCLIBackend(req.Profile); err != nil || b != sandboxbackend.BackendMXCProcess {
		t.Fatalf("backend = %q %v", b, err)
	}
	if p := sandboxCLIFlagValue(req.Rest, "claude-path"); p != `C:\tools\claude.exe` {
		t.Fatalf("claude-path = %q", p)
	}
}

// TestMXCCLIArgvAndPlan: with the bundle present the launch's argv is the
// host helper verb with the run's plan, relay run and observer dir, then
// this binary and the launcher's own arguments; the plan file it names
// exists, reads back and names the workspace; it holds no secret.
func TestMXCCLIArgvAndPlan(t *testing.T) {
	// Attach checks <home>/.claude.json for a finished first run; pin a
	// home and mark it onboarded instead of reading the real profile (FU-20).
	onboardTestClaude(t, pinToolHomes(t))
	countMXCProbes(t, "windows", availableMXC())
	rt := ociTestRuntime(t, mxcTestConfig(t, true, "mxc-process"))
	rt.forceBackend = sandboxbackend.BackendMXCProcess
	d := rt.drivers[sandboxbackend.BackendMXCProcess].(*mxcDriver)
	// The driver's own steps, which ComposePrepare runs after the host's
	// selection (the selection itself needs a Windows host: the Windows
	// test below runs the whole CLI path).
	created, err := d.Create(context.Background(), termsvc.PrepareRequest{
		Tool: "claude-code", ProjectRoot: t.TempDir(), WorkspaceSource: string(workspace.SourceLive),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	attached, err := d.Attach(context.Background(), created)
	if err != nil {
		t.Fatalf("Attach: %v", err)
	}
	t.Cleanup(func() { processMXCOOB.close(created.Run.ID) })
	argv := sandboxCLIInnerArgv(attached.WrapArgv, "/bin/observer", "claude", []string{"--model", "x"})
	if len(argv) < 2 || argv[1] != mxcHostVerb {
		t.Fatalf("argv = %q, want the mxc host verb", argv)
	}
	h, err := parseMXCHostArgs(argv)
	if err != nil {
		t.Fatalf("parse %q: %v", argv, err)
	}
	if strings.Join(h.inner, " ") != "/bin/observer claude --model x" {
		t.Fatalf("inner = %q", h.inner)
	}
	plan, err := readMXCPlan(h.plan)
	if err != nil {
		t.Fatalf("readMXCPlan: %v", err)
	}
	if plan.RunID != h.runID || plan.Workspace == "" || plan.Tier == "" {
		t.Fatalf("plan = %+v", plan)
	}
	raw, _ := os.ReadFile(h.plan)
	for _, bad := range []string{"secret", "token"} {
		if strings.Contains(strings.ToLower(string(raw)), bad) {
			t.Fatalf("the plan file mentions %q: %s", bad, raw)
		}
	}
	_ = removeMXCPlan(rt.observerDir, h.runID)
}
