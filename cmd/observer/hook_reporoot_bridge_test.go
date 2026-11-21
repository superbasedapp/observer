package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestBobBridgeOutsideProjectDeleteBlocks is surface-gap FU-101 at the
// receiver (built as 833a533406, re-scoped onto Event.RepoRoot by the
// 2026-11-08 operator ruling): the IBM Bob IDE on Windows runs `observer
// hook ibm-bob PreToolUse` through the wsl.exe bridge with its own Windows
// cwd, and a recursive delete outside the project was allowed at the gate,
// because the hook looked for the git checkout at the raw Windows cwd, which
// a Linux hook can never find. The receiver now translates the cwd to its
// drvfs mount first (pathnorm.NormalizeForeign) before the checkout lookup
// that fills RepoRoot, so R-101's outside-the-project arm blocks (exit 2,
// the reason after the stderr header); a delete inside the repository
// passes, and a cwd outside any git tree keeps the no-root verdict (the
// directory itself is never taken as the project).
func TestBobBridgeOutsideProjectDeleteBlocks(t *testing.T) {
	const cwd = `d:\sbo-lc`
	wantDir := cwd
	if runtime.GOOS != "windows" {
		wantDir = "/mnt/d/sbo-lc" // the Linux hook reads the Windows cwd through drvfs
	}
	b, ok := standaloneToolGate(models.ToolIBMBob, "PreToolUse")
	if !ok {
		t.Fatal("ibm-bob PreToolUse is not a binding-routed tool gate")
	}
	payload := func(command string) []byte {
		return []byte(fmt.Sprintf(`{"session_id":"s","cwd":%q,"hook_event_name":"PreToolUse","tool_name":"execute_command","tool_input":{"command":%q},"tool_use_id":"t"}`, cwd, command))
	}
	cases := []struct {
		name      string
		command   string
		inTree    bool
		wantBlock bool
	}{
		{"outside the project blocks", `Remove-Item -Recurse -Force C:\sbo-x`, true, true},
		{"inside the project passes", `Remove-Item -Recurse -Force d:\sbo-lc\build`, true, false},
		{"no git tree keeps the no-root verdict", `Remove-Item -Recurse -Force C:\sbo-x`, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			setTestHome(t, home)
			cp := filepath.Join(home, "config.toml")
			writeFileT(t, cp, fmt.Sprintf("[observer]\ndb_path = %q\n[observer.hooks]\nauto_register = false\n[guard]\nenabled = true\nmode = \"enforce\"\n", filepath.Join(home, "o.db")))
			writePosture(t, cp, enforcedPosture)
			var asked []string
			prev := hookFindCheckoutRoot
			hookFindCheckoutRoot = func(dir string) (string, bool) {
				asked = append(asked, dir)
				if !tc.inTree {
					return "", false
				}
				return dir, true
			}
			t.Cleanup(func() { hookFindCheckoutRoot = prev })
			h := newFailureHarness(t, resolveHookFailurePlan(models.ToolIBMBob, "PreToolUse", cp))
			var stdout, stderr bytes.Buffer
			runToolGate(models.ToolIBMBob, "ibm-bob:PreToolUse", b, payload(tc.command), false, cp, &stdout, &stderr)
			if len(asked) == 0 || asked[0] != wantDir {
				t.Errorf("checkout asked for %q, want %q first", asked, wantDir)
			}
			codes := h.exitCodes()
			if !tc.wantBlock {
				if len(codes) != 0 || strings.Contains(stderr.String(), hook.StderrBlockHeader) {
					t.Fatalf("exits %v stderr %q, want an allow", codes, stderr.String())
				}
				return
			}
			if len(codes) == 0 || codes[0] != 2 {
				t.Fatalf("exits %v, want the block carried by exit 2 (stderr %q)", codes, stderr.String())
			}
			if got := stderr.String(); !strings.Contains(got, hook.StderrBlockHeader) || !strings.Contains(got, "outside the project root") {
				t.Errorf("stderr %q, want %q and R-101's outside-the-project reason", got, hook.StderrBlockHeader)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout %q, want nothing (the Bob IDE ignores PreToolUse stdout)", stdout.String())
			}
		})
	}
}
