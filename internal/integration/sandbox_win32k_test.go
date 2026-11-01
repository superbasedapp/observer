package integration_test

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestSandboxNeedsWin32kGrounded pins how Sandbox.NeedsWin32k was decided
// (WINFIX2 audit finding 4): from the PE import tables of the launch
// binaries, read 2026-10-25 on Windows 11 26200. node.exe imports
// USER32.dll statically, so every sandbox-launchable row whose launcher
// runs on node needs Win32k (claude-code's native claude.exe also
// delay-loads it, its Bash tool runs Git Bash, which imports it, and
// codex.exe imports it); no other row has a measured need, so each keeps
// MXC's Win32k mitigation.
func TestSandboxNeedsWin32kGrounded(t *testing.T) {
	marked := 0
	for _, c := range integration.Capabilities() {
		state := len(c.Sandbox.StateRW)+len(c.Sandbox.StateRO) > 0
		node := c.Binary != nil && c.Binary.Runtime != nil && c.Binary.Runtime.Runtime == integration.RuntimeNode
		switch {
		case c.Sandbox.NeedsWin32k && !state:
			t.Errorf("adapter %q: NeedsWin32k on a row that is not sandbox-launchable", c.Tool)
		case state && node && !c.Sandbox.NeedsWin32k:
			t.Errorf("adapter %q: its launcher runs on node (node.exe imports USER32.dll) but the row keeps the Win32k mitigation, so it would fail to start in an mxc-process box", c.Tool)
		case c.Sandbox.NeedsWin32k && !node:
			t.Errorf("adapter %q: NeedsWin32k without a measured need (only node-based launchers were measured)", c.Tool)
		}
		if c.Sandbox.NeedsWin32k {
			marked++
		}
	}
	for _, tool := range []string{"claude-code", "codex"} {
		if c, _ := integration.For(tool); !c.Sandbox.NeedsWin32k {
			t.Errorf("%s needs Win32k (measured) but the row does not say so", tool)
		}
	}
	if marked == 0 {
		t.Fatal("no row needs Win32k")
	}
}
