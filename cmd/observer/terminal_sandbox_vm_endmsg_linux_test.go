//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// terminal_sandbox_vm_endmsg_linux_test.go covers the end-of-run message D9
// of the microVM row's first live run (2026-10-24) names: a hotplug that
// ended a running run printed "...; the agent was not started" although the
// agent had been running.

// TestVMHotplugEndSaysTheRunWasEnded (D9): a device added after the agent
// started ends the run saying so, never that the agent was not started.
func TestVMHotplugEndSaysTheRunWasEnded(t *testing.T) {
	r := newVMRig(t)
	blocked := make(chan struct{})
	r.run = func(*relaymux.Guest, relayStdioArgs) int { <-blocked; return 0 }
	defer close(blocked)
	r.vmmHook = func(f *fakeVM) {
		armed := time.Now().Add(300 * time.Millisecond)
		f.tamper = func(m map[string]any) {
			if time.Now().After(armed) {
				m["config"].(map[string]any)["net"] = []any{map[string]any{"tap": "tap0", "id": "_net0"}}
			}
		}
	}
	code := r.runHost()
	out := r.termOut.String()
	if code == 0 || !strings.Contains(out, "built_below_plan") || !strings.Contains(out, "network device") {
		t.Fatalf("exit %d, terminal %q", code, out)
	}
	if strings.Contains(out, "was not started") || !strings.Contains(out, "the run was ended") {
		t.Fatalf("the end message: %q", out)
	}
}

// TestVMGuestTmpfsModes (D9): the guest's shared temp dirs are mounted
// 1777 (sticky, world-writable), every other writable root 0755. The former
// os.Chmod(path, 0o1777) set 0777: Go's 0o1000 is not os.ModeSticky.
func TestVMGuestTmpfsModes(t *testing.T) {
	for _, r := range sandboxvm.GuestWritableRoots {
		want := "mode=0755"
		if r == "/tmp" || r == "/var/tmp" {
			want = "mode=1777"
		}
		if got := vmTmpfsData(r); got != want {
			t.Errorf("%s: %s, want %s", r, got, want)
		}
	}
	if os.FileMode(0o1777)&os.ModeSticky != 0 {
		t.Fatal("Go's 0o1000 is the sticky bit after all")
	}
}
