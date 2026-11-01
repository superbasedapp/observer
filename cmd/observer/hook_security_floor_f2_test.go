//go:build !sbo_omit_security && !sbo_omit_adapter_claude_code

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// f2Node is a managed node (TestProjectCommitGateFloorEndToEnd's setup) whose
// signed guard posture records its tenancy and, when held, the commit gate
// floor bit (audit SEC-P4 F2).
func f2Node(t *testing.T, held bool) *gate5Repos {
	t.Helper()
	n := pt39Node(t, "observe", true)
	key, err := guardposture.LoadOrCreateKey(guardposture.KeyPath(n.cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	p := guardposture.Posture{
		Enforced: true, Source: guardposture.SourceOrg, Generation: "7",
		GateCaps:         []string{string(integration.HookCapToolGate), string(integration.HookCapPromptGate)},
		Managed:          true,
		TenancyRecorded:  true,
		SecurityRecorded: true, SecurityActive: true, SecurityPacks: gatefixPacks,
		CommitGateFloorHeld: held,
		WrittenAt:           time.Now(),
	}
	if _, err := guardposture.Write(guardposture.PosturePath(n.cfgPath), p, key); err != nil {
		t.Fatal(err)
	}
	resetHookSecurityState()
	return n
}

// TestCommitGateFloorSurvivesMissingPostureFile (audit SEC-P4 F2): on a
// managed node whose signed guard posture says it holds a commit gate floor,
// a project with no posture file, or one that does not verify, takes the
// floor's deny (fail closed), never the unfloored ask; a node holding no
// floor still asks.
func TestCommitGateFloorSurvivesMissingPostureFile(t *testing.T) {
	const claude = "claude-code-pretooluse-bash.json"
	for _, c := range []struct {
		name     string
		held     bool
		garbage  bool
		decision string
	}{
		{"missing file, floor held", true, false, "deny"},
		{"unverifiable file, floor held", true, true, "deny"},
		{"missing file, no floor held", false, false, "ask"},
		{"unverifiable file, no floor held", false, true, "ask"},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := f2Node(t, c.held)
			if c.garbage {
				p := n.layout.PosturePath(secposture.ProjectRootHash(n.root))
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(`{"commit_gate_floor":""}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			out := drivePT39(t, n, "claude-code", "pre-tool", pt39Payload(t, claude, n.root, "git commit -m wip"))
			if !strings.Contains(out, `"permissionDecision":"`+c.decision+`"`) {
				t.Fatalf("stdout %q, want %s", out, c.decision)
			}
		})
	}
}

// TestCommitGateFloorSurvivesContextOverrun (audit SEC-P4 F2): when the
// hook context's posture read overruns (Fill falls back to the unknown
// facts), the floor is read straight from the project's signed posture file:
// a floored file still denies, an unfloored file still asks, and with the
// file unreadable in time a node holding a floor denies.
func TestCommitGateFloorSurvivesContextOverrun(t *testing.T) {
	const claude = "claude-code-pretooluse-bash.json"
	for _, c := range []struct {
		name     string
		held     bool
		writeTo  string // "" no file, else the floor value signed
		write    bool
		decision string
	}{
		{"floored file", false, "quick_scan", true, "deny"},
		{"unfloored file", false, "", true, "ask"},
		{"unfloored file, floor held elsewhere", true, "", true, "ask"},
		{"no file, floor held", true, "", false, "deny"},
		{"no file, no floor held", false, "", false, "ask"},
	} {
		t.Run(c.name, func(t *testing.T) {
			n := f2Node(t, c.held)
			if c.write {
				n.writePostureFor(t, n.root, func(f *secposture.File) { f.CommitGateFloor = c.writeTo })
			}
			orig := hookSecurityPostureRead
			hookSecurityPostureRead = func(l secposture.Layout, root string, m secposture.ModuleSignal, now time.Time, v secposture.Versions) secposture.Reading {
				time.Sleep(hookSecurityReadLimit + 300*time.Millisecond)
				return orig(l, root, m, now, v)
			}
			t.Cleanup(func() { hookSecurityPostureRead = orig })
			out := drivePT39(t, n, "claude-code", "pre-tool", pt39Payload(t, claude, n.root, "git commit -m wip"))
			if !strings.Contains(out, `"permissionDecision":"`+c.decision+`"`) {
				t.Fatalf("stdout %q, want %s", out, c.decision)
			}
		})
	}
}

// TestGuardPostureFloorHeldIsSigned (audit SEC-P4 F2): the floor bit is
// covered by the MAC, so a hand-set bit does not verify, and it is dropped
// on an individual node's posture.
func TestGuardPostureFloorHeldIsSigned(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	p := guardposture.Sign(guardposture.Posture{Managed: true, TenancyRecorded: true, SecurityRecorded: true, SecurityActive: true, CommitGateFloorHeld: true, WrittenAt: time.Now()}, key)
	if !guardposture.Verify(&p, key) || !p.CommitGateFloorHeld {
		t.Fatalf("signed floor bit does not verify: %+v", p)
	}
	q := guardposture.Sign(guardposture.Posture{Managed: true, TenancyRecorded: true, SecurityRecorded: true, SecurityActive: true, WrittenAt: time.Now()}, key)
	q.CommitGateFloorHeld = true
	if guardposture.Verify(&q, key) {
		t.Fatal("a hand-set floor bit verifies")
	}
	ind := guardposture.Sign(guardposture.Posture{TenancyRecorded: true, SecurityRecorded: true, SecurityActive: true, CommitGateFloorHeld: true, WrittenAt: time.Now()}, key)
	if ind.CommitGateFloorHeld {
		t.Fatal("an individual node's posture keeps the floor bit")
	}
}
