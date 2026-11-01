//go:build !sbo_omit_security && !sbo_omit_adapter_claude_code

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// pt39Payload reads a payload fixture from testdata/secp4 and fills it in.
func pt39Payload(t *testing.T, name, cwd, command string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "secp4", name))
	if err != nil {
		t.Fatal(err)
	}
	esc := func(s string) string {
		q, _ := json.Marshal(s)
		return strings.Trim(string(q), `"`)
	}
	r := strings.NewReplacer("{{CWD}}", esc(cwd), "{{COMMAND}}", esc(command), "{{HOME}}", esc(t.TempDir()))
	return r.Replace(string(b))
}

// pt39Node is a gate5Repos node whose config enables guard in mode, with
// a signed guard posture that names the security module active (managed:
// an org source holding the enforced tool gate).
func pt39Node(t *testing.T, mode string, managed bool) *gate5Repos {
	t.Helper()
	n := newGate5Repos(t)
	dir := filepath.Dir(n.cfgPath)
	writeFileT(t, n.cfgPath, fmt.Sprintf("[observer]\ndb_path = %q\n[guard]\nenabled = true\nmode = %q\n", filepath.Join(dir, "o.db"), mode))
	key, err := guardposture.LoadOrCreateKey(guardposture.KeyPath(n.cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	p := guardposture.Posture{Source: guardposture.SourceLocal, SecurityRecorded: true, SecurityActive: true, SecurityPacks: gatefixPacks, WrittenAt: time.Now()}
	if managed {
		p.Enforced, p.Source, p.Generation = true, guardposture.SourceOrg, "7"
		p.GateCaps = []string{string(integration.HookCapToolGate), string(integration.HookCapPromptGate)}
	}
	if _, err := guardposture.Write(guardposture.PosturePath(n.cfgPath), p, key); err != nil {
		t.Fatal(err)
	}
	resetHookSecurityState()
	t.Cleanup(resetHookSecurityState)
	return n
}

// resetHookSecurityState drops the invocation's cached security state, as a
// new hook process starts with none.
func resetHookSecurityState() {
	hookSecMu.Lock()
	hookSecCur = nil
	hookSecMu.Unlock()
}

// drivePT39 runs one payload through the real `observer hook` receiver and
// returns its stdout.
func drivePT39(t *testing.T, n *gate5Repos, tool, event, body string) string {
	t.Helper()
	resetHookSecurityState()
	h := newFailureHarness(t, resolveHookFailurePlan(tool, event, n.cfgPath))
	// The invocation's config path, as `observer hook` records it before a
	// receiver runs (hook.go setInvocationHookContext).
	setInvocationHookContext(nil, n.cfgPath)
	t.Cleanup(func() { setInvocationHookContext(nil, "") })
	if tool == "claude-code" {
		withStdinT(t, body, func() { hookReceivers[tool](context.Background(), event, n.cfgPath) })
	} else {
		driveToolGateReceiver(t, tool, event, body, n.cfgPath)
	}
	return h.stdout.String()
}

// TestPT39OtherRepoCommitEndToEnd (PT-39, lane SEC-P4 milestone 1): `cd
// /other-repo && git commit` from a Claude Code PreToolUse payload, driven
// through the hook receiver with the event's own repository clean and
// signed: an individual node asks (S-794), a host that cannot ask denies,
// and a commit in the own repository is answered as before (no ask). The
// managed deny under a floor is TestPT39ManagedFloorDenies (milestone 4). The Codex row sends a Windows working directory with a
// `Set-Location`, which only the PowerShell second reading sees; on a
// non-Windows host that directory is not a repository, so it asks there
// too (unknown), and on Windows it is placed in the other repository.
func TestPT39OtherRepoCommitEndToEnd(t *testing.T) {
	const claude = "claude-code-pretooluse-bash.json"
	t.Run("claude individual asks", func(t *testing.T) {
		n := pt39Node(t, "observe", false)
		n.writePostureFor(t, n.root, nil)
		out := drivePT39(t, n, "claude-code", "pre-tool", pt39Payload(t, claude, n.root, "cd "+n.other+" && git commit -m wip"))
		if !strings.Contains(out, `"permissionDecision":"ask"`) || !strings.Contains(out, "security state is unknown") {
			t.Fatalf("stdout %q, want the S-794 ask", out)
		}
	})
	t.Run("headless host denies", func(t *testing.T) {
		// Codex cannot show an ask (askhost.go: ask unsupported), so the
		// S-794 ask resolves to a deny naming `observer guard approve`, as
		// a headless Claude Code run (-p) refuses it itself.
		n := pt39Node(t, "observe", false)
		n.writePostureFor(t, n.root, nil)
		out := drivePT39(t, n, "codex", "PreToolUse", pt39Payload(t, "codex-pretooluse-shell-windows.json", n.root, "cd "+n.other+" && git commit -m wip"))
		if !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(out, "S-794") {
			t.Fatalf("stdout %q, want an S-794 deny on a host that cannot ask", out)
		}
	})
	t.Run("claude own repository golden", func(t *testing.T) {
		n := pt39Node(t, "observe", false)
		n.writePostureFor(t, n.root, nil)
		out := drivePT39(t, n, "claude-code", "pre-tool", pt39Payload(t, claude, n.root, "git commit -m wip"))
		if strings.Contains(out, `"ask"`) || strings.Contains(out, `"deny"`) {
			t.Fatalf("stdout %q, want the own repository's clean commit to proceed", out)
		}
	})
	t.Run("codex windows set-location holds", func(t *testing.T) {
		n := pt39Node(t, "observe", false)
		cwd, other := `C:\Users\dev\proj`, `C:\Users\dev\second`
		if runtime.GOOS == "windows" {
			cwd, other = n.root, n.other
		}
		n.writePostureFor(t, n.root, nil)
		out := drivePT39(t, n, "codex", "PreToolUse", pt39Payload(t, "codex-pretooluse-shell-windows.json", cwd, "Set-Location "+other+"; git commit -m wip"))
		if !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(out, "S-794") {
			t.Fatalf("stdout %q, want the commit held (S-794; Codex cannot ask, so deny)", out)
		}
	})
}

// TestPT39ManagedFloorDenies (PT-39, lane SEC-P4 milestones 1 and 4): on a
// managed node whose project holds the commit gate floor, `cd /other-repo
// && git commit` from Claude Code is denied (the managed-floor cell),
// where the same payload on the unfloored project asks; a clean commit in
// the floored repository itself proceeds.
func TestPT39ManagedFloorDenies(t *testing.T) {
	const claude = "claude-code-pretooluse-bash.json"
	n := pt39Node(t, "observe", true)
	floored := func(f *secposture.File) { f.CommitGateFloor = policy.CommitGateFloorQuickScan }
	n.writePostureFor(t, n.root, floored)
	out := drivePT39(t, n, "claude-code", "pre-tool", pt39Payload(t, claude, n.root, "cd "+n.other+" && git commit -m wip"))
	if !strings.Contains(out, `"permissionDecision":"deny"`) {
		t.Fatalf("floored project: stdout %q, want a deny", out)
	}
	n.writePostureFor(t, n.root, floored)
	if out := drivePT39(t, n, "claude-code", "pre-tool", pt39Payload(t, claude, n.root, "git commit -m wip")); strings.Contains(out, `"deny"`) || strings.Contains(out, `"ask"`) {
		t.Fatalf("floored project, own clean commit: stdout %q, want it to proceed", out)
	}
	n.writePostureFor(t, n.root, nil)
	out = drivePT39(t, n, "claude-code", "pre-tool", pt39Payload(t, claude, n.root, "cd "+n.other+" && git commit -m wip"))
	if !strings.Contains(out, `"permissionDecision":"ask"`) {
		t.Fatalf("unfloored project: stdout %q, want the individual ask", out)
	}
}
