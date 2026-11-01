package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOnlyCodexBridgeConflicts pins which conflicts the native Codex
// register words as Observer's own WSL bridge (live proof 2026-10-21).
func TestOnlyCodexBridgeConflicts(t *testing.T) {
	const (
		bridge    = "wsl.exe -d Ubuntu-20.04 -- /home/u/bin/observer hook codex PreToolUse"
		msysBrdg  = "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- /home/u/bin/observer hook codex PreToolUse"
		native    = "/home/u/bin/observer hook codex PreToolUse"
		userHook  = "/usr/local/bin/my-policy"
		wslForeig = "wsl.exe -d Ubuntu-20.04 -- /usr/local/bin/my-policy"
	)
	group := func(cmds ...string) codexHookGroup {
		g := codexHookGroup{Matcher: "*"}
		for _, c := range cmds {
			g.Hooks = append(g.Hooks, claudeHookCommand{Type: "command", Command: c})
		}
		return g
	}
	cases := []struct {
		name   string
		groups []codexHookGroup
		want   bool
	}{
		{"bridge-only", []codexHookGroup{group(bridge)}, true},
		{"msys-bridge", []codexHookGroup{group(msysBrdg)}, true},
		{"bridge-beside-native-ours", []codexHookGroup{group(native), group(bridge)}, true},
		{"user-hook", []codexHookGroup{group(userHook)}, false},
		{"bridge-and-user-hook", []codexHookGroup{group(bridge), group(userHook)}, false},
		{"foreign-wsl-command", []codexHookGroup{group(wslForeig)}, false},
		{"nothing-conflicts", []codexHookGroup{group(native)}, false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := onlyCodexBridgeConflicts(c.groups, isObserverCodexEntryNative); got != c.want {
				t.Errorf("onlyCodexBridgeConflicts = %v, want %v", got, c.want)
			}
		})
	}
}

// TestRegisterCodexNativeOverBridgeWording: native `init --codex` over a
// hooks.json holding Observer's WSL bridge entries still refuses (B4) and
// names the bridge plus the exact removal command; that command's
// unregister really removes the bridge entries, after which the native
// register succeeds without --force. A user's own hook keeps the generic
// wording.
func TestRegisterCodexNativeOverBridgeWording(t *testing.T) {
	t.Parallel()
	r, hooksPath := newCodexCollisionRegistry(t)
	if res := r.Register("codex-windows"); res.Error != nil {
		t.Fatalf("Register(codex-windows): %v", res.Error)
	}
	res := r.Register("codex")
	if res.Error == nil {
		t.Fatal("native register over the bridge entries did not refuse")
	}
	msg := res.Error.Error()
	for _, want := range []string{"Observer hooks that run through WSL", "wsl.exe bridge", "`" + codexBridgeConflictCommand + "`", "keep the WSL daemon"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q is missing %q", msg, want)
		}
	}
	if strings.Contains(msg, "non-observer") {
		t.Errorf("error still calls Observer's bridge a non-observer hook: %q", msg)
	}

	// The named command: uninstall --codex (--force, native checksum
	// never recorded) removes only Observer's entries, bridge included.
	r.opts.Force = true
	if un := r.Unregister("codex"); un.Error != nil || len(un.HooksRemoved) == 0 {
		t.Fatalf("Unregister(codex) --force = %v removed %v", un.Error, un.HooksRemoved)
	}
	if b, _ := os.ReadFile(hooksPath); strings.Contains(string(b), "wsl.exe") {
		t.Fatalf("bridge entries survived the named uninstall:\n%s", b)
	}
	r.opts.Force = false
	if res := r.Register("codex"); res.Error != nil {
		t.Fatalf("native register after the removal: %v", res.Error)
	}
}

// TestRegisterCodexUserHookKeepsGenericWording: a user's own hook beside
// the bridge is a real foreign conflict and keeps the generic refusal.
func TestRegisterCodexUserHookKeepsGenericWording(t *testing.T) {
	t.Parallel()
	r, hooksPath := newCodexCollisionRegistry(t)
	if err := os.MkdirAll(filepath.Dir(hooksPath), 0o755); err != nil {
		t.Fatal(err)
	}
	both := `{"hooks":{"PreToolUse":[` +
		`{"matcher":"*","hooks":[{"type":"command","command":"wsl.exe -d Ubuntu-20.04 -- /home/u/bin/observer hook codex PreToolUse"}]},` +
		`{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/my-policy"}]}]}}`
	if err := os.WriteFile(hooksPath, []byte(both), 0o600); err != nil {
		t.Fatal(err)
	}
	res := r.Register("codex")
	if res.Error == nil || !strings.Contains(res.Error.Error(), "non-observer hook") {
		t.Errorf("error = %v, want the generic non-observer refusal", res.Error)
	}
}
