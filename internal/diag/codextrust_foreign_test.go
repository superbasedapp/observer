package diag

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestCodexTrustPathKey: the three spellings of one Windows hooks.json (a
// Windows Codex's own key, its \\?\ form, and the WSL daemon's /mnt/c view)
// normalize to one key. Linux only: the /mnt/c translation is a WSL rule.
func TestCodexTrustPathKey(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the /mnt/<drive> translation applies on a Linux (WSL) daemon")
	}
	want := CodexTrustPathKey("/mnt/c/Users/Op/.codex/hooks.json")
	for _, p := range []string{`C:\Users\Op\.codex\hooks.json`, `\\?\C:\Users\op\.codex\hooks.json`, "/mnt/c/users/op/.codex/hooks.json"} {
		if got := CodexTrustPathKey(p); got != want {
			t.Errorf("CodexTrustPathKey(%q) = %q, want %q", p, got, want)
		}
	}
	if got := CodexTrustPathKey("/home/u/.codex/hooks.json"); got != "/home/u/.codex/hooks.json" {
		t.Errorf("a native POSIX path changed: %q", got)
	}
}

// TestCheckForeignCodexHookTrust_WindowsHomeGateOff is the live check
// 2026-10-20 regression: a WSL daemon's doctor must read the Windows user's
// ~/.codex (the codex-windows bridge's target), not only the WSL one, and
// report an untrusted tool gate there as a FAIL naming the gate. The
// Windows home is staged under t.TempDir() (crossmount's test layout), never
// the real /mnt/c/Users. A sandboxed caller (homeOverride set) sees none.
func TestCheckForeignCodexHookTrust_WindowsHomeGateOff(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the Windows-side home is reached from a Linux (WSL) daemon")
	}
	usersRoot := filepath.Join(t.TempDir(), "mnt", "c", "Users")
	winHome := filepath.Join(usersRoot, "operator")
	if err := os.MkdirAll(winHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(winHome, "NTUSER.DAT"), []byte("hive"), 0o600); err != nil {
		t.Fatal(err)
	}
	events := codexExpectedHookEvents()
	codexHookTrustWriteHooks(t, winHome, events...)
	crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{Root: usersRoot, WindowsUser: "operator", Discover: true})

	checks := checkForeignCodexHookTrust("")
	if len(checks) != 1 {
		t.Fatalf("got %d foreign checks, want 1: %+v", len(checks), checks)
	}
	c := checks[0]
	if c.Name != "codex.hook_trust.windows" || c.Status != StatusFail {
		t.Fatalf("check = %s/%s, want codex.hook_trust.windows/fail: %q", c.Name, c.Status, c.Message)
	}
	for _, gate := range CodexToolGateEvents() {
		if !strings.Contains(c.Message, gate) {
			t.Errorf("message %q does not name the gate event %s", c.Message, gate)
		}
	}
	if !strings.Contains(strings.Join(c.Details, "\n"), filepath.Join(winHome, ".codex", "hooks.json")) {
		t.Errorf("details do not name the Windows hooks file: %v", c.Details)
	}
	if got := checkForeignCodexHookTrust(t.TempDir()); len(got) != 0 {
		t.Errorf("a sandboxed caller saw foreign homes: %+v", got)
	}

	// Trust every event under the Windows spelling of the key: the check
	// clears (keys are compared through CodexTrustPathKey). The staged
	// layout is not under /mnt/c, so the Windows spelling is derived from
	// the staged path itself here; TestCodexTrustPathKey pins the real
	// C:\ to /mnt/c mapping.
	hashes := map[string]string{}
	for _, e := range events {
		hashes[e] = "sha256:recorded-" + e
	}
	upper := strings.ToUpper(filepath.Join(winHome, ".codex", "hooks.json"))
	if err := os.WriteFile(filepath.Join(winHome, ".codex", "config.toml"), []byte(codexTrustConfig(tomlKeyPath(upper), hashes)), 0o600); err != nil {
		t.Fatal(err)
	}
	checks = checkForeignCodexHookTrust("")
	if len(checks) != 1 || checks[0].Status != StatusOK {
		t.Fatalf("after trusting under a differently cased key: %+v", checks)
	}
}

// TestIsObserverCodexHookSeesTheBridge: the doctor's Codex trust row owns
// the fail-closed hook-bridge entry (AW-37) like the other shapes.
func TestIsObserverCodexHookSeesTheBridge(t *testing.T) {
	bridge := "C:/Users/u/AppData/Local/SuperBased/Observer/bin/observer.exe hook-bridge --distro U --bin //opt/o --tool codex --event PreToolUse"
	if !isObserverCodexHook(bridge) || !isObserverCodexHook("/opt/o hook codex Stop") || isObserverCodexHook("my-hook.sh") {
		t.Fatal("isObserverCodexHook must own every Observer codex shape and nothing else")
	}
}
