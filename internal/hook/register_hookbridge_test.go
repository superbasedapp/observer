package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// hbExe is the Windows spelling the stubbed windowsExeSpelling returns.
const hbExe = "C:/Users/tester/AppData/Local/SuperBased/Observer/bin/observer.exe"

// stubHookBridge runs one test with the hook-bridge gate open or closed, the
// installer's observer.exe present (or not) under winHome, and a fixed
// Windows spelling for it. Not parallel: it swaps package seams.
func stubHookBridge(t *testing.T, gateOpen bool, winHome string, exePresent bool, spelling string) {
	t.Helper()
	prevGate, prevSpell := hookBridgeGateFor, windowsExeSpelling
	if gateOpen {
		hookBridgeGateFor = func(string) integration.LiveGates { return nil }
	}
	windowsExeSpelling = func(string) (string, bool) { return spelling, spelling != "" }
	t.Cleanup(func() { hookBridgeGateFor, windowsExeSpelling = prevGate, prevSpell })
	if exePresent {
		exe := filepath.Join(winHome, windowsObserverExeRel)
		if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(exe, []byte("MZ"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// claudeWindowsFile registers claude-code-windows into a fresh sandbox and
// returns the settings bytes and the Windows home.
func claudeWindowsFile(t *testing.T, failClosed bool, prepare func(winHome string)) ([]byte, string, *Registry) {
	t.Helper()
	wslHome := t.TempDir()
	winHome := nestedWinHome(t, wslHome)
	if err := os.MkdirAll(filepath.Join(winHome, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if prepare != nil {
		prepare(winHome)
	}
	r, err := NewRegistry(Options{
		BinaryPath: apBin, ConfigPath: apCfg, HomeDir: wslHome,
		ChecksumsPath:           filepath.Join(wslHome, ".observer", "hook_checksums.json"),
		WindowsClaudeHome:       winHome,
		WSLDistro:               apDistro,
		WindowsBridgeFailClosed: failClosed,
		binaryWorks:             func(string) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	mustRegister(t, r, "claude-code-windows")
	b, err := os.ReadFile(filepath.Join(winHome, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b, winHome, r
}

// TestHookBridgeGateClosedWritesTodaysBridge pins AW-37's DEC-12 half: while
// LC6 waits, an enforcing managed node with the Windows observer.exe
// installed writes exactly the bytes an unmanaged node writes, for both
// targets the bridge covers.
func TestHookBridgeGateClosedWritesTodaysBridge(t *testing.T) {
	for _, tool := range []string{"claude-code", "codex"} {
		if !integration.RowlessWriterGates(tool, integration.WriterKindHookBridge).Waiting() {
			t.Fatalf("%s: the hook bridge must wait on LC6 (switch-on is its own commit)", tool)
		}
	}
	install := func(winHome string) { stubHookBridge(t, false, winHome, true, hbExe) }
	on, _, _ := claudeWindowsFile(t, true, install)
	off, _, _ := claudeWindowsFile(t, false, nil)
	if !bytes.Equal(on, off) {
		t.Fatalf("claude-code-windows: gated writer changed the file:\n%s\nvs\n%s", on, off)
	}
	if bytes.Contains(on, []byte("hook-bridge")) {
		t.Fatal("claude-code-windows: hook-bridge written while gated")
	}

	codexOn, dirOn := newCodexWindowsRegistry(t, apBin, func(o *Options) { o.WindowsBridgeFailClosed = true; o.ConfigPath = apCfg })
	stubHookBridge(t, false, filepath.Dir(dirOn), true, hbExe)
	codexOff, dirOff := newCodexWindowsRegistry(t, apBin, func(o *Options) { o.ConfigPath = apCfg })
	mustRegister(t, codexOn, "codex-windows")
	mustRegister(t, codexOff, "codex-windows")
	a, _ := os.ReadFile(filepath.Join(dirOn, codexHooksFile))
	b, _ := os.ReadFile(filepath.Join(dirOff, codexHooksFile))
	if !bytes.Equal(a, b) || bytes.Contains(a, []byte("hook-bridge")) {
		t.Fatalf("codex-windows: gated writer changed hooks.json:\n%s\nvs\n%s", a, b)
	}
}

// TestHookBridgeWrittenWhenSwitchedOn runs the switched-on branch: only the
// tool-gate event gets the bridge, re-registering is a no-op, and every
// missing condition keeps today's bridge.
func TestHookBridgeWrittenWhenSwitchedOn(t *testing.T) {
	var winHome string
	body, winHome, r := claudeWindowsFile(t, true, func(h string) { stubHookBridge(t, true, h, true, hbExe) })
	groups := readClaudeHookGroups(t, filepath.Join(winHome, ".claude", "settings.json"))
	wantBridge := hbExe + " hook-bridge --distro " + apDistro + " --bin /" + apBin + " --tool claude-code --event pre-tool --config /" + apCfg
	for _, ev := range claudeCodeEvents {
		want := portableBridgeCommand(apDistro, apBin, "claude-code", hookEventArg(ev), apCfg)
		if ev == "PreToolUse" {
			want = wantBridge
		}
		if len(groups[ev]) != 1 || groups[ev][0] != want {
			t.Errorf("%s: %q, want %q", ev, groups[ev], want)
		}
	}
	if !isObserverWindowsClaudeEntry(wantBridge) || isObserverClaudeEntry(wantBridge) {
		t.Fatal("the bridge entry must read as the Windows target's, never the native one's")
	}
	again := mustRegister(t, r, "claude-code-windows")
	if len(again.HooksAdded) != 0 {
		t.Fatalf("re-register rewrote %v", again.HooksAdded)
	}
	after, _ := os.ReadFile(filepath.Join(winHome, ".claude", "settings.json"))
	if !bytes.Equal(body, after) {
		t.Fatal("re-register changed the file")
	}

	for name, c := range map[string]struct {
		failClosed bool
		exe        bool
		spelling   string
	}{
		"not an enforcing managed node": {false, true, hbExe},
		"no Windows observer.exe":       {true, false, hbExe},
		"exe path with a space":         {true, true, "C:/Users/John Smith/AppData/Local/SuperBased/Observer/bin/observer.exe"},
		"exe outside a drive mount":     {true, true, ""},
	} {
		got, _, _ := claudeWindowsFile(t, c.failClosed, func(h string) { stubHookBridge(t, true, h, c.exe, c.spelling) })
		if bytes.Contains(got, []byte("hook-bridge")) {
			t.Errorf("%s: wrote the bridge", name)
		}
	}

	codexR, dir := newCodexWindowsRegistry(t, apBin, func(o *Options) { o.WindowsBridgeFailClosed = true })
	stubHookBridge(t, true, filepath.Dir(dir), true, hbExe)
	mustRegister(t, codexR, "codex-windows")
	cmds := readCodexHookCommands(t, filepath.Join(dir, codexHooksFile))
	wantCodex := hbExe + " hook-bridge --distro Ubuntu-20.04 --bin /" + apBin + " --tool codex --event PreToolUse"
	for ev, got := range cmds {
		if ev == "PreToolUse" {
			if len(got) != 1 || got[0] != wantCodex {
				t.Errorf("codex PreToolUse = %q, want %q", got, wantCodex)
			}
			continue
		}
		if len(got) != 1 || strings.Contains(got[0], "hook-bridge") || !strings.HasPrefix(got[0], "wsl.exe ") {
			t.Errorf("codex %s = %q, want today's bridge", ev, got)
		}
	}
	if !isObserverCodexEntry(wantCodex) || isObserverCodexEntryNative(wantCodex) {
		t.Fatal("the codex bridge entry must read as the Windows target's, never the native one's")
	}
	if again := mustRegister(t, codexR, "codex-windows"); len(again.HooksAdded) != 0 {
		t.Fatalf("codex re-register rewrote %v", again.HooksAdded)
	}
}

// TestIsObserverCodexHookCommandSeesTheBridge pins audit item 4 (second
// audit of 4767d49c1): the exported predicate the dashboard trust status and
// the doctor use owns every shape the registrar writes, the bridge included.
func TestIsObserverCodexHookCommandSeesTheBridge(t *testing.T) {
	for cmd, want := range map[string]bool{
		"/opt/o hook codex PreToolUse":                                                      true,
		"wsl.exe -d U -- /opt/o hook codex PreToolUse":                                      true,
		hbExe + " hook-bridge --distro U --bin //opt/o --tool codex --event PreToolUse":     true,
		hbExe + " hook-bridge --distro U --bin //opt/o --tool claude-code --event pre-tool": false,
		"my-own-script.sh": false,
	} {
		if got := IsObserverCodexHookCommand(cmd); got != want {
			t.Errorf("IsObserverCodexHookCommand(%q) = %v, want %v", cmd, got, want)
		}
	}
}
