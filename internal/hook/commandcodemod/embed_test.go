package commandcodemod

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestEventsFollowTheRegistry: the mod subscribes exactly the command-code
// row's registered shim events, the prompt gate and the tool gate.
func TestEventsFollowTheRegistry(t *testing.T) {
	ev := Events()
	if ev["transformInput"] != "prompt_gate" || ev["beforeToolCall"] != "tool_gate" || len(ev) != 2 {
		t.Fatalf("Events() = %v", ev)
	}
	if got := strings.Join(EventNames(), ","); got != "beforeToolCall,transformInput" {
		t.Fatalf("EventNames() = %s", got)
	}
}

// TestWritePlugin renders the shim for commandcode: the Mods contract, the
// baked bin / config / posture paths, and both events.
func TestWritePlugin(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := WritePlugin(dir, `C:\obs "x"\observer.exe`, "/home/u/.observer/custom.toml", "/home/u/.observer"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadDir(dir)
	if err != nil || len(got) != 1 || got[0].Name() != ModFileName {
		t.Fatalf("ReadDir = %v %v", got, err)
	}
	ts, _ := os.ReadFile(filepath.Join(dir, ModFileName))
	for _, want := range []string{
		`"shape":"commandcode"`, `"tool":"command-code"`,
		`"beforeToolCall":"tool_gate"`, `"transformInput":"prompt_gate"`,
		`"bin":"C:\\obs \"x\"\\observer.exe"`, `"config":"/home/u/.observer/custom.toml"`,
		// The posture and spool paths are joined in the host separator.
		`"posture":` + strconv.Quote(filepath.Join("/home/u/.observer", "guard-posture.json")),
		`"spool":` + strconv.Quote(filepath.Join("/home/u/.observer", "guard-hookfail.jsonl")),
		`"wsl_bin":""`,
	} {
		if !strings.Contains(string(ts), want) {
			t.Errorf("mod lacks %s", want)
		}
	}
	if !LooksLikeObserverPlugin(ts) {
		t.Error("LooksLikeObserverPlugin = false for an observer-written mod")
	}
}

// TestWritePluginBridge bakes the wsl.exe bridge target.
func TestWritePluginBridge(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := WritePluginBridge(dir, "/home/u/bin/observer", "Ubuntu", "/home/u/.observer/config.toml"); err != nil {
		t.Fatal(err)
	}
	ts, _ := os.ReadFile(filepath.Join(dir, ModFileName))
	for _, want := range []string{`"wsl_bin":"/home/u/bin/observer"`, `"wsl_distro":"Ubuntu"`, `"config":"/home/u/.observer/config.toml"`, `"posture":""`} {
		if !strings.Contains(string(ts), want) {
			t.Errorf("bridge mod lacks %s", want)
		}
	}
}

// TestLooksLikeObserverPlugin recognizes the shim and the pre-shim prompt
// bridge (refreshed in place), and nothing else.
func TestLooksLikeObserverPlugin(t *testing.T) {
	t.Parallel()
	if !LooksLikeObserverPlugin([]byte("// SuperBased Observer prompt-submit guard bridge for commandcode's\n")) {
		t.Error("the pre-shim mod must still be recognized")
	}
	if LooksLikeObserverPlugin([]byte("export default function (cmd) { /* some unrelated mod */ }")) || LooksLikeObserverPlugin(nil) {
		t.Error("an unrelated or empty file must not be recognized")
	}
}

func TestInstalledAndRemove(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if Installed(dir) {
		t.Fatal("Installed before any write")
	}
	if err := RemovePlugin(dir); err != nil {
		t.Fatalf("RemovePlugin on absent file: %v", err)
	}
	if err := WritePlugin(dir, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if !Installed(dir) {
		t.Fatal("not Installed after WritePlugin")
	}
	if err := os.WriteFile(filepath.Join(dir, ModFileName), []byte("previous-render-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WritePlugin(dir, "", "", ""); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, ModFileName)); strings.Contains(string(data), "previous-render-sentinel") {
		t.Fatal("re-write did not overwrite")
	}
	if err := RemovePlugin(dir); err != nil || Installed(dir) {
		t.Fatalf("RemovePlugin: %v installed=%v", err, Installed(dir))
	}
}
