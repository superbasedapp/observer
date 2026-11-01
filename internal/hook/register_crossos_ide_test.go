package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// newIDETestRegistry is a WSL daemon's registry seeing one owned Windows
// home (the crossmount seams are fakes).
func newIDETestRegistry(t *testing.T, winHome string) *Registry {
	t.Helper()
	forceHookCrossmount(t, []crossmount.HomeRoot{{OS: crossmount.OSWindows, Path: winHome}}, map[string]bool{winHome: true})
	home := t.TempDir()
	r, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		ConfigPath:    "/home/me/.observer/config.toml",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		WSLDistro:     "Ubuntu",
	})
	if err != nil {
		t.Fatal(err)
	}
	return clearSandboxPin(r)
}

func mkdirs(t *testing.T, base string, rels ...string) {
	t.Helper()
	for _, rel := range rels {
		if err := os.MkdirAll(filepath.Join(base, rel), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// TestIDETargetsAreGated pins DEC-12 for this lane's IDE targets.
func TestIDETargetsAreGated(t *testing.T) {
	want := map[string]string{"devin-windows": "WSL-4 and FU-87", "devin-jetbrains": "IDE-6-JB", "antigravity-cli-windows": "WSL-4"}
	for target, id := range want {
		if got, ok := LiveCheckGate(target); !ok || got != id {
			t.Errorf("%s gate = %q, %v; want %s", target, got, ok, id)
		}
	}
	winHome := t.TempDir()
	mkdirs(t, winHome, filepath.Join(".codeium", "windsurf"), filepath.Join(".gemini", "antigravity"))
	r := newIDETestRegistry(t, winHome)
	for target := range want {
		res := r.Register(target)
		if !res.Skipped || res.SkipKind != SkipLiveGated {
			t.Errorf("Register(%s) = %+v", target, res)
		}
		if containsString(r.Installed(), target) {
			t.Errorf("Installed lists the gated %s", target)
		}
	}
	if _, err := os.Stat(filepath.Join(winHome, ".codeium", "windsurf", "hooks.json")); !os.IsNotExist(err) {
		t.Errorf("a gated target wrote (%v)", err)
	}
	// DEC-11: devin-windows needs every listed check, and says so.
	if res := r.Register("devin-windows"); !strings.Contains(res.SkipReason, "built, waiting on live check WSL-4 and FU-87") {
		t.Errorf("devin-windows refusal = %q, want both prerequisites named", res.SkipReason)
	}
}

// TestDevinWindowsWritesEachSurfacesSystem pins DEC-11 for devin-windows:
// the Cascade editor's file and Devin Local's (the Devin CLI's) config,
// each only when its surface's directory exists, every command the
// portable bridge.
func TestDevinWindowsWritesEachSurfacesSystem(t *testing.T) {
	cases := []struct {
		name         string
		dirs         []string
		cascade, cli bool
	}{
		{"cascade editor only", []string{filepath.Join(".codeium", "windsurf")}, true, false},
		{"devin local only", []string{filepath.Join("AppData", "Roaming", "devin")}, false, true},
		{"both surfaces", []string{filepath.Join(".codeium", "windsurf"), filepath.Join("AppData", "Roaming", "devin")}, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			winHome := t.TempDir()
			mkdirs(t, winHome, c.dirs...)
			r := newIDETestRegistry(t, winHome)
			if !containsString(r.installedAll(true), "devin-windows") {
				t.Fatalf("installedAll() = %v", r.installedAll(true))
			}
			res := r.register("devin-windows")
			if res.Error != nil {
				t.Fatalf("register: %v", res.Error)
			}
			cascade := filepath.Join(winHome, ".codeium", "windsurf", "hooks.json")
			cli := filepath.Join(winHome, "AppData", "Roaming", "devin", "config.json")
			checkBridgeFile(t, cascade, c.cascade, "hook devin pre_user_prompt")
			checkBridgeFile(t, cli, c.cli, "hook devin")
			if c.cascade {
				var doc struct {
					Hooks map[string][]cascadeHookEntry `json:"hooks"`
				}
				raw, _ := os.ReadFile(cascade)
				if err := json.Unmarshal(raw, &doc); err != nil {
					t.Fatal(err)
				}
				e := doc.Hooks["pre_user_prompt"][0]
				if e.PowerShell == "" || e.PowerShell != e.Command {
					t.Errorf("a Windows Cascade entry carries the bridge in powershell too: %+v", e)
				}
			}
			if again := r.register("devin-windows"); again.Error != nil || len(again.HooksAdded) != 0 {
				t.Errorf("second register: added=%v err=%v", again.HooksAdded, again.Error)
			}
			if un := r.Unregister("devin-windows"); un.Error != nil {
				t.Fatalf("Unregister: %v", un.Error)
			}
			for _, p := range []string{cascade, cli} {
				if raw, err := os.ReadFile(p); err == nil && strings.Contains(string(raw), "wsl.exe") {
					t.Errorf("Unregister left Observer's entry in %s", p)
				}
			}
		})
	}
}

// checkBridgeFile asserts path holds a portable bridge command naming want,
// or does not exist.
func checkBridgeFile(t *testing.T, path string, wantFile bool, want string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if !wantFile {
		if err == nil {
			t.Errorf("%s was written:\n%s", path, raw)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	body := string(raw)
	for _, s := range []string{"wsl.exe -d Ubuntu -- //opt/observer/bin/observer", want, "exit $LASTEXITCODE"} {
		if !strings.Contains(body, s) {
			t.Errorf("%s lacks %q:\n%s", path, s, body)
		}
	}
}

// TestDevinJetBrainsWritesCodeiumHooks pins the JetBrains plugin's file.
func TestDevinJetBrainsWritesCodeiumHooks(t *testing.T) {
	home := t.TempDir()
	mkdirs(t, home, ".codeium")
	r, err := NewRegistry(Options{BinaryPath: "/opt/observer/bin/observer", HomeDir: home, ChecksumsPath: filepath.Join(home, ".observer", "c.json")})
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(r.installedAll(true), "devin-jetbrains") {
		t.Fatalf("installedAll() = %v", r.installedAll(true))
	}
	res := r.register("devin-jetbrains")
	if res.Error != nil || res.ConfigPath != filepath.Join(home, ".codeium", "hooks.json") || len(res.HooksAdded) != len(cascadeEvents) {
		t.Fatalf("register = %+v", res)
	}
	raw, _ := os.ReadFile(res.ConfigPath)
	if !strings.Contains(string(raw), "/opt/observer/bin/observer hook devin pre_run_command") || strings.Contains(string(raw), "powershell") {
		t.Errorf("hooks.json:\n%s", raw)
	}
	if _, err := os.Stat(filepath.Join(home, ".codeium", "windsurf", "hooks.json")); !os.IsNotExist(err) {
		t.Error("devin-jetbrains touched the desktop editor's file")
	}
	if un := r.Unregister("devin-jetbrains"); un.Error != nil || len(un.HooksRemoved) != len(cascadeEvents) {
		t.Errorf("Unregister = %+v", un)
	}
}

// TestAntigravityCLIWindowsWritesBridgedHook pins IDE-10's Windows target.
func TestAntigravityCLIWindowsWritesBridgedHook(t *testing.T) {
	for _, data := range agyHookFileReaderDirs {
		t.Run(data, func(t *testing.T) {
			winHome := t.TempDir()
			mkdirs(t, winHome, filepath.Join(".gemini", data))
			r := newIDETestRegistry(t, winHome)
			if !containsString(r.installedAll(true), "antigravity-cli-windows") {
				t.Fatalf("installedAll() = %v", r.installedAll(true))
			}
			res := r.register("antigravity-cli-windows")
			if res.Error != nil {
				t.Fatalf("register: %v", res.Error)
			}
			path := filepath.Join(winHome, ".gemini", "config", "hooks.json")
			if res.ConfigPath != path {
				t.Errorf("ConfigPath = %q", res.ConfigPath)
			}
			checkBridgeFile(t, path, true, "hook antigravity-cli PreToolUse")
			if again := r.register("antigravity-cli-windows"); len(again.AlreadySet) == 0 || again.Error != nil {
				t.Errorf("second register = %+v", again)
			}
			if un := r.Unregister("antigravity-cli-windows"); un.Error != nil {
				t.Fatalf("Unregister: %v", un.Error)
			}
			if raw, _ := os.ReadFile(path); strings.Contains(string(raw), "wsl.exe") {
				t.Errorf("Unregister left the entry:\n%s", raw)
			}
		})
	}
}
