package mcpregister

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

func forceClineWSLHomes(t *testing.T, owned map[string]bool, homes ...string) {
	t.Helper()
	var roots []crossmount.HomeRoot
	for _, h := range homes {
		roots = append(roots, crossmount.HomeRoot{Path: h, OS: crossmount.OSLinux, Origin: "wslhost:Ubuntu/" + filepath.Base(h)})
	}
	prevHomes, prevOwned := allHomes, wslHomeOwned
	allHomes = func() []crossmount.HomeRoot { return roots }
	wslHomeOwned = func(h string) bool { return owned[h] }
	t.Cleanup(func() { allHomes, wslHomeOwned = prevHomes, prevOwned })
}

func mkClineWSLHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "me")
	if err := os.MkdirAll(filepath.Join(home, ".cline", "data"), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

func newClineWSLRegistrar(t *testing.T, binary string) *Registrar {
	t.Helper()
	r, err := NewRegistrar(RegisterOptions{BinaryPath: binary, ConfigPath: `C:\Users\me\.observer\config.toml`, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r.homeOverride = ""
	return r
}

// TestClineWSLIsGated pins DEC-12 for the MCP twin.
func TestClineWSLIsGated(t *testing.T) {
	home := mkClineWSLHome(t)
	forceClineWSLHomes(t, map[string]bool{home: true}, home)
	r := newClineWSLRegistrar(t, `C:\Users\me\observer\observer.exe`)
	res := r.Register("cline-wsl")
	if !res.Skipped || res.SkipReason != "built, waiting on live check WSL-4" || res.Error != nil {
		t.Fatalf("Register(cline-wsl) = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json")); !os.IsNotExist(err) {
		t.Errorf("gated twin wrote the file (%v)", err)
	}
	for _, tool := range r.Installed() {
		if tool == "cline-wsl" {
			t.Error("Installed lists the gated cline-wsl")
		}
	}
	if !r.ClineWSLDetected() {
		t.Error("ClineWSLDetected = false for a detected home")
	}
	if id, gated := ClineWSLLiveGate(); !gated || id != "WSL-4" {
		t.Errorf("ClineWSLLiveGate = %q, %v", id, gated)
	}
}

// TestClineWSLWrites runs the writer below the gate, then Unregister.
func TestClineWSLWrites(t *testing.T) {
	home := mkClineWSLHome(t)
	forceClineWSLHomes(t, map[string]bool{home: true}, home)
	r := newClineWSLRegistrar(t, `C:\Users\me\observer\observer.exe`)
	res := r.writeClineWSL()
	if res.Error != nil || !res.Added {
		t.Fatalf("writeClineWSL = %+v", res)
	}
	path := filepath.Join(home, ".cline", "data", "settings", "cline_mcp_settings.json")
	if res.ConfigPath != path {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	e := doc.MCPServers[ServerName]
	if e.Command != "/mnt/c/Users/me/observer/observer.exe" || strings.Join(e.Args, " ") != "serve --config C:/Users/me/.observer/config.toml" {
		t.Errorf("entry = %+v", e)
	}
	if again := r.writeClineWSL(); !again.AlreadySet {
		t.Errorf("second write = %+v, want AlreadySet", again)
	}
	if un := r.Unregister("cline-wsl"); un.Error != nil || !un.Removed {
		t.Errorf("Unregister = %+v", un)
	}
}

// TestClineWSLRefusals walks the refusal rows.
func TestClineWSLRefusals(t *testing.T) {
	t.Run("npm launcher", func(t *testing.T) {
		home := mkClineWSLHome(t)
		forceClineWSLHomes(t, map[string]bool{home: true}, home)
		if res := newClineWSLRegistrar(t, `C:\npm\observer.cmd`).writeClineWSL(); res.Error == nil {
			t.Error("a .cmd launcher must be refused")
		}
	})
	t.Run("unowned home", func(t *testing.T) {
		home := mkClineWSLHome(t)
		forceClineWSLHomes(t, nil, home)
		if res := newClineWSLRegistrar(t, `C:\o\observer.exe`).writeClineWSL(); res.Error == nil {
			t.Error("an unowned home must not be written")
		}
	})
	t.Run("native home never counts", func(t *testing.T) {
		home := mkClineWSLHome(t)
		forceClineWSLHomes(t, map[string]bool{home: true})
		prev := allHomes
		allHomes = func() []crossmount.HomeRoot {
			return []crossmount.HomeRoot{{Path: home, OS: crossmount.OSLinux, Origin: "native"}}
		}
		t.Cleanup(func() { allHomes = prev })
		if res := newClineWSLRegistrar(t, `C:\o\observer.exe`).writeClineWSL(); res.Error == nil {
			t.Error("a native home must not be treated as a WSL home")
		}
	})
	t.Run("pinned sandbox", func(t *testing.T) {
		home := mkClineWSLHome(t)
		forceClineWSLHomes(t, map[string]bool{home: true}, home)
		r, err := NewRegistrar(RegisterOptions{BinaryPath: `C:\o\observer.exe`, HomeDir: t.TempDir()})
		if err != nil {
			t.Fatal(err)
		}
		if res := r.writeClineWSL(); !res.Skipped || res.Error != nil {
			t.Errorf("sandboxed = %+v, want a skip", res)
		}
	})
}
