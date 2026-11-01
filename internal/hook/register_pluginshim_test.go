package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook/pluginshim"
)

func pluginShimRegistry(t *testing.T, home string, force bool, getenv func(string) string) *Registry {
	t.Helper()
	r, err := NewRegistry(Options{
		BinaryPath: "/opt/observer/bin/observer", HomeDir: home, Force: force,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"), Getenv: getenv,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestRegisterPluginShim walks the plugin-shim format writer for every host
// with a grounded plugin directory: place, refresh, refuse a foreign file,
// take it over under --force with a backup, unregister checksum-guarded.
func TestRegisterPluginShim(t *testing.T) {
	cases := []struct {
		tool, rel string
		events    []string
	}{
		{"opencode", ".config/opencode/plugins/superbased-observer.ts", []string{"chat.message", "tool.execute.before"}},
		{"kilo-code-cli", ".config/kilo/plugin/superbased-observer.ts", []string{"chat.message", "tool.execute.before"}},
		{"pi", ".pi/agent/extensions/superbased-observer.ts", []string{"input", "tool_call"}},
	}
	for _, c := range cases {
		t.Run(c.tool, func(t *testing.T) {
			home := t.TempDir()
			r := pluginShimRegistry(t, home, false, nil)
			res := r.Register(c.tool)
			if res.Error != nil {
				t.Fatal(res.Error)
			}
			path := filepath.Join(home, filepath.FromSlash(c.rel))
			if res.ConfigPath != path || strings.Join(res.HooksAdded, ",") != strings.Join(c.events, ",") {
				t.Fatalf("result = %+v", res)
			}
			data, err := os.ReadFile(path)
			if err != nil || !pluginshim.LooksLikeObserverShim(data) {
				t.Fatalf("shim not written: %v", err)
			}
			for _, want := range []string{`"tool":"` + c.tool + `"`, `"bin":"/opt/observer/bin/observer"`, `"posture":` + jsonString(filepath.Join(home, ".observer", "guard-posture.json"))} {
				if !strings.Contains(string(data), want) {
					t.Errorf("shim lacks %s", want)
				}
			}
			for _, ev := range c.events {
				if !strings.Contains(string(data), `"`+ev+`":`) {
					t.Errorf("shim does not subscribe %s", ev)
				}
			}
			// Re-register refreshes in place.
			if res := r.Register(c.tool); res.Error != nil || len(res.AlreadySet) != len(c.events) {
				t.Fatalf("re-register = %+v", res)
			}
			// Unregister is checksum-guarded: a modified file is refused.
			if err := os.WriteFile(path, append(data, []byte("\n// edited\n")...), 0o600); err != nil {
				t.Fatal(err)
			}
			if res := r.Unregister(c.tool); res.Error == nil {
				t.Fatal("unregister of a modified shim must be refused without --force")
			}
			if res := pluginShimRegistry(t, home, true, nil).Unregister(c.tool); res.Error != nil {
				t.Fatal(res.Error)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("shim still present: %v", err)
			}
			// A foreign file is refused, then taken over with a backup.
			if err := os.WriteFile(path, []byte("// someone else's plugin\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if res := r.Register(c.tool); res.Error == nil {
				t.Fatal("a foreign file must be refused without --force")
			}
			if res := pluginShimRegistry(t, home, true, nil).Register(c.tool); res.Error != nil {
				t.Fatal(res.Error)
			}
			if bak, err := os.ReadFile(path + ".bak"); err != nil || string(bak) != "// someone else's plugin\n" {
				t.Fatalf("backup = %q %v", bak, err)
			}
			if res := r.Unregister(c.tool); res.Error != nil {
				t.Fatal(res.Error)
			}
		})
	}
}

// TestRegisterPluginShimHonoursEnvOnlyWhenGiven: the XDG / pi overrides
// are consulted only through Options.Getenv (nil = HomeDir only).
func TestRegisterPluginShimHonoursEnvOnlyWhenGiven(t *testing.T) {
	home, xdg := t.TempDir(), t.TempDir()
	env := map[string]string{"XDG_CONFIG_HOME": xdg}
	res := pluginShimRegistry(t, home, false, func(k string) string { return env[k] }).Register("opencode")
	if res.Error != nil || res.ConfigPath != filepath.Join(xdg, "opencode", "plugins", "superbased-observer.ts") {
		t.Fatalf("with env: %+v", res)
	}
	res = pluginShimRegistry(t, home, false, nil).Register("opencode")
	if res.Error != nil || !strings.HasPrefix(res.ConfigPath, home) {
		t.Fatalf("without env: %+v", res)
	}
}

// TestRegisterPluginShimUngroundedHosts: OpenClaw and DeepSeek render the
// shim but have no grounded install location: Register refuses with the
// reason, and writes nothing.
// TestInstalledDetectsPluginShimHosts: Installed() (the list `observer
// start` auto-registers from and `observer init --all` selects from) names a
// plugin-shim host exactly when its vendor config directory exists, and
// never an ungrounded host or the commandcode Mods row twice.
func TestInstalledDetectsPluginShimHosts(t *testing.T) {
	home := t.TempDir()
	pi := t.TempDir()
	env := map[string]string{"PI_CODING_AGENT_DIR": pi}
	r, err := NewRegistry(Options{HomeDir: home, BinaryPath: "/bin/observer", Getenv: func(k string) string { return env[k] }})
	if err != nil {
		t.Fatal(err)
	}
	has := func(tool string) bool {
		for _, x := range r.Installed() {
			if x == tool {
				return true
			}
		}
		return false
	}
	if has("opencode") || has("kilo-code-cli") || has("openclaw") || has("deepseek") {
		t.Fatalf("Installed() = %v before any vendor dir exists", r.Installed())
	}
	if !has("pi") {
		t.Fatal("pi: $PI_CODING_AGENT_DIR exists, want detected")
	}
	for _, d := range []string{".config/opencode", ".config/kilo", ".commandcode"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	n := 0
	for _, x := range r.Installed() {
		if x == "command-code" {
			n++
		}
	}
	if !has("opencode") || !has("kilo-code-cli") || n != 1 {
		t.Fatalf("Installed() = %v, want opencode + kilo-code-cli and command-code once", r.Installed())
	}

	// Hermes (its own plugin installer, outside Register): out-of-band,
	// detected only when its vendor home exists, never on Installed().
	if has("hermes") {
		t.Fatalf("Installed() = %v lists hermes (Register cannot serve it)", r.Installed())
	}
	if got := r.InstalledOutOfBand(); len(got) != 0 {
		t.Fatalf("InstalledOutOfBand() = %v with no Hermes home", got)
	}
	// The platform default: ~/.hermes, or on Windows %LOCALAPPDATA%\hermes
	// whose fallback (no LOCALAPPDATA) is ~/AppData/Local/hermes, as Hermes
	// itself resolves it (hermes_constants._platform_default_hermes_home).
	hermesHome := filepath.Join(home, ".hermes")
	if runtime.GOOS == "windows" {
		hermesHome = filepath.Join(home, "AppData", "Local", "hermes")
	}
	if err := os.MkdirAll(hermesHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := r.InstalledOutOfBand(); len(got) != 1 || got[0] != "hermes" {
		t.Fatalf("InstalledOutOfBand() = %v, want [hermes] once ~/.hermes exists", got)
	}
	if has("hermes") {
		t.Fatal("Installed() lists hermes once ~/.hermes exists")
	}
	// HERMES_HOME wins over ~/.hermes (through the injected getenv only).
	env["HERMES_HOME"] = filepath.Join(home, "elsewhere")
	if got := r.InstalledOutOfBand(); len(got) != 0 {
		t.Fatalf("InstalledOutOfBand() = %v, want none: $HERMES_HOME does not exist", got)
	}
	if err := os.MkdirAll(env["HERMES_HOME"], 0o755); err != nil {
		t.Fatal(err)
	}
	if got := r.InstalledOutOfBand(); len(got) != 1 {
		t.Fatalf("InstalledOutOfBand() = %v, want [hermes] under $HERMES_HOME", got)
	}
}

func TestRegisterPluginShimUngroundedHosts(t *testing.T) {
	for _, tool := range []string{"openclaw", "deepseek"} {
		home := t.TempDir()
		res := pluginShimRegistry(t, home, false, nil).Register(tool)
		if res.Error == nil || !strings.Contains(res.Error.Error(), "no install location") {
			t.Fatalf("%s: %+v", tool, res)
		}
	}
}

// jsonString is s as a JSON string literal (a Windows path's backslashes
// are escaped in the shim, so the test compares that spelling).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
