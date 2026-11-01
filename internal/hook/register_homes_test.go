package hook

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// homesRegistry is a registry pinned to a throwaway home and a fake
// environment (surface-gap Wave 4, lane w4-homes-b).
func homesRegistry(t *testing.T, home string, env map[string]string) *Registry {
	t.Helper()
	reg, err := NewRegistry(Options{
		BinaryPath:    "/opt/observer/bin/observer",
		HomeDir:       home,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
		Getenv:        func(k string) string { return env[k] },
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return reg
}

// homeRelocationRows: per tool, the vendor's home variable, the file
// Observer writes relative to the relocated directory, and the default
// directory under the home that must stay untouched. Red on the old
// writers, which hard-coded the default home (S-17, CLI-4, W-4, OI-1).
var homeRelocationRows = []struct {
	tool, env  string
	file       []string
	defaultDir []string
	// relativeFallsThrough: the vendor ignores a relative value (Kiro).
	relativeFallsThrough bool
}{
	{tool: "gemini-cli", env: "GEMINI_CLI_HOME", file: []string{".gemini", "settings.json"}, defaultDir: []string{".gemini"}},
	{tool: "qwen-code", env: "QWEN_HOME", file: []string{"settings.json"}, defaultDir: []string{".qwen"}},
	{tool: "qoder", env: "QODER_CONFIG_DIR", file: []string{"settings.json"}, defaultDir: []string{".qoder"}},
	{tool: "grok", env: "GROK_HOME", file: []string{"hooks", "superbased-observer.json"}, defaultDir: []string{".grok"}},
	{tool: "copilot-cli", env: "COPILOT_HOME", file: []string{"hooks", "superbased-observer.json"}, defaultDir: []string{".copilot"}},
	{tool: "junie", env: "JUNIE_HOME", file: []string{"config.json"}, defaultDir: []string{".junie"}},
	{tool: "crush", env: "CRUSH_GLOBAL_CONFIG", file: []string{"crush.json"}, defaultDir: []string{".config", "crush"}},
	{tool: "open-interpreter", env: "INTERPRETER_HOME", file: []string{"hooks.json"}, defaultDir: []string{".openinterpreter"}},
	{tool: "mistral-code", env: "VIBE_HOME", file: []string{"hooks.toml"}, defaultDir: []string{".vibe"}},
	{tool: "kimi-code", env: "KIMI_CODE_HOME", file: []string{"config.toml"}, defaultDir: []string{".kimi-code"}},
	{tool: "kiro-cli", env: "KIRO_HOME", file: []string{"agents", kiroAgentName + ".json"}, defaultDir: []string{".kiro"}, relativeFallsThrough: true},
}

// TestHookWritersFollowTheVendorHome: with the vendor's home variable set to
// an absolute directory, the writer puts Observer's hook there and never
// creates the default home; unregistration finds it there too.
func TestHookWritersFollowTheVendorHome(t *testing.T) {
	for _, tc := range homeRelocationRows {
		t.Run(tc.tool, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "home")
			relocated := filepath.Join(root, "relocated")
			for _, d := range []string{home, relocated} {
				if err := os.MkdirAll(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			reg := homesRegistry(t, home, map[string]string{tc.env: relocated})
			res := reg.Register(tc.tool)
			if res.Error != nil {
				t.Fatalf("Register: %v", res.Error)
			}
			want := filepath.Join(append([]string{relocated}, tc.file...)...)
			if _, err := os.Stat(want); err != nil {
				t.Errorf("no hook written at %s (%s set): %v", want, tc.env, err)
			}
			if _, err := os.Stat(filepath.Join(append([]string{home}, tc.defaultDir...)...)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the default home was written too (err %v)", err)
			}
			if !reg.homeArtifactExists(tc.tool) {
				t.Errorf("install detection does not find the relocated home")
			}
			if un := reg.Unregister(tc.tool); un.Error != nil {
				t.Errorf("Unregister: %v", un.Error)
			}
		})
	}
}

// TestHookWritersRefuseARelativeVendorHome (FU-31): a relative home value
// is what the vendor reads against its own working directory, so the
// writer reports it and writes nothing, never the default home. Kiro
// ignores a relative KIRO_HOME itself, so its writer keeps the default.
func TestHookWritersRefuseARelativeVendorHome(t *testing.T) {
	for _, tc := range homeRelocationRows {
		t.Run(tc.tool, func(t *testing.T) {
			home := t.TempDir()
			reg := homesRegistry(t, home, map[string]string{tc.env: filepath.Join("rel", "home")})
			res := reg.Register(tc.tool)
			defaultDir := filepath.Join(append([]string{home}, tc.defaultDir...)...)
			if tc.relativeFallsThrough {
				if res.Error != nil {
					t.Fatalf("Register: %v", res.Error)
				}
				if _, err := os.Stat(defaultDir); err != nil {
					t.Errorf("the vendor ignores a relative value, so the default home is the target: %v", err)
				}
				return
			}
			if res.Error == nil {
				t.Fatalf("Register with a relative %s = %+v, want an error", tc.env, res)
			}
			if _, err := os.Stat(defaultDir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("a relative %s wrote the default home (err %v)", tc.env, err)
			}
		})
	}
}

// TestGooseDetectedAtItsNativeWindowsHome: Goose keeps its config under
// %APPDATA%\Block\goose\config on Windows, which the old probe of
// ~/.config/goose never found (S-17).
func TestGooseDetectedAtItsNativeWindowsHome(t *testing.T) {
	home := t.TempDir()
	appData := filepath.Join(home, "Roaming")
	if err := os.MkdirAll(filepath.Join(appData, "Block", "goose", "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	reg, err := NewRegistry(Options{
		BinaryPath: "/opt/observer/bin/observer", HomeDir: home, GOOS: "windows",
		Getenv: func(k string) string {
			if k == "APPDATA" {
				return rowAbs("windows", appData)
			}
			return ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reg.homeArtifactExists("goose") {
		t.Errorf("goose's Windows home %s not detected", filepath.Join(appData, "Block", "goose", "config"))
	}
	linux := homesRegistry(t, home, nil)
	linux.opts.GOOS = "linux"
	if linux.homeArtifactExists("goose") {
		t.Errorf("a Linux registry found goose with no ~/.config/goose")
	}
}
