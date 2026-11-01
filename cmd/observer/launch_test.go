package main

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

func TestResolveProxyURL(t *testing.T) {
	cases := []struct {
		name     string
		port     int
		override string
		want     string
	}{
		{"override wins", 8820, "http://example:9000", "http://example:9000"},
		{"default port when zero", 0, "", "http://127.0.0.1:8820"},
		{"default port when negative", -1, "", "http://127.0.0.1:8820"},
		{"configured port", 9100, "", "http://127.0.0.1:9100"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveProxyURL(tc.port, tc.override); got != tc.want {
				t.Errorf("resolveProxyURL(%d, %q) = %q, want %q", tc.port, tc.override, got, tc.want)
			}
		})
	}
}

// fakeBinInfo is a minimal fs.FileInfo for the map-backed resolver env.
type fakeBinInfo struct {
	name string
	mode fs.FileMode
}

func (f fakeBinInfo) Name() string       { return f.name }
func (f fakeBinInfo) Size() int64        { return 0 }
func (f fakeBinInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeBinInfo) ModTime() time.Time { return time.Time{} }
func (f fakeBinInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeBinInfo) Sys() any           { return nil }

// swapResolveEnv installs a map-backed fake toolresolve.Env for the duration of
// a test, restoring the production memoized env on cleanup. files maps an
// absolute path to its mode bits (0o755 = executable regular file).
func swapResolveEnv(t *testing.T, env toolresolve.Env) {
	t.Helper()
	orig := resolveEnv
	resolveEnv = func() toolresolve.Env { return env }
	t.Cleanup(func() { resolveEnv = orig })
}

// fakeEnv builds a toolresolve.Env whose filesystem is the files map (path ->
// mode). EvalSymlinks is identity for present files; Glob is empty.
func fakeEnv(goos string, wsl bool, home string, foreignHomes, processPath []string, files map[string]fs.FileMode) toolresolve.Env {
	return toolresolve.Env{
		GOOS:         goos,
		WSL:          wsl,
		Home:         home,
		ForeignHomes: foreignHomes,
		ProcessPath:  processPath,
		LoginPath:    nil,
		Stat: func(p string) (fs.FileInfo, error) {
			m, ok := files[p]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return fakeBinInfo{name: filepath.Base(p), mode: m}, nil
		},
		EvalSymlinks: func(p string) (string, error) {
			if _, ok := files[p]; ok {
				return p, nil
			}
			return "", fs.ErrNotExist
		},
		Glob: func(string) ([]string, error) { return nil, nil },
	}
}

// writeLaunchConfig writes a temp config.toml pinning [launch.tools.<tool>].path
// and returns its path.
func writeLaunchConfig(t *testing.T, tool, path string) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[launch.tools." + tool + "]\npath = \"" + filepath.ToSlash(path) + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath
}

const exeBin = fs.FileMode(0o755)

func TestResolveToolBin(t *testing.T) {
	// The install Display surfaced when opencode is unresolvable — asserted in
	// the foreign_only / not_found error text so the tests stay grounded in the
	// registry data rather than a hardcoded string.
	row, ok := integration.For("opencode")
	if !ok || row.Binary == nil || len(row.Binary.Installs) == 0 {
		t.Fatalf("registry precondition: opencode needs a Binary row with install hints")
	}
	wantInstall := row.Binary.Installs[0].Display

	t.Run("override flag wins over config and ladder", func(t *testing.T) {
		cfgPath := writeLaunchConfig(t, "opencode", "/opt/config/opencode")
		got, err := resolveToolBin("opencode", "/opt/flag/opencode", "--opencode-path", cfgPath, io.Discard)
		if err != nil || got != "/opt/flag/opencode" {
			t.Fatalf("got (%q, %v), want (/opt/flag/opencode, nil)", got, err)
		}
	})

	t.Run("config path wins over ladder", func(t *testing.T) {
		// A real temp file so the stat-check passes.
		binDir := t.TempDir()
		binPath := filepath.Join(binDir, "opencode")
		if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cfgPath := writeLaunchConfig(t, "opencode", binPath)
		// Even with an OK ladder available, config wins.
		swapResolveEnv(t, fakeEnv("linux", false, "/home/u", nil,
			[]string{"/usr/bin"}, map[string]fs.FileMode{"/usr/bin/opencode": exeBin}))
		got, err := resolveToolBin("opencode", "", "--opencode-path", cfgPath, io.Discard)
		// The configured path comes back as written (slash form in the
		// TOML); compare it in the host form.
		if err != nil || filepath.FromSlash(got) != binPath {
			t.Fatalf("got (%q, %v), want (%q, nil)", got, err, binPath)
		}
	})

	t.Run("config path set-but-missing errors name the key", func(t *testing.T) {
		cfgPath := writeLaunchConfig(t, "opencode", "/no/such/opencode")
		_, err := resolveToolBin("opencode", "", "--opencode-path", cfgPath, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "[launch.tools.opencode].path") {
			t.Fatalf("err = %v, want one naming [launch.tools.opencode].path", err)
		}
	})

	t.Run("verdict ok returns bin silently", func(t *testing.T) {
		skipLinuxFakeOnWindows(t)
		swapResolveEnv(t, fakeEnv("linux", false, "/home/u", nil,
			[]string{"/usr/bin"}, map[string]fs.FileMode{"/usr/bin/opencode": exeBin}))
		var stderr strings.Builder
		got, err := resolveToolBin("opencode", "", "--opencode-path", "", &stderr)
		if err != nil || got != "/usr/bin/opencode" {
			t.Fatalf("got (%q, %v), want (/usr/bin/opencode, nil)", got, err)
		}
		if stderr.Len() != 0 {
			t.Errorf("ok verdict wrote to stderr: %q", stderr.String())
		}
	})

	t.Run("shadowed prints a note and returns the native bin", func(t *testing.T) {
		skipLinuxFakeOnWindows(t)
		swapResolveEnv(t, fakeEnv("linux", true, "/home/u", nil,
			[]string{"/mnt/c/npm", "/usr/bin"},
			map[string]fs.FileMode{
				"/mnt/c/npm/opencode": exeBin, // Windows interop shim, earlier on PATH
				"/usr/bin/opencode":   exeBin, // native install
			}))
		var stderr strings.Builder
		got, err := resolveToolBin("opencode", "", "--opencode-path", "", &stderr)
		if err != nil || got != "/usr/bin/opencode" {
			t.Fatalf("got (%q, %v), want (/usr/bin/opencode, nil)", got, err)
		}
		if !strings.Contains(stderr.String(), "shim") {
			t.Errorf("shadowed verdict stderr = %q, want a shim note", stderr.String())
		}
	})

	t.Run("foreign_only errors with the install command", func(t *testing.T) {
		skipLinuxFakeOnWindows(t)
		swapResolveEnv(t, fakeEnv("linux", true, "/home/u", nil,
			[]string{"/mnt/c/npm"},
			map[string]fs.FileMode{"/mnt/c/npm/opencode": exeBin}))
		_, err := resolveToolBin("opencode", "", "--opencode-path", "", io.Discard)
		if err == nil {
			t.Fatal("want an error for a Windows-only install")
		}
		if !strings.Contains(err.Error(), "Windows") || !strings.Contains(err.Error(), wantInstall) {
			t.Fatalf("err = %v, want one naming Windows + the install %q", err, wantInstall)
		}
	})

	t.Run("not_found errors with the install command", func(t *testing.T) {
		swapResolveEnv(t, fakeEnv("linux", false, "/home/u", nil,
			[]string{"/usr/bin"}, map[string]fs.FileMode{}))
		_, err := resolveToolBin("opencode", "", "--opencode-path", "", io.Discard)
		if err == nil || !strings.Contains(err.Error(), wantInstall) {
			t.Fatalf("err = %v, want one naming the install %q", err, wantInstall)
		}
	})
}

func TestApplyBaseURLEnv(t *testing.T) {
	t.Run("injects unset keys, sorted, appended", func(t *testing.T) {
		env, applied, presets := applyBaseURLEnv(
			[]string{"PATH=/bin"},
			map[string]string{"OPENAI_BASE_URL": "http://p/v1", "COPILOT_PROVIDER_TYPE": "openai"},
		)
		if len(presets) != 0 {
			t.Errorf("presets = %v, want none", presets)
		}
		if !containsKV(env, "OPENAI_BASE_URL=http://p/v1") || !containsKV(env, "COPILOT_PROVIDER_TYPE=openai") {
			t.Errorf("env missing injected keys: %v", env)
		}
		// applied is sorted for determinism.
		if strings.Join(applied, ",") != "COPILOT_PROVIDER_TYPE,OPENAI_BASE_URL" {
			t.Errorf("applied = %v, want sorted", applied)
		}
	})

	t.Run("user's non-empty value wins (preset, not clobbered)", func(t *testing.T) {
		env, applied, presets := applyBaseURLEnv(
			[]string{"OPENAI_BASE_URL=https://mine/v1"},
			map[string]string{"OPENAI_BASE_URL": "http://p/v1"},
		)
		if len(applied) != 0 {
			t.Errorf("applied = %v, want none (user wins)", applied)
		}
		if strings.Join(presets, ",") != "OPENAI_BASE_URL" {
			t.Errorf("presets = %v", presets)
		}
		if envValue(env, "OPENAI_BASE_URL") != "https://mine/v1" {
			t.Errorf("user value clobbered: %q", envValue(env, "OPENAI_BASE_URL"))
		}
		if countKey(env, "OPENAI_BASE_URL") != 1 {
			t.Errorf("OPENAI_BASE_URL appears %d times, want 1", countKey(env, "OPENAI_BASE_URL"))
		}
	})

	t.Run("empty existing value counts as unset", func(t *testing.T) {
		_, applied, presets := applyBaseURLEnv(
			[]string{"OPENAI_BASE_URL="},
			map[string]string{"OPENAI_BASE_URL": "http://p/v1"},
		)
		if len(presets) != 0 {
			t.Errorf("presets = %v, want none (empty is unset)", presets)
		}
		if len(applied) != 1 {
			t.Errorf("applied = %v, want injected", applied)
		}
	})

	t.Run("never injects a key not in the inject map (no secret leakage)", func(t *testing.T) {
		env, _, _ := applyBaseURLEnv(
			[]string{"PATH=/bin"},
			map[string]string{"OPENAI_BASE_URL": "http://p/v1"},
		)
		if countKey(env, "COPILOT_PROVIDER_API_KEY") != 0 {
			t.Error("helper injected a key it was never given")
		}
	})
}

func TestAgentRuntimeEnv(t *testing.T) {
	t.Run("empty dir is off (nil)", func(t *testing.T) {
		if got := agentRuntimeEnv(""); got != nil {
			t.Errorf("agentRuntimeEnv(\"\") = %v, want nil (feature off)", got)
		}
		if got := agentRuntimeEnv("   "); got != nil {
			t.Errorf("agentRuntimeEnv(whitespace) = %v, want nil", got)
		}
	})

	t.Run("relocates config/cache/state + pkg caches, never data", func(t *testing.T) {
		got := agentRuntimeEnv("/opt/agent-runtime")
		// The dirs are host paths, joined with the host's separator.
		want := map[string]string{
			"XDG_CONFIG_HOME":       filepath.Join("/opt/agent-runtime", "config"),
			"XDG_CACHE_HOME":        filepath.Join("/opt/agent-runtime", "cache"),
			"XDG_STATE_HOME":        filepath.Join("/opt/agent-runtime", "state"),
			"npm_config_cache":      filepath.Join("/opt/agent-runtime", "npm"),
			"BUN_INSTALL_CACHE_DIR": filepath.Join("/opt/agent-runtime", "bun"),
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("agentRuntimeEnv[%s] = %q, want %q", k, got[k], v)
			}
		}
		// XDG_DATA_HOME must NOT be relocated: agents write session storage
		// there and the watcher reads it under $HOME/.local/share.
		if _, ok := got["XDG_DATA_HOME"]; ok {
			t.Error("agentRuntimeEnv must not set XDG_DATA_HOME (would blind the watcher)")
		}
		if len(got) != len(want) {
			t.Errorf("agentRuntimeEnv returned %d keys, want %d: %v", len(got), len(want), got)
		}
	})
}

func TestApplyAgentRuntimeEnv(t *testing.T) {
	t.Run("off: base env untouched", func(t *testing.T) {
		base := []string{"PATH=/bin", "HOME=/home/me"}
		got := applyAgentRuntimeEnv(base, "")
		if len(got) != len(base) {
			t.Errorf("applyAgentRuntimeEnv(off) changed env: %v", got)
		}
	})

	t.Run("on: layers runtime keys + creates dirs", func(t *testing.T) {
		dir := t.TempDir()
		got := applyAgentRuntimeEnv([]string{"PATH=/bin"}, dir)
		if envValue(got, "XDG_CONFIG_HOME") != filepath.Join(dir, "config") {
			t.Errorf("XDG_CONFIG_HOME = %q", envValue(got, "XDG_CONFIG_HOME"))
		}
		if envValue(got, "XDG_DATA_HOME") != "" {
			t.Error("XDG_DATA_HOME was set - must stay on the share for capture")
		}
		// dirs are created so the agent's package manager can write into them.
		for _, sub := range []string{"config", "cache", "state", "npm", "bun"} {
			if fi, err := os.Stat(filepath.Join(dir, sub)); err != nil || !fi.IsDir() {
				t.Errorf("expected dir %s to be created: err=%v", sub, err)
			}
		}
	})

	t.Run("on: user's own XDG_CONFIG_HOME wins", func(t *testing.T) {
		dir := t.TempDir()
		got := applyAgentRuntimeEnv([]string{"XDG_CONFIG_HOME=/my/own"}, dir)
		if envValue(got, "XDG_CONFIG_HOME") != "/my/own" {
			t.Errorf("user XDG_CONFIG_HOME clobbered: %q", envValue(got, "XDG_CONFIG_HOME"))
		}
		if countKey(got, "XDG_CONFIG_HOME") != 1 {
			t.Errorf("XDG_CONFIG_HOME appears %d times, want 1", countKey(got, "XDG_CONFIG_HOME"))
		}
	})
}

func TestEnvValue(t *testing.T) {
	env := []string{"A=1", "B=2", "A=3"}
	if got := envValue(env, "A"); got != "3" { // last wins
		t.Errorf("envValue last-wins = %q, want 3", got)
	}
	if got := envValue(env, "Z"); got != "" {
		t.Errorf("envValue absent = %q, want empty", got)
	}
}

// skipLinuxFakeOnWindows skips a case whose fake environment models a Linux
// host with POSIX paths: the resolver joins with the host's separator, so on
// Windows the fake's paths never match (Windows 11 Pro rerun 2026-10-25,
// D5 group 4).
func skipLinuxFakeOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake models a Linux host with POSIX paths")
	}
}
