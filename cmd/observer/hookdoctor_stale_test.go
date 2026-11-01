package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/hook"
)

func TestObserverHookBinary(t *testing.T) {
	cases := []struct {
		cmd   string
		bin   string
		owned bool
		ok    bool
	}{
		{"/opt/observer/bin/observer hook qwen-code UserPromptSubmit", "/opt/observer/bin/observer", true, true},
		{"wsl.exe -d Ubuntu -- /home/u/bin/observer hook gemini-cli BeforeAgent --config /home/u/.observer/config.toml", "/home/u/bin/observer", true, true},
		{"MSYS_NO_PATHCONV=1 wsl.exe -d 'Ubuntu-22.04' -- /home/u/bin/observer hook claude-code pre-tool", "/home/u/bin/observer", true, true},
		{`"C:\Users\u\AppData\Roaming\npm\observer.exe" hook droid PreToolUse`, "C:/Users/u/AppData/Roaming/npm/observer.exe", true, true},
		// FU-162: the native Codex writer's PowerShell form on Windows.
		{`& 'C:\Users\First Last\AppData\Local\SuperBased\Observer\bin\observer.exe' hook codex PreToolUse --config 'C:\Users\First Last\.observer\config.toml'`, "C:/Users/First Last/AppData/Local/SuperBased/Observer/bin/observer.exe", true, true},
		{"wsl.exe -d Ubuntu -- /tmp/go-build1234/b001/observer.test hook qoder UserPromptSubmit --config /tmp/TestX/001/config.toml", "/tmp/go-build1234/b001/observer.test", false, true},
		{"/opt/acme/audit --note 'run hook cursor stop'", "", false, false},
		{"/opt/observer/bin/observer statusline", "", false, false},
		{"/usr/local/bin/other.test hook qwen-code x", "", false, false},
	}
	for _, tc := range cases {
		bin, owned, ok := observerHookBinary(tc.cmd)
		if bin != tc.bin || owned != tc.owned || ok != tc.ok {
			t.Errorf("observerHookBinary(%q) = %q, %v, %v; want %q, %v, %v", tc.cmd, bin, owned, ok, tc.bin, tc.owned, tc.ok)
		}
	}
}

func TestStaleBinaryRules(t *testing.T) {
	// A missing binary is reported only for a path that is absolute on this
	// host: a POSIX path in a Windows settings file (a WSL bridge target)
	// cannot be checked from Windows (Windows 11 Pro rerun 2026-10-25, D5 group 4).
	missingHookBinary := "/opt/old/observer"
	if runtime.GOOS == "windows" {
		missingHookBinary = "C:/opt/old/observer.exe"
	}
	present := map[string]bool{"/opt/observer/bin/observer": true}
	env := staleEnv{exists: func(p string) bool { return present[filepath.ToSlash(p)] }, tempRoots: []string{"/tmp"}}
	cases := []struct {
		cmd    string
		reason string // "" = not stale
	}{
		{"/opt/observer/bin/observer hook qwen-code UserPromptSubmit", ""},
		{"wsl.exe -d Ubuntu -- /tmp/go-build1234/b001/observer.test hook qwen-code UserPromptSubmit", "go-build directory"},
		{"/home/u/proj/observer.test hook qwen-code UserPromptSubmit", "Go test binary"},
		{"/tmp/TestFoo123/001/observer hook gemini-cli BeforeAgent", "temp directory"},
		{"C:/Users/u/AppData/Local/Temp/x/observer.exe hook droid PreToolUse", "temp directory"},
		{missingHookBinary + " hook qoder PreToolUse", "missing"},
		{"observer hook qoder PreToolUse", ""},
		{"/opt/acme/audit hook qoder PreToolUse", ""},
	}
	for _, tc := range cases {
		body, _ := json.Marshal(map[string]any{"hooks": map[string]any{"E": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": tc.cmd}}}}}})
		got := findStaleHookEntries("settings.json", body, env)
		switch {
		case tc.reason == "" && len(got) != 0:
			t.Errorf("%q reported stale: %+v", tc.cmd, got)
		case tc.reason != "" && (len(got) != 1 || !strings.Contains(got[0].Reason, tc.reason)):
			t.Errorf("%q = %+v, want one entry naming %q", tc.cmd, got, tc.reason)
		}
	}
}

// pt06LaptopFiles are the four files PT-06 names, as the laptop's test run
// left them: a prompt entry running a long-gone observer.test through the
// WSL bridge (droid's hooks.json also has the legacy hooks wrapper).
var pt06LaptopFiles = map[string]string{
	filepath.Join(".qwen", "settings.json"):   `{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"wsl.exe -d Ubuntu -- /tmp/go-build4242/b001/observer.test hook qwen-code UserPromptSubmit --config /tmp/TestAutoRegisterHooks_PromptLaneOnlyGate1/001/config.toml"}]}]}}`,
	filepath.Join(".qoder", "settings.json"):  `{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"wsl.exe -d Ubuntu -- /tmp/go-build4242/b001/observer.test hook qoder UserPromptSubmit"}]}]}}`,
	filepath.Join(".gemini", "settings.json"): `{"hooks":{"BeforeAgent":[{"hooks":[{"type":"command","command":"wsl.exe -d Ubuntu -- /tmp/go-build4242/b001/observer.test hook gemini-cli BeforeAgent"}]}]}}`,
	filepath.Join(".factory", "hooks.json"):   `{"PreToolUse":[],"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"wsl.exe -d Ubuntu -- /tmp/go-build4242/b001/observer.test hook droid UserPromptSubmit"}]}]}}`,
}

// TestHookDoctorListsStaleEntriesReadOnly is milestone 4's doctor check: on
// a Windows home holding the laptop's four stale files, `observer doctor
// --hooks` names each file and entry with the remedy, and leaves every
// file byte-identical; a clean home gets no stale line at all.
func TestHookDoctorListsStaleEntriesReadOnly(t *testing.T) {
	sandbox := t.TempDir()
	// The Windows home lives inside the pinned HOME: a cross-OS override
	// outside a pinned home is suppressed by design (incident 2026-07-31).
	home := filepath.Join(sandbox, "home")
	win := filepath.Join(home, "mnt", "c", "Users", "operator")
	for _, d := range []string{home, win} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	orig := hookRegistrationOptions
	t.Cleanup(func() { hookRegistrationOptions = orig })
	hookRegistrationOptions = func(binary, configPath string) hook.Options {
		o := orig(binary, configPath)
		o.HomeDir, o.WSLDistro = home, "Ubuntu"
		o.WindowsQwenHome, o.WindowsQoderHome, o.WindowsGeminiHome, o.WindowsFactoryHome = win, win, win, win
		// The doctor reads writers with the process environment (as init
		// does); this sandbox pins every home itself, so no variable of the
		// real environment (APPDATA, XDG_CONFIG_HOME, a vendor home) may
		// move a writer out of it.
		o.Getenv = func(string) string { return "" }
		return o
	}
	run := func() []string {
		var buf bytes.Buffer
		_ = runHookDoctor(context.Background(), &buf, hookDoctorOptions{
			Binary: filepath.Join(home, "bin", "observer"), ConfigPath: filepath.Join(home, ".observer", "config.toml"),
			Bindings: true, JSON: true,
		})
		var rep struct {
			Checks []struct {
				Name, Message string
				Details       []string
			}
		}
		if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
			t.Fatalf("doctor JSON: %v\n%s", err, buf.String())
		}
		var stale []string
		for _, c := range rep.Checks {
			if strings.HasPrefix(c.Name, "hook.stale:") {
				stale = append(stale, c.Name+"\n"+c.Message+"\n"+strings.Join(c.Details, "\n"))
			}
		}
		return stale
	}

	if got := run(); len(got) != 0 {
		t.Fatalf("a clean machine got stale lines:\n%s", strings.Join(got, "\n---\n"))
	}

	before := map[string]string{}
	for rel, body := range pt06LaptopFiles {
		p := filepath.Join(win, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		before[p] = body
	}
	got := strings.Join(run(), "\n---\n")
	for p := range before {
		if !strings.Contains(got, "hook.stale:"+p) {
			t.Errorf("doctor did not list %s:\n%s", p, got)
		}
	}
	for _, want := range []string{"go-build directory", "observer.test hook qwen-code UserPromptSubmit", "remove this entry from the file by hand"} {
		if !strings.Contains(got, want) {
			t.Errorf("doctor output lacks %q:\n%s", want, got)
		}
	}
	for p, body := range before {
		after, err := os.ReadFile(p)
		if err != nil || string(after) != body {
			t.Errorf("the doctor changed %s (read-only check): %q (%v)", p, after, err)
		}
	}
}
