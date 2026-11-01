package hook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestCopilotCLIWindowsTarget pins the copilot-cli-windows bridge (live check
// 2026-10-20): it is a tool-gate writer row, it is detected from an owned
// Windows-side .copilot, and its hooks file carries both the bash spelling
// (ownership) and the powershell field Copilot CLI runs on Windows, the
// latter through `wsl.exe -e` with PowerShell quoting.
func TestCopilotCLIWindowsTarget(t *testing.T) {
	if _, ok := toolGateWriters["copilot-cli-windows"]; !ok {
		t.Fatal("copilot-cli-windows is not a registrar row")
	}
	sandbox := t.TempDir()
	home := filepath.Join(sandbox, "home")
	// The Windows home lives UNDER the pinned HomeDir, the only shape a
	// sandboxed caller may name (crossmount.AutoDetectSuppressed).
	winHome := filepath.Join(home, "win")
	for _, d := range []string{filepath.Join(home, ".copilot"), filepath.Join(winHome, ".copilot")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r, err := NewRegistry(Options{
		BinaryPath: "/opt/observer dir/observer", HomeDir: home, ConfigPath: "/etc/observer/config.toml",
		WSLDistro: "Ubuntu-20.04", WindowsCopilotHome: winHome,
		ChecksumsPath: filepath.Join(home, ".observer", "hook_checksums.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.Installed(), "copilot-cli-windows") {
		t.Fatalf("Installed() = %v, want copilot-cli-windows", r.Installed())
	}
	res := r.Register("copilot-cli-windows")
	if res.Error != nil {
		t.Fatalf("Register: %v", res.Error)
	}
	if want := filepath.Join(winHome, ".copilot", "hooks", "superbased-observer.json"); res.ConfigPath != want {
		t.Errorf("ConfigPath = %q, want %q", res.ConfigPath, want)
	}
	raw, err := os.ReadFile(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int                         `json:"version"`
		Hooks   map[string][]map[string]any `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.Version != 1 {
		t.Errorf("version = %d, want 1", doc.Version)
	}
	for _, ev := range []string{"preToolUse", "userPromptSubmitted"} {
		hs := doc.Hooks[ev]
		if len(hs) != 1 {
			t.Fatalf("%s: %d handlers, want 1", ev, len(hs))
		}
		wantBash := "MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-20.04 -- '/opt/observer dir/observer' hook copilot-cli " + ev + " --config '/etc/observer/config.toml'"
		if got := hs[0]["bash"]; got != wantBash {
			t.Errorf("%s bash = %q, want %q", ev, got, wantBash)
		}
		wantPS := "wsl.exe -d Ubuntu-20.04 -e '/opt/observer dir/observer' hook copilot-cli " + ev + " --config /etc/observer/config.toml; if ($LASTEXITCODE -is [int]) { exit $LASTEXITCODE } else { exit 1 }"
		if got := hs[0]["powershell"]; got != wantPS {
			t.Errorf("%s powershell = %q, want %q", ev, got, wantPS)
		}
	}
	// Idempotent: a second registration adds nothing.
	if again := r.Register("copilot-cli-windows"); again.Error != nil || len(again.HooksAdded) != 0 {
		t.Errorf("second Register = %+v, want no change", again)
	}
	// The native target on this (non-Windows) host keeps the bash-only shape.
	if runtime.GOOS != "windows" {
		nat := r.Register("copilot-cli")
		if nat.Error != nil {
			t.Fatalf("native Register: %v", nat.Error)
		}
		b, _ := os.ReadFile(nat.ConfigPath)
		if strings.Contains(string(b), "powershell") {
			t.Errorf("native non-Windows hooks file carries a powershell field:\n%s", b)
		}
	}
	if un := r.Unregister("copilot-cli-windows"); un.Error != nil {
		t.Fatalf("Unregister: %v", un.Error)
	}
	if _, err := os.Stat(res.ConfigPath); !os.IsNotExist(err) {
		t.Errorf("hooks file still present after Unregister (err=%v)", err)
	}
}

// TestPSQuoteIfNeeded pins the PowerShell quoting the copilot-cli powershell
// field uses.
func TestPSQuoteIfNeeded(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "''",
		"/home/u/bin/observer":   "/home/u/bin/observer",
		"C:/Program Files/o.exe": "'C:/Program Files/o.exe'",
		"it's":                   "'it''s'",
		"a$b":                    "'a$b'",
		"Ubuntu-20.04":           "Ubuntu-20.04",
	} {
		if got := psQuoteIfNeeded(in); got != want {
			t.Errorf("psQuoteIfNeeded(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestHookTargetWritersTable pins the registrar table that replaced the
// Register / Unregister switches (lane MP-ADP): the same 20 targets in the
// same table, every row carrying both directions, and no target in both
// tables (the tool-gate-only table is consulted first, so an overlap would
// silently shadow a row).
func TestHookTargetWritersTable(t *testing.T) {
	want := []string{
		"antigravity-cli", "claude-code", "claude-code-windows", "codex", "codex-windows",
		"command-code", "command-code-windows", "cursor", "cursor-windows", "devin",
		"droid", "droid-windows", "gemini-cli", "gemini-cli-windows", "poolside",
		"poolside-windows", "qoder", "qoder-windows", "qwen-code", "qwen-code-windows",
		// The 2026-10-21 wave.
		"autohand", "codebuddy", "codebuddy-windows", "deepagents-code", "deepagents-code-windows",
		"dimcode", "dimcode-windows", "dirac", "dirac-windows", "ibm-bob", "ibm-bob-windows",
		"kimchi", "vtcode", "vtcode-windows",
		// Surface-gap Wave 7 IDE targets (gated).
		"antigravity-cli-windows", "devin-jetbrains", "devin-windows",
		// Surface-gap W-2a (register_cortex.go, switched off until LC18).
		"cortex-code",
		// Surface-gap FU-145 / FU-160 Xcode agent homes (register_xcode.go;
		// the Gemini one gated on LCR-91).
		"claude-code-xcode", "codex-xcode", "gemini-cli-xcode",
	}
	sort.Strings(want)
	var got []string
	for k, w := range hookTargetWriters {
		got = append(got, k)
		if w.register == nil || w.unregister == nil {
			t.Errorf("%s: a row without both directions", k)
		}
		if _, dup := toolGateWriters[k]; dup {
			t.Errorf("%s is in both writer tables", k)
		}
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("targets:\n got %v\nwant %v", got, want)
	}
}

// TestUnknownHookTargetIsRefused keeps the fall-through: a target in neither
// table and with no plugin-shim capability is refused in both directions.
func TestUnknownHookTargetIsRefused(t *testing.T) {
	r, err := NewRegistry(Options{HomeDir: t.TempDir(), BinaryPath: "/usr/local/bin/observer", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res := r.Register("no-such-tool"); res.Error == nil || !strings.Contains(res.Error.Error(), "not supported") {
		t.Fatalf("register: %+v", res)
	}
	if res := r.Unregister("no-such-tool"); res.Error == nil || !strings.Contains(res.Error.Error(), "not supported") {
		t.Fatalf("unregister: %+v", res)
	}
}
