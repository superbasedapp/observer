package hook

import (
	"bytes"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// Hook-parity golden gate (docs/plans/hook-parity-lane0-brief.md section 2).
//
// These goldens were generated on the PRE-CHANGE tree (Lane 0 step 1) and
// pin, byte for byte, what every hook registration writer produces and which
// events each mechanism registers. Lane 0 steps 2 to 8 are refactors and data
// additions that must leave every golden identical: a step that cannot is
// wrong, not the golden. Regenerate only with an explicit
//
//	go test ./internal/hook/ -run TestHookParityGolden -hookparity-update
//
// and a commit message that names the expected diff.

var hookParityUpdate = flag.Bool("hookparity-update", false, "rewrite the hook-parity goldens under testdata/hookparity")

// hookParityGoldenDir is the repo-root testdata/hookparity directory.
const hookParityGoldenDir = "../../testdata/hookparity"

// checkHookParityGolden compares got against the named golden, or rewrites
// it under -hookparity-update.
func checkHookParityGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join(hookParityGoldenDir, name)
	if *hookParityUpdate {
		if err := os.MkdirAll(hookParityGoldenDir, 0o755); err != nil {
			t.Fatalf("mkdir golden dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run with -hookparity-update on the pre-change tree)", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("hook-parity golden %s changed (Lane 0 golden-equality gate).\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// marshalGolden renders v as indented JSON with a trailing newline; map keys
// are sorted by encoding/json, so the output is stable.
func marshalGolden(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal golden: %v", err)
	}
	return append(out, '\n')
}

// hookParityTargets is every target hook.Registry.Register accepts today, in
// the switch's own order.
var hookParityTargets = []string{
	"claude-code", "claude-code-windows",
	"cursor", "cursor-windows",
	"codex", "codex-windows",
	"gemini-cli", "gemini-cli-windows",
	"qwen-code", "qwen-code-windows",
	"droid", "droid-windows",
	"qoder", "qoder-windows",
	"poolside", "poolside-windows",
	"devin",
	"command-code", "command-code-windows",
	"antigravity-cli",
	// Hook-parity Lane A6 tool-gate writers.
	"grok", "copilot-cli", "goose", "junie", "crush", "open-interpreter", "zcode",
	"mistral-code", "cline-cli",
	// Live check 2026-10-20: the Copilot CLI cross-OS bridge.
	"copilot-cli-windows",
	// Live-ground lane 2 (T-479): the Muse settings writer.
	"muse",
	// Live-ground lane 3 (T-378): the Kimi Code config.toml writer.
	"kimi-code",
	// gfiD (2026-10-15): the Kiro CLI agent JSON + V3 hooks writer.
	"kiro-cli",
	// hook-parity Lane D: the plugin-shim format writer.
	"opencode", "kilo-code-cli", "pi",
	// The 2026-10-21 wave.
	"ibm-bob", "ibm-bob-windows", "codebuddy", "codebuddy-windows",
	"deepagents-code", "deepagents-code-windows", "dimcode", "dimcode-windows",
	"dirac", "dirac-windows", "autohand", "vtcode", "vtcode-windows", "kimchi",
}

// hookParityToolDirs are the native config directories pre-created in every
// throwaway home (relative to the home), so each writer finds its install.
var hookParityToolDirs = []string{
	".claude", ".cursor", ".codex", ".gemini", filepath.Join(".gemini", "config"),
	".qwen", ".factory", ".qoder", filepath.Join(".config", "poolside"),
	filepath.Join(".codeium", "windsurf"), ".commandcode",
	".grok", ".copilot", ".agents", ".junie", filepath.Join(".config", "crush"),
	".openinterpreter", ".zcode", ".vibe", ".cline", filepath.Join(".config", "devin"), filepath.Join(".config", "muse"),
	".kimi-code", ".kiro",
	".bob", ".codebuddy", ".deepagents", ".dimcode", ".dirac", ".autohand",
	filepath.Join(".config", "vtcode"), filepath.Join("AppData", "Roaming", "vinhnx", "vtcode", "config"),
	filepath.Join(".config", "kimchi"),
}

// hookParityTarget registers one target into a fresh throwaway home with a
// pinned HomeDir (never auto-detect: TEST-ISO-1) and returns the result plus
// every file the writer left under the home, with the home path normalised.
type hookParityWrite struct {
	Tool         string            `json:"tool"`
	ConfigPath   string            `json:"config_path"`
	HooksAdded   []string          `json:"hooks_added"`
	AlreadySet   []string          `json:"already_set"`
	Skipped      bool              `json:"skipped"`
	SkipReason   string            `json:"skip_reason"`
	ProbeWarning string            `json:"probe_warning"`
	Error        string            `json:"error"`
	Files        map[string]string `json:"files"`
}

func hookParityRegister(t *testing.T, target string) hookParityWrite {
	t.Helper()
	home, err := os.MkdirTemp("", "hookparity")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	if home == "" {
		t.Fatal("empty temp home")
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	winHome := filepath.Join(home, "win")
	for _, base := range []string{home, winHome} {
		for _, d := range hookParityToolDirs {
			if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
		}
	}
	checksums := filepath.Join(home, ".observer", "hook_checksums.json")
	r, err := NewRegistry(Options{
		BinaryPath:             "/opt/observer/bin/observer",
		HomeDir:                home,
		ChecksumsPath:          checksums,
		ConfigPath:             "/etc/observer/config.toml",
		WSLDistro:              "Ubuntu-Golden",
		WindowsCursorHome:      winHome,
		WindowsClaudeHome:      winHome,
		WindowsCodexHome:       winHome,
		WindowsGeminiHome:      winHome,
		WindowsQwenHome:        winHome,
		WindowsFactoryHome:     winHome,
		WindowsQoderHome:       winHome,
		WindowsPoolsideHome:    winHome,
		WindowsCommandCodeHome: winHome,
		WindowsCopilotHome:     winHome,
		WindowsUserHome:        winHome,
		// The native writers whose file shape follows the OS write the
		// Linux shape here (the golden is a Linux golden on every host).
		GOOS: "linux",
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	res := r.Register(target)
	norm := func(s string) string {
		s = strings.ReplaceAll(s, home, "$HOME")
		s = strings.ReplaceAll(s, filepath.ToSlash(home), "$HOME")
		s = strings.ReplaceAll(s, strings.ReplaceAll(home, "/", `\`), "$HOME")
		s = strings.ReplaceAll(s, strings.ReplaceAll(home, "/", `\\`), "$HOME")
		// A native Windows home written into a TOML or JSON string is
		// escaped (C:\\Users\\...): fold that spelling too.
		s = strings.ReplaceAll(s, strings.ReplaceAll(home, `\`, `\\`), "$HOME")
		return s
	}
	w := hookParityWrite{
		Tool:         res.Tool,
		ConfigPath:   norm(res.ConfigPath),
		HooksAdded:   res.HooksAdded,
		AlreadySet:   res.AlreadySet,
		Skipped:      res.Skipped,
		SkipReason:   norm(res.SkipReason),
		ProbeWarning: norm(res.ProbeWarning),
		Files:        map[string]string{},
	}
	if res.Error != nil {
		w.Error = norm(res.Error.Error())
	}
	_ = filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || p == checksums {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		rel, _ := filepath.Rel(home, p)
		w.Files[filepath.ToSlash(rel)] = norm(string(data))
		return nil
	})
	token := filepath.Base(home)
	for k, v := range w.Files {
		if strings.Contains(v, token) || strings.Contains(k, token) {
			t.Fatalf("golden for %s still carries the temp-home token %q in %s; extend norm()", target, token, k)
		}
	}
	return w
}

// TestHookParityGolden_WriterBytes pins the exact bytes every registration
// writer produces into a fresh home, native and -windows.
func TestHookParityGolden_WriterBytes(t *testing.T) {
	skipGoldenOffLinuxShape(t)
	out := map[string]hookParityWrite{}
	for _, target := range hookParityTargets {
		out[target] = hookParityRegister(t, target)
	}
	checkHookParityGolden(t, "writer_bytes.json", marshalGolden(t, out))
}

// TestHookParityGolden_EventLists pins the event list each mechanism
// registers: the three per-vendor slices plus the events every other writer
// reports in HooksAdded.
func TestHookParityGolden_EventLists(t *testing.T) {
	skipGoldenOffLinuxShape(t)
	events := map[string][]string{
		"claudeCodeEvents": append([]string(nil), claudeCodeEvents...),
		"cursorEvents":     append([]string(nil), cursorEvents...),
		"codexEvents":      append([]string(nil), codexEvents...),
	}
	for _, target := range hookParityTargets {
		w := hookParityRegister(t, target)
		added := append([]string(nil), w.HooksAdded...)
		sort.Strings(added)
		events["registered:"+target] = added
	}
	checkHookParityGolden(t, "event_lists.json", marshalGolden(t, events))
}

// skipGoldenOffLinuxShape skips the byte-equality gate on Windows. The
// goldens are the writers' bytes on Linux and macOS; on Windows the same
// writers write different bytes by design (native path separators, and the
// Cline guard plugin is not installed there, cline/cline #14767), so the
// gate cannot be byte-equal (Windows 11 Pro live run, PT-02). The writers'
// Windows behaviour is pinned by their own tests.
func skipGoldenOffLinuxShape(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the hook-parity goldens are the Linux and macOS writer bytes; Windows writes native separators and skips the Cline guard by design")
	}
}
