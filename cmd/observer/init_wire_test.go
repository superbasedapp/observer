package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/browserhost"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// fakeWinRegistry is a cmd-layer in-memory RegistryWriter so cmd tests can
// drive the Windows registration path end-to-end WITHOUT ever constructing the
// production reg.exe writer or touching the real registry. It records every
// SetDefault for assertions.
type fakeWinRegistry struct {
	values map[string]string
	sets   []string
}

func newFakeWinRegistry() *fakeWinRegistry { return &fakeWinRegistry{values: map[string]string{}} }

func (f *fakeWinRegistry) GetDefault(keyPath string) (string, bool, error) {
	v, ok := f.values[keyPath]
	return v, ok, nil
}

func (f *fakeWinRegistry) SetDefault(keyPath, value string) error {
	f.values[keyPath] = value
	f.sets = append(f.sets, keyPath)
	return nil
}

// fakeWinTranslator maps any WSL path to a synthetic C:\ path so artifact
// writes land in the injected temp dir while the manifest/registry still carry
// a Windows-looking path — it NEVER resolves a real /mnt/c profile.
func fakeWinTranslator(p string) (string, bool) {
	return `C:\FAKE` + strings.ReplaceAll(p, "/", `\`), true
}

// mkWinChromeProfile creates a Windows Chrome profile dir under winHome so the
// Windows browser detection sees it (temp dir only — never a real profile).
func mkWinChromeProfile(t *testing.T, winHome string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(winHome, "AppData", "Local", "Google", "Chrome"), 0o755); err != nil {
		t.Fatalf("mkdir win chrome profile: %v", err)
	}
}

// failFactory is an injected NewWindowsRegistry that MUST NOT be called — it
// fails the test if the step ever tries to build a registry writer on a path
// the test expected to short-circuit.
func failFactory(t *testing.T) func() (browserhost.RegistryWriter, error) {
	return func() (browserhost.RegistryWriter, error) {
		t.Fatalf("NewWindowsRegistry factory was called — the step should not have reached registry construction")
		return nil, nil
	}
}

// TestPromptBrowserExtensionID pins the interactive id resolver: a valid id
// is accepted, a bad-then-blank sequence returns "" (keep placeholder), and a
// bare blank returns "" without error.
func TestPromptBrowserExtensionID(t *testing.T) {
	const good = "abcdefghijklmnopabcdefghijklmnop"
	cases := []struct {
		name, input, want string
	}{
		{"valid", good + "\n", good},
		{"blank", "\n", ""},
		{"bad-then-blank", "not-an-id\n\n", ""},
		{"bad-then-valid", "nope\n" + good + "\n", good},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			got, err := promptBrowserExtensionID(&out, bufio.NewReader(strings.NewReader(tc.input)))
			if err != nil {
				t.Fatalf("promptBrowserExtensionID: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q (prompt:\n%s)", got, tc.want, out.String())
			}
		})
	}
}

// TestWireAIClients_BatchClaudeCode pins the batch-init seam newInitCmd
// delegates to: a claude-code-only dry-run wire reports all three
// registration sides (hook / mcp / route) without writing anything,
// and no proxy hint fires because the route write wasn't skipped.
// OnlyClaudeCode bypasses tool detection entirely, so the test is
// deterministic regardless of crossmount *-windows detection.
func TestWireAIClients_BatchClaudeCode(t *testing.T) {
	home := interactiveHome(t)
	lines, claudeHint, codexHint, codexHooksHint, err := wireAIClients(WireAIClientsOptions{
		ProxyPort:      18820,
		DryRun:         true,
		HomeDir:        home,
		OnlyClaudeCode: true,
	})
	if err != nil {
		t.Fatalf("wireAIClients: %v", err)
	}
	text := strings.Join(lines, "\n")
	for _, want := range []string{"hook", "mcp", "route", "would register"} {
		if !strings.Contains(text, want) {
			t.Errorf("lines missing %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "18820") {
		t.Errorf("route line should carry the configured proxy port:\n%s", text)
	}
	if claudeHint != "" {
		t.Errorf("route not skipped — claude hint should be empty, got:\n%s", claudeHint)
	}
	if codexHint != "" || codexHooksHint {
		t.Errorf("no codex in the wire — hints should be silent (codexHint=%q codexHooksHint=%v)", codexHint, codexHooksHint)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(statErr) {
		raw, _ := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
		t.Errorf("dry run wrote settings.json:\n%s", raw)
	}
}

// TestInitWindowsHomeFlagsExist pins R4: `observer init` exposes the two
// disambiguation flags that make the registrar's refusal-advertised fix
// reachable. Flag registration is asserted directly (executing the command
// would reach real wiring); the plumbing into the proxyroute + hook registrars
// is a compile-checked field pass in wireAIClients.
func TestInitWindowsHomeFlagsExist(t *testing.T) {
	cmd := newInitCmd()
	for _, name := range []string{"windows-claude-home", "windows-codex-home", "windows-cursor-home"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("`observer init` should register the --%s flag", name)
		}
	}
}

// TestWireAIClients_ExplicitCodexSelectsWindowsTarget pins F3 by OUTCOME: an
// explicit `--codex --windows-codex-home=<home>` must also select the
// codex-windows virtual target and actually WRITE the cross-OS route into that
// Windows home — the pre-fix selectTools dropped every "-windows" target under
// an explicit base selector, so nothing landed. proxyroute.SetWSLForTest pins
// the WSL gate ON so the cross-OS writer engages on any host; the Windows home
// is a temp dir so the write never touches a real /mnt/c profile.
func TestWireAIClients_ExplicitCodexSelectsWindowsTarget(t *testing.T) {
	defer proxyroute.SetWSLForTest(true)()

	home := interactiveHome(t) // native home for the base-codex writes
	// The Windows USER home must live UNDER the pinned HomeDir — a sandboxed
	// caller's override is honoured only when contained
	// (crossmount.AutoDetectSuppressed, 2026-07-31 follow-up round).
	winHome := filepath.Join(home, "mnt", "c", "Users", "tester")
	if err := os.MkdirAll(filepath.Join(winHome, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	lines, _, _, _, err := wireAIClients(WireAIClientsOptions{
		ProxyPort:        18820,
		HomeDir:          home,
		OnlyCodex:        true,
		WindowsCodexHome: winHome,
	})
	if err != nil {
		t.Fatalf("wireAIClients: %v", err)
	}
	text := strings.Join(lines, "\n")
	// The codex-windows route write must have produced a config.toml under the
	// override Windows home.
	winCfg := filepath.Join(winHome, ".codex", "config.toml")
	if _, statErr := os.Stat(winCfg); statErr != nil {
		t.Fatalf("codex-windows route did not write %s: %v\nlines:\n%s", winCfg, statErr, text)
	}
	if !strings.Contains(text, "codex-windows") {
		t.Errorf("expected a codex-windows result line, got:\n%s", text)
	}
	// The config.toml points at the localhost cross-OS base URL.
	body, rerr := os.ReadFile(winCfg)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if !strings.Contains(string(body), "http://localhost:18820/v1") {
		t.Errorf("codex-windows config.toml missing the localhost route:\n%s", body)
	}
}

// TestWireAIClients_WindowsHomeOptionsPlumbed pins that the Windows-home
// overrides flow through WireAIClientsOptions without breaking the wire when
// the cross-OS gate is OFF (native host): a dry-run claude-code wire with both
// overrides set still succeeds and writes nothing.
func TestWireAIClients_WindowsHomeOptionsPlumbed(t *testing.T) {
	home := interactiveHome(t)
	if _, _, _, _, err := wireAIClients(WireAIClientsOptions{
		ProxyPort:         18820,
		DryRun:            true,
		HomeDir:           home,
		OnlyClaudeCode:    true,
		WindowsClaudeHome: filepath.Join(home, "winclaude"),
		WindowsCodexHome:  filepath.Join(home, "wincodex"),
	}); err != nil {
		t.Fatalf("wireAIClients with windows-home overrides: %v", err)
	}
}

// TestWireAIClients_SkipProxyEmitsCodexHint pins the hint contract the
// batch path prints: with the route write skipped, the codex hint comes
// back non-empty (it is deliberately NOT dry-run-gated — matching the
// pre-dedup inline loop), no route line appears, and the dry-run-gated
// codex trust hint stays false.
func TestWireAIClients_SkipProxyEmitsCodexHint(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	lines, claudeHint, codexHint, codexHooksHint, err := wireAIClients(WireAIClientsOptions{
		DryRun:    true,
		SkipProxy: true,
		HomeDir:   home,
		OnlyCodex: true,
	})
	if err != nil {
		t.Fatalf("wireAIClients: %v", err)
	}
	text := strings.Join(lines, "\n")
	if strings.Contains(text, "route") {
		t.Errorf("route skipped but a route line appeared:\n%s", text)
	}
	if codexHint == "" {
		t.Error("codex hint should fire when the route write is skipped")
	}
	if claudeHint != "" {
		t.Errorf("claude hint is dry-run-gated and claude-code wasn't wired, got:\n%s", claudeHint)
	}
	if codexHooksHint {
		t.Error("codex trust hint is dry-run-gated — must be false under DryRun")
	}
}

// TestWireAIClients_PromptLaneOnlyGate pins B3 (final-fix review) at the
// `observer init --all` / zero-flag batch entry point: mirrors
// TestAutoRegisterHooks_PromptLaneOnlyGate (start_test.go) for
// wireAIClients — the seam `observer init`/`observer enroll` delegate to.
// A disabled prompt-submit hook lane must skip a PromptLaneOnly tool's hook
// registration (gemini-cli, native here — the "-windows" bridge variant is
// covered by TestAutoRegisterHooks_PromptLaneOnlyGateAppliesToWindowsBridgeTargets,
// which pins the advertisedCapability resolution itself) without touching
// claude-code's own hook write, since claude-code carries session/tool-call
// value beyond the one prompt-submit event.
func TestWireAIClients_PromptLaneOnlyGate(t *testing.T) {
	writeGuardPromptConfig := func(t *testing.T, hookLane bool) string {
		t.Helper()
		dir := t.TempDir()
		cfgPath := filepath.Join(dir, "config.toml")
		body := fmt.Sprintf("[guard.prompt]\nenabled = true\nhook_lane = %v\n", hookLane)
		if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return cfgPath
	}
	setupHome := func(t *testing.T) string {
		t.Helper()
		home := t.TempDir()
		for _, dir := range []string{".claude", ".gemini"} {
			if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		return home
	}

	// NOTE: subtest names deliberately avoid embedding a tool id like
	// "gemini-cli" — t.TempDir() folds the subtest name into the
	// sandbox home path, and that path is itself echoed back inside
	// printHookResult's "registered N hook(s) in <path>" line, which
	// would make a substring check on the FULL output ambiguous
	// (matching the subtest's own name rather than a genuine gemini-cli
	// registration line). The os.Stat checks below are the real,
	// unambiguous assertion; the disabled case skips the substring
	// check entirely for this reason.
	t.Run("hook_lane_false", func(t *testing.T) {
		home := setupHome(t)
		cfgPath := writeGuardPromptConfig(t, false)
		lines, _, _, _, err := wireAIClients(WireAIClientsOptions{
			HomeDir:    home,
			ConfigPath: cfgPath,
			All:        true,
			SkipMCP:    true,
			SkipProxy:  true,
		})
		if err != nil {
			t.Fatalf("wireAIClients: %v", err)
		}
		text := strings.Join(lines, "\n")
		if !strings.Contains(text, "claude-code") {
			t.Errorf("lines missing claude-code (PromptLaneOnly=false, must always register):\n%s", text)
		}
		if _, err := os.Stat(filepath.Join(home, ".gemini", "settings.json")); err == nil {
			t.Errorf("~/.gemini/settings.json was written even though hook_lane=false")
		}
		if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
			t.Errorf("~/.claude/settings.json was NOT written: %v", err)
		}
	})

	t.Run("hook_lane_true", func(t *testing.T) {
		home := setupHome(t)
		cfgPath := writeGuardPromptConfig(t, true)
		lines, _, _, _, err := wireAIClients(WireAIClientsOptions{
			HomeDir:    home,
			ConfigPath: cfgPath,
			All:        true,
			SkipMCP:    true,
			SkipProxy:  true,
		})
		if err != nil {
			t.Fatalf("wireAIClients: %v", err)
		}
		text := strings.Join(lines, "\n")
		if !strings.Contains(text, "claude-code") {
			t.Errorf("lines missing claude-code:\n%s", text)
		}
		if _, err := os.Stat(filepath.Join(home, ".gemini", "settings.json")); err != nil {
			t.Errorf("~/.gemini/settings.json was NOT written even though hook_lane=true: %v", err)
		}
		if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
			t.Errorf("~/.claude/settings.json was NOT written: %v", err)
		}
	})
}

// TestMCPSupportedIsRegistryDriven pins that the MCP write-eligibility
// predicate dispatches on the integration registry's MCP capability shape,
// not a hardcoded tool switch. The mcp.Registrar writes the JSON + Codex
// TOML + OpenCode JSON formats; Hermes' YAML is Implemented but written by
// runHermesInit, so it (and every watcher-only adapter) must be excluded.
// cline carries a native JSON target AND a cross-OS "cline-windows" bridge
// (MCP.CrossOSBridge) — both supported; "cline-cli" stays out (no MCP file).
func TestMCPSupportedIsRegistryDriven(t *testing.T) {
	in := []string{"claude-code", "cursor", "codex", "opencode", "cline", "cline-windows"}
	out := []string{"hermes", "cline-cli", "copilot", "antigravity", "pi", "kilo-code", "definitely-not-a-tool", ""}
	for _, tool := range in {
		if !mcpSupported(tool) {
			t.Errorf("mcpSupported(%q) = false, want true (registrar-handled MCP format)", tool)
		}
	}
	for _, tool := range out {
		if mcpSupported(tool) {
			t.Errorf("mcpSupported(%q) = true, want false (no registrar-handled MCP writer)", tool)
		}
	}
}

// TestHookSupportedIsRegistryDriven pins that hook write-eligibility
// dispatches on the integration registry's HookMechanism + CrossOSBridge,
// not a hardcoded tool switch. The hook.Registry handles claude-code /
// cursor / codex (and the -windows bridge for claude-code/cursor/codex —
// codex-windows grounded 2026-09-02, IDE-surface remediation T2); Hermes'
// embedded plugin (runHermesInit) and cline-cli's manual hooks.jsonl tailer
// are excluded. Behaviour-identical to the pre-Phase-2 switch.
func TestHookSupportedIsRegistryDriven(t *testing.T) {
	in := []string{
		"claude-code", "claude-code-windows", "cursor", "cursor-windows", "codex", "codex-windows",
		// Part B item 1: the new registerGenericSettingsHooks /
		// registerFactoryDroid writers (BLOCK-1's real-world close-out).
		"gemini-cli", "qwen-code", "droid",
		// Part B item 2 (phase-3a): the documented long-tail vendors —
		// Qoder/Poolside/Devin-Cascade/commandcode, the 4 remaining
		// AutoWired:true mechanisms this NIT was missing (B2, phase-3a
		// review). zcode deliberately stays in `out` below:
		// AutoWired:false, no register* writer exists at all.
		"qoder", "poolside", "devin", "command-code",
		// The six long-tail vendors' own cross-OS bridge targets
		// (registerGeminiCLIWindows et al.) — CrossOSBridge:true now set
		// on their registry rows, so hookSupported's isWindows branch
		// answers true exactly like claude-code-windows/cursor-windows/
		// codex-windows above. devin/Cascade correctly has NO -windows
		// counterpart (see internal/integration's devin row) and is not
		// listed here or in `out`.
		"gemini-cli-windows", "qwen-code-windows", "droid-windows",
		"qoder-windows", "poolside-windows", "command-code-windows",
	}
	out := []string{
		"hermes", "cline-cli", "opencode", "cline", "copilot", "antigravity", "pi", "zcode",
		// devin/Windsurf Desktop Cascade's only grounded install channel
		// is the macOS Homebrew cask — no Windows-native client exists
		// to bridge to, so its registry row has no CrossOSBridge and no
		// register*Windows writer exists at all (unlike the six above).
		"devin-windows",
		"definitely-not-a-tool", "",
	}
	for _, tool := range in {
		if !hookSupported(tool) {
			t.Errorf("hookSupported(%q) = false, want true", tool)
		}
	}
	for _, tool := range out {
		if hookSupported(tool) {
			t.Errorf("hookSupported(%q) = true, want false", tool)
		}
	}
}

// TestExtensionSupportedIsRegistryDriven pins the 4th consent step's
// predicate: extensionSupported is true exactly for the browser-chatbot
// rails whose Hook.Mechanism is HookBrowserExtension (registry-driven, not a
// tool switch), and false for every AI-CLI tool + unknown names. It also
// pins that hookSupported stays FALSE for the *-web rails (the browser step
// is a distinct predicate — the extension attaches via native-messaging, not
// the AI-tool hook registrar).
func TestExtensionSupportedIsRegistryDriven(t *testing.T) {
	in := []string{"chatgpt-web", "claude-web", "perplexity-web", "gemini-web", "copilot-web"}
	out := []string{"claude-code", "codex", "cursor", "hermes", "copilot", "copilot-cli", "definitely-not-a-tool", ""}
	for _, tool := range in {
		if !extensionSupported(tool) {
			t.Errorf("extensionSupported(%q) = false, want true", tool)
		}
		if hookSupported(tool) {
			t.Errorf("hookSupported(%q) = true, want false (browser rail is not an AI-tool hook)", tool)
		}
	}
	for _, tool := range out {
		if extensionSupported(tool) {
			t.Errorf("extensionSupported(%q) = true, want false", tool)
		}
	}
	if !anyExtensionSupported() {
		t.Errorf("anyExtensionSupported() = false, want true (5 *-web rails registered)")
	}
}

// TestRunBrowserExtensionStep pins the 4th-step writer: with a Chromium
// profile dir present it vendors the native-messaging host AND writes the
// per-browser manifest (idempotent manifest on re-run), and with none it
// writes nothing.
func TestRunBrowserExtensionStep(t *testing.T) {
	home := t.TempDir()
	// No browser → no output, no error (an honest no-op).
	var empty strings.Builder
	if err := runBrowserExtensionStep(&empty, browserExtStepParams{HomeDir: home}); err != nil {
		t.Fatalf("no-browser run errored: %v", err)
	}
	if empty.Len() != 0 {
		t.Errorf("no-browser run wrote %q, want nothing", empty.String())
	}
	// Create a Chrome profile dir → the step writes the host + manifest.
	if err := os.MkdirAll(filepath.Join(home, ".config", "google-chrome"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	var first strings.Builder
	if err := runBrowserExtensionStep(&first, browserExtStepParams{HomeDir: home, ObserverBin: "/opt/observer"}); err != nil {
		t.Fatalf("first run errored: %v", err)
	}
	if !strings.Contains(first.String(), "wrote native-messaging host →") {
		t.Errorf("first run = %q, want a host 'wrote' line", first.String())
	}
	if !strings.Contains(first.String(), "wrote native-messaging host manifest →") {
		t.Errorf("first run = %q, want a manifest 'wrote' line", first.String())
	}
	var second strings.Builder
	if err := runBrowserExtensionStep(&second, browserExtStepParams{HomeDir: home, ObserverBin: "/opt/observer"}); err != nil {
		t.Fatalf("second run errored: %v", err)
	}
	if !strings.Contains(second.String(), "manifest already set") {
		t.Errorf("second run = %q, want 'manifest already set' (idempotent)", second.String())
	}
}

// TestRunBrowserExtensionStep_WindowsInjection pins that the Windows-registry
// path is driven ONLY by the injected WindowsHomes/WSLDistro params — never by
// ambient crossmount/registry state — so the step is safe to run in tests
// without touching a real /mnt/c profile or reg.exe. The registry logic itself
// is covered by internal/browserhost's fake-writer tests; here we only assert
// the cmd-layer plumbing, staying on paths that never shell out to reg.exe.
func TestRunBrowserExtensionStep_WindowsInjection(t *testing.T) {
	home := t.TempDir()

	// A Windows home whose profile dir is absent → no Windows output at all.
	noBrowserWin := t.TempDir()
	var a strings.Builder
	if err := runBrowserExtensionStep(&a, browserExtStepParams{
		HomeDir: home, ObserverBin: "/opt/observer",
		WindowsHomes: []string{noBrowserWin}, WSLDistro: "Ubuntu",
	}); err != nil {
		t.Fatalf("absent Windows profile errored: %v", err)
	}
	if strings.Contains(a.String(), "browser (windows") || strings.Contains(a.String(), "found a Windows browser") {
		t.Errorf("absent Windows profile should produce no Windows output, got %q", a.String())
	}

	// A Windows home WITH a Chrome profile but an unknown distro → the honest
	// "distro unknown" note, and NOTHING written (the empty distro
	// short-circuits before any registrar/reg.exe call).
	winHome := t.TempDir()
	if err := os.MkdirAll(filepath.Join(winHome, "AppData", "Local", "Google", "Chrome"), 0o755); err != nil {
		t.Fatalf("mkdir win profile: %v", err)
	}
	var b strings.Builder
	if err := runBrowserExtensionStep(&b, browserExtStepParams{
		HomeDir: home, ObserverBin: "/opt/observer",
		WindowsHomes: []string{winHome}, WSLDistro: "",
	}); err != nil {
		t.Fatalf("empty-distro run errored: %v", err)
	}
	if !strings.Contains(b.String(), "WSL distro is unknown") {
		t.Errorf("Windows browser + empty distro should print the honest note, got %q", b.String())
	}
	if strings.Contains(b.String(), "browser (windows): wrote") {
		t.Errorf("empty distro must not write anything for Windows, got %q", b.String())
	}
	// No bridge/manifest under the Windows home (nothing written).
	if _, err := os.Stat(filepath.Join(winHome, ".observer", "browser-host")); !os.IsNotExist(err) {
		t.Errorf("empty distro must not create the Windows browser-host dir (stat err=%v)", err)
	}
}

// TestRunBrowserExtensionStep_WritesWorkingManifest is the A1 core: with a
// real extension id via the flag path, the written manifest has a NON-empty
// Path (pointing at the vendored launcher under the observer dir) AND the
// supplied id in allowed_origins — no placeholder, no instruction.
func TestRunBrowserExtensionStep_WritesWorkingManifest(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "google-chrome"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	const extID = "abcdefghijklmnopabcdefghijklmnop"
	var buf strings.Builder
	if err := runBrowserExtensionStep(&buf, browserExtStepParams{
		HomeDir:     home,
		ObserverBin: "/opt/observer/bin/observer",
		ConfigPath:  "/home/u/.observer/config.toml",
		ExtensionID: extID,
	}); err != nil {
		t.Fatalf("runBrowserExtensionStep: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "no extension id supplied") {
		t.Errorf("with an id, no placeholder instruction should print:\n%s", out)
	}

	// The vendored launcher must exist under <home>/.observer/browser-host.
	launcher := filepath.Join(home, ".observer", "browser-host", "host-launcher.sh")
	if _, err := os.Stat(launcher); err != nil {
		t.Fatalf("vendored launcher missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".observer", "browser-host", "host.js")); err != nil {
		t.Fatalf("vendored host.js missing: %v", err)
	}

	// The manifest Path must be non-empty and point at the launcher; the
	// allowed_origins must carry the supplied id, not the placeholder.
	manifestPath := filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts", "com.superbased.observer.browser.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	s := string(raw)
	if !strings.Contains(s, `"path": "`+launcher+`"`) {
		t.Errorf("manifest Path is empty or wrong (want launcher %q):\n%s", launcher, s)
	}
	if !strings.Contains(s, "chrome-extension://"+extID+"/") {
		t.Errorf("manifest allowed_origins missing the supplied id:\n%s", s)
	}
	if strings.Contains(s, "REPLACE_WITH_EXTENSION_ID") {
		t.Errorf("manifest still carries the placeholder id:\n%s", s)
	}
}

// TestRunBrowserExtensionStep_PlaceholderInstruction is the A1 non-TTY-no-flag
// path: no id → the manifest is still written (with the placeholder) AND a
// precise follow-up instruction names the exact file + field to edit.
func TestRunBrowserExtensionStep_PlaceholderInstruction(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "google-chrome"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	var buf strings.Builder
	if err := runBrowserExtensionStep(&buf, browserExtStepParams{HomeDir: home, ObserverBin: "/opt/observer"}); err != nil {
		t.Fatalf("runBrowserExtensionStep: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "no extension id supplied") {
		t.Errorf("no-id run should print the follow-up instruction:\n%s", out)
	}
	if !strings.Contains(out, "observer init --browser-extension-id") {
		t.Errorf("instruction should name the re-run flag:\n%s", out)
	}
	manifestPath := filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts", "com.superbased.observer.browser.json")
	if !strings.Contains(out, manifestPath) {
		t.Errorf("instruction should name the exact manifest file %q:\n%s", manifestPath, out)
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("manifest must still be written: %v", err)
	}
	if !strings.Contains(string(raw), "REPLACE_WITH_EXTENSION_ID") {
		t.Errorf("no-id manifest should carry the placeholder:\n%s", raw)
	}
}

// TestRunBrowserExtensionStep_DryRun pins dry-run honesty: it prints the
// would-be host path but writes NOTHING to disk.
func TestRunBrowserExtensionStep_DryRun(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "google-chrome"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	var buf strings.Builder
	if err := runBrowserExtensionStep(&buf, browserExtStepParams{HomeDir: home, ExtensionID: "abcdefghijklmnopabcdefghijklmnop", DryRun: true}); err != nil {
		t.Fatalf("runBrowserExtensionStep: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "would write native-messaging host") {
		t.Errorf("dry-run should preview the host write:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".observer", "browser-host", "host-launcher.sh")); !os.IsNotExist(err) {
		t.Errorf("dry-run must not vendor the host (stat err = %v)", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "google-chrome", "NativeMessagingHosts")); !os.IsNotExist(err) {
		t.Errorf("dry-run must not write the manifest dir (stat err = %v)", err)
	}
}

// TestRouteSupportedIsRegistryDriven pins that proxy-route write-eligibility
// dispatches on the integration registry's RouteKind, not a tool switch.
// Only the persisted kinds (RouteEnvSettings claude-code, RouteConfigFile
// codex) are writable by init; opencode's RouteLauncher kind is applied by
// the `observer opencode` launcher (false here), and proxy-exempt tools
// (Proxy==nil) are false. Behaviour-identical to the pre-Phase-3 predicate.
func TestRouteSupportedIsRegistryDriven(t *testing.T) {
	// The "-windows" cross-OS virtual targets are supported exactly for the
	// base adapters whose ProxyRoute carries CrossOSBridge (claude-code +
	// codex) — resolved by strings.CutSuffix, mirroring hookSupported. A
	// "-windows" suffix on a non-bridge tool (cursor routes via launcher,
	// not a persisted kind) stays false.
	in := []string{"claude-code", "codex", "claude-code-windows", "codex-windows"}
	out := []string{"opencode", "cursor", "cursor-windows", "cline", "copilot", "hermes", "antigravity", "pi", "kilo-code-cli", "definitely-not-a-tool", ""}
	for _, tool := range in {
		if !routeSupported(tool) {
			t.Errorf("routeSupported(%q) = false, want true (persisted route kind)", tool)
		}
	}
	for _, tool := range out {
		if routeSupported(tool) {
			t.Errorf("routeSupported(%q) = true, want false (launcher-only or proxy-exempt)", tool)
		}
	}
}

// TestRouteProbeSupportedIsRegistryDriven pins the SEPARATE probe-route
// gate: it is true exactly for the tools carrying a registry ProxyProbe
// (guarded config-lane writer exists, route not yet live-verified) and
// false for the verified routes (which routeSupported handles) and every
// proxy-exempt tool. The set derives from the registry, not a hand-list,
// and probeRouteWriter must resolve a writer for each probe tool.
func TestRouteProbeSupportedIsRegistryDriven(t *testing.T) {
	reg, err := proxyroute.NewRegistrar(proxyroute.RegisterOptions{ProxyPort: 18820, HomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewRegistrar: %v", err)
	}
	in := []string{"kimi-code", "crush", "qwen-code"}
	out := []string{"claude-code", "codex", "opencode", "cursor", "hermes", "pi", "definitely-not-a-tool", ""}
	for _, tool := range in {
		if !routeProbeSupported(tool) {
			t.Errorf("routeProbeSupported(%q) = false, want true (registry ProxyProbe)", tool)
		}
		if _, ok := probeRouteWriter(reg, tool); !ok {
			t.Errorf("probeRouteWriter(%q) has no writer — every probe tool needs one", tool)
		}
	}
	for _, tool := range out {
		if routeProbeSupported(tool) {
			t.Errorf("routeProbeSupported(%q) = true, want false", tool)
		}
	}
	// probeRouteTools derives from the registry and includes exactly the probe set.
	got := map[string]bool{}
	for _, tool := range probeRouteTools() {
		got[tool] = true
	}
	for _, tool := range in {
		if !got[tool] {
			t.Errorf("probeRouteTools() missing %q", tool)
		}
	}
}

// TestBrowserOfferedBrowsers_WindowsOnly pins FIX 2: the browser step is
// offered when ONLY a Windows browser exists (empty dir-based det) — the gate
// branches on "any target (dir OR Windows)", not on len(det) alone. It reads
// only injected windowsHomes (temp dirs), never ambient crossmount.
func TestBrowserOfferedBrowsers_WindowsOnly(t *testing.T) {
	// No dir-based browser, no Windows home → nothing offered.
	if ids := browserOfferedBrowsers(nil, nil); len(ids) != 0 {
		t.Fatalf("empty inputs offered %v, want none", ids)
	}
	// A Windows home WITH a Chrome profile, but NO dir-based browser → the
	// step is still offered (this is the WSL-daemon + Windows-browser box).
	winHome := t.TempDir()
	mkWinChromeProfile(t, winHome)
	ids := browserOfferedBrowsers(nil, []string{winHome})
	if len(ids) != 1 || ids[0] != "chrome" {
		t.Fatalf("Windows-only offered %v, want [chrome]", ids)
	}
}

// TestRunBrowserExtensionStep_WindowsHappyPathInjected drives the FULL Windows
// registration path through the cmd step with an INJECTED fake registry +
// fake path translator: no dir-based browser, only a Windows one. It proves
// FIX 1 (nothing reaches the real reg.exe / real /mnt/c) AND FIX 2 (a
// Windows-only box is registered), and that the registry entry + artifacts
// were written under the injected temp dir.
func TestRunBrowserExtensionStep_WindowsHappyPathInjected(t *testing.T) {
	home := t.TempDir() // NO Linux/dir browser
	winHome := t.TempDir()
	mkWinChromeProfile(t, winHome)
	fake := newFakeWinRegistry()

	var buf strings.Builder
	err := runBrowserExtensionStep(&buf, browserExtStepParams{
		HomeDir:           home,
		ObserverBin:       "/opt/observer",
		ExtensionID:       "abcdefghijklmnopabcdefghijklmnop",
		WindowsHomes:      []string{winHome},
		WSLDistro:         "Ubuntu",
		WinPathTranslator: fakeWinTranslator,
		NewWindowsRegistry: func() (browserhost.RegistryWriter, error) {
			return fake, nil
		},
	})
	if err != nil {
		t.Fatalf("runBrowserExtensionStep: %v (out=%s)", err, buf.String())
	}
	if !strings.Contains(buf.String(), "browser (windows): wrote") {
		t.Errorf("expected a Windows 'wrote' line, got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "browser (windows/chrome): set registry key") {
		t.Errorf("expected a chrome registry-set line, got:\n%s", buf.String())
	}
	// The fake registry recorded exactly one HKCU set (chrome), and the
	// bridge + manifest were written under the injected Windows temp home —
	// never a real profile.
	if len(fake.sets) != 1 {
		t.Errorf("fake registry sets = %d, want 1", len(fake.sets))
	}
	hostDir := filepath.Join(winHome, ".observer", "browser-host")
	if _, serr := os.Stat(filepath.Join(hostDir, "com.superbased.observer.browser.json")); serr != nil {
		t.Errorf("manifest not written under injected temp home: %v", serr)
	}
	if _, serr := os.Stat(filepath.Join(hostDir, "com.superbased.observer.browser.bat")); serr != nil {
		t.Errorf("bridge .bat not written under injected temp home: %v", serr)
	}
}

// TestRunBrowserExtensionStep_IgnoresAmbientEnv is the "would fail if ambient
// detection ran" guard (FIX 1): with WindowsHomes deliberately left nil but
// $WSL_DISTRO_NAME set, the step must produce ZERO Windows output — proving it
// reads ONLY injected homes, never ambient env / crossmount / the real writer.
func TestRunBrowserExtensionStep_IgnoresAmbientEnv(t *testing.T) {
	t.Setenv("WSL_DISTRO_NAME", "Ubuntu")
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "google-chrome"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	var buf strings.Builder
	// A failFactory that fatals if constructed proves no registry writer is
	// ever built off ambient state.
	if err := runBrowserExtensionStep(&buf, browserExtStepParams{
		HomeDir: home, ObserverBin: "/opt/observer",
		WindowsHomes:       nil, // no injected Windows homes
		WSLDistro:          "",  // ambient env must NOT leak in
		NewWindowsRegistry: failFactory(t),
	}); err != nil {
		t.Fatalf("runBrowserExtensionStep: %v", err)
	}
	if strings.Contains(buf.String(), "browser (windows") || strings.Contains(buf.String(), "found a Windows browser") {
		t.Errorf("ambient env leaked into the step — got Windows output:\n%s", buf.String())
	}
}

// TestRunBrowserExtensionStep_NilFactoryFailsClosed pins FIX 1's fail-closed
// posture: a Windows browser is present and the distro is known, but NO
// registry factory was injected. The step must NOT construct the real writer —
// it prints an honest skip and writes nothing for Windows.
func TestRunBrowserExtensionStep_NilFactoryFailsClosed(t *testing.T) {
	home := t.TempDir()
	winHome := t.TempDir()
	mkWinChromeProfile(t, winHome)
	var buf strings.Builder
	err := runBrowserExtensionStep(&buf, browserExtStepParams{
		HomeDir: home, ObserverBin: "/opt/observer",
		WindowsHomes:       []string{winHome},
		WSLDistro:          "Ubuntu",
		NewWindowsRegistry: nil, // nil in a testable path must fail closed
	})
	if err != nil {
		t.Fatalf("nil factory should skip, not error: %v", err)
	}
	if !strings.Contains(buf.String(), "no registry writer was provided") {
		t.Errorf("expected the fail-closed note, got:\n%s", buf.String())
	}
	if _, serr := os.Stat(filepath.Join(winHome, ".observer", "browser-host")); !os.IsNotExist(serr) {
		t.Errorf("nil factory must not write anything for Windows (stat err=%v)", serr)
	}
}

// TestRunBrowserExtensionStep_FactoryErrorFailsClosed pins FIX 3's surface at
// the cmd layer: when the registry factory fails (reg.exe absent from the
// trusted system path), the step skips Windows with an honest note and writes
// nothing — it does NOT fall back to any other reg.exe.
func TestRunBrowserExtensionStep_FactoryErrorFailsClosed(t *testing.T) {
	home := t.TempDir()
	winHome := t.TempDir()
	mkWinChromeProfile(t, winHome)
	var buf strings.Builder
	err := runBrowserExtensionStep(&buf, browserExtStepParams{
		HomeDir: home, ObserverBin: "/opt/observer",
		WindowsHomes: []string{winHome},
		WSLDistro:    "Ubuntu",
		NewWindowsRegistry: func() (browserhost.RegistryWriter, error) {
			return nil, fmt.Errorf("Windows registry tool not found at the expected system path")
		},
	})
	if err != nil {
		t.Fatalf("factory error should skip, not error the whole step: %v", err)
	}
	if !strings.Contains(buf.String(), "Windows registry tool not found") {
		t.Errorf("expected the reg.exe-absent note, got:\n%s", buf.String())
	}
}

// TestRunBrowserExtensionStep_AllWindowsFail pins FIX 4: when Windows
// registration was requested but EVERY registry write fails, the step returns
// an aggregate error (so the CLI exits non-zero).
func TestRunBrowserExtensionStep_AllWindowsFail(t *testing.T) {
	home := t.TempDir()
	winHome := t.TempDir()
	mkWinChromeProfile(t, winHome)
	var buf strings.Builder
	err := runBrowserExtensionStep(&buf, browserExtStepParams{
		HomeDir: home, ObserverBin: "/opt/observer",
		ExtensionID:       "abcdefghijklmnopabcdefghijklmnop",
		WindowsHomes:      []string{winHome},
		WSLDistro:         "Ubuntu",
		WinPathTranslator: fakeWinTranslator,
		NewWindowsRegistry: func() (browserhost.RegistryWriter, error) {
			return &erroringWinRegistry{}, nil
		},
	})
	if err == nil {
		t.Fatalf("all-fail Windows registration should return an aggregate error; out=%s", buf.String())
	}
	if !strings.Contains(err.Error(), "failed for every target") {
		t.Errorf("aggregate error should name the all-failed condition, got: %v", err)
	}
}

// erroringWinRegistry fails every SetDefault so the all-fail aggregate path is
// exercised. GetDefault reports "not set" so a set is always attempted.
type erroringWinRegistry struct{}

func (erroringWinRegistry) GetDefault(string) (string, bool, error) { return "", false, nil }
func (erroringWinRegistry) SetDefault(string, string) error {
	return fmt.Errorf("simulated reg write failure")
}

// TestRunBrowserExtensionStep_NoBrowserIsCleanNoOp pins FIX 4's honest-no-op
// boundary: no browser at all (dir or Windows) returns nil, not an error.
func TestRunBrowserExtensionStep_NoBrowserIsCleanNoOp(t *testing.T) {
	home := t.TempDir()
	var buf strings.Builder
	if err := runBrowserExtensionStep(&buf, browserExtStepParams{
		HomeDir: home, ObserverBin: "/opt/observer",
		NewWindowsRegistry: failFactory(t), // must never be called
	}); err != nil {
		t.Fatalf("no-browser run must be a clean no-op, got: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("no-browser run wrote %q, want nothing", buf.String())
	}
}
