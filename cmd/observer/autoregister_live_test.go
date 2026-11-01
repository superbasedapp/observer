package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// TestGrandfatheredAutoRegisterOwesLiveGrounding fails once a grandfathered
// mechanism's registered bindings are ALL live: it no longer needs the
// exemption, so the entry must be removed (the live gate admits it).
func TestGrandfatheredAutoRegisterOwesLiveGrounding(t *testing.T) {
	for mech, why := range grandfatheredAutoRegister {
		if why == "" {
			t.Errorf("%s: grandfathered without a reason", mech)
		}
		rows := 0
		for _, c := range integration.Capabilities() {
			if c.Hook.Mechanism != mech {
				continue
			}
			rows++
			if c.Hook.RegisteredAllLive() {
				t.Errorf("%s (%s) is now fully live-grounded: remove it from grandfatheredAutoRegister", mech, c.Tool)
			}
		}
		if rows == 0 {
			t.Errorf("%s is grandfathered but no registry row uses it", mech)
		}
	}
}

// notGrandfathered names the auto-registrable mechanisms that are NOT
// grandfathered although they are not yet live, with the reason: they are
// `observer init` only until they go live.
var notGrandfathered = map[integration.HookMechanism]string{
	integration.HookAntigravityJSON: "Sol A2-08: PreInvocation was added the day of the ruling with no live run; since hook-parity Lane A6 it registers the PreToolUse tool gate, live-grounded on node 1 2026-10-03, so `observer start` writes it through the live gate (never the grandfather list)",
	// Hook-parity Lane A6 (2026-10-03): new tool-gate mechanisms. Each is
	// written by `observer init` only until its registered bindings are
	// live-grounded (D-043: a new mechanism joins auto-registration by
	// going live, never by being grandfathered).
	integration.HookGrokHooksJSON:        "hook-parity Lane A6: live-grounded on node 1 2026-10-03 (admitted by the live gate)",
	integration.HookCopilotCLIHooks:      "hook-parity Lane A6: init-only until live",
	integration.HookVibeHooksTOML:        "hook-parity Lane A6: init-only until live",
	integration.HookGoosePlugin:          "hook-parity Lane A6: init-only until live",
	integration.HookClineHookFiles:       "hook-parity Lane A6: init-only until live",
	integration.HookJunieConfig:          "hook-parity Lane A6: init-only until live",
	integration.HookCrushJSON:            "hook-parity Lane A6: init-only until live",
	integration.HookOpenInterpreterHooks: "hook-parity Lane A6: init-only until live",
	integration.HookZcodeJSON:            "hook-parity Lane A4: init-only until live",
	integration.HookMuseSettings:         "T-479 (2026-10-06): live-grounded on node 1 (admitted by the live gate)",
	integration.HookKimiCodeTOML:         "T-378 (2026-10-07): live-grounded on node 1 (admitted by the live gate)",
	integration.HookKiroAgentJSON:        "gfiD (2026-10-15): vendor semantics live with probe hooks, Observer's own writer not yet live-run; init-only until live",
	integration.HookPluginShimTS:         "hook-parity Lane D (2026-10-03): a new mechanism; it joins `observer start` only by going live per row, never by grandfathering",
	// The 2026-10-21 wave: new mechanisms, init-only until each writer's
	// registered bindings pass a live end-to-end run (D-043).
	integration.HookIBMBobSettings:    "2026-10-21 wave: live E2E on WSL, Windows wsl.exe bridges live 2026-10-22 (admitted by the live gate); the Windows-native shapes stay init-only (initOnlyHookTargets)",
	integration.HookCodeBuddySettings: "2026-10-21 wave: live E2E on WSL, Windows wsl.exe bridges live 2026-10-22 (admitted by the live gate); the Windows-native shapes stay init-only (initOnlyHookTargets)",
	integration.HookDeepAgentsJSON:    "2026-10-21 wave: live E2E on WSL, Windows wsl.exe bridges live 2026-10-22 (admitted by the live gate); the Windows-native shapes stay init-only (initOnlyHookTargets)",
	integration.HookDimCodeJSON:       "2026-10-21 wave: live E2E on WSL, Windows wsl.exe bridges live 2026-10-22 (admitted by the live gate); the Windows-native shapes stay init-only (initOnlyHookTargets)",
	integration.HookDiracHookFiles:    "2026-10-21 wave: live E2E on WSL, Windows wsl.exe bridges live 2026-10-22 (admitted by the live gate); the Windows-native shapes stay init-only (initOnlyHookTargets)",
	integration.HookAutohandConfig:    "2026-10-21 wave: init-only always (initOnlyHookMechanisms: device sync)",
	integration.HookVTCodeTOML:        "2026-10-21 wave: live E2E on WSL, Windows wsl.exe bridges live 2026-10-22 (admitted by the live gate); the Windows-native shapes stay init-only (initOnlyHookTargets)",
	integration.HookKimchiBashHook:    "2026-10-21 wave: live E2E on WSL (admitted by the live gate); no Windows hook shape (the bash pre-gate is Linux and macOS only)",
	integration.HookCortexHooksJSON:   "surface-gap W-2a: built, switched off until live check LC18 (DEC-12); never auto-registered while gated",
}

// TestInitOnlyMechanismsNeverAutoRegister: a mechanism on the init-only list
// fails the `observer start` live gate even with every binding live.
func TestInitOnlyMechanismsNeverAutoRegister(t *testing.T) {
	for mech := range initOnlyHookMechanisms {
		c := integration.Capability{Hook: integration.HookSpec{Mechanism: mech}}
		if autoRegisterLiveGate(c) {
			t.Errorf("%s: init-only mechanism passed the auto-register live gate", mech)
		}
	}
}

// frozenGrandfathered is the grandfather list as the 2026-10-02 ruling
// froze it (minus Sol A2-08's Antigravity). The list may only SHRINK: a
// mechanism leaves it by going live. Adding one here is the exact bypass
// D-043 closes, so this test fails on any key not in this set.
var frozenGrandfathered = map[integration.HookMechanism]bool{
	integration.HookClaudeSettings: true, integration.HookCursor: true,
	integration.HookCodexConfig: true, integration.HookGeminiSettings: true,
	integration.HookQwenSettings: true, integration.HookFactoryJSON: true,
	integration.HookQoderJSON: true, integration.HookPoolsideYAML: true,
	integration.HookCascadeJSON: true, integration.HookCommandCodeMod: true,
}

// TestGrandfatheredAutoRegisterOnlyShrinks pins that no mechanism enters
// auto-registration through the grandfather list (Sol A2-08).
func TestGrandfatheredAutoRegisterOnlyShrinks(t *testing.T) {
	for mech := range grandfatheredAutoRegister {
		if !frozenGrandfathered[mech] {
			t.Errorf("%s joined the grandfather list: a new mechanism joins auto-registration only by going live (D-043)", mech)
		}
	}
	for mech := range notGrandfathered {
		if _, ok := grandfatheredAutoRegister[mech]; ok {
			t.Errorf("%s is listed as not grandfathered but is in grandfatheredAutoRegister", mech)
		}
	}
}

// TestAntigravityIsInitOnlyUntilLive is Sol A2-08's regression: the
// Antigravity registration must not pass the `observer start` live gate
// while any of its bindings is not live. Since hook-parity Lane A6 it is
// the PreToolUse tool gate (PreInvocation stays retired, D-188).
func TestAntigravityIsInitOnlyUntilLive(t *testing.T) {
	c, ok := integration.For("antigravity-cli")
	if !ok {
		t.Fatal("no antigravity-cli registry row")
	}
	if c.Hook.Mechanism != integration.HookAntigravityJSON {
		t.Fatalf("mechanism = %s", c.Hook.Mechanism)
	}
	if !c.Hook.RegisteredAllLive() && autoRegisterLiveGate(c) {
		t.Error("observer start would auto-register Antigravity's not-yet-live PreInvocation hook")
	}
	// The node 1 live test (2026-10-03) retired the PreInvocation
	// registration (D-188); T-476 restored it after agy 1.3.0 proved live
	// on node 1 (2026-10-06). A registered PreInvocation must be live, so
	// `observer start` never writes an unproven prompt hook.
	if !hookSupported("antigravity-cli") {
		t.Error("antigravity-cli PreToolUse tool gate is not offered by observer init")
	}
	for _, b := range c.Hook.Bindings {
		if b.NativeEvent == "PreInvocation" && b.Registered && b.Grounding.Kind != integration.GroundingLive {
			t.Error("antigravity-cli PreInvocation is registered without a live grounding")
		}
	}
	if !hookRemovable("antigravity-cli") {
		t.Error("observer uninstall can no longer remove an earlier antigravity-cli registration")
	}
}

// TestGrandfatheredAutoRegisterIsTodaysSet: the grandfather list holds
// exactly the mechanisms `observer start` could auto-register when the
// ruling landed, no more (a new mechanism joins by going live, never by
// being listed) and no fewer (dropping one silently stops auto-registration
// on every node that has it), except the named notGrandfathered entries.
func TestGrandfatheredAutoRegisterIsTodaysSet(t *testing.T) {
	autoRegistrable := map[integration.HookMechanism]bool{}
	for _, c := range integration.Capabilities() {
		if hookSupported(c.Tool) {
			autoRegistrable[c.Hook.Mechanism] = true
		}
	}
	for mech := range autoRegistrable {
		if _, ok := grandfatheredAutoRegister[mech]; !ok && !anyRowLive(mech) && notGrandfathered[mech] == "" {
			t.Errorf("%s is auto-registrable but neither grandfathered nor live", mech)
		}
	}
	for mech := range grandfatheredAutoRegister {
		if !autoRegistrable[mech] {
			t.Errorf("%s is grandfathered but `observer start` never registers it", mech)
		}
	}
}

func anyRowLive(mech integration.HookMechanism) bool {
	for _, c := range integration.Capabilities() {
		if c.Hook.Mechanism == mech && c.Hook.RegisteredAllLive() {
			return true
		}
	}
	return false
}

// TestAutoRegisterLiveGate pins the pure decision on synthetic rows.
func TestAutoRegisterLiveGate(t *testing.T) {
	live := integration.Grounding{Kind: integration.GroundingLive, Source: "s", Date: "d"}
	doc := integration.Grounding{Kind: integration.GroundingDoc, Source: "s", Date: "d"}
	synthetic := func(mech integration.HookMechanism, g integration.Grounding) integration.Capability {
		return integration.Capability{Tool: "synthetic", Hook: integration.HookSpec{Mechanism: mech, Bindings: []integration.HookBinding{
			{Cap: integration.HookCapPromptGate, Phase: integration.HookPhasePre, NativeEvent: "E", Registered: true, Grounding: g},
		}}}
	}
	if autoRegisterLiveGate(synthetic(integration.HookZcodeJSON, doc)) {
		t.Error("a doc-grounded, non-grandfathered mechanism must be `observer init` only")
	}
	if !autoRegisterLiveGate(synthetic(integration.HookZcodeJSON, live)) {
		t.Error("an all-live mechanism must auto-register")
	}
	if !autoRegisterLiveGate(synthetic(integration.HookQwenSettings, doc)) {
		t.Error("a grandfathered mechanism keeps auto-registering")
	}
}

// TestAutoRegisterWritesOnlyLiveBindings drives the real writer under the
// TEST-ISO-1 guard (throwaway pinned HOME, a staged, empty foreign layout:
// no foreign home is ever discovered). Qwen Code's mechanism is made a
// synthetic doc-grounded, NON-grandfathered mechanism for the test: start
// must not write ~/.qwen/settings.json, while Claude Code (grandfathered)
// is still written. The control run restores the list and Qwen is written.
func TestAutoRegisterWritesOnlyLiveBindings(t *testing.T) {
	requireComponents(t, "integration.hooks")
	requireActiveAdapters(t, "claude-code", "qwen-code")
	requireAdapter(t, "claude-code")
	crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{Root: t.TempDir()})
	setupHome := func(t *testing.T) string {
		t.Helper()
		home := t.TempDir()
		for _, dir := range []string{".claude", ".qwen"} {
			if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		// Every profile root and tool home stays in the throwaway home
		// (surface-gap S-10, FU-4).
		pinToolHomesAt(t, home)
		return home
	}

	saved := grandfatheredAutoRegister[integration.HookQwenSettings]
	delete(grandfatheredAutoRegister, integration.HookQwenSettings)
	home := setupHome(t)
	var stdout, stderr bytes.Buffer
	autoRegisterHooks(&stdout, &stderr, "", true)
	grandfatheredAutoRegister[integration.HookQwenSettings] = saved
	if _, err := os.Stat(filepath.Join(home, ".qwen", "settings.json")); err == nil {
		t.Errorf("a doc-grounded, non-grandfathered mechanism was auto-registered (stdout %q)", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Errorf("grandfathered Claude Code was not registered: %v", err)
	}

	home = setupHome(t)
	stdout.Reset()
	autoRegisterHooks(&stdout, &stderr, "", true)
	if _, err := os.Stat(filepath.Join(home, ".qwen", "settings.json")); err != nil {
		t.Errorf("control: grandfathered Qwen Code was not registered: %v (stdout %q)", err, stdout.String())
	}
}

// TestInitOnlyHookTargetsAreCurrent: every initOnlyHookTargets row names a
// target whose mechanism the live gate would otherwise admit (a row for a
// mechanism that is init-only anyway is dead weight), and the row keeps
// that target off `observer start` on its host OS.
func TestInitOnlyHookTargetsAreCurrent(t *testing.T) {
	prev := autoRegisterHostGOOS
	t.Cleanup(func() { autoRegisterHostGOOS = prev })
	for _, row := range initOnlyHookTargets {
		c, _, ok := advertisedCapability(row.target)
		if !ok {
			t.Errorf("%s: no registry row", row.target)
			continue
		}
		if !autoRegisterLiveGate(c) {
			t.Errorf("%s: the live gate refuses its mechanism anyway; remove the row", row.target)
		}
		autoRegisterHostGOOS = row.goos
		if row.goos == "" {
			autoRegisterHostGOOS = "linux"
		}
		if autoRegisterDecision(row.target, true) {
			t.Errorf("%s on %q: still auto-registered", row.target, autoRegisterHostGOOS)
		}
	}
}
