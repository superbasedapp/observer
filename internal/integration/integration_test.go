package integration

import "testing"

func TestForProxyRoutableTools(t *testing.T) {
	tests := []struct {
		tool       string
		wantOK     bool
		wantProxy  bool
		wantEnvVar string
		wantSuffix string
		wantConfig bool // routes via config file (EnvVar == "", Note set)
	}{
		{"claude-code", true, true, "ANTHROPIC_BASE_URL", "", false},
		{"opencode", true, true, "OPENAI_BASE_URL", "/v1", false},
		{"codex", true, true, "", "", true},
		// Registered now (discovery spike), but NOT proxy-routable: own
		// backend, no base-URL knob → Proxy == nil. ok=true, wantProxy=false.
		{"cursor", true, false, "", "", false},
		{"antigravity", true, false, "", "", false},
		// Never registered → zero-value Capability that still echoes Tool.
		{"definitely-not-a-tool", false, false, "", "", false},
		{"", false, false, "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.tool, func(t *testing.T) {
			c, ok := For(tc.tool)
			if ok != tc.wantOK {
				t.Fatalf("For(%q) ok = %v, want %v", tc.tool, ok, tc.wantOK)
			}
			if c.Tool != tc.tool {
				t.Errorf("For(%q).Tool = %q, want %q (must echo the tool name)", tc.tool, c.Tool, tc.tool)
			}
			hasProxy := c.Proxy != nil
			if hasProxy != tc.wantProxy {
				t.Fatalf("For(%q) hasProxy = %v, want %v", tc.tool, hasProxy, tc.wantProxy)
			}
			if !hasProxy {
				return
			}
			if c.Proxy.EnvVar != tc.wantEnvVar {
				t.Errorf("For(%q).Proxy.EnvVar = %q, want %q", tc.tool, c.Proxy.EnvVar, tc.wantEnvVar)
			}
			if c.Proxy.Suffix != tc.wantSuffix {
				t.Errorf("For(%q).Proxy.Suffix = %q, want %q", tc.tool, c.Proxy.Suffix, tc.wantSuffix)
			}
			if tc.wantConfig && (c.Proxy.EnvVar != "" || c.Proxy.Note == "") {
				t.Errorf("For(%q): expected config-file route (EnvVar empty + Note set), got EnvVar=%q Note=%q", tc.tool, c.Proxy.EnvVar, c.Proxy.Note)
			}
			if c.Proxy.Launcher == "" {
				t.Errorf("For(%q).Proxy.Launcher must be set", tc.tool)
			}
		})
	}
}

// TestProxyRouteKinds pins the route-application kind for each routable
// adapter — the capability the init proxy-route step dispatches on. Only
// the persisted kinds are written by init; opencode is launcher-applied.
func TestProxyRouteKinds(t *testing.T) {
	want := map[string]RouteKind{
		"claude-code": RouteEnvSettings,
		"codex":       RouteConfigFile,
		"opencode":    RouteLauncher,
		"gemini-cli":  RouteLauncher,     // Phase E bridge, live-verified 2026-06-27
		"copilot-cli": RouteLauncher,     // BYOK COPILOT_PROVIDER_BASE_URL, live-verified 2026-06-27
		"pi":          RouteProviderJSON, // models.json custom provider, live-verified 2026-06-27
		"cline-cli":   RouteProviderJSON, // openai-compatible settings.baseUrl, live-verified 2026-06-27
		"hermes":      RouteProviderJSON, // user-config provider + key_env (Approach B), live-verified 2026-06-27
		"kimi-code":   RouteConfigFile,   // ~/.kimi-code/config.toml [providers.openai].base_url, live-verified 2026-07-09 (api_turns 23075)
		"crush":       RouteProviderJSON, // crush.json providers.openai.base_url, live-verified 2026-07-09 via the Windows crush.cmd → WSL :8820 (api_turns 23081)
		"qwen-code":   RouteConfigFile,   // ~/.qwen/settings.json model.baseUrl + matching modelProviders entry, live-verified 2026-07-10 (api_turns 23728-23730)
		// Promoted 2026-08-21: live turns landed through each launcher path
		// (grok: successful /up/grok turn, 12155/24 tokens; aider +
		// prime-agent: api_turns rows recorded through the route — keyed
		// prime-agent turn captured real usage 4119/2; goose: rows landed
		// once the operator shell's ambient OPENAI_HOST was unset — it had
		// been silently overriding the injection).
		"grok":        RouteLauncher, // GROK_CLI_CHAT_PROXY_BASE_URL at the /up/grok upstream, opt-in --proxy flag
		"aider":       RouteLauncher, // OPENAI_API_BASE=<proxy>/v1 injected by observer aider
		"prime-agent": RouteLauncher, // 'observer' provider in ~/.prime/agent/models.json, exec --provider observer
		"goose":       RouteLauncher, // OPENAI_HOST=<proxy root>, opt-in --proxy flag; needs GOOSE_PROVIDER=openai + no ambient OPENAI_HOST
	}
	for tool, kind := range want {
		c, ok := For(tool)
		if !ok || c.Proxy == nil {
			t.Fatalf("For(%q): expected a routable capability", tool)
		}
		if c.Proxy.Kind != kind {
			t.Errorf("For(%q).Proxy.Kind = %q, want %q", tool, c.Proxy.Kind, kind)
		}
	}
	// Every other registered adapter must be proxy-exempt (Proxy == nil).
	for _, c := range Capabilities() {
		if _, routable := want[c.Tool]; routable {
			continue
		}
		if c.Proxy != nil {
			t.Errorf("%s: Proxy = %+v, want nil (proxy-exempt)", c.Tool, c.Proxy)
		}
	}
}

// TestRoutabilityClassifiedForEveryAdapter pins the honesty rule for the
// surface-specific reclassification (Phase 0): every adapter declares a
// routability bucket — no row may be left RouteStatusUnknown — and the
// bucket is consistent with the Proxy field (a route observer drives today
// implies the surface is routable). This is the guardrail that forces a new
// adapter to be classified, not silently defaulted to "impossible".
func TestRoutabilityClassifiedForEveryAdapter(t *testing.T) {
	for _, c := range Capabilities() {
		if c.Routability == RouteStatusUnknown {
			t.Errorf("%s: Routability is unclassified (RouteStatusUnknown) — assign a surface bucket", c.Tool)
		}
		if c.Proxy != nil && c.Routability != RouteStatusRoutableNow {
			t.Errorf("%s: Proxy is non-nil (route applied today) but Routability = %q, want RouteStatusRoutableNow",
				c.Tool, c.Routability)
		}
	}
}

// TestProxyProbeRouteKinds pins the config-lane WRITER BINDINGS: each tool
// with a guarded, additive proxyroute writer carries a ProxyProbe recording
// the RouteKind init writes it with. ProxyProbe PERSISTS after promotion —
// kimi-code + crush were promoted to a verified Proxy (live-verified
// 2026-07-09) but KEEP their ProxyProbe, because the writer remains init's
// apply mechanism on a machine whose config is not yet routed. qwen-code was
// promoted 2026-07-10 once the writer learned to ALSO retarget the matching
// openai-lane modelProviders entry (the original model.baseUrl-only rewrite was
// ignored when it matched no provider); it keeps its ProxyProbe like the others.
func TestProxyProbeRouteKinds(t *testing.T) {
	want := map[string]RouteKind{
		"kimi-code": RouteConfigFile,   // ~/.kimi-code/config.toml [providers.openai].base_url (promoted; probe binding kept)
		"crush":     RouteProviderJSON, // crush.json providers.openai.base_url (promoted; probe binding kept)
		"qwen-code": RouteConfigFile,   // ~/.qwen/settings.json model.baseUrl + matching modelProviders entry (promoted 2026-07-10; probe binding kept)
	}
	// No un-promoted probe writers remain: every tool with a ProxyProbe was
	// live-verified and carries a Proxy. (Kept as a map so re-adding an
	// un-promoted probe writer is a one-line change with the invariant intact.)
	unpromoted := map[string]bool{}
	for tool, kind := range want {
		c, ok := For(tool)
		if !ok || c.ProxyProbe == nil {
			t.Fatalf("For(%q): expected a ProxyProbe (guarded writer exists)", tool)
		}
		if c.ProxyProbe.Kind != kind {
			t.Errorf("For(%q).ProxyProbe.Kind = %q, want %q", tool, c.ProxyProbe.Kind, kind)
		}
		if unpromoted[tool] {
			// An un-promoted probe writer must NOT masquerade as a verified route.
			if c.Proxy != nil {
				t.Errorf("For(%q): Proxy = %+v, want nil (unverified probe route)", tool, c.Proxy)
			}
			if c.Routability != RouteStatusProbeRequired {
				t.Errorf("For(%q).Routability = %q, want probe_required", tool, c.Routability)
			}
		}
	}
	// Only these three tools carry a ProxyProbe today.
	for _, c := range Capabilities() {
		if _, expected := want[c.Tool]; expected {
			continue
		}
		if c.ProxyProbe != nil {
			t.Errorf("%s: ProxyProbe = %+v, want nil (no config-lane writer)", c.Tool, c.ProxyProbe)
		}
	}
}

func TestCapabilitiesCoversRegistry(t *testing.T) {
	caps := Capabilities()
	if len(caps) == 0 {
		t.Fatal("Capabilities() returned empty")
	}
	for _, c := range caps {
		if c.Tool == "" {
			t.Errorf("Capabilities() entry with empty Tool: %+v", c)
		}
		if _, ok := For(c.Tool); !ok {
			t.Errorf("Capabilities() lists %q but For(%q) is not ok", c.Tool, c.Tool)
		}
	}
}

// TestHookCapabilities pins the grounded hook mechanisms from the discovery
// spike. Phase 2 will replace internal/hook/register.go's switch with a
// walk over these; the AutoWired flag keeps cline-cli honest (receiver
// exists, init does not yet register it).
func TestHookCapabilities(t *testing.T) {
	tests := []struct {
		tool          string
		wantMechanism HookMechanism
		wantBridge    bool
		wantAutoWired bool
	}{
		{"claude-code", HookClaudeSettings, true, true},
		{"cursor", HookCursor, true, true},
		{"codex", HookCodexConfig, true, true},
		{"hermes", HookHermesPlugin, false, true},
		{"cline-cli", HookClineCLIJSONL, false, false}, // receiver exists, not auto-wired
		{"opencode", HookNone, false, false},
		{"cline", HookNone, false, false},
		{"pi", HookNone, false, false},
		// The six Part B item 1/2 long-tail vendors' own cross-OS bridge
		// targets (internal/hook's register*Windows writers) —
		// CrossOSBridge flipped true once the wsl.exe bridge writer
		// existed for each. devin/Windsurf Desktop Cascade stays false:
		// its only grounded install channel is the macOS Homebrew cask,
		// so there is no Windows-native client to bridge to.
		{"gemini-cli", HookGeminiSettings, true, true},
		{"qwen-code", HookQwenSettings, true, true},
		{"droid", HookFactoryJSON, true, true},
		{"qoder", HookQoderJSON, true, true},
		{"poolside", HookPoolsideYAML, true, true},
		{"command-code", HookCommandCodeMod, true, true},
		{"devin", HookCascadeJSON, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.tool, func(t *testing.T) {
			c, ok := For(tc.tool)
			if !ok {
				t.Fatalf("For(%q) not registered", tc.tool)
			}
			if c.Hook.Mechanism != tc.wantMechanism {
				t.Errorf("Hook.Mechanism = %q, want %q", c.Hook.Mechanism, tc.wantMechanism)
			}
			if c.Hook.CrossOSBridge != tc.wantBridge {
				t.Errorf("Hook.CrossOSBridge = %v, want %v", c.Hook.CrossOSBridge, tc.wantBridge)
			}
			if c.Hook.AutoWired != tc.wantAutoWired {
				t.Errorf("Hook.AutoWired = %v, want %v", c.Hook.AutoWired, tc.wantAutoWired)
			}
		})
	}
}

// TestMCPTargets pins the five clients with a grounded, implemented MCP
// writer today (claude-code/cursor/codex/hermes/opencode). Every other
// adapter must carry MCP == nil so init only writes config where a writer
// exists.
func TestMCPTargets(t *testing.T) {
	wantImplemented := map[string]struct {
		format   MCPFormat
		pathHint string
	}{
		"claude-code":  {MCPServersJSON, ".claude.json"},
		"cursor":       {MCPServersJSON, ".cursor/mcp.json"},
		"codex":        {MCPCodexTOML, ".codex/config.toml"},
		"hermes":       {MCPHermesYAML, ".hermes/config.yaml"},
		"opencode":     {MCPOpenCodeJSON, ".config/opencode/opencode.json"},
		"cline":        {MCPServersJSON, "<vscode>/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"},
		"droid":        {MCPServersJSON, ".factory/mcp.json"},
		"command-code": {MCPServersJSON, ".commandcode/mcp.json"},
	}
	for _, c := range Capabilities() {
		want, expect := wantImplemented[c.Tool]
		switch {
		case expect:
			if c.MCP == nil {
				t.Errorf("%s: MCP target is nil, want implemented %s", c.Tool, want.format)
				continue
			}
			if !c.MCP.Implemented {
				t.Errorf("%s: MCP.Implemented = false, want true", c.Tool)
			}
			if c.MCP.Format != want.format {
				t.Errorf("%s: MCP.Format = %q, want %q", c.Tool, c.MCP.Format, want.format)
			}
			if c.MCP.PathHint != want.pathHint {
				t.Errorf("%s: MCP.PathHint = %q, want %q", c.Tool, c.MCP.PathHint, want.pathHint)
			}
		default:
			if c.MCP != nil {
				t.Errorf("%s: MCP target = %+v, want nil (no grounded writer)", c.Tool, c.MCP)
			}
		}
	}
}

// TestNativeRailsLedger pins the native-console ledger: only the three
// 3-rail vendors carry rails; everyone else is enrollment-only (Any()
// false). Phase 4 keeps this a ledger — no new poller is built.
func TestNativeRailsLedger(t *testing.T) {
	withRails := map[string]bool{"claude-code": true, "codex": true, "copilot": true}
	for _, c := range Capabilities() {
		got := c.Native.Any()
		want := withRails[c.Tool]
		if got != want {
			t.Errorf("%s: Native.Any() = %v, want %v", c.Tool, got, want)
		}
	}
}

// TestTokenTierGroundedForEveryAdapter ensures the discovery spike left no
// adapter with an un-set best-tier (the ledger Phase 5 measures against).
func TestTokenTierGroundedForEveryAdapter(t *testing.T) {
	for _, c := range Capabilities() {
		if c.TokenTier.Best == "" {
			t.Errorf("%s: TokenTier.Best is empty — every registered adapter must name a capture tier", c.Tool)
		}
	}
}

// TestPromptLaneGroundedForTouchedAdapters pins the prompt-submit
// intervention hook lane's PromptLane field (docs/plans/
// prompt-submit-intervention-exploration-2026-09-07.md Part B) for
// every adapter this build touched. NOT a full-registry assertion
// (unlike TestRoutabilityClassifiedForEveryAdapter) — scoping to the
// touched set is a disclosed deviation from the contract's "every
// adapter row declares it" ask; a follow-up should widen this once
// every registry row has been reviewed for a grounded PromptLane
// value (most legitimately stay PromptLaneNone, the zero value).
// TestPromptLaneClassifiedForEveryAdapter is FIX-7's total-coverage
// test (phase-2 review), in the TestRoutabilityClassifiedForEveryAdapter
// style: EVERY registry row gets an EXPLICIT, audited PromptLane
// expectation here — not just the handful the hook lane happens to
// have touched so far. A row missing from this table, or a row whose
// live PromptLane drifts from what's recorded here, fails loudly: the
// map below IS the single canonical audit trail for "why does this
// tool have this PromptLane", in one place rather than scattered across
// 45 struct literals in integration.go (most of which — the
// PromptLaneNone rows — carry the zero value with no line to comment
// on at all).
func TestPromptLaneClassifiedForEveryAdapter(t *testing.T) {
	want := map[string]PromptLane{
		// --- PromptLaneHook: VERIFIED dialects, wired in
		// internal/hook/promptsubmit.go with a conformance.go
		// CanBlock:true row AND a hookReceivers entry
		// (cmd/observer/hook.go, TestPromptLaneHookRowsHaveAReceiver).
		"claude-code": PromptLaneHook,
		"codex":       PromptLaneHook,
		"cursor":      PromptLaneHook,
		"gemini-cli":  PromptLaneHook,
		"qwen-code":   PromptLaneHook,
		"droid":       PromptLaneHook,
		// Part B item 2, phase-3a (2026-09-07): the documented
		// long-tail vendors, live-fetched and wired. zcode's writer is
		// deliberately not auto-registered (Hook.AutoWired:false)
		// pending a liveness probe, but its receiver/dialect are built
		// and tested like every other PromptLaneHook row.
		"qoder":        PromptLaneHook,
		"poolside":     PromptLaneHook,
		"zcode":        PromptLaneHook,
		"command-code": PromptLaneHook,
		"devin":        PromptLaneHook,

		// --- PromptLaneProxyOnly: no prompt-submit hook exists (or
		// the one that does can't block/redact), but the tool is
		// already proxy-routed today (contract §2.4/§2.6) — the proxy
		// lane (internal/guard/proxyguard.go's scanPrompt, built and
		// wired) is the only realistic path.
		"opencode":    PromptLaneProxyOnly,
		"copilot-cli": PromptLaneProxyOnly,
		"cline-cli":   PromptLaneProxyOnly,
		"hermes":      PromptLaneProxyOnly,
		"pi":          PromptLaneProxyOnly,
		"grok":        PromptLaneProxyOnly,
		"crush":       PromptLaneProxyOnly,
		"aider":       PromptLaneProxyOnly,
		"goose":       PromptLaneProxyOnly,
		"prime-agent": PromptLaneProxyOnly,

		// --- PromptLaneProbeRequired: a documented mechanism exists,
		// but the exact wire shape (the prompt field's presence, or
		// whether a block reason ever reaches the developer) is
		// genuinely UNVERIFIED or contested in the vendor's own
		// tracker — a live `observer doctor --probe-hook` run, not a
		// docs re-read, is what would resolve it.
		"kimi-code":        PromptLaneProbeRequired,
		"kiro-cli":         PromptLaneProbeRequired,
		"cline":            PromptLaneProbeRequired,
		"open-interpreter": PromptLaneProbeRequired,

		// --- PromptLaneNone: no grounded prompt-submit intervention
		// capability at all today, for one of three honest reasons —
		// (a) genuinely uncoverable (no hook, no route, no third
		// lane: antigravity, antigravity-cli, deepseek, cowork), (b)
		// hook-uncoverable but not proxy-routed either so even the
		// weaker lane doesn't apply yet (copilot/junie/zed/mistral-code
		// are route-wiring-away per contract §2.5.C, kilo-code/
		// kilo-code-cli are redact-only-and-unbuilt with no route,
		// openclaw's fully-documented block is a DIFFERENT mechanism
		// — an in-process JS plugin, deferred per the vendor's own
		// runner-scope warning — grokbot/freebuff/kiro-crew/muse have
		// no lane evidence at all), or (c) covered by a DIFFERENT lane
		// entirely (the five *-web rows, MV3 browser extension,
		// deferred to a later phase per contract §2.5.D).
		"copilot":         PromptLaneNone,
		"kilo-code":       PromptLaneNone,
		"kilo-code-cli":   PromptLaneNone,
		"cowork":          PromptLaneNone,
		"openclaw":        PromptLaneNone,
		"antigravity":     PromptLaneNone,
		"antigravity-cli": PromptLaneNone,
		"deepseek":        PromptLaneNone,
		"chatgpt-web":     PromptLaneNone,
		"claude-web":      PromptLaneNone,
		"perplexity-web":  PromptLaneNone,
		"gemini-web":      PromptLaneNone,
		"copilot-web":     PromptLaneNone,
		"muse":            PromptLaneNone,
		"junie":           PromptLaneNone,
		"mistral-code":    PromptLaneNone,
		"freebuff":        PromptLaneNone,
		"grokbot":         PromptLaneNone,
		"kiro-crew":       PromptLaneNone,
		"zed":             PromptLaneNone,
	}
	byTool := map[string]Capability{}
	for _, c := range Capabilities() {
		byTool[c.Tool] = c
	}
	for tool := range byTool {
		if _, ok := want[tool]; !ok {
			t.Errorf("%s: registry row has no PromptLane expectation in this test's want table — a new adapter needs a conscious PromptLane decision, not silence", tool)
		}
	}
	for tool, wantLane := range want {
		c, ok := byTool[tool]
		if !ok {
			t.Errorf("%s: want table names a tool with no registry row (stale entry?)", tool)
			continue
		}
		if c.PromptLane != wantLane {
			t.Errorf("%s: PromptLane = %q, want %q", tool, c.PromptLane, wantLane)
		}
	}
}
