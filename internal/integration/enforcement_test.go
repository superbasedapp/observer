package integration

import "testing"

// wantEnforcementChannel pins every EnabledAdapters row (Capabilities(), 42
// rows — roo-code is the documented rowless exception, see
// registryRowlessTaxonomyTools) into exactly one EnforcementChannel bucket.
// Derived 2026-08-30 from the grounded ladder in (Capability).
// EnforcementChannel(): a live-verified blocking tool gate wins (T-340,
// 2026-10-04: per binding, no longer a mechanism list), else a
// launchable tool, else a proxy-routed tool, else recorded_acceptance. This
// map is a GOLDEN PIN, not the classification logic itself — the logic is
// computed (capability.go), so this test exists to catch a silent
// reclassification when a future edit changes a row's Hook/Handoff/Proxy
// shape, not to duplicate the ladder.
var wantEnforcementChannel = map[string]EnforcementChannel{
	// hook_block (13): a wired tool gate whose deny a live test proved
	// aborts the action before it runs (HookSpec.LiveBlockingToolGate).
	// T-340 (2026-10-04) moved codex, qoder, antigravity-cli and grok
	// (hook-parity Lane A live tests) and the three plugin-shim hosts
	// opencode, kilo-code-cli and pi (Lane D live tests) here from
	// sandbox_enforce. The 2026-10-04 live-ground lanes added qwen-code,
	// droid (T-357) and goose (Integration 6 merge).
	"claude-code":     EnforceHookBlock,
	"cursor":          EnforceHookBlock,
	"codex":           EnforceHookBlock,
	"qoder":           EnforceHookBlock,
	"antigravity-cli": EnforceHookBlock,
	"grok":            EnforceHookBlock,
	"opencode":        EnforceHookBlock,
	"kilo-code-cli":   EnforceHookBlock,
	"pi":              EnforceHookBlock,
	"qwen-code":       EnforceHookBlock,
	"droid":           EnforceHookBlock,
	"goose":           EnforceHookBlock,
	// T-342: the Cline CLI gate's live grounding (2026-10-04) sits on the
	// cline-cli row.
	"cline-cli": EnforceHookBlock,

	// sandbox_enforce (18): no live-verified blocking tool gate, but
	// launchable via `observer <x>`, so a guard-enforce policy can require
	// the bwrap sandbox. A wired gate that is only doc-grounded (gemini-cli,
	// copilot-cli, ...) stays here until a live test proves it.
	"copilot-cli":      EnforceHookBlock,
	"hermes":           EnforceSandbox,
	"gemini-cli":       EnforceHookBlock,
	"openclaw":         EnforceSandbox,
	"kiro-cli":         EnforceSandbox,
	"kimi-code":        EnforceHookBlock,
	"devin":            EnforceHookBlock,
	"open-interpreter": EnforceSandbox,
	"command-code":     EnforceSandbox,
	"muse":             EnforceHookBlock,
	"prime-agent":      EnforceSandbox,
	"zcode":            EnforceSandbox,
	"mistral-code":     EnforceSandbox,
	"freebuff":         EnforceSandbox,
	// The 2026-10-03 terminal-picker coverage wave: crush and aider were
	// org_disallow (proxy route, no launcher) until their launchers gained
	// a Launch row; junie and poolside were recorded_acceptance until their
	// standalone CLIs (`junie`, `pool`) got launchers.
	"crush":    EnforceSandbox,
	"aider":    EnforceSandbox,
	"junie":    EnforceSandbox,
	"poolside": EnforceSandbox,

	// org_disallow (0): neither a blocking hook nor a launcher, but observer
	// drives a proxy route, so refusing to route is the only lever. No row
	// derives it today; the ladder rung stays for a future proxy-only row.

	// recorded_acceptance (24): no grounded lever at all — no blocking hook,
	// no launcher, no proxy route. The five *-web rows are browser-capture
	// only; the rest are watcher/SQLite-only or IDE-extension surfaces.
	"cline":       EnforceRecordedAcceptance,
	"copilot":     EnforceRecordedAcceptance,
	"kilo-code":   EnforceRecordedAcceptance,
	"cowork":      EnforceRecordedAcceptance,
	"antigravity": EnforceRecordedAcceptance,
	"deepseek":    EnforceRecordedAcceptance,
	// Merged from origin/main 2026-09-10 (registry rows added there; the
	// ladder above is unchanged): kiro-crew and zed carry no hook mechanism,
	// no launcher and no proxy route, so both derive recorded_acceptance.
	"kiro-crew":      EnforceRecordedAcceptance,
	"zed":            EnforceRecordedAcceptance,
	"chatgpt-web":    EnforceRecordedAcceptance,
	"claude-web":     EnforceRecordedAcceptance,
	"perplexity-web": EnforceRecordedAcceptance,
	"gemini-web":     EnforceRecordedAcceptance,
	"copilot-web":    EnforceRecordedAcceptance,
	"grokbot":        EnforceRecordedAcceptance,
	// The 2026-10-21 wave: hook-gated (autohand live E2E on WSL 2026-10-22,
	// still `observer init`-only), no launcher, no proxy route.
	"autohand":        EnforceHookBlock,
	"ibm-bob":         EnforceHookBlock,
	"cortex-code":     EnforceHookBlock,
	"codebuddy":       EnforceHookBlock,
	"deepagents-code": EnforceHookBlock,
	"dimcode":         EnforceHookBlock,
	"dirac":           EnforceHookBlock,
	"kimchi":          EnforceHookBlock,
	"stakpak":         EnforceRecordedAcceptance,
	"vtcode":          EnforceHookBlock,
}

// TestEnforcementChannelClassifiedForEveryAdapter pins the honesty rule for
// the P7 enforcement-bucket classification: every registered adapter lands
// in exactly one non-zero EnforcementChannel bucket, and the pinned bucket
// stays consistent with the golden expectation above — so a future edit to
// a row's Hook/Handoff/Proxy shape that silently reclassifies it is loud,
// mirroring TestRoutabilityClassifiedForEveryAdapter's mechanics.
func TestEnforcementChannelClassifiedForEveryAdapter(t *testing.T) {
	caps := Capabilities()
	if len(caps) != len(wantEnforcementChannel) {
		t.Fatalf("Capabilities() returned %d rows, wantEnforcementChannel pins %d — keep them in sync",
			len(caps), len(wantEnforcementChannel))
	}
	seen := map[string]bool{}
	for _, c := range caps {
		seen[c.Tool] = true
		got := c.EnforcementChannel()
		if got == EnforcementUnknown {
			t.Errorf("%s: EnforcementChannel() returned the zero value — every row must land in a bucket", c.Tool)
			continue
		}
		want, ok := wantEnforcementChannel[c.Tool]
		if !ok {
			t.Errorf("%s: no pinned expectation in wantEnforcementChannel — add one", c.Tool)
			continue
		}
		if got != want {
			t.Errorf("%s: EnforcementChannel() = %q, want %q (pinned) — a Hook/Handoff/Proxy edit reclassified this row; update the pin if intentional",
				c.Tool, got, want)
		}
	}
	for tool := range wantEnforcementChannel {
		if !seen[tool] {
			t.Errorf("wantEnforcementChannel pins %q but Capabilities() has no such row", tool)
		}
	}
}

// TestEnforcementChannelConsistentWithFields re-derives the same ladder
// independently of the pinned map, as a belt-and-suspenders check that the
// implementation actually matches its documented rules (not just the golden
// pin, which could theoretically be co-edited with a logic bug).
func TestEnforcementChannelConsistentWithFields(t *testing.T) {
	for _, c := range Capabilities() {
		got := c.EnforcementChannel()
		switch {
		case c.Hook.LiveBlockingToolGate():
			if got != EnforceHookBlock {
				t.Errorf("%s: has a live-verified blocking tool gate but EnforcementChannel() = %q, want %q",
					c.Tool, got, EnforceHookBlock)
			}
		case c.Handoff.Launchable():
			if got != EnforceSandbox {
				t.Errorf("%s: is launchable with no blocking hook but EnforcementChannel() = %q, want %q",
					c.Tool, got, EnforceSandbox)
			}
		case c.Proxy != nil:
			if got != EnforceOrgDisallow {
				t.Errorf("%s: is proxy-routed with no hook/launcher but EnforcementChannel() = %q, want %q",
					c.Tool, got, EnforceOrgDisallow)
			}
		default:
			if got != EnforceRecordedAcceptance {
				t.Errorf("%s: has no grounded lever but EnforcementChannel() = %q, want %q",
					c.Tool, got, EnforceRecordedAcceptance)
			}
		}
	}
}

// TestEffectiveEnforcementDegradesSandboxWhenUnavailable pins Item 3's
// platform-degrade rule: EnforceSandbox becomes EnforceRecordedAcceptance
// when the platform can't actually build a bwrap sandbox, every other
// bucket is unaffected, and nothing is ever upgraded.
func TestEffectiveEnforcementDegradesSandboxWhenUnavailable(t *testing.T) {
	for _, c := range Capabilities() {
		base := c.EnforcementChannel()

		available := c.EffectiveEnforcement(true)
		if available != base {
			t.Errorf("%s: EffectiveEnforcement(true) = %q, want base %q (available should never change the bucket)",
				c.Tool, available, base)
		}

		unavailable := c.EffectiveEnforcement(false)
		switch base {
		case EnforceSandbox:
			if unavailable != EnforceRecordedAcceptance {
				t.Errorf("%s: EffectiveEnforcement(false) = %q, want %q (sandbox unavailable degrades to recorded acceptance)",
					c.Tool, unavailable, EnforceRecordedAcceptance)
			}
		default:
			if unavailable != base {
				t.Errorf("%s: EffectiveEnforcement(false) = %q, want unchanged base %q (only sandbox_enforce degrades)",
					c.Tool, unavailable, base)
			}
		}
	}
}

// TestEffectiveEnforcementUnderOrgFallback pins D-178's org-configurable
// degrade (operator ruling 2026-10-04): with the org choosing org_disallow, a
// sandbox_enforce tool on a machine with no sandbox degrades to org_disallow
// ONLY when Observer proxy-routes it; a tool with no proxy lever still
// degrades to recorded_acceptance, every other bucket is untouched, an
// available sandbox always wins, and the default (recorded_acceptance) is
// byte-identical to EffectiveEnforcement.
func TestEffectiveEnforcementUnderOrgFallback(t *testing.T) {
	sawProxied, sawUnproxied := false, false
	for _, c := range Capabilities() {
		base := c.EnforcementChannel()
		for _, avail := range []bool{true, false} {
			if got, want := c.EffectiveEnforcementUnder(true, avail, EnforceRecordedAcceptance), c.EffectiveEnforcement(avail); got != want {
				t.Errorf("%s: default fallback %q != EffectiveEnforcement %q", c.Tool, got, want)
			}
			if got := c.EffectiveEnforcementUnder(true, avail, EnforcementChannel("bogus")); got != c.EffectiveEnforcement(avail) {
				t.Errorf("%s: an unknown fallback must read as recorded_acceptance, got %q", c.Tool, got)
			}
		}
		if got := c.EffectiveEnforcementUnder(true, true, EnforceOrgDisallow); got != base {
			t.Errorf("%s: an available sandbox must win, got %q want %q", c.Tool, got, base)
		}
		got := c.EffectiveEnforcementUnder(true, false, EnforceOrgDisallow)
		switch {
		case base != EnforceSandbox:
			if got != base {
				t.Errorf("%s: only sandbox_enforce degrades, got %q want %q", c.Tool, got, base)
			}
		case c.Proxy != nil:
			sawProxied = true
			if got != EnforceOrgDisallow {
				t.Errorf("%s: proxied sandbox tool with no sandbox = %q, want org_disallow", c.Tool, got)
			}
		default:
			sawUnproxied = true
			if got != EnforceRecordedAcceptance {
				t.Errorf("%s: unproxied sandbox tool with no sandbox = %q, want recorded_acceptance", c.Tool, got)
			}
		}
	}
	if !sawProxied || !sawUnproxied {
		t.Fatalf("registry no longer exercises both branches (proxied=%v unproxied=%v)", sawProxied, sawUnproxied)
	}
}

// TestEffectiveEnforcementUnderNodeGate pins D-262: the org fallback composes
// with the node's own tool-gate state. A hook_block tool whose gate is not
// registered and current on this node is judged like a tool with no hook:
// sandbox when the platform has one, else the org's choice (org_disallow for
// a proxied tool), and NodeEnforcement is exactly the recorded_acceptance
// default of it.
func TestEffectiveEnforcementUnderNodeGate(t *testing.T) {
	saw := false
	for _, c := range Capabilities() {
		for _, gate := range []bool{true, false} {
			for _, avail := range []bool{true, false} {
				if got, want := c.EffectiveEnforcementUnder(gate, avail, EnforceRecordedAcceptance), c.NodeEnforcement(gate, avail); got != want {
					t.Errorf("%s gate=%v sandbox=%v: default fallback %q != NodeEnforcement %q", c.Tool, gate, avail, got, want)
				}
			}
		}
		if c.EnforcementChannel() != EnforceHookBlock {
			continue
		}
		if got := c.EffectiveEnforcementUnder(true, false, EnforceOrgDisallow); got != EnforceHookBlock {
			t.Errorf("%s: a current gate must hold whatever the fallback, got %q", c.Tool, got)
		}
		if c.channelWithoutHook() != EnforceSandbox {
			continue
		}
		if got := c.EffectiveEnforcementUnder(false, true, EnforceOrgDisallow); got != EnforceSandbox {
			t.Errorf("%s: a missing gate with a sandbox = %q, want sandbox_enforce", c.Tool, got)
		}
		want := EnforceRecordedAcceptance
		if c.Proxy != nil {
			want = EnforceOrgDisallow
			saw = true
		}
		if got := c.EffectiveEnforcementUnder(false, false, EnforceOrgDisallow); got != want {
			t.Errorf("%s: a missing gate, no sandbox, org_disallow = %q, want %q", c.Tool, got, want)
		}
	}
	if !saw {
		t.Fatal("no proxied hook_block tool exercises the org_disallow fall-through")
	}
}
