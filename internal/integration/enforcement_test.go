package integration

import "testing"

// wantEnforcementChannel pins every EnabledAdapters row (Capabilities(), 42
// rows — roo-code is the documented rowless exception, see
// registryRowlessTaxonomyTools) into exactly one EnforcementChannel bucket.
// Derived 2026-08-30 from the grounded ladder in (Capability).
// EnforcementChannel(): a wired blocking-capable hook wins, else a
// launchable tool, else a proxy-routed tool, else recorded_acceptance. This
// map is a GOLDEN PIN, not the classification logic itself — the logic is
// computed (capability.go), so this test exists to catch a silent
// reclassification when a future edit changes a row's Hook/Handoff/Proxy
// shape, not to duplicate the ladder.
var wantEnforcementChannel = map[string]EnforcementChannel{
	// hook_block (2): a wired hook mechanism verified to support a genuine
	// deny reply that aborts the action before it runs.
	"claude-code": EnforceHookBlock,
	"cursor":      EnforceHookBlock,

	// sandbox_enforce (25): no blocking hook, but launchable via
	// `observer <x>` — a guard-enforce policy can require the bwrap sandbox.
	"codex":            EnforceSandbox,
	"opencode":         EnforceSandbox,
	"copilot-cli":      EnforceSandbox,
	"kilo-code-cli":    EnforceSandbox,
	"cline-cli":        EnforceSandbox,
	"hermes":           EnforceSandbox,
	"gemini-cli":       EnforceSandbox,
	"openclaw":         EnforceSandbox,
	"pi":               EnforceSandbox,
	"antigravity-cli":  EnforceSandbox,
	"qwen-code":        EnforceSandbox,
	"kiro-cli":         EnforceSandbox,
	"grok":             EnforceSandbox,
	"kimi-code":        EnforceSandbox,
	"devin":            EnforceSandbox,
	"qoder":            EnforceSandbox,
	"goose":            EnforceSandbox,
	"droid":            EnforceSandbox,
	"open-interpreter": EnforceSandbox,
	"command-code":     EnforceSandbox,
	"muse":             EnforceSandbox,
	"prime-agent":      EnforceSandbox,
	"zcode":            EnforceSandbox,
	"mistral-code":     EnforceSandbox,
	"freebuff":         EnforceSandbox,

	// org_disallow (2): neither a blocking hook nor a launcher, but observer
	// drives a proxy route — refusing to route is the only lever.
	"crush": EnforceOrgDisallow,
	"aider": EnforceOrgDisallow,

	// recorded_acceptance (16): no grounded lever at all — no blocking hook,
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
	// no launcher and no proxy route; poolside's poolside_settings_yaml hook
	// mechanism is wired but is NOT in blockingHookMechanisms (no grounded
	// deny-reply verification yet), so all three derive recorded_acceptance.
	"kiro-crew":      EnforceRecordedAcceptance,
	"poolside":       EnforceRecordedAcceptance,
	"zed":            EnforceRecordedAcceptance,
	"chatgpt-web":    EnforceRecordedAcceptance,
	"claude-web":     EnforceRecordedAcceptance,
	"perplexity-web": EnforceRecordedAcceptance,
	"gemini-web":     EnforceRecordedAcceptance,
	"copilot-web":    EnforceRecordedAcceptance,
	"junie":          EnforceRecordedAcceptance,
	"grokbot":        EnforceRecordedAcceptance,
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
		case blockingHookMechanisms[c.Hook.Mechanism]:
			if got != EnforceHookBlock {
				t.Errorf("%s: has a blocking-capable hook (%q) but EnforcementChannel() = %q, want %q",
					c.Tool, c.Hook.Mechanism, got, EnforceHookBlock)
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
