package config

import (
	"reflect"
	"testing"
)

// TestResolveProfileName pins the assignment-table walk, one case per
// tier: tool match (R2) → provider match (R1) → table default →
// package default.
func TestResolveProfileName(t *testing.T) {
	cases := []struct {
		name     string
		pc       ProfilesConfig
		provider string
		tool     string
		want     string
	}{
		{
			"provider match wins",
			ProfilesConfig{Default: "codex-safe", ByProvider: map[string]string{"anthropic": "claude-code"}},
			"anthropic", "", "claude-code",
		},
		{
			"unmatched provider falls to table default",
			ProfilesConfig{Default: "codex-variant", ByProvider: map[string]string{"anthropic": "claude-code"}},
			"openai", "", "codex-variant",
		},
		{
			"empty table falls to package default",
			ProfilesConfig{},
			"openai", "", DefaultProfileName,
		},
		{
			"empty assignment value is skipped",
			ProfilesConfig{ByProvider: map[string]string{"openai": ""}},
			"openai", "", DefaultProfileName,
		},
		{
			"baked defaults pair anthropic with claude-code",
			defaultProfiles(),
			"anthropic", "", "claude-code",
		},
		{
			"baked defaults pair openai with codex-safe",
			defaultProfiles(),
			"openai", "", "codex-safe",
		},
		{
			"tool assignment beats provider assignment (R2)",
			ProfilesConfig{
				ByProvider: map[string]string{"anthropic": "claude-code"},
				ByTool:     map[string]string{"cline": "codex-variant"},
			},
			"anthropic", "cline", "codex-variant",
		},
		{
			"unassigned tool inherits provider assignment",
			ProfilesConfig{
				ByProvider: map[string]string{"anthropic": "claude-code"},
				ByTool:     map[string]string{"cline": "codex-variant"},
			},
			"anthropic", "kilo-code-cli", "claude-code",
		},
		{
			"empty tool string skips the tool tier",
			ProfilesConfig{
				ByProvider: map[string]string{"anthropic": "claude-code"},
				ByTool:     map[string]string{"": "codex-variant"},
			},
			"anthropic", "", "claude-code",
		},
		{
			"empty tool assignment value is skipped",
			ProfilesConfig{
				ByProvider: map[string]string{"anthropic": "claude-code"},
				ByTool:     map[string]string{"cline": ""},
			},
			"anthropic", "cline", "claude-code",
		},
		{
			"baked defaults carry no tool assignments (inherit by design)",
			defaultProfiles(),
			"anthropic", "cline", "claude-code",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ResolveProfileName(c.pc, c.provider, c.tool); got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

// TestResolveCompression_DefaultIsByteIdentical is the P2.8 compat
// pin: the default profile must pass master settings through
// untouched — a no-profile-config daemon behaves exactly like today's.
func TestResolveCompression_DefaultIsByteIdentical(t *testing.T) {
	master := Default().Compression
	master.Conversation.Enabled = true
	master.Conversation.TargetRatio = 0.42 // operator-tuned value
	for _, name := range []string{"", DefaultProfileName} {
		got, err := ResolveCompression(master, name)
		if err != nil {
			t.Fatalf("ResolveCompression(%q): %v", name, err)
		}
		if !reflect.DeepEqual(got, master) {
			t.Errorf("ResolveCompression(%q) mutated master settings:\ngot  %+v\nwant %+v", name, got, master)
		}
	}
}

// TestResolveCompression_EnablementSplit pins §2.3 decision 2 (Q6):
// a profile NEVER flips the master conversation switch — in either
// direction — while its parameters apply once enabled.
func TestResolveCompression_EnablementSplit(t *testing.T) {
	for _, masterEnabled := range []bool{true, false} {
		master := Default().Compression
		master.Conversation.Enabled = masterEnabled

		got, err := ResolveCompression(master, "claude-code")
		if err != nil {
			t.Fatal(err)
		}
		if got.Conversation.Enabled != masterEnabled {
			t.Errorf("masterEnabled=%v: profile overrode the master conversation switch", masterEnabled)
		}
		// And the profile's parameters DID apply: claude-code pins
		// cache_aware mode + 0.85 ratio (recipe content of record).
		if got.Conversation.Mode != "cache_aware" {
			t.Errorf("claude-code profile mode: got %q want cache_aware", got.Conversation.Mode)
		}
		if got.Conversation.TargetRatio != 0.85 {
			t.Errorf("claude-code profile ratio: got %v want 0.85", got.Conversation.TargetRatio)
		}
	}
}

// TestResolveCompression_PerProviderPairing is the Track-R correctness
// fix in miniature: ONE master config, two providers, each resolving
// to its own tuned parameters simultaneously — the thing a daemon-wide
// --recipe could never do.
func TestResolveCompression_PerProviderPairing(t *testing.T) {
	master := Default().Compression
	master.Conversation.Enabled = true
	pc := defaultProfiles()

	anth, err := ResolveCompression(master, ResolveProfileName(pc, "anthropic", ""))
	if err != nil {
		t.Fatal(err)
	}
	oai, err := ResolveCompression(master, ResolveProfileName(pc, "openai", ""))
	if err != nil {
		t.Fatal(err)
	}
	if anth.Conversation.Mode != "cache_aware" {
		t.Errorf("anthropic mode: got %q want cache_aware", anth.Conversation.Mode)
	}
	if oai.Conversation.Mode != "token" {
		t.Errorf("openai mode: got %q want token (codex-safe)", oai.Conversation.Mode)
	}
	if oai.Conversation.PreserveLastN != 15 {
		t.Errorf("openai preserve_last_n: got %d want 15 (codex-safe)", oai.Conversation.PreserveLastN)
	}
	if !anth.Conversation.Enabled || !oai.Conversation.Enabled {
		t.Errorf("master enablement must flow to both providers")
	}
}

// TestResolveCompression_MasterParamsFallThrough pins the partial-
// merge contract: keys a profile's TOML doesn't set fall through to
// the MASTER config, not to baked defaults. Rolling-summary settings
// are the canonical case — no recipe pins them, so an operator's
// tuned rolling setup must survive profile resolution.
func TestResolveCompression_MasterParamsFallThrough(t *testing.T) {
	master := Default().Compression
	master.Conversation.Enabled = true
	master.Conversation.Rolling.Enabled = true
	master.Conversation.Rolling.SummaryModel = "claude-haiku-4-5-operator-pick"
	master.Conversation.Rolling.ThresholdTokens = 12345

	got, err := ResolveCompression(master, "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Conversation.Rolling.Enabled {
		t.Error("master rolling.enabled stripped by profile resolution")
	}
	if got.Conversation.Rolling.SummaryModel != master.Conversation.Rolling.SummaryModel {
		t.Errorf("rolling summary_model: got %q want master's %q",
			got.Conversation.Rolling.SummaryModel, master.Conversation.Rolling.SummaryModel)
	}
	if got.Conversation.Rolling.ThresholdTokens != 12345 {
		t.Errorf("rolling threshold_tokens: got %d want 12345", got.Conversation.Rolling.ThresholdTokens)
	}
	// And a recipe-pinned key still wins over a master-tuned value.
	master2 := master
	master2.Conversation.TargetRatio = 0.5
	got2, err := ResolveCompression(master2, "claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if got2.Conversation.TargetRatio != 0.85 {
		t.Errorf("profile-pinned target_ratio: got %v want 0.85 (recipe wins over master)", got2.Conversation.TargetRatio)
	}
}

// TestResolveCompression_ExplicitZerosApply pins that a profile's
// EXPLICIT zero values overlay master non-zeros: codex-variant
// deliberately sets logs max_lines=0 (no truncation) and
// compress_types=[] (no per-type compression). A merge that treated
// zero as "unset" would silently re-enable compression the recipe
// turned off.
func TestResolveCompression_ExplicitZerosApply(t *testing.T) {
	master := Default().Compression
	master.Conversation.Enabled = true
	master.Conversation.CompressTypes = []string{"json", "logs", "code"}
	master.Conversation.Logs.MaxLines = 200

	got, err := ResolveCompression(master, "codex-variant")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Conversation.CompressTypes) != 0 {
		t.Errorf("compress_types: got %v want [] (codex-variant pins empty)", got.Conversation.CompressTypes)
	}
	if got.Conversation.Logs.MaxLines != 0 {
		t.Errorf("logs max_lines: got %d want 0 (codex-variant pins zero)", got.Conversation.Logs.MaxLines)
	}
}

// TestLoadProfile_UnknownName errors with the available set rather
// than silently falling back — a typo in an assignment must be loud.
func TestLoadProfile_UnknownName(t *testing.T) {
	if _, _, err := LoadProfile("no-such-profile"); err == nil {
		t.Fatal("want error for unknown profile")
	}
}

// TestProfileNames lists default + every embedded recipe.
func TestProfileNames(t *testing.T) {
	names := ProfileNames()
	want := map[string]bool{DefaultProfileName: true, "claude-code": true, "codex-safe": true, "codex-variant": true}
	for _, n := range names {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Errorf("ProfileNames() missing %v (got %v)", want, names)
	}
}
