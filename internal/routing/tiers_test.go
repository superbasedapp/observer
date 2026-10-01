package routing

import "testing"

// TestTierTable_NormalizationOrder pins the lookup ladder reused from the
// cost engine: exact → :free guard → date-strip → family prefix →
// last-resort provider-prefix strip → miss. One row per ladder step.
func TestTierTable_NormalizationOrder(t *testing.T) {
	t.Parallel()
	r := NewTierResolver()
	cases := []struct {
		name       string
		model      string
		wantTier   Tier
		wantSource TierSource
	}{
		{"exact_match", "claude-opus-4-8", TierOpusClass, TierSourceExact},
		// :free guard fires BEFORE the family ladder: the claude-sonnet
		// family says sonnet-class, but the free SKU is free tier.
		{"free_guard_beats_family", "claude-sonnet-4-6:free", TierFree, TierSourceExact},
		{"free_guard_case_insensitive", "nemotron-3-super-120b-a12b:FREE", TierFree, TierSourceExact},
		// Date-strip lands on the exact "claude-opus-4-1" entry before the
		// shorter "claude-opus-4" family prefix could claim it.
		{"date_strip", "claude-opus-4-1-20250805", TierOpusClass, TierSourceDateStripped},
		{"family_prefix", "claude-sonnet-4-9", TierSonnetClass, TierSourceFamily},
		{"family_longest_wins", "gemini-3-flash-experimental", TierHaikuClass, TierSourceFamily},
		{"provider_prefix_strip", "anthropic/claude-sonnet-4-6", TierSonnetClass, TierSourceFamily},
		{"openrouter_path_strip", "openrouter/openai/gpt-oss-120b", TierHaikuClass, TierSourceFamily},
		{"capi_router_strip", "capi:claude-haiku-4-5", TierHaikuClass, TierSourceFamily},
		{"miss_unclassified", "totally-novel-model-x", TierUnclassified, TierSourceMiss},
		{"empty_model", "", TierUnclassified, TierSourceMiss},
		// Auto-router sentinels stay unplaced: we audit routers (§R17.4),
		// we don't pretend to know what they serve.
		{"auto_sentinel_unplaced", "auto", TierUnclassified, TierSourceMiss},
		{"cursor_default_unplaced", "default", TierUnclassified, TierSourceMiss},
		{"kilo_auto_family_unplaced", "kilo-auto/large", TierUnclassified, TierSourceMiss},
		{"kilo_auto_free_exact", "kilo-auto/free", TierFree, TierSourceExact},
		{"local_family", "ollama/gemma4:e4b", TierLocal, TierSourceFamily},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tier, src := r.Lookup(tc.model)
			if tier != tc.wantTier || src != tc.wantSource {
				t.Errorf("Lookup(%q) = (%s, %s), want (%s, %s)",
					tc.model, tier, src, tc.wantTier, tc.wantSource)
			}
		})
	}
}

// TestTierTable_OverridesWinOverSeed pins the override semantics: a user
// entry replaces the seed placement wholesale.
func TestTierTable_OverridesWinOverSeed(t *testing.T) {
	t.Parallel()
	r := NewTierResolver()
	r.Reload(map[string]Tier{
		"claude-opus-4-8": TierSonnetClass, // demote
		"my-finetune-v2":  TierSonnetClass, // novel model placed
	})
	if tier, src := r.Lookup("claude-opus-4-8"); tier != TierSonnetClass || src != TierSourceExact {
		t.Errorf("override lookup = (%s, %s), want (sonnet-class, exact)", tier, src)
	}
	if tier, _ := r.Lookup("my-finetune-v2"); tier != TierSonnetClass {
		t.Errorf("novel override = %s, want sonnet-class", tier)
	}
}

// TestTierResolver_HotReloadSnapshot pins the atomic.Pointer contract: a
// table snapshot taken before Reload keeps answering with the old data
// while fresh lookups see the new table — never a torn state.
func TestTierResolver_HotReloadSnapshot(t *testing.T) {
	t.Parallel()
	r := NewTierResolver()
	old := r.Table()
	r.Reload(map[string]Tier{"claude-opus-4-8": TierHaikuClass})
	if tier, _ := old.Lookup("claude-opus-4-8"); tier != TierOpusClass {
		t.Errorf("old snapshot mutated: got %s, want opus-class", tier)
	}
	if tier, _ := r.Lookup("claude-opus-4-8"); tier != TierHaikuClass {
		t.Errorf("fresh lookup = %s, want haiku-class", tier)
	}
}

// TestTierTable_SeedSelfConsistent sweeps the shipped seed: every
// placement is a known tier, and no seed key accidentally resolves to a
// different tier than its own entry (a longer family key shadowing an
// exact entry would be a seed-authoring bug).
func TestTierTable_SeedSelfConsistent(t *testing.T) {
	t.Parallel()
	r := NewTierResolver()
	for model, want := range seedTiers {
		if !want.Known() {
			t.Errorf("seed %q places into unknown tier %q", model, want)
		}
		if got, src := r.Lookup(model); got != want || src != TierSourceExact {
			t.Errorf("seed %q resolves (%s, %s), want (%s, exact)", model, got, src, want)
		}
	}
}

// TestTierTable_RepresentativesSelfConsistent sweeps the curated
// downshift targets: each representative resolves to its own cell's tier,
// carries the cell's shape, and is itself placeable (never unclassified).
func TestTierTable_RepresentativesSelfConsistent(t *testing.T) {
	t.Parallel()
	r := NewTierResolver()
	tbl := r.Table()
	for shape, byTier := range seedRepresentatives {
		for tier, model := range byTier {
			gotTier, _ := tbl.Lookup(model)
			if gotTier != tier {
				t.Errorf("representative %q for (%s,%s) resolves to tier %s", model, shape, tier, gotTier)
			}
			if gotShape := ShapeForModel(model); gotShape != shape {
				t.Errorf("representative %q for (%s,%s) resolves to shape %q", model, shape, tier, gotShape)
			}
		}
	}
}

// TestTierTable_Representative covers the lookup both ways.
func TestTierTable_Representative(t *testing.T) {
	t.Parallel()
	tbl := NewTierResolver().Table()
	cases := []struct {
		name      string
		shape     ProviderShape
		tier      Tier
		wantModel string
		wantOK    bool
	}{
		{"anthropic_haiku", ShapeAnthropic, TierHaikuClass, "claude-haiku-4-5", true},
		{"openai_sonnet", ShapeOpenAI, TierSonnetClass, "gpt-5.4", true},
		{"google_opus", ShapeGoogle, TierOpusClass, "gemini-3.1-pro-preview", true},
		{"no_unclassified_target", ShapeAnthropic, TierUnclassified, "", false},
		{"no_local_target", ShapeAnthropic, TierLocal, "", false},
		{"unknown_shape", ShapeUnknown, TierHaikuClass, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, ok := tbl.Representative(tc.shape, tc.tier)
			if m != tc.wantModel || ok != tc.wantOK {
				t.Errorf("Representative(%s,%s) = (%q,%v), want (%q,%v)",
					tc.shape, tc.tier, m, ok, tc.wantModel, tc.wantOK)
			}
		})
	}
}

// TestTierTable_OpusFivePlacement pins the 2026-07-25 Claude Opus 5
// registration. Two distinct claims:
//
//  1. claude-opus-5 places Opus-class by an EXACT seed entry, not by the
//     bare "claude-opus" family prefix. The prefix already covered it, so
//     this asserts the explicit flagship pin exists as authored.
//  2. The Anthropic Opus-class downshift representative is claude-opus-5.
//     This is the live-behaviour cell (what enforce mode rewrites to);
//     pricing parity with claude-opus-4-8 is what makes it cost-neutral.
//
// The remaining rows are the regression guard: registering a new flagship
// must not disturb any neighbouring Anthropic placement.
func TestTierTable_OpusFivePlacement(t *testing.T) {
	t.Parallel()
	tbl := NewTierResolver().Table()

	if tier, src := tbl.Lookup("claude-opus-5"); tier != TierOpusClass || src != TierSourceExact {
		t.Errorf("Lookup(claude-opus-5) = (%s,%s), want (opus-class, exact)", tier, src)
	}
	if got := ShapeForModel("claude-opus-5"); got != ShapeAnthropic {
		t.Errorf("ShapeForModel(claude-opus-5) = %q, want %q", got, ShapeAnthropic)
	}
	if m, ok := tbl.Representative(ShapeAnthropic, TierOpusClass); !ok || m != "claude-opus-5" {
		t.Errorf("Representative(anthropic, opus-class) = (%q,%v), want (claude-opus-5, true)", m, ok)
	}

	// Unchanged neighbours — the swap is additive, not invasive.
	for _, tc := range []struct {
		model string
		want  Tier
	}{
		{"claude-opus-4-8", TierOpusClass},
		{"claude-opus-4-1", TierOpusClass},
		{"claude-fable-5", TierOpusClass},
		{"claude-fable-5-1", TierOpusClass}, // 2026-09-01 Fable flagship — explicit seed pin

		{"claude-sonnet-4-6", TierSonnetClass},
		{"claude-haiku-4-5", TierHaikuClass},
	} {
		if got, src := tbl.Lookup(tc.model); got != tc.want || src != TierSourceExact {
			t.Errorf("Lookup(%q) = (%s,%s), want (%s, exact)", tc.model, got, src, tc.want)
		}
	}
}

// TestTierTable_MythosAndMinistralSeeds pins two 2026-09-07 seed additions
// that a missing row would silently strand at TierUnclassified:
//
//   - claude-mythos-5-1 has no bare "claude-mythos" (or "claude-mythos-5")
//     family row in this seed table, so it needs its own explicit entry —
//     same tier as its Fable 5.1 twin (identical rate card in pricing.go).
//   - ministral-3b/8b/14b cannot inherit the bare "mistral" family row:
//     "mistral" is not a string prefix of "ministral-*" (the leading "mi"
//     breaks the match), so each needs its own entry too.
func TestTierTable_MythosAndMinistralSeeds(t *testing.T) {
	t.Parallel()
	r := NewTierResolver()
	for _, tc := range []struct {
		model string
		want  Tier
	}{
		{"claude-mythos-5-1", TierOpusClass},
		{"ministral-3b", TierHaikuClass},
		{"ministral-8b", TierHaikuClass},
		{"ministral-14b", TierHaikuClass},
	} {
		t.Run(tc.model, func(t *testing.T) {
			t.Parallel()
			if tier, src := r.Lookup(tc.model); tier != tc.want || src != TierSourceExact {
				t.Errorf("Lookup(%q) = (%s,%s), want (%s, exact)", tc.model, tier, src, tc.want)
			}
		})
	}
}

// TestShapeForModel covers the prefix resolution table — one row per
// table entry plus the conservative-unknown cases.
func TestShapeForModel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		model string
		want  ProviderShape
	}{
		{"claude-sonnet-4-6", ShapeAnthropic},
		{"gpt-5.4-mini", ShapeOpenAI},
		{"o1-pro", ShapeOpenAI},
		{"o3-mini", ShapeOpenAI},
		{"o4-mini", ShapeOpenAI},
		{"davinci-002", ShapeOpenAI},
		{"babbage-002", ShapeOpenAI},
		{"gemini-3.5-flash", ShapeGoogle},
		{"anthropic/claude-haiku-4-5", ShapeAnthropic},
		{"openrouter/openai/gpt-5.4", ShapeOpenAI},
		{"CLAUDE-OPUS-4-8", ShapeAnthropic}, // case-insensitive
		{"grok-4.3", ShapeUnknown},          // OpenAI-compatible served, but we don't claim it
		// §R11.7 (P1): local-host prefixes resolve to the OpenAI shape
		// — every local inference server we route to speaks it.
		{"ollama/gemma4:e4b", ShapeOpenAI},
		{"", ShapeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.model, func(t *testing.T) {
			t.Parallel()
			if got := ShapeForModel(tc.model); got != tc.want {
				t.Errorf("ShapeForModel(%q) = %q, want %q", tc.model, got, tc.want)
			}
		})
	}
}

// TestTierTable_Known smoke-checks the debug surface: sorted, non-empty,
// includes a seed key.
func TestTierTable_Known(t *testing.T) {
	t.Parallel()
	keys := NewTierResolver().Table().Known()
	if len(keys) == 0 {
		t.Fatal("Known() empty")
	}
	found := false
	for i, k := range keys {
		if k == "claude-opus-4-8" {
			found = true
		}
		if i > 0 && keys[i-1] > k {
			t.Fatalf("Known() not sorted at %d: %q > %q", i, keys[i-1], k)
		}
	}
	if !found {
		t.Error("Known() missing seed key claude-opus-4-8")
	}
}

// TestTierTable_NilSafety pins nil-receiver behavior — a nil table or
// resolver degrades to unclassified/empty, never panics (G7: routing must
// not add failure modes).
func TestTierTable_NilSafety(t *testing.T) {
	t.Parallel()
	var tbl *TierTable
	if tier, src := tbl.Lookup("claude-opus-4-8"); tier != TierUnclassified || src != TierSourceMiss {
		t.Errorf("nil table Lookup = (%s,%s), want (unclassified,miss)", tier, src)
	}
	if _, ok := tbl.Representative(ShapeAnthropic, TierHaikuClass); ok {
		t.Error("nil table Representative ok=true")
	}
	if got := tbl.Known(); got != nil {
		t.Errorf("nil table Known = %v, want nil", got)
	}
	var r *TierResolver
	if r.Table() != nil {
		t.Error("nil resolver Table != nil")
	}
}

// TestTierTable_OrgObserverUnpricedIDs2026Q3 pins the tier placement for the
// Cursor-Grok and Codex-auto-review ids added alongside the cost-registry fix
// (F-MODELS3, org-observer UI review 2026-09-02). The -high effort variant
// must resolve via the cursor-grok family; the base ids exactly.
func TestTierTable_OrgObserverUnpricedIDs2026Q3(t *testing.T) {
	t.Parallel()
	r := NewTierResolver()
	cases := []struct {
		model string
		want  Tier
	}{
		{"cursor-grok", TierSonnetClass},
		{"cursor-grok-4.5-high", TierSonnetClass},
		{"cursor-grok-4.6-high", TierSonnetClass},
		{"codex-auto-review", TierSonnetClass},
	}
	for _, tc := range cases {
		got, src := r.Lookup(tc.model)
		if got != tc.want {
			t.Errorf("Lookup(%q) = %s (%s); want %s", tc.model, got, src, tc.want)
		}
		if got == TierUnclassified {
			t.Errorf("Lookup(%q) unclassified; want %s", tc.model, tc.want)
		}
	}
}

// TestTierTable_AdapterSweep20260927 pins the placements added for the
// 2026-09-27 adapter sweep. Each row is a model that the family ladder used to
// place WRONG (a Flash-Lite as Opus-class through "gemini-3.1", a Flash as
// Sonnet-class through "glm") or not at all (MiMo), so the assertion is on
// the resolved tier for the ids an adapter actually emits, not just the seed
// key.
func TestTierTable_AdapterSweep20260927(t *testing.T) {
	t.Parallel()
	r := NewTierResolver()
	for _, tc := range []struct {
		model string
		want  Tier
	}{
		{"gemini-3.1-flash-lite", TierHaikuClass},
		{"gemini-3.1-flash-lite-preview", TierHaikuClass},
		{"gemini-3.1-pro-preview", TierOpusClass}, // the family the Flash-Lite used to fall into, unchanged
		{"gemini-3.5-flash-lite", TierHaikuClass},
		{"glm-5.3-flash", TierHaikuClass},
		{"glm-5.3", TierSonnetClass},
		{"mimo-v2.6-flash", TierHaikuClass},
		{"mimo-v2.6-pro", TierSonnetClass},
		{"xiaomi/mimo-v2.6-flash", TierHaikuClass},
	} {
		if got, _ := r.Lookup(tc.model); got != tc.want {
			t.Errorf("Lookup(%q) = %s, want %s", tc.model, got, tc.want)
		}
	}
}

// TestTierTable_SonnetFiveFiveFamilyFallback pins how Claude Sonnet 5.5
// (claude-sonnet-5-5, launched 2026-09-28) resolves. There is deliberately
// NO explicit tier seed row: the bare "claude-sonnet" family prefix places
// the id in the Sonnet class, the Anthropic shape resolves from the "claude" prefix, and
// the Sonnet-class representative (which also seeds cross-family handoffs,
// cmd/observer/handoff_target.go) is unchanged.
func TestTierTable_SonnetFiveFiveFamilyFallback(t *testing.T) {
	t.Parallel()
	tbl := NewTierResolver().Table()
	for _, model := range []string{"claude-sonnet-5-5", "anthropic/claude-sonnet-5-5", "claude-sonnet-5"} {
		if tier, src := tbl.Lookup(model); tier != TierSonnetClass || src != TierSourceFamily {
			t.Errorf("Lookup(%q) = (%s,%s), want (sonnet-class, family)", model, tier, src)
		}
		if got := ShapeForModel(model); got != ShapeAnthropic {
			t.Errorf("ShapeForModel(%q) = %q, want %q", model, got, ShapeAnthropic)
		}
	}
	if m, ok := tbl.Representative(ShapeAnthropic, TierSonnetClass); !ok || m != "claude-sonnet-4-6" {
		t.Errorf("Representative(anthropic, sonnet-class) = (%q,%v), want (claude-sonnet-4-6, true) - unchanged", m, ok)
	}
	// Context windows are NOT a routing-package fact: they come from the
	// Tokenomics window table through Snapshot.ContextWindow (see
	// TestCapabilityBasis_ContextWindowFit).
}
