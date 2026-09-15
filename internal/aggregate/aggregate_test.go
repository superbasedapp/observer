package aggregate

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// TestFamilyClosedVocabTotal asserts Family is total over the closed set: every
// representative id maps to the expected family, and every input — including
// exotic/long-tail strings — returns a member of Families, never a raw string.
func TestFamilyClosedVocabTotal(t *testing.T) {
	t.Parallel()

	inSet := map[string]bool{}
	for _, f := range Families {
		inSet[f] = true
	}

	cases := []struct {
		model string
		want  string
	}{
		{"claude-opus-4-8", FamilyClaudeOpus},
		{"claude-3-opus-20240229", FamilyClaudeOpus},
		{"claude-fable-5", FamilyClaudeOpus},
		{"claude-fable-5-1", FamilyClaudeOpus}, // 2026-09-01 Fable flagship — "fable" substring covers it
		{"claude-sonnet-5", FamilyClaudeSonnet},
		{"claude-3-5-sonnet-20241022", FamilyClaudeSonnet},
		{"stealth/claude-sonnet-4.6", FamilyClaudeSonnet},
		{"claude-haiku-4-5", FamilyClaudeHaiku},
		{"claude-3-5-haiku", FamilyClaudeHaiku},
		{"gpt-5", FamilyGPT5},
		{"gpt-5.4", FamilyGPT5},
		{"gpt-5-codex", FamilyGPT5},
		{"gpt-5.3-codex-spark", FamilyGPT5},
		{"gpt-5-mini", FamilyGPT5Mini},
		{"gpt-5.4-nano", FamilyGPT5Mini},
		{"gpt-5.1-codex-mini", FamilyGPT5Mini},
		{"gemini-3.1-pro-preview", FamilyGeminiPro},
		{"gemini-2.5-pro", FamilyGeminiPro},
		{"gemini-3.5-flash", FamilyGeminiFlash},
		{"gemini-2.5-flash-lite", FamilyGeminiFlash},
		{"grok-4.5", FamilyGrok},
		{"x-ai/grok-4.3", FamilyGrok},
		{"openai/gpt-oss-120b", FamilyOpenWeight},
		{"nvidia/nemotron-3-super-120b-a12b", FamilyOpenWeight},
		{"nousresearch/hermes-4-405b", FamilyOpenWeight},
		{"qwen3-coder", FamilyOpenWeight},
		{"z-ai/glm-5.1", FamilyOpenWeight},
		{"mistral-large", FamilyOpenWeight},
		{"minimax-m2.7", FamilyOpenWeight},
		{"moonshotai/kimi-k2.6", FamilyOpenWeight},
		{"deepseek-v4-flash", FamilyOpenWeight},
		{"ollama", FamilyOpenWeight},
		// Everything the closed set does not name → "other".
		{"gpt-4o", FamilyOther},
		{"gpt-4.1-mini", FamilyOther},
		{"o3-pro", FamilyOther},
		{"composer-2.5", FamilyOther},
		{"kilo-auto/small", FamilyOther},
		{"gemini-2", FamilyOther},
		{"", FamilyOther},
		{"<unknown>", FamilyOther},
		{"totally-made-up-model-zzz-9000", FamilyOther},
	}
	for _, tc := range cases {
		got := Family(tc.model)
		if got != tc.want {
			t.Errorf("Family(%q) = %q, want %q", tc.model, got, tc.want)
		}
		if !inSet[got] {
			t.Errorf("Family(%q) = %q which is NOT in the closed Families set", tc.model, got)
		}
	}
}

// TestFamilyMapVersionStable guards the mapping version against silent drift —
// a change to Family rules must be a conscious version bump (design §3.3).
func TestFamilyMapVersionStable(t *testing.T) {
	t.Parallel()
	if FamilyMapVersion != "1" {
		t.Fatalf("FamilyMapVersion changed to %q — bump intentionally and update this pin (mapping changes break longitudinal comparability)", FamilyMapVersion)
	}
}

// TestCoarsenVersion pins the minor-only coarsening.
func TestCoarsenVersion(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"1.20.3":      "1.20",
		"v1.20.3":     "1.20",
		"1.20.3-rc.1": "1.20",
		"1.20":        "1.20",
		"2.0.0+build": "2.0",
		"dev":         "dev",
		"":            "",
	}
	for in, want := range cases {
		if got := CoarsenVersion(in); got != want {
			t.Errorf("CoarsenVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMonthHelpers checks the finalized-month + window math.
func TestMonthHelpers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 12, 9, 0, 0, 0, time.UTC)
	if got := FinalizedMonth(now); got != "2026-06" {
		t.Fatalf("FinalizedMonth = %q, want 2026-06", got)
	}
	// January edge: previous month is prior-year December.
	if got := FinalizedMonth(time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)); got != "2025-12" {
		t.Fatalf("FinalizedMonth(Jan) = %q, want 2025-12", got)
	}
	start, end, err := MonthWindowUTC("2026-06")
	if err != nil {
		t.Fatalf("MonthWindowUTC: %v", err)
	}
	if !start.Equal(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)) || !end.Equal(time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("window = [%s, %s)", start, end)
	}
	if !IsFinalizedMonth("2026-06", now) {
		t.Error("2026-06 should be finalized as of 2026-07-12")
	}
	if IsFinalizedMonth("2026-07", now) {
		t.Error("2026-07 (current partial month) must NOT be finalized")
	}
}

// TestCostMethodVersionFoldsFamily checks the Open Q12 fold.
func TestCostMethodVersionFoldsFamily(t *testing.T) {
	t.Parallel()
	want := "1+fam" + FamilyMapVersion
	if got := CostMethodVersion(); got != want {
		t.Fatalf("CostMethodVersion() = %q, want %q", got, want)
	}
}

// TestBuildProvenanceSplit verifies the _acc/_est twins and that the envelope
// version fields come from constants + the registry.
func TestBuildProvenanceSplit(t *testing.T) {
	t.Parallel()
	stats := []ModelToolStat{
		// Same (family, tool) via two model ids that both map to claude-opus:
		// one accurate, one estimated. Volumes well above the coarsening floor.
		{Model: "claude-opus-4-8", Tool: "claude-code", Accurate: true, Turns: 100, InputTokens: 5000, OutputTokens: 2000, CacheReadTokens: 40000, CostUSD: 12.34, CacheObservable: true, FastObservable: true},
		{Model: "claude-opus-4-7", Tool: "claude-code", Accurate: false, Turns: 40, InputTokens: 1000, OutputTokens: 500, CostUSD: 3.00, CacheObservable: true},
	}
	sub := Build(Meta{ObserverVersion: "1.20", SubmissionID: "fixed-id", Month: "2026-06"}, stats)

	if sub.SchemaVersion != SchemaVersion || sub.PricingVersion != PricingVersion ||
		sub.CostMethodVersion != CostMethodVersion() || sub.ToolRegistryVersion != integration.RegistryVersion {
		t.Fatalf("envelope version fields wrong: %+v", sub)
	}
	if sub.Month != "2026-06" || sub.SubmissionID != "fixed-id" || sub.ObserverVersion != "1.20" {
		t.Fatalf("envelope meta wrong: %+v", sub)
	}
	if len(sub.Cells) != 1 {
		t.Fatalf("want 1 merged cell, got %d: %+v", len(sub.Cells), sub.Cells)
	}
	c := sub.Cells[0]
	if c.ModelFamily != FamilyClaudeOpus || c.Tool != "claude-code" {
		t.Fatalf("cell key = (%q,%q)", c.ModelFamily, c.Tool)
	}
	if c.TurnsAcc != 100 || c.TurnsEst != 40 {
		t.Errorf("turns acc/est = %d/%d, want 100/40", c.TurnsAcc, c.TurnsEst)
	}
	if c.InputTokensAcc != 5000 || c.InputTokensEst != 1000 {
		t.Errorf("input acc/est = %d/%d", c.InputTokensAcc, c.InputTokensEst)
	}
	if c.CacheReadTokensAcc != 40000 || c.CacheReadTokensEst != 0 {
		t.Errorf("cache_read acc/est = %d/%d", c.CacheReadTokensAcc, c.CacheReadTokensEst)
	}
	if c.CostUSDAcc != 12.34 || c.CostUSDEst != 3.00 {
		t.Errorf("cost acc/est = %v/%v", c.CostUSDAcc, c.CostUSDEst)
	}
	if !c.CacheObservable || !c.FastObservable {
		t.Errorf("observability should OR to true: %+v", c)
	}
}

// TestBuildRareCellCoarsening verifies a sparse family collapses to "other"
// while a busy family survives, and that exotic model ids never leak.
func TestBuildRareCellCoarsening(t *testing.T) {
	t.Parallel()
	stats := []ModelToolStat{
		// Busy gpt-5 cell — above the floor, must survive as its own family.
		{Model: "gpt-5", Tool: "codex", Accurate: true, Turns: 200, CostUSD: 9.00},
		// Sparse grok cell — below both floors, collapses to ("other","codex").
		{Model: "grok-4.5", Tool: "codex", Accurate: true, Turns: 2, CostUSD: 0.01},
		// Exotic unknown model, sparse — family is already "other".
		{Model: "megacorp-secret-model-x", Tool: "codex", Accurate: false, Turns: 1, CostUSD: 0.02},
	}
	sub := Build(Meta{Month: "2026-06"}, stats)

	byKey := map[string]Cell{}
	for _, c := range sub.Cells {
		byKey[c.ModelFamily+"|"+c.Tool] = c
	}
	if _, ok := byKey["gpt-5|codex"]; !ok {
		t.Fatalf("busy gpt-5 cell should survive; cells=%+v", sub.Cells)
	}
	if _, ok := byKey["grok|codex"]; ok {
		t.Fatalf("sparse grok cell should have collapsed to other; cells=%+v", sub.Cells)
	}
	other, ok := byKey["other|codex"]
	if !ok {
		t.Fatalf("expected merged (other,codex) cell; cells=%+v", sub.Cells)
	}
	// grok(2t) + exotic(1t) merged into other.
	if other.TurnsAcc != 2 || other.TurnsEst != 1 {
		t.Errorf("other cell turns acc/est = %d/%d, want 2/1", other.TurnsAcc, other.TurnsEst)
	}
}

// TestBuildUnknownToolCollapses checks tool vocabulary closure.
func TestBuildUnknownToolCollapses(t *testing.T) {
	t.Parallel()
	sub := Build(Meta{Month: "2026-06"}, []ModelToolStat{
		{Model: "gpt-5", Tool: "some-unregistered-tool", Accurate: true, Turns: 100, CostUSD: 5},
		{Model: "gpt-5", Tool: "<no-tool>", Accurate: true, Turns: 100, CostUSD: 5},
	})
	for _, c := range sub.Cells {
		if c.Tool != FamilyOther {
			t.Errorf("unknown tool did not collapse: %q", c.Tool)
		}
	}
}
