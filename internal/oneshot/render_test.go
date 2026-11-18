package oneshot

import (
	"strings"
	"testing"
)

// baseTable returns a 5-row, 3-model table shaped like the plan §1.4 mock
// (aider's row is deliberately Reliability:"approximate" to exercise the
// "~" marker; codex's CacheCreation is deliberately 0 to exercise the
// em-dash cache cell).
func baseTable() Table {
	rows := []Row{
		{Tool: "claude-code", Model: "claude-opus-4-8", Input: 1_200_000, Output: 310_000, CacheRead: 18_400_000, CacheCreation: 2_100_000, Turns: 1284, USD: 412.88, Reliability: "accurate"},
		{Tool: "claude-code", Model: "claude-sonnet-5", Input: 480_100, Output: 96_000, CacheRead: 5_200_000, CacheCreation: 640_000, Turns: 402, USD: 38.14, Reliability: "accurate"},
		{Tool: "codex", Model: "gpt-5.6", Input: 210_400, Output: 88_200, CacheRead: 9_900_000, CacheCreation: 0, Turns: 311, USD: 61.02, Reliability: "accurate"},
		{Tool: "cursor", Model: "claude-sonnet-5", Input: 90_200, Output: 22_100, CacheRead: 0, CacheCreation: 0, Turns: 88, USD: 6.41, Reliability: "accurate"},
		{Tool: "aider", Model: "claude-sonnet-5", Input: 8_100, Output: 2_000, CacheRead: 0, CacheCreation: 0, Turns: 12, USD: 0.51, Reliability: "approximate"},
	}
	return Table{
		WindowLabel:        "last 30 days",
		Rows:               rows,
		ToolCount:          5,
		ModelCount:         3,
		TotalInput:         1_988_800,
		TotalOutput:        518_300,
		TotalCacheRead:     33_500_000,
		TotalCacheCreation: 2_740_000,
		TotalTurns:         2097,
		TotalUSD:           518.96,
		Reliability:        "approximate",
	}
}

func TestRenderMultiRowStructure(t *testing.T) {
	out := Render(baseTable(), RenderOptions{})
	lines := strings.Split(out, "\n")

	if !strings.HasPrefix(lines[0], "superbased - observed agent spend, last 30 days") {
		t.Errorf("title line = %q", lines[0])
	}
	if !strings.Contains(lines[0], "one-shot · no daemon") {
		t.Errorf("title line missing right-hand marker: %q", lines[0])
	}
	if lines[1] != "" {
		t.Errorf("expected a blank line after the title, got %q", lines[1])
	}

	header := lines[2]
	for _, want := range tableHeaders {
		if !strings.Contains(header, want) {
			t.Errorf("column header %q missing %q in %q", want, want, header)
		}
	}
	// Column order.
	idxTool := strings.Index(header, "TOOL")
	idxModel := strings.Index(header, "MODEL")
	idxUSD := strings.Index(header, "USD")
	if !(idxTool < idxModel && idxModel < idxUSD) {
		t.Errorf("column header out of order: %q", header)
	}

	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		"claude-code", "claude-opus-4-8", "1.20M", "310.0k", "18.40M", "2.10M", "1,284", "$412.88",
		"codex", "gpt-5.6",
		"cursor",
		"aider ~", // approximate row earns the marker
		"TOTAL", "5 tools · 3 models", "2,097", "$518.96",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("output missing expected substring %q\n---\n%s", want, joined)
		}
	}

	// claude-code's accurate rows must never carry the marker.
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "claude-code") && strings.Contains(l, "~") {
			t.Errorf("accurate claude-code row unexpectedly marked approximate: %q", l)
		}
	}
}

func TestRenderEmDashForZeroCache(t *testing.T) {
	out := Render(baseTable(), RenderOptions{})
	lines := strings.Split(out, "\n")

	var cursorLine, codexLine string
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "cursor") {
			cursorLine = l
		}
		if strings.HasPrefix(trimmed, "codex") {
			codexLine = l
		}
	}
	if cursorLine == "" || codexLine == "" {
		t.Fatalf("could not locate cursor/codex rows in output:\n%s", out)
	}
	if strings.Count(cursorLine, "—") != 2 {
		t.Errorf("cursor row (zero CACHE_R and CACHE_W) should show 2 em-dashes: %q", cursorLine)
	}
	if strings.Count(codexLine, "—") != 1 {
		t.Errorf("codex row (zero CACHE_W only) should show 1 em-dash: %q", codexLine)
	}
}

func TestRenderSingleRow(t *testing.T) {
	tbl := Table{
		WindowLabel: "last 7 days",
		Rows: []Row{
			{Tool: "claude-code", Model: "claude-opus-4-8", Input: 100, Output: 50, Turns: 3, USD: 1.23, Reliability: "accurate"},
		},
		ToolCount:   1,
		ModelCount:  1,
		TotalInput:  100,
		TotalOutput: 50,
		TotalTurns:  3,
		TotalUSD:    1.23,
		Reliability: "accurate",
	}
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "1 tool · 1 model") {
		t.Errorf("singular tool/model summary missing:\n%s", out)
	}
	if strings.Count(out, "\n") == 0 {
		t.Fatalf("expected multi-line output, got %q", out)
	}
}

func TestRenderEmptyCorpus(t *testing.T) {
	tbl := Table{
		WindowLabel: "last 30 days",
		Notes: []Note{
			{Code: "empty_state", Text: "no AI-coding session activity found under $HOME in the last 30 days. Looked in: ~/.claude/projects, ~/.codex/sessions (29 adapters). Try --since all."},
		},
	}
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "no AI-coding session activity found under $HOME") {
		t.Errorf("empty corpus output = %q", out)
	}
	if strings.Contains(out, "TOOL") || strings.Contains(out, "TOTAL") {
		t.Errorf("empty corpus output must not print the table/footer: %q", out)
	}
	if strings.Contains(out, PriceBasis) {
		t.Errorf("empty corpus output must not carry the price disclaimer (no dollars shown): %q", out)
	}
}

func TestRenderEmptyCorpusFallbackWhenNoteMissing(t *testing.T) {
	// Defensive: Render must never panic or print nothing if the caller
	// forgot to attach an empty_state note.
	out := Render(Table{}, RenderOptions{})
	if out == "" {
		t.Fatal("expected a non-empty fallback message for an empty table with no notes")
	}
}

func TestRenderEmptyCorpusWithPartialNote(t *testing.T) {
	tbl := Table{
		Notes: []Note{
			{Code: "empty_state", Text: "no session activity found."},
			{Code: "partial", Text: "scan stopped at the 30s budget - read 3 of 900 session files, so totals are a partial view"},
		},
	}
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "no session activity found.") {
		t.Errorf("missing empty_state text: %q", out)
	}
	if !strings.Contains(out, "scan stopped at the 30s budget") {
		t.Errorf("missing partial text alongside empty_state: %q", out)
	}
}

// TestRenderEmptyCorpusWithNoLocalTokenSourceNote pins F10: a user whose
// only detected tool is qoder (no local token/model data at all) must see
// WHY the report is empty, not just "no session activity found" — the
// no_local_token_source note must render alongside empty_state.
func TestRenderEmptyCorpusWithNoLocalTokenSourceNote(t *testing.T) {
	tbl := Table{
		Notes: []Note{
			{Code: "empty_state", Text: "no session activity found."},
			{
				Code:  "no_local_token_source",
				Tools: []string{"qoder"},
				Text:  "qoder: no local token source - usage server-side only - local logs carry zero tokens and no model; no base-URL knob",
			},
		},
	}
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "no session activity found.") {
		t.Errorf("missing empty_state text: %q", out)
	}
	if !strings.Contains(out, "qoder: no local token source") {
		t.Errorf("missing no_local_token_source text alongside empty_state: %q", out)
	}
}

// TestRenderEmptyCorpusWithScanErrorsNote pins F10: a corpus whose files
// all failed to parse must not be silently reported as "no activity" with
// no explanation — the scan_errors note must render alongside empty_state.
func TestRenderEmptyCorpusWithScanErrorsNote(t *testing.T) {
	tbl := Table{
		Notes: []Note{
			{Code: "empty_state", Text: "no session activity found."},
			{Code: "scan_errors", Text: "12 of 12 session files failed to parse - see --verbose for details"},
		},
	}
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "no session activity found.") {
		t.Errorf("missing empty_state text: %q", out)
	}
	if !strings.Contains(out, "12 of 12 session files failed to parse") {
		t.Errorf("missing scan_errors text alongside empty_state: %q", out)
	}
}

// TestRenderEmptyCorpusWithUnpricedModelsNote pins F10: a corpus whose
// every model has no pricing entry (so the cost engine excluded every
// token) must surface the unpriced_models explanation alongside
// empty_state, not just the bare "no activity" line.
func TestRenderEmptyCorpusWithUnpricedModelsNote(t *testing.T) {
	tbl := Table{
		Notes: []Note{
			{Code: "empty_state", Text: "no session activity found."},
			{Code: "unpriced_models", Text: "1 model has no pricing entry - its tokens are excluded from the dollar totals"},
		},
	}
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "no session activity found.") {
		t.Errorf("missing empty_state text: %q", out)
	}
	if !strings.Contains(out, "1 model has no pricing entry") {
		t.Errorf("missing unpriced_models text alongside empty_state: %q", out)
	}
}

// TestRenderEmptyCorpusOmitsGapNote pins the boundary of F10: "gap" notes
// describe a known per-tool CAPTURE LIMITATION unrelated to why THIS scan
// is empty (they exist for a tool with SOME local capture, which is
// inconsistent with a truly empty corpus for that tool) — they are
// deliberately NOT in the emptyStateExplanatoryCodes set and must not leak
// into the empty-state branch.
func TestRenderEmptyCorpusOmitsGapNote(t *testing.T) {
	tbl := Table{
		Notes: []Note{
			{Code: "empty_state", Text: "no session activity found."},
			{Code: "gap", Tools: []string{"copilot-cli"}, Text: "copilot-cli: per-turn input/cache attribution needs --log-level debug"},
		},
	}
	out := Render(tbl, RenderOptions{})
	if strings.Contains(out, "copilot-cli: per-turn input/cache attribution") {
		t.Errorf("gap note leaked into empty-state output: %q", out)
	}
}

func TestRenderUnpricedModelsNote(t *testing.T) {
	tbl := baseTable()
	tbl.UnknownModelCount = 2
	tbl.Notes = append(tbl.Notes, Note{Code: "unpriced_models", Text: "2 models have no pricing entry - their tokens are excluded from the dollar totals"})
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "2 models have no pricing entry") {
		t.Errorf("unpriced_models note missing from output:\n%s", out)
	}
}

func TestRenderNoLocalTokenSourceNote(t *testing.T) {
	tbl := baseTable()
	tbl.Notes = append(tbl.Notes, Note{
		Code:  "no_local_token_source",
		Tools: []string{"qoder"},
		Text:  "qoder: no local token source - usage server-side only - local logs carry zero tokens and no model; no base-URL knob",
	})
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "qoder: no local token source") {
		t.Errorf("no_local_token_source note missing:\n%s", out)
	}
}

func TestRenderGapNote(t *testing.T) {
	tbl := baseTable()
	tbl.Notes = append(tbl.Notes, Note{
		Code:  "gap",
		Tools: []string{"copilot-cli"},
		Text:  "copilot-cli: per-turn input/cache attribution needs --log-level debug",
	})
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "copilot-cli: per-turn input/cache attribution needs --log-level debug") {
		t.Errorf("gap note missing:\n%s", out)
	}
}

func TestRenderPartialNote(t *testing.T) {
	tbl := baseTable()
	tbl.Partial = &PartialScan{Budget: "30s", FilesWalked: 40, FilesTotal: 412}
	tbl.Notes = append(tbl.Notes, Note{
		Code: "partial",
		Text: "scan stopped at the 30s budget - read 40 of 412 session files, so totals are a partial view",
	})
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "scan stopped at the 30s budget") {
		t.Errorf("partial note missing:\n%s", out)
	}
}

func TestRenderLongModelNameTruncation(t *testing.T) {
	longName := "a-very-long-model-name-that-should-be-truncated-because-it-is-too-long"
	tbl := Table{
		WindowLabel: "last 30 days",
		Rows: []Row{
			{Tool: "codex", Model: longName, Input: 1, Output: 1, Turns: 1, USD: 0.01, Reliability: "accurate"},
		},
		ToolCount:  1,
		ModelCount: 1,
		TotalUSD:   0.01,
	}
	out := Render(tbl, RenderOptions{})
	if strings.Contains(out, longName) {
		t.Errorf("long model name was not truncated:\n%s", out)
	}
	if !strings.Contains(out, "…") {
		t.Errorf("expected an ellipsis marking the truncation:\n%s", out)
	}
	truncated := truncateModel(longName)
	if runeLen(truncated) != maxModelWidth {
		t.Errorf("truncateModel(%q) width = %d, want %d", longName, runeLen(truncated), maxModelWidth)
	}
	if !strings.Contains(out, truncated) {
		t.Errorf("output does not contain the truncated model name %q:\n%s", truncated, out)
	}
}

func TestFormatTokensBoundaries(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{9_999, "9,999"},
		{10_000, "10.0k"},
		{999_999, "999.9k"},
		{1_000_000, "1.00M"},
		{0, "0"},
		{1_234_567, "1.23M"},
	}
	for _, tt := range tests {
		if got := formatTokens(tt.n); got != tt.want {
			t.Errorf("formatTokens(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestFormatCacheCellZeroIsEmDash(t *testing.T) {
	if got := formatCacheCell(0); got != "—" {
		t.Errorf("formatCacheCell(0) = %q, want em-dash", got)
	}
	if got := formatCacheCell(10_000); got != "10.0k" {
		t.Errorf("formatCacheCell(10000) = %q, want 10.0k", got)
	}
}

func TestCommaInt(t *testing.T) {
	tests := []struct {
		n    int64
		want string
	}{
		{0, "0"},
		{9, "9"},
		{999, "999"},
		{1000, "1,000"},
		{1284, "1,284"},
		{1000000, "1,000,000"},
		{-1234, "-1,234"},
	}
	for _, tt := range tests {
		if got := commaInt(tt.n); got != tt.want {
			t.Errorf("commaInt(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestFormatUSD(t *testing.T) {
	tests := []struct {
		v    float64
		want string
	}{
		{412.88, "$412.88"},
		{0.51, "$0.51"},
		{518.96, "$518.96"},
		{1234.5, "$1,234.50"},
		{0, "$0.00"},
	}
	for _, tt := range tests {
		if got := formatUSD(tt.v); got != tt.want {
			t.Errorf("formatUSD(%v) = %q, want %q", tt.v, got, tt.want)
		}
	}
}

func TestRenderColorNoColorBytes(t *testing.T) {
	tbl := baseTable()

	plain := Render(tbl, RenderOptions{Color: false})
	if strings.ContainsRune(plain, 0x1b) {
		t.Errorf("Color:false output must contain no ANSI escape bytes:\n%q", plain)
	}

	colored := Render(tbl, RenderOptions{Color: true})
	if !strings.ContainsRune(colored, 0x1b) {
		t.Errorf("Color:true output should contain ANSI escape bytes")
	}

	// Color must never change the visible (escape-stripped) content —
	// only add escape codes around whole lines.
	stripped := stripANSI(colored)
	if stripped != plain {
		t.Errorf("colorized output differs from plain output once ANSI codes are stripped\nplain:\n%s\nstripped:\n%s", plain, stripped)
	}
}

// stripANSI removes every ANSI CSI escape sequence introduced by colorize
// (the bold/dim/reset codes render.go uses), for comparing colored output
// against the plain baseline.
func stripANSI(s string) string {
	for _, code := range []string{ansiBold, ansiDim, ansiReset} {
		s = strings.ReplaceAll(s, code, "")
	}
	return s
}

func TestRenderHonestyInvariants(t *testing.T) {
	tbl := baseTable()
	tbl.Notes = append(
		tbl.Notes,
		Note{Code: "unpriced_models", Text: "1 model has no pricing entry - its tokens are excluded from the dollar totals"},
		Note{Code: "gap", Text: "copilot-cli: per-turn input/cache attribution needs --log-level debug"},
	)
	out := Render(tbl, RenderOptions{})

	if !strings.Contains(out, PriceBasis) {
		t.Errorf("output with rows must always carry the price-basis disclaimer %q:\n%s", PriceBasis, out)
	}
	lower := strings.ToLower(out)
	if strings.Contains(lower, "% sav") || strings.Contains(lower, "%sav") {
		t.Errorf("output must never contain a savings-percentage claim:\n%s", out)
	}
	if strings.Contains(lower, "saved") {
		t.Errorf("output must never contain the word \"saved\":\n%s", out)
	}
	if strings.Contains(out, "compress") {
		t.Errorf("output must never mention compression (no compression column exists):\n%s", out)
	}
}

func TestRenderLogTierMentionsProxyUpsell(t *testing.T) {
	out := Render(baseTable(), RenderOptions{})
	if !strings.Contains(out, "observer start") {
		t.Errorf("log-tier output must point to observer start:\n%s", out)
	}
	if !strings.Contains(out, "log-tier") {
		t.Errorf("log-tier output must name its own tier honestly:\n%s", out)
	}
}

func TestRenderProxyTierSkipsUpsell(t *testing.T) {
	tbl := baseTable()
	tbl.Tier = "proxy"
	out := Render(tbl, RenderOptions{})
	if !strings.Contains(out, "proxy-tier") {
		t.Errorf("proxy-tier output must name its own tier:\n%s", out)
	}
	if strings.Contains(out, "need the proxy") {
		t.Errorf("proxy-tier output must not upsell the proxy it is already using:\n%s", out)
	}
}
