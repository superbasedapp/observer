package statusline

import (
	"strings"
	"testing"
)

// assertNoNewline pins the render.go doc comment's decision: Render
// output never carries a trailing newline. The caller owns line
// termination.
func assertNoNewline(t *testing.T, out string) {
	t.Helper()
	if strings.HasSuffix(out, "\n") {
		t.Errorf("Render output must not end in a newline: %q", out)
	}
}

// assertHonestyInvariants pins plan §4.2: no savings/percentage framing
// anywhere in any rendered output, in every case this file exercises.
func assertHonestyInvariants(t *testing.T, out string) {
	t.Helper()
	if strings.Contains(out, "%") {
		t.Errorf("Render output must never contain a %% character: %q", out)
	}
	lower := strings.ToLower(out)
	if strings.Contains(lower, "saved") {
		t.Errorf("Render output must never contain the word \"saved\": %q", out)
	}
	if strings.Contains(lower, "savings") {
		t.Errorf("Render output must never contain the word \"savings\": %q", out)
	}
}

func TestRenderGoldenCases(t *testing.T) {
	tests := []struct {
		name string
		in   Input
		tile DaemonTile
		opts RenderOptions
		want string // exact expected output
	}{
		{
			name: "full segment set, all data present (plan §4.1 example)",
			in: Input{
				Cost:  &Cost{TotalCostUSD: f64Ptr(3.42)},
				Model: &Model{DisplayName: strPtr("claude-opus-4-5")},
			},
			tile: DaemonTile{TodayUSD: f64Ptr(18.90)},
			opts: RenderOptions{},
			want: "▞ superbased · $3.42 session · $18.90 today · claude-opus-4-5",
		},
		{
			name: "session-only, no daemon tile",
			in: Input{
				Cost: &Cost{TotalCostUSD: f64Ptr(3.42)},
			},
			tile: DaemonTile{},
			opts: RenderOptions{},
			want: "▞ superbased · $3.42 session",
		},
		{
			name: "today-only, no stdin JSON",
			in:   Input{},
			tile: DaemonTile{TodayUSD: f64Ptr(18.90)},
			opts: RenderOptions{},
			want: "▞ superbased · $18.90 today",
		},
		{
			name: "model-only",
			in: Input{
				Model: &Model{DisplayName: strPtr("claude-opus-4-5")},
			},
			tile: DaemonTile{},
			opts: RenderOptions{},
			want: "▞ superbased · claude-opus-4-5",
		},
		{
			name: "wordmark-alone, everything absent (the worst case)",
			in:   Input{},
			tile: DaemonTile{},
			opts: RenderOptions{},
			want: "▞ superbased",
		},
		{
			name: "segment subset via --segments (wordmark,today only)",
			in: Input{
				Cost:  &Cost{TotalCostUSD: f64Ptr(3.42)},
				Model: &Model{DisplayName: strPtr("claude-opus-4-5")},
			},
			tile: DaemonTile{TodayUSD: f64Ptr(18.90)},
			opts: RenderOptions{Segments: []string{SegmentWordmark, SegmentToday}},
			want: "▞ superbased · $18.90 today",
		},
		{
			// F12 fix changed this golden: the wordmark is now forced to
			// the front regardless of where the caller placed it in
			// Segments (normalizeSegments) — this case used to expect
			// the wordmark to stay in its caller-given middle position
			// ("$18.90 today · ▞ superbased · $3.42 session"), which is exactly the
			// bug F12 fixed (a caller could push the wordmark out of
			// first position, or off the line entirely). Every OTHER
			// requested kind still keeps the caller's relative order
			// (today before session here), only the wordmark itself is
			// relocated.
			name: "wordmark forced to front even when listed elsewhere in Segments",
			in: Input{
				Cost: &Cost{TotalCostUSD: f64Ptr(3.42)},
			},
			tile: DaemonTile{TodayUSD: f64Ptr(18.90)},
			opts: RenderOptions{Segments: []string{SegmentToday, SegmentWordmark, SegmentSession}},
			want: "▞ superbased · $18.90 today · $3.42 session",
		},
		{
			// F12 regression: "today,wordmark" (wordmark last) must still
			// render the wordmark first.
			name: "today,wordmark renders wordmark first",
			in:   Input{},
			tile: DaemonTile{TodayUSD: f64Ptr(18.90)},
			opts: RenderOptions{Segments: []string{SegmentToday, SegmentWordmark}},
			want: "▞ superbased · $18.90 today",
		},
		{
			// F12 regression: a Segments list that never mentions
			// "wordmark" at all still gets it forced to the front — the
			// wordmark is not opt-in via inclusion, it is unconditional.
			name: "wordmark forced present even when caller's Segments omits it entirely",
			in: Input{
				Cost: &Cost{TotalCostUSD: f64Ptr(3.42)},
			},
			tile: DaemonTile{},
			opts: RenderOptions{Segments: []string{SegmentSession}},
			want: "▞ superbased · $3.42 session",
		},
		{
			// F12 regression: "model" alone with no model data must
			// render exactly the wordmark, never a blank line.
			name: "model alone with no model data renders exactly the wordmark",
			in:   Input{},
			tile: DaemonTile{},
			opts: RenderOptions{Segments: []string{SegmentModel}},
			want: "▞ superbased",
		},
		{
			// F12 regression: duplicate segment kinds (including
			// duplicate wordmarks) are deduped to their first
			// occurrence.
			name: "duplicate segments deduped",
			in: Input{
				Cost: &Cost{TotalCostUSD: f64Ptr(3.42)},
			},
			tile: DaemonTile{},
			opts: RenderOptions{Segments: []string{SegmentWordmark, SegmentSession, SegmentSession, SegmentWordmark}},
			want: "▞ superbased · $3.42 session",
		},
		{
			name: "session falls back to daemon SessionUSD when stdin absent",
			in:   Input{},
			tile: DaemonTile{SessionUSD: f64Ptr(7.00)},
			opts: RenderOptions{},
			want: "▞ superbased · $7.00 session",
		},
		{
			name: "stdin session cost preferred over daemon session cost",
			in: Input{
				Cost: &Cost{TotalCostUSD: f64Ptr(3.42)},
			},
			tile: DaemonTile{SessionUSD: f64Ptr(999.00)},
			opts: RenderOptions{},
			want: "▞ superbased · $3.42 session",
		},
		{
			name: "model id used when display_name absent",
			in: Input{
				Model: &Model{ID: strPtr("claude-opus-4-5-20260101")},
			},
			tile: DaemonTile{},
			opts: RenderOptions{},
			want: "▞ superbased · claude-opus-4-5-20260101",
		},
		{
			name: "unknown segment kind skipped silently",
			in: Input{
				Cost: &Cost{TotalCostUSD: f64Ptr(3.42)},
			},
			tile: DaemonTile{},
			opts: RenderOptions{Segments: []string{"wordmark", "bogus-kind", "session"}},
			want: "▞ superbased · $3.42 session",
		},
		{
			name: "money above $100 renders whole dollars",
			in: Input{
				Cost: &Cost{TotalCostUSD: f64Ptr(1234.5)},
			},
			tile: DaemonTile{},
			opts: RenderOptions{},
			want: "▞ superbased · $1234 session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := Render(tt.in, tt.tile, tt.opts)
			if out != tt.want {
				t.Errorf("Render() = %q, want %q", out, tt.want)
			}
			assertNoNewline(t, out)
			assertHonestyInvariants(t, out)
		})
	}
}

func TestRenderLongModelNameTruncation(t *testing.T) {
	longName := "a-very-long-model-name-that-should-be-truncated-because-it-is-too-long"
	in := Input{Model: &Model{DisplayName: strPtr(longName)}}

	out := Render(in, DaemonTile{}, RenderOptions{})
	if strings.Contains(out, longName) {
		t.Errorf("long model name was not truncated: %q", out)
	}
	if !strings.Contains(out, "…") {
		t.Errorf("expected an ellipsis marking the truncation: %q", out)
	}
	truncated := truncateModel(longName)
	if got := []rune(truncated); len(got) != maxModelWidth {
		t.Errorf("truncateModel(%q) width = %d, want %d", longName, len(got), maxModelWidth)
	}
	if !strings.Contains(out, truncated) {
		t.Errorf("output does not contain the truncated model name %q: %q", truncated, out)
	}
	assertNoNewline(t, out)
	assertHonestyInvariants(t, out)
}

func TestRenderShortModelNameUntouched(t *testing.T) {
	in := Input{Model: &Model{DisplayName: strPtr("claude-opus-4-5")}}
	out := Render(in, DaemonTile{}, RenderOptions{})
	if !strings.Contains(out, "claude-opus-4-5") {
		t.Errorf("short model name should render unmodified: %q", out)
	}
	if strings.Contains(out, "…") {
		t.Errorf("short model name should not be truncated: %q", out)
	}
}

func TestRenderColorNoColorBytes(t *testing.T) {
	in := Input{
		Cost:  &Cost{TotalCostUSD: f64Ptr(3.42)},
		Model: &Model{DisplayName: strPtr("claude-opus-4-5")},
	}
	tile := DaemonTile{TodayUSD: f64Ptr(18.90)}

	plain := Render(in, tile, RenderOptions{Color: false})
	if strings.ContainsRune(plain, 0x1b) {
		t.Errorf("Color:false output must contain no ANSI escape bytes: %q", plain)
	}
	if plain != "▞ superbased · $3.42 session · $18.90 today · claude-opus-4-5" {
		t.Errorf("Color:false output = %q", plain)
	}

	colored := Render(in, tile, RenderOptions{Color: true})
	if !strings.ContainsRune(colored, 0x1b) {
		t.Errorf("Color:true output should contain ANSI escape bytes: %q", colored)
	}
	stripped := strings.ReplaceAll(strings.ReplaceAll(colored, ansiBold, ""), ansiReset, "")
	if stripped != plain {
		t.Errorf("colorized output differs from plain output once ANSI codes are stripped\nplain: %q\nstripped: %q", plain, stripped)
	}
	assertHonestyInvariants(t, plain)
	assertHonestyInvariants(t, colored)
}

func TestRenderColorWordmarkAloneStillDegrades(t *testing.T) {
	out := Render(Input{}, DaemonTile{}, RenderOptions{Color: true})
	if !strings.Contains(out, Wordmark) {
		t.Errorf("colored wordmark-alone output must still carry the wordmark text: %q", out)
	}
	assertNoNewline(t, out)
}

func TestRenderEmptySegmentsFallsBackToDefault(t *testing.T) {
	in := Input{Cost: &Cost{TotalCostUSD: f64Ptr(3.42)}}
	got := Render(in, DaemonTile{}, RenderOptions{Segments: nil})
	want := Render(in, DaemonTile{}, RenderOptions{Segments: DefaultSegments})
	if got != want {
		t.Errorf("nil Segments = %q, want same as DefaultSegments %q", got, want)
	}
}

// assertRenderIsControlFree pins F1's final-output assertion: Render's
// result must contain no '\n', '\r', or control rune — with the one
// carve-out the fix explicitly calls for: when colorAllowed is true, the
// EXACT ANSI sequences Render itself legitimately emits around the
// wordmark (ansiBold/ansiReset) are stripped first, so the check is
// "no control runes ANYWHERE ELSE in the line," never a blanket ban on
// bytes this renderer produces on purpose.
func assertRenderIsControlFree(t *testing.T, out string, colorAllowed bool) {
	t.Helper()
	checked := out
	if colorAllowed {
		checked = strings.ReplaceAll(checked, ansiBold, "")
		checked = strings.ReplaceAll(checked, ansiReset, "")
	}
	for _, r := range checked {
		if isControlRune(r) {
			t.Errorf("Render output contains a control rune %U outside the renderer's own known ANSI sequences: %q", r, out)
		}
	}
}

func TestRenderSanitizesNewlineInjectionInModelName(t *testing.T) {
	in := Input{Model: &Model{DisplayName: strPtr("safe\nERROR")}}
	out := Render(in, DaemonTile{}, RenderOptions{})
	if strings.ContainsAny(out, "\n\r") {
		t.Fatalf("Render output must never contain a raw newline or CR from Input-sourced text: %q", out)
	}
	want := "▞ superbased · safe ERROR"
	if out != want {
		t.Errorf("Render() = %q, want %q", out, want)
	}
	assertRenderIsControlFree(t, out, false)
	assertHonestyInvariants(t, out)
}

func TestRenderSanitizesANSIEscapeInjectionInModelName(t *testing.T) {
	in := Input{Model: &Model{DisplayName: strPtr("safe\x1b[31mRED")}}
	out := Render(in, DaemonTile{}, RenderOptions{})
	if strings.ContainsRune(out, 0x1b) {
		t.Fatalf("Render output must never contain a raw ESC byte from Input-sourced text: %q", out)
	}
	// Stripping the leading ESC neutralizes the escape sequence — what's
	// left ("[31mRED") is inert literal text to a terminal, not a color
	// change, because ESC is the byte that gives it meaning.
	want := "▞ superbased · safe [31mRED"
	if out != want {
		t.Errorf("Render() = %q, want %q", out, want)
	}
	assertRenderIsControlFree(t, out, false)
}

func TestRenderSanitizesC1BytesInModelName(t *testing.T) {
	in := Input{Model: &Model{DisplayName: strPtr("safeEND")}} // U+0085 NEL, a C1 control
	out := Render(in, DaemonTile{}, RenderOptions{})
	if strings.ContainsRune(out, 0x85) {
		t.Fatalf("Render output must never contain a raw C1 control rune from Input-sourced text: %q", out)
	}
	want := "▞ superbased · safe END"
	if out != want {
		t.Errorf("Render() = %q, want %q", out, want)
	}
	assertRenderIsControlFree(t, out, false)
}

func TestRenderTabInModelNameBecomesSpace(t *testing.T) {
	// Documented policy decision: tab is a C0 control (0x09) under this
	// package's sanitization and collapses to a single space like every
	// other control character — it is never preserved as a literal tab
	// in the rendered line.
	in := Input{Model: &Model{DisplayName: strPtr("safe\tEND")}}
	out := Render(in, DaemonTile{}, RenderOptions{})
	if strings.ContainsRune(out, '\t') {
		t.Fatalf("Render output must never contain a literal tab from Input-sourced text: %q", out)
	}
	want := "▞ superbased · safe END"
	if out != want {
		t.Errorf("Render() = %q, want %q", out, want)
	}
	assertRenderIsControlFree(t, out, false)
}

func TestRenderModelIDSanitizedWhenDisplayNameAbsent(t *testing.T) {
	in := Input{Model: &Model{ID: strPtr("safe\nERROR-id")}}
	out := Render(in, DaemonTile{}, RenderOptions{})
	want := "▞ superbased · safe ERROR-id"
	if out != want {
		t.Errorf("Render() = %q, want %q", out, want)
	}
	assertRenderIsControlFree(t, out, false)
}

// TestRenderFinalOutputNeverContainsControlRunes is F1's headline
// regression: a battery of hostile model names, rendered both with and
// without Color, must never leave a control rune (other than Render's
// own legitimate ANSI, when Color is on) anywhere in the output.
func TestRenderFinalOutputNeverContainsControlRunes(t *testing.T) {
	malicious := []string{
		"safe\nERROR",
		"safe\r\nERROR",
		"safe\x1b[31mRED\x1b[0m",
		"safeEND",
		"safe\tEND",
		"\x00\x01\x02control-only-prefix",
		string([]byte{0x7f}) + "DEL-prefixed",
	}
	for _, name := range malicious {
		name := name
		t.Run(name, func(t *testing.T) {
			in := Input{Model: &Model{DisplayName: strPtr(name)}}
			for _, color := range []bool{false, true} {
				out := Render(in, DaemonTile{TodayUSD: f64Ptr(1.0)}, RenderOptions{Color: color})
				if strings.ContainsAny(out, "\n\r") {
					t.Errorf("Color=%v: output contains a raw newline/CR: %q", color, out)
				}
				assertRenderIsControlFree(t, out, color)
			}
		})
	}
}

// TestRenderCleanModelNameGoldenUnchangedBySanitization pins that
// sanitization is a no-op for already-clean input — the F1 fix must not
// alter any existing golden case's output.
func TestRenderCleanModelNameGoldenUnchangedBySanitization(t *testing.T) {
	in := Input{Model: &Model{DisplayName: strPtr("claude-opus-4-5")}}
	out := Render(in, DaemonTile{}, RenderOptions{})
	want := "▞ superbased · claude-opus-4-5"
	if out != want {
		t.Errorf("Render() = %q, want unchanged clean golden %q", out, want)
	}
}

func TestFormatUSDBoundaries(t *testing.T) {
	tests := []struct {
		v    float64
		want string
	}{
		{0, "$0.00"},
		{3.42, "$3.42"},
		{18.90, "$18.90"},
		{99.99, "$99.99"},
		{100, "$100"},
		{100.4, "$100"},
		{1234.5, "$1234"},
	}
	for _, tt := range tests {
		if got := formatUSD(tt.v); got != tt.want {
			t.Errorf("formatUSD(%v) = %q, want %q", tt.v, got, tt.want)
		}
	}
}

// TestRenderSecuritySegment (lane sec-c3): the security segment renders
// the caller's text, sanitized, only when listed and set.
func TestRenderSecuritySegment(t *testing.T) {
	label := "sec 2!\x1b[31m"
	got := Render(Input{}, DaemonTile{Security: &label}, RenderOptions{Segments: []string{SegmentSecurity}})
	if !strings.Contains(got, "sec 2!") || strings.ContainsRune(got, 0x1b) {
		t.Fatalf("listed: %q", got)
	}
	if got := Render(Input{}, DaemonTile{Security: &label}, RenderOptions{}); strings.Contains(got, "sec") {
		t.Fatalf("not in the defaults: %q", got)
	}
	if got := Render(Input{}, DaemonTile{}, RenderOptions{Segments: []string{SegmentSecurity}}); strings.Contains(got, "sec") {
		t.Fatalf("nil text: %q", got)
	}
}
