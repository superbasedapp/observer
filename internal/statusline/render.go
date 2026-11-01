package statusline

import "strings"

// ansiBold/ansiReset wrap only the wordmark segment when RenderOptions.
// Color is true (a small brand emphasis, not a whole-line color scheme —
// the rest of the line stays plain so the numbers themselves are never
// harder to read in a themed terminal).
const (
	ansiBold  = "\x1b[1m"
	ansiReset = "\x1b[0m"
)

// RenderOptions controls presentation for Render.
type RenderOptions struct {
	// Color, when true, wraps the wordmark segment in ANSI bold/reset
	// codes. When false (the default), Render's output contains no
	// escape bytes at all — golden tests assert this exactly.
	Color bool
	// Segments is the ordered list of segment kinds to render (the
	// SegmentWordmark/SegmentSession/SegmentToday/SegmentModel
	// vocabulary, plus any future kind — unknown strings are skipped
	// silently, never an error). An empty slice falls back to
	// DefaultSegments.
	//
	// F12 fix: this list no longer controls WHETHER or WHERE the
	// wordmark appears. Render normalizes it first (normalizeSegments)
	// so the wordmark is always forced to the front exactly once,
	// regardless of whether the caller included it, where they placed
	// it, or how many times they repeated it; every other requested kind
	// is also deduped (first occurrence wins) but otherwise keeps the
	// caller's relative order. There is no supported way to produce a
	// wordmark-less or wordmark-reordered line — see normalizeSegments.
	Segments []string
}

// Render turns an Input, a DaemonTile, and a RenderOptions into EXACTLY
// ONE line of text — no trailing newline, and (F1 fix) no embedded
// control character of any kind: no CR, no LF, no other C0/C1 control,
// no DEL. The caller (cmd/observer/statusline.go) owns terminating the
// line when it writes to stdout; Render's job stops at producing the
// bytes a Claude Code statusLine command is expected to print verbatim
// — and a statusLine command that ever emits a newline or a raw escape
// byte corrupts the host's own status render, the single worst failure
// mode this command can produce (plan §2.3 point 6).
//
// Render first normalizes opts.Segments via normalizeSegments (F12: the
// wordmark is forced present exactly once at the front; every other kind
// is deduped, order otherwise preserved). It then walks the normalized
// list; for each kind it asks the matching per-segment renderer in
// segments.go for a (text, ok) pair. A segment whose datum is absent is
// OMITTED entirely — never rendered as a fabricated "$0.00" or empty
// model name (plan §4.1). Because normalization guarantees the wordmark
// is always present, the maximally degraded composition (no daemon, no
// stdin JSON, or every other requested segment's datum absent) is the
// wordmark alone — a fully empty rendered line is no longer possible.
//
// Every externally-sourced segment (currently: the model name,
// segments.go's renderModelSegment / modelName) is sanitized at the
// point it's read out of Input (sanitizeControls, sanitize.go) — that is
// the primary fix for F1. As defense in depth, Render ALSO hard-strips
// any control rune from the fully-composed, not-yet-colorized line
// before returning it, so the "no control rune reaches stdout" invariant
// holds even for a future segment kind that forgets to sanitize its own
// input. Color wrapping happens LAST, strictly after that hard-strip
// pass, and wraps only the wordmark's own known-safe leading text
// (colorizeWordmarkPrefix) — so the ANSI bytes Render itself legitimately
// emits when Color is true are added only after every control byte from
// caller-supplied text has already been stripped, and no caller-supplied
// text is ever mistaken for part of that trusted sequence.
//
// Every segment after the wordmark joins to its predecessor with " · ".
// The wordmark itself is special-cased in joinSegments: if Wordmark's
// own text already ends in the separator glyph ("·"), it joins to
// whatever follows with a single plain space instead, so the glyph isn't
// doubled (e.g. a provisional "sb·" candidate would otherwise render
// "sb· · ..."). The current Wordmark does not end in the separator glyph,
// so this degrades to the standard " · " join — the check is
// capability-based (does Wordmark end in the glyph), not a hardcoded
// assumption about any one candidate's shape.
//
// Render never prints "%", "saved", or "savings" in any segment or
// fallback string — there is no comparison, no savings framing anywhere
// in this package's vocabulary (plan §4.2; render_test.go pins this as a
// negative assertion on every golden case).
func Render(in Input, tile DaemonTile, opts RenderOptions) string {
	kinds := normalizeSegments(opts.Segments)

	var rendered []segment
	for _, kind := range kinds {
		switch kind {
		case SegmentWordmark:
			rendered = append(rendered, segment{text: Wordmark, isWordmark: true})
		case SegmentSession:
			if text, ok := renderSessionSegment(in, tile); ok {
				rendered = append(rendered, segment{text: text})
			}
		case SegmentToday:
			if text, ok := renderTodaySegment(tile); ok {
				rendered = append(rendered, segment{text: text})
			}
		case SegmentModel:
			if text, ok := renderModelSegment(in); ok {
				rendered = append(rendered, segment{text: text})
			}
		case SegmentBudget:
			if text, ok := renderBudgetSegment(tile); ok {
				rendered = append(rendered, segment{text: text})
			}
		case SegmentGrants:
			if text, ok := renderGrantsSegment(tile); ok {
				rendered = append(rendered, segment{text: text})
			}
		case SegmentMessages:
			if text, ok := renderMessagesSegment(tile); ok {
				rendered = append(rendered, segment{text: text})
			}
		case SegmentSecurity:
			if text, ok := renderSecuritySegment(tile); ok {
				rendered = append(rendered, segment{text: text})
			}
		}
	}

	// Defense in depth (F1): every externally-sourced segment text was
	// already sanitized at its source (segments.go's modelName), but
	// hard-strip the fully-composed, not-yet-colorized line too, so the
	// "no control rune in the final line" invariant holds regardless of
	// how a future segment kind is implemented.
	plain := sanitizeControls(joinSegments(rendered))

	if !opts.Color {
		return plain
	}
	return colorizeWordmarkPrefix(plain)
}

// normalizeSegments turns a caller-supplied segment-kind list into the
// actual order Render walks: SegmentWordmark forced present exactly once
// at the front — regardless of whether, where, or how many times the
// caller's list mentioned it — followed by every other requested kind in
// the caller's original relative order with duplicates of the same kind
// collapsed to their first occurrence (F12).
//
// An empty input falls back to DefaultSegments, which already begins
// with SegmentWordmark, so the fallback runs through this same
// normalization as a no-op. This makes a fully-empty rendered line
// impossible: the worst case after normalization is the wordmark-alone
// line — never a caller-triggered blank statusline (e.g. a bare
// []string{SegmentModel} with no model data), and never a caller
// dropping, duplicating, or reordering the wordmark away from the front
// (e.g. "today,wordmark" no longer puts the wordmark last).
func normalizeSegments(kinds []string) []string {
	if len(kinds) == 0 {
		kinds = DefaultSegments
	}
	out := make([]string, 0, len(kinds)+1)
	out = append(out, SegmentWordmark)
	seen := map[string]bool{SegmentWordmark: true}
	for _, k := range kinds {
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	return out
}

// separatorGlyph is the middle dot used between rendered segments. It is
// also checked against Wordmark's own trailing text so joinSegments can
// avoid doubling it — see Render's doc comment.
const separatorGlyph = "·"

// joinSegments concatenates the already-rendered segments in order,
// using " · " between every pair — except that the wordmark joins to
// whatever follows it with a single plain space when Wordmark's own text
// already ends in separatorGlyph, avoiding a doubled glyph (see Render's
// doc comment for why the wordmark is special-cased). This is a
// capability check against Wordmark's actual content, not a hardcoded
// assumption about its shape.
func joinSegments(segs []segment) string {
	wordmarkEndsInSeparator := strings.HasSuffix(Wordmark, separatorGlyph)
	var b strings.Builder
	for i, s := range segs {
		if i > 0 {
			if segs[i-1].isWordmark && wordmarkEndsInSeparator {
				b.WriteString(" ")
			} else {
				b.WriteString(" · ")
			}
		}
		b.WriteString(s.text)
	}
	return b.String()
}

// colorizeWordmarkPrefix wraps the leading Wordmark text of an
// already-composed, already-sanitized plain line in ansiBold/ansiReset.
//
// This runs strictly AFTER Render's control-rune hard-strip pass — by
// construction the wordmark segment is always first post-normalization
// (normalizeSegments) and its rendered text is always exactly the
// Wordmark constant (never externally sourced, never sanitized-away), so
// wrapping the literal Wordmark prefix is a safe, targeted operation: it
// can never wrap, truncate, or get confused by caller-supplied text, and
// it never re-introduces a control byte anywhere else in the line. If
// plain unexpectedly doesn't start with Wordmark (it always should), this
// degrades to returning plain unchanged rather than risking a malformed
// wrap.
func colorizeWordmarkPrefix(plain string) string {
	if !strings.HasPrefix(plain, Wordmark) {
		return plain
	}
	return ansiBold + Wordmark + ansiReset + plain[len(Wordmark):]
}
