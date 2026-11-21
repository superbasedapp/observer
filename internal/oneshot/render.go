package oneshot

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// RenderOptions controls presentation-only aspects of Render's output.
// Color is the only field: when true, a handful of whole lines (never a
// partial cell) are wrapped in ANSI escape codes. Padding/alignment is
// always computed on the plain, un-colored text first, so turning Color on
// or off never changes a single column's width — only whether some lines
// carry escape codes around them. Golden tests assert the Color:false
// bytes exactly.
type RenderOptions struct {
	Color bool
}

const (
	ansiBold  = "\x1b[1m"
	ansiDim   = "\x1b[2m"
	ansiReset = "\x1b[0m"
)

// colGap is the fixed number of spaces separating adjacent table columns.
const colGap = 2

// maxModelWidth is the longest a MODEL cell is allowed to display before
// truncation with an ellipsis (plan §4 "long model-name truncation" case).
const maxModelWidth = 28

// tableHeaders names the 8 fixed columns, in order, per plan §1.4.
var tableHeaders = [8]string{"TOOL", "MODEL", "IN", "OUT", "CACHE_R", "CACHE_W", "TURNS", "USD"}

// Render turns a Table into the exact terminal design of plan §1.4: a
// title line, an aligned TOOL/MODEL/IN/OUT/CACHE_R/CACHE_W/TURNS/USD table,
// a TOTAL row, and a fixed honesty footer (reliability/tier line, the
// PriceBasis disclaimer, the proxy upsell, a "next:" pointer, then the
// conditional Notes) — or, when the table has no rows, the empty-state
// note's text plus any explanatory notes (partial / scan_errors /
// no_local_token_source / unpriced_models) that say WHY it's empty.
//
// Render never prints a compression column or a "%"-savings figure of any
// kind; every dollar amount is accompanied by PriceBasis somewhere in the
// output. This is a non-negotiable honesty rule (CLAUDE.md, the
// accuracy-check Check-D retracted-claim class) — it is enforced here, not
// left to callers.
func Render(t Table, opts RenderOptions) string {
	if len(t.Rows) == 0 {
		return renderEmpty(t, opts)
	}

	var b strings.Builder

	writeTitle(&b, t, opts)
	b.WriteByte('\n')

	writeTable(&b, t, opts)
	b.WriteByte('\n')

	writeFooter(&b, t, opts)

	return b.String()
}

// emptyStateExplanatoryCodes are the Note codes that explain WHY the scan
// came back empty (as opposed to merely reporting the empty_state fact
// itself, or the "gap" notes, which describe a known per-tool CAPTURE
// LIMITATION unrelated to why this particular scan found nothing). A user
// whose only detected tool is qoder (no_local_token_source), or whose
// files all failed to parse (scan_errors), or whose corpus is entirely
// unpriced models (unpriced_models) deserves the explanation, not just
// "no session activity found" — see F10.
var emptyStateExplanatoryCodes = map[string]bool{
	"scan_errors":           true,
	"no_local_token_source": true,
	"unpriced_models":       true,
}

// renderEmpty is the whole-output branch for a zero-row Table: it prints
// the "empty_state" note's text (falling back to a generic sentence if the
// caller forgot to attach one), the "partial" note's text when the empty
// result was itself caused by a budget-truncated scan, and then any of the
// emptyStateExplanatoryCodes notes present — every one of these are
// suppressed everywhere else once a table has rows (writeFooter prints
// the FULL Notes list unconditionally in that branch instead), so the
// empty-state branch must surface them itself or they're lost entirely.
func renderEmpty(t Table, opts RenderOptions) string {
	text := "no AI-coding session activity found in this window."
	var partial string
	var explanatory []string
	for _, n := range t.Notes {
		switch {
		case n.Code == "empty_state":
			text = n.Text
		case n.Code == "partial":
			partial = n.Text
		case emptyStateExplanatoryCodes[n.Code]:
			explanatory = append(explanatory, n.Text)
		}
	}

	var b strings.Builder
	b.WriteString(colorize(opts, ansiDim, text))
	b.WriteByte('\n')
	if partial != "" {
		b.WriteString(colorize(opts, ansiDim, partial))
		b.WriteByte('\n')
	}
	for _, e := range explanatory {
		b.WriteString(colorize(opts, ansiDim, e))
		b.WriteByte('\n')
	}
	return b.String()
}

// writeTitle writes the one-line banner: the brand + window label on the
// left, "one-shot · no daemon" right-aligned to the table's overall width
// (or to a minimum width when the table itself is narrower).
func writeTitle(b *strings.Builder, t Table, opts RenderOptions) {
	left := "superbased - observed agent spend, " + t.WindowLabel
	const right = "one-shot · no daemon"

	width := tableWidth(t)
	minWidth := runeLen(left) + colGap + runeLen(right)
	if width < minWidth {
		width = minWidth
	}

	gap := width - runeLen(left) - runeLen(right)
	line := left + strings.Repeat(" ", gap) + right
	b.WriteString(colorize(opts, ansiBold, line))
	b.WriteByte('\n')
}

// columnWidths computes the visible width of every one of the 8 fixed
// columns, given the (already-formatted) row cells and the TOTAL row's own
// cells, so the header, every data row, and the TOTAL row all line up.
func columnWidths(rows [][8]string, total [8]string) [8]int {
	var w [8]int
	for i, h := range tableHeaders {
		w[i] = runeLen(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if n := runeLen(c); n > w[i] {
				w[i] = n
			}
		}
	}
	for i, c := range total {
		if n := runeLen(c); n > w[i] {
			w[i] = n
		}
	}
	return w
}

// tableWidth is the full rendered width of the table (used to size the
// title line and the TOTAL separator).
func tableWidth(t Table) int {
	rows := buildRowCells(t)
	total := buildTotalCells(t)
	w := columnWidths(rows, total)
	sum := 0
	for _, n := range w {
		sum += n
	}
	return sum + colGap*(len(w)-1)
}

// buildRowCells formats every Row into its 8 display cells, in column
// order, before any padding is applied.
func buildRowCells(t Table) [][8]string {
	rows := make([][8]string, len(t.Rows))
	for i, r := range t.Rows {
		tool := r.Tool
		if r.Approx() {
			tool += " ~"
		}
		rows[i] = [8]string{
			tool,
			truncateModel(r.Model),
			formatTokens(r.Input),
			formatTokens(r.Output),
			formatCacheCell(r.CacheRead),
			formatCacheCell(r.CacheCreation),
			commaInt(int64(r.Turns)),
			formatUSD(r.USD),
		}
	}
	return rows
}

// buildTotalCells formats the TOTAL row's 8 display cells.
func buildTotalCells(t Table) [8]string {
	return [8]string{
		"TOTAL",
		summaryLabel(t),
		formatTokens(t.TotalInput),
		formatTokens(t.TotalOutput),
		formatCacheCell(t.TotalCacheRead),
		formatCacheCell(t.TotalCacheCreation),
		commaInt(int64(t.TotalTurns)),
		formatUSD(t.TotalUSD),
	}
}

// summaryLabel builds the TOTAL row's MODEL-column text, e.g.
// "5 tools · 3 models".
func summaryLabel(t Table) string {
	tools := pluralCount(t.ToolCount, "tool", "tools")
	models := pluralCount(t.ModelCount, "model", "models")
	return tools + " · " + models
}

func pluralCount(n int, singular, plural string) string {
	unit := plural
	if n == 1 {
		unit = singular
	}
	return strconv.Itoa(n) + " " + unit
}

// writeTable writes the column header, every data row, the separator, and
// the TOTAL row.
func writeTable(b *strings.Builder, t Table, opts RenderOptions) {
	rows := buildRowCells(t)
	total := buildTotalCells(t)
	w := columnWidths(rows, total)

	header := formatRow(tableHeaders[:], w, false)
	b.WriteString(colorize(opts, ansiDim, header))
	b.WriteByte('\n')

	for _, r := range rows {
		b.WriteString(formatRow(r[:], w, false))
		b.WriteByte('\n')
	}

	sepWidth := 0
	for _, n := range w {
		sepWidth += n
	}
	sepWidth += colGap * (len(w) - 1)
	sep := strings.Repeat("─", sepWidth)
	b.WriteString(colorize(opts, ansiDim, sep))
	b.WriteByte('\n')

	b.WriteString(colorize(opts, ansiBold, formatRow(total[:], w, true)))
	b.WriteByte('\n')
}

// formatRow pads the 8 cells to the given widths and joins them with
// colGap spaces. Columns 0 and 1 (TOOL, MODEL) are left-justified;
// columns 2-7 (the numeric columns) are right-justified. total additionally
// left-justifies column 1 (the "N tools · M models" summary) the same way
// as a normal MODEL cell — the only difference is the caller-applied bold.
func formatRow(cells []string, w [8]int, total bool) string {
	_ = total // alignment is identical for the TOTAL row; kept for clarity at call sites
	parts := make([]string, len(cells))
	for i, c := range cells {
		if i < 2 {
			parts[i] = padRight(c, w[i])
		} else {
			parts[i] = padLeft(c, w[i])
		}
	}
	return strings.Join(parts, strings.Repeat(" ", colGap))
}

// writeFooter writes the fixed reliability/tier explanation, the
// PriceBasis disclaimer, the proxy upsell (log tier only), the "next:"
// pointer, and finally every conditional Note, one per line.
func writeFooter(b *strings.Builder, t Table, opts RenderOptions) {
	tier := t.Tier
	if tier == "" {
		tier = "log"
	}

	if tier == "proxy" {
		b.WriteString("reliability: proxy-tier - wire-accurate per-turn tokens captured live via the\n")
		b.WriteString("  proxy (~ = the tool's own counts are rounded/self-reported). dollars are\n")
		b.WriteString("  " + PriceBasis + ".\n")
	} else {
		b.WriteString("reliability: log-tier - parsed from each tool's own local session files (~ = the tool's\n")
		b.WriteString("  own counts are rounded/self-reported). dollars are " + PriceBasis + ".\n")
		b.WriteString("per-turn wire-accurate tokens (net input, 5m/1h cache splits, reasoning) need the proxy:\n")
		b.WriteString("  observer start\n")
	}

	b.WriteString("next: observer start  →  local dashboard on http://127.0.0.1:8081     superbased.app\n")

	for _, n := range t.Notes {
		b.WriteString(colorize(opts, ansiDim, n.Text))
		b.WriteByte('\n')
	}
}

// colorize wraps s in the given ANSI code + reset when opts.Color is true,
// and returns s unchanged otherwise. It is only ever applied to a whole
// already-padded line, never a partial cell, so it never disturbs the
// column-width math (which always runs on the plain text first).
func colorize(opts RenderOptions, code, s string) string {
	if !opts.Color {
		return s
	}
	return code + s + ansiReset
}

// padRight left-justifies s in a field of the given rune width.
func padRight(s string, width int) string {
	n := runeLen(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

// padLeft right-justifies s in a field of the given rune width.
func padLeft(s string, width int) string {
	n := runeLen(s)
	if n >= width {
		return s
	}
	return strings.Repeat(" ", width-n) + s
}

// runeLen returns the visible rune count of s (never a byte count) so
// multi-byte UTF-8 characters like "—", "…", and "·" occupy exactly one
// column, matching every terminal's fixed-width rendering.
func runeLen(s string) int {
	return utf8.RuneCountInString(s)
}

// truncateModel shortens a model name to at most maxModelWidth runes,
// replacing the tail with a single "…" when it does not fit.
func truncateModel(s string) string {
	if runeLen(s) <= maxModelWidth {
		return s
	}
	r := []rune(s)
	return string(r[:maxModelWidth-1]) + "…"
}

// formatCacheCell formats a cache token count, rendering exactly zero as
// an em-dash ("no cache data for this row") rather than "0" — the honest
// signal that this row's tool never reported a cache figure at all,
// distinct from a row that legitimately used zero cache tokens (table.go).
func formatCacheCell(n int64) string {
	if n == 0 {
		return "—"
	}
	return formatTokens(n)
}

// formatTokens renders a token count with a humanized k/M suffix once it
// reaches 5 figures, truncating (never rounding) the fractional digit so a
// value one below a unit boundary never appears to have crossed it (e.g.
// 999,999 always reads "999.9k", never rounds up to a spurious "1000.0k"):
//
//   - n < 10,000: a plain, comma-grouped integer ("9,999").
//   - 10,000 <= n < 1,000,000: "<N>.<d>k" with one decimal digit ("10.0k",
//     "999.9k").
//   - n >= 1,000,000: "<N>.<dd>M" with two decimal digits ("1.00M").
func formatTokens(n int64) string {
	switch {
	case n < 10_000:
		return commaInt(n)
	case n < 1_000_000:
		return strconv.FormatFloat(truncateDiv(n, 1_000, 10), 'f', 1, 64) + "k"
	default:
		return strconv.FormatFloat(truncateDiv(n, 1_000_000, 100), 'f', 2, 64) + "M"
	}
}

// truncateDiv computes n/unit truncated (never rounded) to the given
// decimal scale (10 for one decimal digit, 100 for two), returned as a
// float64 ready for strconv.FormatFloat.
func truncateDiv(n, unit, scale int64) float64 {
	return float64(n*scale/unit) / float64(scale)
}

// commaInt renders an integer with thousands separators, e.g. 1284 ->
// "1,284". Negative values are supported defensively (a leading "-" is
// kept out of the grouping) even though no field in this package is
// expected to go negative.
func commaInt(n int64) string {
	neg := n < 0
	if neg {
		n = -n
	}
	s := strconv.FormatInt(n, 10)
	var groups []string
	for len(s) > 3 {
		groups = append([]string{s[len(s)-3:]}, groups...)
		s = s[:len(s)-3]
	}
	groups = append([]string{s}, groups...)
	out := strings.Join(groups, ",")
	if neg {
		out = "-" + out
	}
	return out
}

// formatUSD renders a dollar amount as "$" + a comma-grouped, two-decimal
// figure, e.g. 412.884 -> "$412.88" (standard rounding, since a dollar
// amount is a sum of already-rounded per-row costs, not a token count
// where truncation matters for the boundary tests).
func formatUSD(v float64) string {
	cents := int64(v*100 + 0.5)
	if v < 0 {
		cents = int64(v*100 - 0.5)
	}
	whole := cents / 100
	frac := cents % 100
	if frac < 0 {
		frac = -frac
	}
	// no-bare-usd:allow (one-shot report on a machine with no observer state, so dollars)
	return "$" + commaInt(whole) + "." + padZero(frac)
}

// padZero renders 0-99 as a zero-padded two-digit string ("5" -> "05").
func padZero(n int64) string {
	if n < 10 {
		return "0" + strconv.FormatInt(n, 10)
	}
	return strconv.FormatInt(n, 10)
}
