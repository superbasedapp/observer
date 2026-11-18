package sharecard

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"text/template"
)

// LineItem is one (label → observed spend) row — a model id or a tool name with
// its observed USD spend over the period. Content-free.
type LineItem struct {
	Label   string
	CostUSD float64
}

// Data is the fully-assembled, content-free input to Markdown and SVG. The
// caller (cmd/observer/report.go) populates it from the cost engine. Every
// dollar figure is OBSERVED spend. NO project names, paths, or session titles
// ever appear here.
type Data struct {
	// PeriodKind is "week" or "month" — drives the "this week"/"this month"
	// phrasing. Any other value falls back to a neutral "this period".
	PeriodKind string
	// PeriodLabel is the human window label, e.g. "Jun 30 – Jul 6, 2026".
	PeriodLabel string
	// TotalUSD is the observed spend over the period.
	TotalUSD float64
	// TurnCount is the number of model turns that fed the total.
	TurnCount int
	// TopModels is the ranked (cost desc) per-model spend, already truncated by
	// the caller (top 3 for the card).
	TopModels []LineItem
	// Tools is the ranked (cost desc) per-tool spend (the tool mix).
	Tools []LineItem
	// CacheReadShare is the fraction [0,1] of input-side tokens served from
	// prefix cache (cache_read / (input + cache_read + cache_creation)).
	// HasCacheShare gates its rendering — a corpus with no cache columns should
	// not imply a real 0%.
	CacheReadShare float64
	HasCacheShare  bool
	// Version stamps the artifact provenance line.
	Version string
}

// periodPhrase renders "this week" / "this month" / "this period".
func (d Data) periodPhrase() string {
	switch strings.ToLower(strings.TrimSpace(d.PeriodKind)) {
	case "week", "weekly":
		return "this week"
	case "month", "monthly":
		return "this month"
	default:
		return "this period"
	}
}

// Markdown renders a copy-pasteable block summarizing the period's spend. It is
// deterministic and safe to paste into GitHub, Slack, or a social post.
func (d Data) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## My AI agent spend - %s\n\n", d.PeriodLabel)
	if d.TurnCount > 0 {
		fmt.Fprintf(&b, "**%s** observed %s across %s turns.\n",
			money(d.TotalUSD), d.periodPhrase(), integer(int64(d.TurnCount)))
	} else {
		fmt.Fprintf(&b, "**%s** observed %s.\n", money(d.TotalUSD), d.periodPhrase())
	}

	if len(d.TopModels) > 0 {
		b.WriteString("\n**Top models**\n")
		for _, m := range d.TopModels {
			fmt.Fprintf(&b, "- %s - %s\n", labelOrNone(m.Label), money(m.CostUSD))
		}
	}

	if d.HasCacheShare {
		fmt.Fprintf(&b, "\n**Cache-read share:** %s of input tokens served from cache.\n", percent(d.CacheReadShare))
	}

	if len(d.Tools) > 0 {
		names := make([]string, 0, len(d.Tools))
		for _, t := range d.Tools {
			names = append(names, labelOrNone(t.Label))
		}
		fmt.Fprintf(&b, "\n**Tool mix:** %s\n", strings.Join(names, ", "))
	}

	b.WriteString("\n_Tracked locally by superbased Observer - superbased.app_\n")
	return b.String()
}

// --- SVG ---------------------------------------------------------------------

// svgW / svgH are the social-card dimensions (1.91:1, the Open Graph ratio).
const (
	svgW = 1200
	svgH = 630
)

// svgBar is one leaderboard row in the rendered card: an already-escaped label,
// a formatted cost, and a precomputed fill width in px.
type svgBar struct {
	Label     string // XML-escaped
	Cost      string // formatted, safe
	FillWidth int
	Y         int // row top (px)
}

// svgView is the fully-prepared, injection-safe view model handed to the
// template. Every string is either XML-escaped user data or a self-formatted
// numeric — the template performs no escaping of its own.
type svgView struct {
	W, H          int
	Period        string // escaped
	TotalLabel    string // e.g. "OBSERVED SPEND · THIS WEEK"
	Total         string // "$1,234.56"
	HasCache      bool
	CacheShare    string // "63%"
	TurnCount     string // "1,204"
	HasTurns      bool
	Models        []svgBar
	HasModels     bool
	Tools         []svgBar
	HasTools      bool
	EmptyNote     string
	HasEmpty      bool
	ModelTrackW   int
	ModelTrackR   int // right edge of the model track (x + width)
	ToolTrackW    int
	ToolTrackR    int
	ModelX        int
	ToolX         int
	Colors        palette
	ModelHeadingY int
}

type palette struct {
	Base   string
	Panel  string
	Ink    string
	Muted  string
	Gold   string
	Teal   string
	Track  string
	Border string
}

// SVG renders the 1200×630 dark social card. No external resources: system
// fonts only, all geometry inline. Pure and deterministic.
func (d Data) SVG() string {
	const (
		modelX      = 72
		modelTrackW = 540
		toolX       = 680
		toolTrackW  = 456
		modelRowH   = 52
		modelRowTop = 372
	)

	view := svgView{
		W:           svgW,
		H:           svgH,
		Period:      xmlEscape(d.PeriodLabel),
		TotalLabel:  "OBSERVED SPEND",
		Total:       money(d.TotalUSD),
		ModelX:      modelX,
		ModelTrackW: modelTrackW,
		ModelTrackR: modelX + modelTrackW,
		ToolX:       toolX,
		ToolTrackW:  toolTrackW,
		ToolTrackR:  toolX + toolTrackW,
		Colors: palette{
			Base:   "#0D0D12",
			Panel:  "#16324F",
			Ink:    "#F5F2E8",
			Muted:  "#8FA6B8",
			Gold:   "#F4A024",
			Teal:   "#2EC4B6",
			Track:  "#1B2A3A",
			Border: "#243B52",
		},
	}
	if d.HasCacheShare {
		view.HasCache = true
		view.CacheShare = percent(d.CacheReadShare)
	}
	if d.TurnCount > 0 {
		view.HasTurns = true
		view.TurnCount = integer(int64(d.TurnCount))
	}

	view.Models = leaderboard(d.TopModels, modelTrackW, modelRowTop, modelRowH)
	view.HasModels = len(view.Models) > 0
	view.Tools = leaderboard(d.Tools, toolTrackW, modelRowTop, modelRowH)
	view.HasTools = len(view.Tools) > 0
	view.ModelHeadingY = modelRowTop - 28
	if !view.HasModels && !view.HasTools {
		view.HasEmpty = true
		view.EmptyNote = "No agent spend recorded " + d.periodPhrase() + "."
	}

	var buf bytes.Buffer
	if err := svgTemplate.Execute(&buf, view); err != nil {
		// The template is static and the view is plain data; an error here is a
		// programming bug, not a runtime condition. Fall back to a minimal valid
		// SVG rather than panicking in library code.
		return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d"></svg>`, svgW, svgH)
	}
	return buf.String()
}

// leaderboard converts ranked line items into escaped, geometry-ready bars. The
// widest bar (highest cost) fills the track; the rest scale linearly. Zero-cost
// rows render a hairline so the label still reads.
func leaderboard(items []LineItem, trackW, rowTop, rowH int) []svgBar {
	if len(items) == 0 {
		return nil
	}
	maxCost := 0.0
	for _, it := range items {
		if it.CostUSD > maxCost {
			maxCost = it.CostUSD
		}
	}
	bars := make([]svgBar, 0, len(items))
	for i, it := range items {
		fill := 4
		if maxCost > 0 {
			fill = int(math.Round(float64(trackW) * (it.CostUSD / maxCost)))
			if fill < 4 {
				fill = 4
			}
		}
		bars = append(bars, svgBar{
			Label:     xmlEscape(labelOrNone(it.Label)),
			Cost:      money(it.CostUSD),
			FillWidth: fill,
			Y:         rowTop + i*rowH,
		})
	}
	return bars
}

// --- formatting helpers ------------------------------------------------------

// money formats a USD amount with thousands separators and two decimals, e.g.
// "$1,234.56" — matching the dashboard's currency rendering.
func money(v float64) string {
	neg := v < 0
	if neg {
		v = -v
	}
	whole := int64(v)
	cents := int64(math.Round((v - float64(whole)) * 100))
	if cents == 100 { // rounding carry
		whole++
		cents = 0
	}
	// no-bare-usd:allow (the spend card; report share refuses it under the token display)
	s := "$" + group(whole) + fmt.Sprintf(".%02d", cents)
	if neg {
		return "-" + s
	}
	return s
}

// integer formats a whole number with thousands separators.
func integer(n int64) string {
	if n < 0 {
		return "-" + group(-n)
	}
	return group(n)
}

// group inserts thousands separators into a non-negative integer.
func group(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	return strings.Join(parts, ",")
}

// percent renders a [0,1] fraction as a whole-number percentage, e.g. "63%".
func percent(f float64) string {
	if f < 0 {
		f = 0
	}
	if f > 1 {
		f = 1
	}
	return fmt.Sprintf("%d%%", int(math.Round(f*100)))
}

// labelOrNone renders an empty label as a readable placeholder.
func labelOrNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(unattributed)"
	}
	return s
}

// xmlEscape escapes a string for safe inclusion in SVG/XML text and attribute
// contexts.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

var svgTemplate = template.Must(template.New("sharecard").Funcs(template.FuncMap{
	"add": func(a, b int) int { return a + b },
	"sub": func(a, b int) int { return a - b },
}).Parse(svgTemplateSrc))
