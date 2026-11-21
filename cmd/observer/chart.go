package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/costtext"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/intelligence/costseries"
	"github.com/marmutapp/superbased-observer/internal/termchart"
	"github.com/marmutapp/superbased-observer/internal/timebucket"
)

// `observer chart` draws usage charts in the terminal (docs/cli-chart.md,
// P-228 phase 1a). Spend and tokens by model come from costseries (the cost
// engine, bucketed by internal/timebucket), the seam the dashboard's
// /api/timeseries/cost and /api/timeseries/tokens-by-model read. The cache
// read share is cost.CacheReadShare (the share card's formula, not the Cache
// page's read/write ratio or Analysis's Cache Efficacy) over those same
// buckets; no dashboard chart draws that series. Drawing is internal/termchart.
// The command renders the developer cost display natively (dollars or token
// usage, costReportCommands row "chart").

// chartNow is the clock (tests pin it).
var chartNow = time.Now

// chartFlags are the flags every chart takes.
type chartFlags struct {
	configPath string
	days       int
	since      string
	until      string
	gran       string
	tz         string
	project    string
	tool       string
	width      int
	height     int
	top        int
	jsonOut    bool
	ascii      bool
	colorMode  string
}

func newChartCmd() *cobra.Command {
	f := &chartFlags{}
	cmd := &cobra.Command{
		Use:   "chart",
		Short: "Draw spend, tokens by model or cache read share as a terminal chart",
		Long: "Draws usage charts in the terminal from the same cost engine and bucket\n" +
			"rules the dashboard uses: window totals agree with the dashboard, and\n" +
			"per-bucket numbers agree when the zones match (--tz, default local).\n\n" +
			"  observer chart spend        spend per bucket (AI spend and tool fees)\n" +
			"  observer chart models       tokens by model: ranked bars, then top models over time\n" +
			"  observer chart cache-share  cache read share of input-side tokens per bucket\n\n" +
			"The window is --days (default 30) or --since/--until. Buckets follow the\n" +
			"dashboard's auto rule, coarsened when the terminal is too narrow; --gran\n" +
			"picks one. --json prints the series instead of the picture (for scripts\n" +
			"and agents). When your organization shows token usage instead of costs\n" +
			"on this machine, spend is drawn in tokens and dollar fields are left out.",
	}
	pf := cmd.PersistentFlags()
	pf.StringVar(&f.configPath, "config", "", "Path to config.toml")
	pf.IntVar(&f.days, "days", 30, "Window: the last N days (ignored when --since is set)")
	pf.StringVar(&f.since, "since", "", "Window start: RFC3339 or YYYY-MM-DD (in --tz)")
	pf.StringVar(&f.until, "until", "", "Window end (exclusive): RFC3339 or YYYY-MM-DD (in --tz); default now")
	pf.StringVar(&f.gran, "gran", "auto", "Bucket size: auto, 5m, 1h, 1d, 1w")
	pf.StringVar(&f.tz, "tz", "", "IANA zone for buckets and labels, or \"local\" (default: the system's local zone)")
	pf.StringVar(&f.project, "project", "", "Only this project root path")
	pf.StringVar(&f.tool, "tool", "", "Only this AI tool (sessions.tool, e.g. claude-code)")
	pf.IntVar(&f.width, "width", 0, "Chart width in columns (default: the terminal width, else 80)")
	pf.IntVar(&f.height, "height", termchart.DefaultHeight, "Plot height in rows")
	pf.BoolVar(&f.jsonOut, "json", false, "Print the series as JSON instead of a chart")
	pf.BoolVar(&f.ascii, "ascii", false, "Draw with 7-bit ASCII only")
	pf.StringVar(&f.colorMode, "color", "auto", "Colour: auto (a terminal and NO_COLOR unset), always, never")
	for _, c := range []struct {
		name, short string
		kind        chartKind
	}{
		{"spend", "Spend per bucket (dollars, or tokens under the token-usage display)", chartSpend},
		{"models", "Tokens by model: ranked totals, then the top models per bucket", chartModels},
		{"cache-share", "Cache read share per bucket: cache read / (input + cache read + cache write), the share card's formula", chartCacheShare},
	} {
		kind := c.kind
		sub := &cobra.Command{
			Use:   c.name,
			Short: c.short,
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return runChart(cmd, kind, f)
			},
		}
		if kind == chartModels {
			sub.Flags().IntVar(&f.top, "top", 8, "Models listed before the rest fold into \"other\"")
		}
		cmd.AddCommand(sub)
	}
	return cmd
}

type chartKind string

const (
	chartSpend      chartKind = "spend"
	chartModels     chartKind = "models"
	chartCacheShare chartKind = "cache-share"
)

// chartWindow is the resolved window and bucket spec.
type chartWindow struct {
	since, until time.Time // engine window; zero until = now
	spec         timebucket.Spec
}

func runChart(cmd *cobra.Command, kind chartKind, f *chartFlags) error {
	mode := costModeFrom(cmd.Context())
	opts := termchart.Options{Width: f.width, Height: f.height, ASCII: f.ascii}
	if opts.Width <= 0 {
		opts.Width = chartTerminalWidth()
	}
	color, err := chartColor(f.colorMode, f.ascii)
	if err != nil {
		return err
	}
	opts.Color = color
	capacity := termchart.ColumnsCapacity(opts)
	if kind == chartCacheShare {
		capacity = termchart.LineCapacity(opts)
	}
	win, err := resolveChartWindow(f, capacity)
	if err != nil {
		return err
	}

	cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), f.configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	engine := acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default())
	q := costseries.Query{
		Spec: win.spec, Days: f.days, Since: win.since, Until: win.until,
		Tool: f.tool, Project: f.project,
	}
	out := cmd.OutOrStdout()
	switch kind {
	case chartModels:
		points, grid, err := costseries.TokensByModel(cmd.Context(), engine, database, q)
		if err != nil {
			return err
		}
		if !f.jsonOut {
			starts := make([]time.Time, len(grid))
			for i, g := range grid {
				starts[i] = g.T
			}
			if err := chartPostFit(win.spec, starts, capacity); err != nil {
				return err
			}
		}
		return renderModelsChart(out, win, points, grid, f, mode, opts)
	default:
		buckets, err := costseries.Cost(cmd.Context(), engine, database, q)
		if err != nil {
			return err
		}
		if !f.jsonOut {
			starts := make([]time.Time, len(buckets))
			for i, b := range buckets {
				starts[i] = b.T
			}
			if err := chartPostFit(win.spec, starts, capacity); err != nil {
				return err
			}
		}
		if kind == chartCacheShare {
			return renderCacheShareChart(out, win, buckets, f, opts)
		}
		return renderSpendChart(out, win, buckets, f, mode, opts)
	}
}

// chartTerminalWidth is stdout's width when it is a terminal, else 80.
func chartTerminalWidth() int {
	if stdoutIsTerminal() {
		if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 { //nolint:gosec // G115: a file descriptor fits an int
			return w
		}
	}
	return termchart.DefaultWidth
}

// chartStdoutIsTTY reports whether stdout is a terminal. A package var so
// tests can decide it and assert the NO_COLOR and TERM rules on their own.
var chartStdoutIsTTY = stdoutIsTerminal

// chartColor resolves --color. auto colours only a terminal with NO_COLOR
// unset or empty (https://no-color.org) and TERM not "dumb"; ASCII never
// colours.
func chartColor(mode string, ascii bool) (bool, error) {
	switch strings.ToLower(mode) {
	case "", "auto":
		return !ascii && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" && chartStdoutIsTTY(), nil
	case "always":
		return !ascii, nil
	case "never":
		return false, nil
	default:
		return false, fmt.Errorf("--color %q not in {auto, always, never}", mode)
	}
}

// chartSystemZone is the zone the dashboard's viewer most likely has: the
// system's local zone and its IANA name ("" when the system does not say).
// A package var so tests pin it.
var chartSystemZone = systemZone

// systemZone returns the system's local zone and an IANA name for it.
//
// $TZ is checked here first, on every OS: when it names a zone, that zone
// and name win. This matters on Windows, where Go builds time.Local from the
// system time zone setting and ignores $TZ; on Unix Go builds time.Local
// from $TZ, else /etc/localtime, so the two agree. Without a usable $TZ the
// zone is time.Local, named on Unix by the zoneinfo path the /etc/localtime
// link points at; on Windows (or a copied /etc/localtime) no IANA name is
// available and the name is "". The name only labels output; buckets follow
// the location's own rules either way.
func systemZone() (*time.Location, string) {
	if v, ok := os.LookupEnv("TZ"); ok {
		v = strings.TrimPrefix(v, ":")
		if v == "" {
			return time.UTC, "UTC" // Go reads an empty TZ as UTC
		}
		if l, name, fellBack := timebucket.LoadZone(v); !fellBack {
			return l, name
		}
		return time.Local, ""
	}
	if runtime.GOOS != "windows" {
		if target, err := os.Readlink("/etc/localtime"); err == nil {
			if i := strings.LastIndex(target, "zoneinfo/"); i >= 0 {
				if _, name, fellBack := timebucket.LoadZone(target[i+len("zoneinfo/"):]); !fellBack {
					return time.Local, name
				}
			}
		}
	}
	return time.Local, ""
}

// chartZoneLocal is the --tz value (and the window.tz label) for the system
// zone when it has no IANA name. --tz accepts it, so every window.tz the
// command prints can be passed back as --tz.
const chartZoneLocal = "local"

// chartZone resolves --tz: empty or "local" is the system zone; anything
// else must be an IANA name (unknown is an error, not a silent UTC). The
// name is "local" when the system gives none.
func chartZone(flag string) (*time.Location, string, error) {
	if flag != "" && !strings.EqualFold(flag, chartZoneLocal) {
		l, name, fellBack := timebucket.LoadZone(flag)
		if fellBack {
			return nil, "", fmt.Errorf("--tz %q is not an IANA zone name (for example Europe/Berlin or UTC)", flag)
		}
		return l, name, nil
	}
	l, name := chartSystemZone()
	if name == "" {
		name = chartZoneLocal
	}
	return l, name, nil
}

// parseChartTime reads RFC3339 or a bare date in loc.
func parseChartTime(s string, loc *time.Location) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, loc); err == nil {
		return t.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%q is not RFC3339 or YYYY-MM-DD", s)
}

// resolveChartWindow resolves the window and the bucket. Auto starts from the
// dashboard's own Auto granularity for the span and, for a drawn chart, walks
// to a coarser one until the buckets fit the width (never finer than the
// dashboard). An explicit --gran is used as given; a drawn chart with more
// buckets than columns is an error naming the fix. --json is never limited
// by the width.
func resolveChartWindow(f *chartFlags, capacity int) (chartWindow, error) {
	now := chartNow().UTC()
	var w chartWindow
	loc, tz, err := chartZone(f.tz)
	if err != nil {
		return w, err
	}
	if f.until != "" {
		t, err := parseChartTime(f.until, loc)
		if err != nil {
			return w, fmt.Errorf("--until: %w", err)
		}
		w.until = t
	}
	switch {
	case f.since != "":
		t, err := parseChartTime(f.since, loc)
		if err != nil {
			return w, fmt.Errorf("--since: %w", err)
		}
		w.since = t
	case f.days >= 1:
		w.since = now.Add(-time.Duration(f.days) * 24 * time.Hour)
	default:
		return w, errors.New("--days must be at least 1 (or pass --since)")
	}
	end := now
	if !w.until.IsZero() {
		end = w.until
	}
	if !end.After(w.since) {
		return w, errors.New("the window is empty: --since must be before --until")
	}
	gran := strings.ToLower(f.gran)
	if gran == "auto" {
		gran = ""
	}
	resolve := func(g string) (timebucket.Spec, error) {
		return timebucket.Resolve(timebucket.Request{Gran: g, TZ: tz, Loc: loc, Since: w.since, Until: w.until, Now: now})
	}
	if gran == "" && !f.jsonOut {
		span := end.Sub(w.since).Round(time.Second)
		start := timebucket.Choose(span)
		seen := false
		var last error
		for _, r := range timebucket.Table {
			if r.Gran == start {
				seen = true
			}
			if !seen {
				continue
			}
			sp, err := resolve(string(r.Gran))
			if err == nil {
				err = chartPreFit(sp, capacity)
			}
			if err == nil {
				gran = string(r.Gran)
				break
			}
			last = err
		}
		if gran == "" {
			// The coarsest bucket's own reason: it names --width only when
			// the width is what refused it.
			return w, last
		}
	}
	spec, err := resolve(gran)
	if err != nil {
		return w, err
	}
	spec.Auto = f.gran == "" || strings.EqualFold(f.gran, "auto")
	w.spec = spec
	if !f.jsonOut {
		if err := chartPreFit(spec, capacity); err != nil {
			return w, err
		}
	}
	return w, nil
}

// chartDataBounded reports a granularity whose zero-fill grid, for a window
// over timebucket.MaxPoints, starts at the earliest bucket holding data
// instead of vanishing (timebucket's always-allowed day and week rows). A
// chart over such a window is drawn honestly from that bucket, as
// costseries already returns it, so only the data can say whether it fits.
func chartDataBounded(g timebucket.Granularity) bool {
	for _, r := range timebucket.Table {
		if r.Gran == g {
			return r.AlwaysAllowed
		}
	}
	return false
}

// chartPreFit is the width check before the query. A window with a grid
// fits when its slots do. A window with no grid is refused when its bucket
// is not data-bounded (its axis would hold only the buckets that have
// data); a data-bounded one passes here and chartPostFit decides from the
// buckets costseries returns.
func chartPreFit(spec timebucket.Spec, capacity int) error {
	if chartGridMissing(spec) {
		if chartDataBounded(spec.Gran) {
			return nil
		}
		return chartNoGrid(spec.Gran, false)
	}
	if n := chartSlotCount(spec); n > capacity {
		return chartTooWide(spec.Gran, n, capacity)
	}
	return nil
}

// chartPostFit is the width check after the query, over the bucket starts
// the renderer will draw. When the window's own grid is over the cap the
// axis starts at the earliest data bucket; if even that grid is over the
// cap the buckets are not contiguous and the chart is refused, and
// otherwise the drawn buckets must fit the width.
func chartPostFit(spec timebucket.Spec, starts []time.Time, capacity int) error {
	if len(starts) == 0 {
		return nil
	}
	var earliest time.Time
	for _, t := range starts {
		if !t.IsZero() && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	if spec.Span() > 0 && spec.Grid(earliest) == nil {
		return chartNoGrid(spec.Gran, true)
	}
	if n := len(starts); n > capacity {
		return chartTooWide(spec.Gran, n, capacity)
	}
	return nil
}

// chartNoGrid is the refusal of an axis over timebucket.MaxPoints. No width
// can draw it, so it never suggests --width.
func chartNoGrid(g timebucket.Granularity, fromData bool) error {
	where := "over this window"
	if fromData {
		where = "from the earliest data in this window"
	}
	return fmt.Errorf("%s buckets %s are more than %d points, the most a chart axis holds; use a coarser --gran, a shorter window, or --json", g, where, timebucket.MaxPoints)
}

// chartSlotCount is how many buckets a drawn chart gets for spec: the
// length of the zero-filled grid timebucket.Slots builds, the same slots
// costseries hands the renderer (data outside the grid can add a slot; the
// renderer's own check catches that one, see chartFit).
//
// A window whose grid would exceed timebucket.MaxPoints has NO window grid
// (Spec.Grid returns nil); the count then is more than the cap, never zero.
// chartPreFit and chartPostFit decide what such a window may draw.
func chartSlotCount(spec timebucket.Spec) int {
	if n := len(timebucket.Slots(spec, nil)); n > 0 || spec.Span() <= 0 {
		return n
	}
	return max(timebucket.Points(spec.Span(), spec.Gran), timebucket.MaxPoints+1)
}

// chartGridMissing reports a non-empty window with no window grid (wider
// than timebucket.MaxPoints at spec's bucket).
func chartGridMissing(spec timebucket.Spec) bool {
	return spec.Span() > 0 && len(timebucket.Slots(spec, nil)) == 0
}

// chartTooWide is the refusal of an axis the width cannot draw (but a wider
// terminal could).
func chartTooWide(g timebucket.Granularity, n, capacity int) error {
	return fmt.Errorf("%s buckets over this window are %d points, more than %d columns can draw; widen --width, or use a coarser --gran, a shorter window, or --json", g, n, capacity)
}

// chartFit turns the renderer's too-many-points refusal into the same
// actionable message the window check gives.
func chartFit(err error, g timebucket.Granularity, n, capacity int) error {
	if errors.Is(err, termchart.ErrTooManyPoints) {
		return chartTooWide(g, n, capacity)
	}
	return err
}

// granNoun names a bucket for a title.
func granNoun(g timebucket.Granularity) string {
	switch g {
	case timebucket.Min5:
		return "5 minutes"
	case timebucket.Hour:
		return "hour"
	case timebucket.Week:
		return "week"
	default:
		return "day"
	}
}

// chartLabel is a bucket's x-axis label in the spec's zone.
func chartLabel(spec timebucket.Spec, t time.Time) string {
	if t.IsZero() {
		return "?"
	}
	t = t.In(spec.Loc)
	if spec.Gran.SubDay() {
		return t.Format("01-02 15:04")
	}
	return t.Format("01-02")
}

// chartTitle is "<what> per <bucket>, <first> to <last> <tz>".
//
// first is the first drawn bucket's start. When it is more than a bucket
// after the window start, the axis was bounded by the earliest data (a day
// or week window over the point cap, chartPostFit), and the title says so
// rather than claiming an axis that starts at the window start.
func chartTitle(what string, win chartWindow, n int, first time.Time) string {
	end := win.spec.Until.Add(-time.Second).In(win.spec.Loc)
	start := win.spec.Since.In(win.spec.Loc)
	layout := "2006-01-02"
	if win.spec.Gran.SubDay() {
		layout = "2006-01-02 15:04"
	}
	if !first.IsZero() && first.After(win.spec.Since.Add(win.spec.Gran.Step())) {
		return fmt.Sprintf("%s per %s, %s to %s %s (%d buckets from the first data; the window starts %s)",
			what, granNoun(win.spec.Gran), first.In(win.spec.Loc).Format(layout), end.Format(layout), win.spec.TZ, n, start.Format(layout))
	}
	return fmt.Sprintf("%s per %s, %s to %s %s (%d buckets)", what, granNoun(win.spec.Gran), start.Format(layout), end.Format(layout), win.spec.TZ, n)
}

// firstBucket is the first slot's start, zero when there are none.
func firstBucket(buckets []costseries.Bucket) time.Time {
	if len(buckets) == 0 {
		return time.Time{}
	}
	return buckets[0].T
}

// chartUSD is a compact dollar tick ("$0.50", "$12.40", "$340", "$1.2K").
func chartUSD(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("$%.1fM", v/1e6)
	case v >= 1e4:
		return fmt.Sprintf("$%.1fK", v/1e3)
	case v >= 100:
		return fmt.Sprintf("$%.0f", v)
	default:
		return fmt.Sprintf("$%.2f", v)
	}
}

// chartTokens is a compact token figure ("950", "212.4K", "1.5M").
func chartTokens(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.1fB", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fK", v/1e3)
	default:
		return fmt.Sprintf("%.0f", v)
	}
}

func chartPct(v float64) string { return fmt.Sprintf("%.0f%%", v*100) }

// chartBucketJSON is the per-bucket JSON point of the spend and cache charts.
// Dollar fields are nil (left out) under the token-usage display.
type chartBucketJSON struct {
	Bucket        string   `json:"bucket"`
	T             string   `json:"t"`
	Input         int64    `json:"input"`
	Output        int64    `json:"output"`
	CacheRead     int64    `json:"cache_read"`
	CacheCreation int64    `json:"cache_creation"`
	TotalTokens   int64    `json:"total_tokens"`
	Turns         int      `json:"turns"`
	CostUSD       *float64 `json:"cost_usd,omitempty"`
	AICostUSD     *float64 `json:"ai_cost_usd,omitempty"`
	ToolCostUSD   *float64 `json:"tool_cost_usd,omitempty"`
	// CacheReadShare is cost.CacheReadShare; null when the bucket has no
	// input-side tokens (unknown, not zero).
	CacheReadShare *float64 `json:"cache_read_share"`
}

type chartWindowJSON struct {
	Since    string `json:"since"`
	Until    string `json:"until"`
	Gran     string `json:"gran"`
	GranAuto bool   `json:"gran_auto"`
	TZ       string `json:"tz"`
}

func windowJSON(win chartWindow) chartWindowJSON {
	return chartWindowJSON{
		Since: win.spec.Since.UTC().Format(time.RFC3339), Until: win.spec.Until.UTC().Format(time.RFC3339),
		Gran: string(win.spec.Gran), GranAuto: win.spec.Auto, TZ: win.spec.TZ,
	}
}

func bucketJSON(b costseries.Bucket, dollars bool) chartBucketJSON {
	tk := b.Row.Tokens
	p := chartBucketJSON{
		Bucket: b.Key, Input: tk.Input, Output: tk.Output, CacheRead: tk.CacheRead,
		CacheCreation: tk.CacheCreation, TotalTokens: costseries.TotalTokens(tk), Turns: b.Row.TurnCount,
	}
	if !b.T.IsZero() {
		p.T = b.T.UTC().Format(time.RFC3339)
	}
	if dollars {
		c, a, tl := b.Row.CostUSD, b.Row.AICostUSD, b.Row.ToolCostUSD
		p.CostUSD, p.AICostUSD, p.ToolCostUSD = &c, &a, &tl
	}
	if r, ok := cost.CacheReadShare(tk); ok {
		p.CacheReadShare = &r
	}
	return p
}

func writeChartJSON(out io.Writer, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, string(body))
	return err
}

func renderSpendChart(out io.Writer, win chartWindow, buckets []costseries.Bucket, f *chartFlags, mode string, o termchart.Options) error {
	dollars := !costtext.Tokens(mode)
	if f.jsonOut {
		series := make([]chartBucketJSON, 0, len(buckets))
		for _, b := range buckets {
			series = append(series, bucketJSON(b, dollars))
		}
		display := costtext.ModeUSD
		if !dollars {
			display = costtext.ModeTokens
		}
		return writeChartJSON(out, map[string]any{
			"chart": "spend", "window": windowJSON(win), "display": display, "series": series,
		})
	}
	labels := make([]string, len(buckets))
	var tokens cost.TokenBundle
	var totalUSD, toolUSD float64
	turns := 0
	for i, b := range buckets {
		labels[i] = chartLabel(win.spec, b.T)
		tokens.Add(b.Row.Tokens)
		totalUSD += b.Row.CostUSD
		toolUSD += b.Row.ToolCostUSD
		turns += b.Row.TurnCount
	}
	if turns == 0 {
		fmt.Fprintln(out, chartTitle("Spend", win, len(buckets), firstBucket(buckets)))
		fmt.Fprintln(out, "No usage in this window.")
		return nil
	}
	var series []termchart.Series
	var format termchart.Format
	what := "Spend"
	if dollars {
		ai := make([]float64, len(buckets))
		fees := make([]float64, len(buckets))
		for i, b := range buckets {
			ai[i], fees[i] = b.Row.AICostUSD, b.Row.ToolCostUSD
		}
		series = []termchart.Series{{Name: "AI spend", Values: ai}}
		if toolUSD > 0 {
			series = append(series, termchart.Series{Name: "tool fees", Values: fees})
		}
		format = chartUSD
	} else {
		what = "Token usage"
		names := []string{"input", "output", "cache read", "cache write"}
		vals := make([][]float64, 4)
		for k := range vals {
			vals[k] = make([]float64, len(buckets))
		}
		for i, b := range buckets {
			t := b.Row.Tokens
			vals[0][i], vals[1][i], vals[2][i], vals[3][i] = float64(t.Input), float64(t.Output), float64(t.CacheRead), float64(t.CacheCreation)
		}
		for k, n := range names {
			series = append(series, termchart.Series{Name: n, Values: vals[k]})
		}
		format = chartTokens
	}
	plot, err := termchart.Columns(labels, series, format, o)
	if err != nil {
		return chartFit(err, win.spec.Gran, len(labels), termchart.ColumnsCapacity(o))
	}
	fmt.Fprintln(out, chartTitle(what, win, len(buckets), firstBucket(buckets)))
	fmt.Fprintln(out)
	fmt.Fprint(out, plot)
	fmt.Fprintln(out)
	if dollars {
		fmt.Fprintf(out, "Total %s over %d turns", chartUSDTotal(totalUSD), turns)
		if toolUSD > 0 {
			fmt.Fprintf(out, " (tool fees %s)", chartUSDTotal(toolUSD))
		}
		fmt.Fprintln(out, ".")
	} else {
		fmt.Fprintf(out, "Total %s tokens over %d turns.\n", chartTokens(float64(costseries.TotalTokens(tokens))), turns)
		fmt.Fprintln(out, tokenViewNote)
	}
	return nil
}

// chartUSDTotal is a total in full ("$1,234.56" style without separators).
func chartUSDTotal(v float64) string { return fmt.Sprintf("$%.2f", v) }

// modelTotal is one model's window total.
type modelTotal struct {
	Model       string   `json:"model"`
	TotalTokens int64    `json:"total_tokens"`
	Share       float64  `json:"share"`
	Turns       int      `json:"turns"`
	CostUSD     *float64 `json:"cost_usd,omitempty"`
}

type modelPointJSON struct {
	Bucket        string   `json:"bucket"`
	T             string   `json:"t"`
	Model         string   `json:"model"`
	Input         int64    `json:"input"`
	Output        int64    `json:"output"`
	CacheRead     int64    `json:"cache_read"`
	CacheCreation int64    `json:"cache_creation"`
	TotalTokens   int64    `json:"total_tokens"`
	Turns         int      `json:"turns"`
	CostUSD       *float64 `json:"cost_usd,omitempty"`
}

// stackedModels is how many top models get their own stack in the
// over-time columns (the rest are "other"), so the stack stays within the
// shades a no-colour terminal can tell apart.
const stackedModels = termchart.MaxShades - 1

func renderModelsChart(out io.Writer, win chartWindow, points []costseries.ModelPoint, grid []timebucket.GridSlot, f *chartFlags, mode string, o termchart.Options) error {
	dollars := !costtext.Tokens(mode)
	byModel := map[string]*modelTotal{}
	usd := map[string]float64{}
	var all int64
	for _, p := range points {
		m := byModel[p.Model]
		if m == nil {
			m = &modelTotal{Model: p.Model}
			byModel[p.Model] = m
		}
		n := costseries.TotalTokens(p.Row.Tokens)
		m.TotalTokens += n
		m.Turns += p.Row.TurnCount
		usd[p.Model] += p.Row.CostUSD
		all += n
	}
	totals := make([]*modelTotal, 0, len(byModel))
	for _, m := range byModel {
		if all > 0 {
			m.Share = float64(m.TotalTokens) / float64(all)
		}
		if dollars {
			c := usd[m.Model]
			m.CostUSD = &c
		}
		totals = append(totals, m)
	}
	sort.Slice(totals, func(i, j int) bool {
		if totals[i].TotalTokens != totals[j].TotalTokens {
			return totals[i].TotalTokens > totals[j].TotalTokens
		}
		return totals[i].Model < totals[j].Model
	})
	if f.jsonOut {
		series := make([]modelPointJSON, 0, len(points))
		for _, p := range points {
			tk := p.Row.Tokens
			mp := modelPointJSON{
				Bucket: p.Bucket, Model: p.Model, Input: tk.Input, Output: tk.Output, CacheRead: tk.CacheRead,
				CacheCreation: tk.CacheCreation, TotalTokens: costseries.TotalTokens(tk), Turns: p.Row.TurnCount,
			}
			if !p.T.IsZero() {
				mp.T = p.T.UTC().Format(time.RFC3339)
			}
			if dollars {
				c := p.Row.CostUSD
				mp.CostUSD = &c
			}
			series = append(series, mp)
		}
		gridOut := make([]map[string]string, 0, len(grid))
		for _, g := range grid {
			t := ""
			if !g.T.IsZero() {
				t = g.T.UTC().Format(time.RFC3339)
			}
			gridOut = append(gridOut, map[string]string{"bucket": g.Key, "t": t})
		}
		return writeChartJSON(out, map[string]any{
			"chart": "models", "window": windowJSON(win), "totals": totals, "series": series, "grid": gridOut,
		})
	}
	var first time.Time
	if len(grid) > 0 {
		first = grid[0].T
	}
	title := chartTitle("Tokens by model", win, len(grid), first)
	if all == 0 {
		fmt.Fprintln(out, title)
		fmt.Fprintln(out, "No usage in this window.")
		return nil
	}
	top := f.top
	if top < 1 {
		top = 1
	}
	// The bars and the stacked columns share one split: the first nStack
	// models keep their own tone, everything after shares "other"'s.
	nStack := min(len(totals), stackedModels, top)
	hasOther := len(totals) > nStack
	tone := func(rank int) int { return min(rank, nStack) }
	var bars []termchart.Bar
	for i, m := range totals {
		if i == top && len(totals) > top {
			var rest int64
			for _, r := range totals[top:] {
				rest += r.TotalTokens
			}
			bars = append(bars, termchart.Bar{
				Label: fmt.Sprintf("other (%d models)", len(totals)-top), Value: float64(rest),
				Note: chartPct(float64(rest) / float64(all)), Tone: nStack,
			})
			break
		}
		bars = append(bars, termchart.Bar{Label: m.Model, Value: float64(m.TotalTokens), Note: chartPct(m.Share), Tone: tone(i)})
	}

	// Over time: the top models stacked, the rest folded into "other".
	idx := map[string]int{}
	for i, g := range grid {
		idx[g.Key] = i
	}
	series := make([]termchart.Series, 0, nStack+1)
	slot := map[string]int{}
	for i := 0; i < nStack; i++ {
		series = append(series, termchart.Series{Name: totals[i].Model, Values: make([]float64, len(grid))})
		slot[totals[i].Model] = i
	}
	if hasOther {
		series = append(series, termchart.Series{Name: "other", Values: make([]float64, len(grid))})
	}
	for _, p := range points {
		gi, ok := idx[p.Bucket]
		if !ok {
			continue
		}
		s, ok := slot[p.Model]
		if !ok {
			s = nStack
		}
		series[s].Values[gi] += float64(costseries.TotalTokens(p.Row.Tokens))
	}
	labels := make([]string, len(grid))
	for i, g := range grid {
		labels[i] = chartLabel(win.spec, g.T)
	}
	plot, err := termchart.Columns(labels, series, chartTokens, o)
	if err != nil {
		return chartFit(err, win.spec.Gran, len(labels), termchart.ColumnsCapacity(o))
	}
	fmt.Fprintln(out, title)
	fmt.Fprintln(out)
	fmt.Fprint(out, termchart.Bars(bars, chartTokens, o))
	fmt.Fprintln(out)
	if hasOther {
		fmt.Fprintf(out, "Tokens per %s, top %d models and the rest as other:\n\n", granNoun(win.spec.Gran), nStack)
	} else {
		fmt.Fprintf(out, "Tokens per %s by model:\n\n", granNoun(win.spec.Gran))
	}
	fmt.Fprint(out, plot)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Total %s tokens across %d models. Tokens = input + output + cache read + cache write.\n", chartTokens(float64(all)), len(totals))
	return nil
}

func renderCacheShareChart(out io.Writer, win chartWindow, buckets []costseries.Bucket, f *chartFlags, o termchart.Options) error {
	if f.jsonOut {
		series := make([]chartBucketJSON, 0, len(buckets))
		var tk cost.TokenBundle
		for _, b := range buckets {
			p := bucketJSON(b, false)
			series = append(series, p)
			tk.Add(b.Row.Tokens)
		}
		var overall *float64
		if r, ok := cost.CacheReadShare(tk); ok {
			overall = &r
		}
		return writeChartJSON(out, map[string]any{
			"chart": "cache_share", "window": windowJSON(win),
			"formula": "cache_read / (input + cache_read + cache_creation)",
			"overall": overall, "series": series,
		})
	}
	labels := make([]string, len(buckets))
	rates := make([]float64, len(buckets))
	volume := make([]float64, len(buckets))
	var tk cost.TokenBundle
	known := 0
	for i, b := range buckets {
		labels[i] = chartLabel(win.spec, b.T)
		rates[i] = math.NaN()
		if r, ok := cost.CacheReadShare(b.Row.Tokens); ok {
			rates[i] = r
			known++
		}
		t := b.Row.Tokens
		volume[i] = float64(t.Input + t.CacheRead + t.CacheCreation)
		tk.Add(t)
	}
	title := chartTitle("Cache read share", win, len(buckets), firstBucket(buckets))
	overall, ok := cost.CacheReadShare(tk)
	if !ok {
		fmt.Fprintln(out, title)
		fmt.Fprintln(out, "No input-side tokens in this window.")
		return nil
	}
	plot, err := termchart.Line(labels, rates, 0, 1, chartPct, o)
	if err != nil {
		return chartFit(err, win.spec.Gran, len(labels), termchart.LineCapacity(o))
	}
	fmt.Fprintln(out, title)
	fmt.Fprintln(out)
	fmt.Fprint(out, plot)
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Overall %.1f%% of input-side tokens were read from cache (cache read / (input + cache read + cache write)).\n", overall*100)
	if gaps := len(buckets) - known; gaps > 0 {
		fmt.Fprintf(out, "%d of %d buckets had no input-side tokens and are left blank.\n", gaps, len(buckets))
	}
	// The volume behind each rate: a rate over few tokens is noisy.
	if prefix := "Input-side tokens per bucket: "; len(volume)+len(prefix) <= o.Width {
		fmt.Fprintf(out, "%s%s\n", prefix, termchart.Sparkline(volume, o))
	}
	return nil
}
