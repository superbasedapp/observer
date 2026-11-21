package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/costtext"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/timebucket"
)

var updateChartGolden = flag.Bool("update-chart", false, "rewrite cmd/observer/testdata/chart goldens")

// chartTestEnd is the fixed window end of every chart test.
var chartTestEnd = time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)

// seedChartCorpus writes a temp DB with proxy turns over October 2026 for
// two tools and four models (with cache reads and writes), plus a config
// pointing at it. Returns the config path.
func seedChartCorpus(t *testing.T) string {
	t.Helper()
	return seedChartCorpusWith(t, nil)
}

// seedChartCorpusWith is seedChartCorpus plus extra turns (priced models
// only).
func seedChartCorpusWith(t *testing.T, extra []chartTurn) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "o.db")
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()
	var pid int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES ('/work/app', '2026-10-01T00:00:00Z') RETURNING id`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	for _, s := range []struct{ id, tool string }{{"cc", "claude-code"}, {"cx", "codex"}} {
		if _, err := database.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, ?, '2026-10-01T00:00:00Z')`, s.id, pid, s.tool); err != nil {
			t.Fatal(err)
		}
	}
	for i, tr := range append(chartCorpusTurns(), extra...) {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO api_turns (session_id, project_id, timestamp, provider, model,
				input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, request_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			tr.sid, pid, tr.ts.Format(time.RFC3339Nano), tr.provider, tr.model, tr.in, tr.out, tr.cr, tr.cc, fmt.Sprintf("r%d", i+1)); err != nil {
			t.Fatal(err)
		}
	}
	// Every corpus model is priced in the config, so the goldens and totals
	// do not move when the embedded price snapshot or a pricing feed does
	// (a local [intelligence.pricing.models] row wins last on a node with
	// no org pricing).
	var cfgText strings.Builder
	fmt.Fprintf(&cfgText, "[observer]\ndb_path = %q\n", dbPath)
	for _, m := range chartCorpusModels {
		p := chartPinnedPrices[m.model]
		fmt.Fprintf(&cfgText, "\n[intelligence.pricing.models.%q]\ninput = %v\noutput = %v\ncache_read = %v\ncache_creation = %v\ncache_creation_1h = %v\n",
			m.model, p.in, p.out, p.cr, p.cc, p.cc)
	}
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgText.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// chartCorpusModels are the corpus's (session, model, provider) triples.
var chartCorpusModels = []struct {
	sid, model, provider string
}{
	{"cc", "claude-sonnet-4-5", "anthropic"},
	{"cc", "claude-opus-4-1", "anthropic"},
	{"cc", "claude-haiku-4-5", "anthropic"},
	{"cx", "gpt-5", "openai"},
}

// chartPinnedPrices are the test config's prices, USD per million tokens.
// They are deliberately NOT any vendor's list price, so
// TestChartUsesPinnedPrices fails if a seed or feed price leaks through.
var chartPinnedPrices = map[string]struct{ in, out, cr, cc float64 }{
	"claude-sonnet-4-5": {2, 10, 0.2, 2.5},
	"claude-opus-4-1":   {10, 50, 1, 12.5},
	"claude-haiku-4-5":  {0.5, 2.5, 0.05, 0.625},
	"gpt-5":             {1, 8, 0.1, 0},
}

type chartTurn struct {
	sid, model, provider string
	ts                   time.Time
	in, out, cr, cc      int64
}

// chartCorpusTurns is the deterministic October 2026 corpus.
func chartCorpusTurns() []chartTurn {
	var out []chartTurn
	for day := 1; day <= 30; day++ {
		if day%9 == 0 {
			continue // an idle day: a zero bucket and a cache-share gap
		}
		for mi, m := range chartCorpusModels {
			if (day+mi)%4 == 0 {
				continue
			}
			tr := chartTurn{
				sid: m.sid, model: m.model, provider: m.provider,
				ts:  time.Date(2026, 10, day, 9+mi, 30, 0, 0, time.UTC),
				in:  int64(2000 + 300*((day*7+mi*3)%11)),
				out: int64(400 + 50*((day+mi)%7)),
				cr:  int64(20000 + 4000*((day*3+mi)%9)),
				cc:  int64(1500 * ((day + mi) % 3)),
			}
			if m.model == "gpt-5" {
				tr.cr = int64(3000 * ((day % 5) + 1))
				tr.cc = 0
			}
			out = append(out, tr)
		}
	}
	return out
}

// TestChartUsesPinnedPrices: the spend total is exactly the corpus priced
// at the config's pinned rates, so no seed or feed price reaches the
// goldens.
func TestChartUsesPinnedPrices(t *testing.T) {
	cfg := seedChartCorpus(t)
	want := 0.0
	for _, tr := range chartCorpusTurns() {
		p := chartPinnedPrices[tr.model]
		want += (float64(tr.in)*p.in + float64(tr.out)*p.out + float64(tr.cr)*p.cr + float64(tr.cc)*p.cc) / 1e6
	}
	out, err := runChartCmd(t, "", "spend", "--config", cfg, "--since", "2026-10-01", "--until", "2026-10-31", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Series []struct {
			CostUSD *float64 `json:"cost_usd"`
		} `json:"series"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	got := 0.0
	for _, p := range doc.Series {
		if p.CostUSD != nil {
			got += *p.CostUSD
		}
	}
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("spend total $%.6f, want $%.6f from the pinned prices", got, want)
	}
}

func runChartCmd(t *testing.T, mode string, args ...string) (string, error) {
	t.Helper()
	return runChartCmdIn(t, mode, func() (*time.Location, string) { return time.UTC, "UTC" }, args...)
}

// runChartCmdZone runs the command with the system zone injected.
func runChartCmdZone(t *testing.T, zone func() (*time.Location, string), args ...string) (string, error) {
	t.Helper()
	return runChartCmdIn(t, "", zone, args...)
}

func runChartCmdIn(t *testing.T, mode string, zone func() (*time.Location, string), args ...string) (string, error) {
	t.Helper()
	prev := chartNow
	chartNow = func() time.Time { return chartTestEnd }
	prevZone := chartSystemZone
	chartSystemZone = zone
	t.Cleanup(func() { chartNow, chartSystemZone = prev, prevZone })
	cmd := newChartCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	ctx := context.Background()
	if mode != "" {
		ctx = context.WithValue(ctx, costModeKey{}, mode)
	}
	err := cmd.ExecuteContext(ctx)
	return out.String(), err
}

func chartGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "chart", name+".golden")
	if *updateChartGolden {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test ./cmd/observer -run %s -update-chart)", err, t.Name())
	}
	if got != string(want) {
		t.Errorf("%s differs\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func TestChartGolden(t *testing.T) {
	cfg := seedChartCorpus(t)
	window := []string{"--config", cfg, "--since", "2026-10-01", "--until", "2026-10-31", "--color", "never"}
	cases := []struct {
		name string
		mode string
		args []string
	}{
		{"spend_80", "", []string{"spend", "--width", "80"}},
		{"spend_tokens_80", costtext.ModeTokens, []string{"spend", "--width", "80"}},
		{"spend_ascii_80", "", []string{"spend", "--width", "80", "--ascii"}},
		{"spend_codex_80", "", []string{"spend", "--width", "80", "--tool", "codex"}},
		{"models_80", "", []string{"models", "--width", "80"}},
		{"models_top2_60", "", []string{"models", "--width", "60", "--top", "2"}},
		{"cache_share_80", "", []string{"cache-share", "--width", "80"}},
		{"cache_share_ascii_120", "", []string{"cache-share", "--width", "120", "--ascii"}},
		{"spend_project_none_80", "", []string{"spend", "--width", "80", "--project", "/nowhere"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := runChartCmd(t, c.mode, append(c.args, window...)...)
			if err != nil {
				t.Fatalf("%v\n%s", err, got)
			}
			if strings.Contains(got, "\x1b[") {
				t.Errorf("--color never output carries an escape")
			}
			if c.mode == costtext.ModeTokens && strings.Contains(got, "$") {
				t.Errorf("token display output shows a dollar figure:\n%s", got)
			}
			chartGolden(t, c.name, got)
		})
	}
}

func TestChartColorAlways(t *testing.T) {
	cfg := seedChartCorpus(t)
	got, err := runChartCmd(t, "", "spend", "--config", cfg, "--since", "2026-10-01", "--until", "2026-10-31", "--width", "80", "--color", "always")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "\x1b[") {
		t.Error("--color always output has no escape")
	}
}

// TestChartColorDecision pins every input of the colour decision with the
// TTY check injected, so each row really exercises its rule.
func TestChartColorDecision(t *testing.T) {
	prev := chartStdoutIsTTY
	t.Cleanup(func() { chartStdoutIsTTY = prev })
	cases := []struct {
		name    string
		mode    string
		ascii   bool
		tty     bool
		noColor string
		term    string
		want    bool
	}{
		{"auto on a terminal", "auto", false, true, "", "xterm-256color", true},
		{"empty mode is auto", "", false, true, "", "xterm", true},
		{"NO_COLOR set", "auto", false, true, "1", "xterm", false},
		{"NO_COLOR any non-empty value", "auto", false, true, "false", "xterm", false},
		{"TERM=dumb", "auto", false, true, "", "dumb", false},
		{"not a terminal", "auto", false, false, "", "xterm", false},
		{"ascii never colours on auto", "auto", true, true, "", "xterm", false},
		{"always ignores NO_COLOR and the TTY", "always", false, false, "1", "dumb", true},
		{"always with ascii", "always", true, true, "", "xterm", false},
		{"never", "never", false, true, "", "xterm", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tty := c.tty
			chartStdoutIsTTY = func() bool { return tty }
			t.Setenv("NO_COLOR", c.noColor)
			t.Setenv("TERM", c.term)
			got, err := chartColor(c.mode, c.ascii)
			if err != nil || got != c.want {
				t.Errorf("chartColor(%q, ascii=%v) = %v, %v; want %v", c.mode, c.ascii, got, err, c.want)
			}
		})
	}
	if _, err := chartColor("rainbow", false); err == nil {
		t.Error("unknown --color must error")
	}
}

// TestChartColorAutoReachesOutput: with the TTY decided true, the command's
// auto mode colours its output, and NO_COLOR turns it off end to end.
func TestChartColorAutoReachesOutput(t *testing.T) {
	cfg := seedChartCorpus(t)
	prev := chartStdoutIsTTY
	chartStdoutIsTTY = func() bool { return true }
	t.Cleanup(func() { chartStdoutIsTTY = prev })
	t.Setenv("TERM", "xterm")
	args := []string{"spend", "--config", cfg, "--since", "2026-10-01", "--until", "2026-10-31", "--width", "80"}
	for _, c := range []struct {
		noColor string
		want    bool
	}{{"", true}, {"1", false}} {
		t.Setenv("NO_COLOR", c.noColor)
		out, err := runChartCmd(t, "", args...)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(out, "\x1b["); got != c.want {
			t.Errorf("NO_COLOR=%q: escapes=%v want %v", c.noColor, got, c.want)
		}
	}
}

func TestChartJSON(t *testing.T) {
	cfg := seedChartCorpus(t)
	window := []string{"--config", cfg, "--since", "2026-10-01", "--until", "2026-10-31", "--json"}
	type point struct {
		Bucket         string   `json:"bucket"`
		TotalTokens    int64    `json:"total_tokens"`
		CostUSD        *float64 `json:"cost_usd"`
		CacheReadShare *float64 `json:"cache_read_share"`
	}
	type spendDoc struct {
		Chart   string `json:"chart"`
		Display string `json:"display"`
		Window  struct {
			Gran string `json:"gran"`
			TZ   string `json:"tz"`
		} `json:"window"`
		Series []point `json:"series"`
	}
	cases := []struct {
		mode       string
		wantDollar bool
	}{{"", true}, {costtext.ModeTokens, false}}
	for _, c := range cases {
		got, err := runChartCmd(t, c.mode, append([]string{"spend"}, window...)...)
		if err != nil {
			t.Fatal(err)
		}
		var spend spendDoc
		if err := json.Unmarshal([]byte(got), &spend); err != nil {
			t.Fatalf("%v\n%s", err, got)
		}
		if spend.Chart != "spend" || spend.Window.Gran != "1d" || spend.Window.TZ != "UTC" || len(spend.Series) != 30 {
			t.Fatalf("spend json: chart=%s gran=%s tz=%s points=%d", spend.Chart, spend.Window.Gran, spend.Window.TZ, len(spend.Series))
		}
		if has := spend.Series[0].CostUSD != nil; has != c.wantDollar {
			t.Errorf("mode %q: cost_usd present=%v want %v", c.mode, has, c.wantDollar)
		}
		if strings.Contains(got, "cost_usd") != c.wantDollar {
			t.Errorf("mode %q: cost_usd key in output=%v want %v", c.mode, !c.wantDollar, c.wantDollar)
		}
		// Day 9 is idle: zero tokens and an unknown (null) cache read share.
		if p := spend.Series[8]; p.Bucket != "2026-10-09" || p.TotalTokens != 0 || p.CacheReadShare != nil {
			t.Errorf("idle day: %+v", p)
		}
	}

	got, err := runChartCmd(t, "", append([]string{"models"}, window...)...)
	if err != nil {
		t.Fatal(err)
	}
	var models struct {
		Totals []struct {
			Model string  `json:"model"`
			Share float64 `json:"share"`
		} `json:"totals"`
		Grid []map[string]string `json:"grid"`
	}
	if err := json.Unmarshal([]byte(got), &models); err != nil {
		t.Fatal(err)
	}
	sum := 0.0
	for _, m := range models.Totals {
		sum += m.Share
	}
	if len(models.Totals) != 4 || len(models.Grid) != 30 || sum < 0.999 || sum > 1.001 {
		t.Errorf("models json: %d totals, %d grid, share sum %v", len(models.Totals), len(models.Grid), sum)
	}

	got, err = runChartCmd(t, "", append([]string{"cache-share"}, window...)...)
	if err != nil {
		t.Fatal(err)
	}
	var cache struct {
		Chart   string   `json:"chart"`
		Overall *float64 `json:"overall"`
		Formula string   `json:"formula"`
		Series  []struct {
			CacheReadShare *float64 `json:"cache_read_share"`
		} `json:"series"`
	}
	if err := json.Unmarshal([]byte(got), &cache); err != nil {
		t.Fatal(err)
	}
	if cache.Chart != "cache_share" {
		t.Errorf(`cache-share json "chart" = %q, want "cache_share"`, cache.Chart)
	}
	if cache.Overall == nil || *cache.Overall <= 0 || *cache.Overall >= 1 || cache.Formula != "cache_read / (input + cache_read + cache_creation)" {
		t.Errorf("cache json: %+v", cache)
	}
	if len(cache.Series) != 30 || cache.Series[0].CacheReadShare == nil || cache.Series[8].CacheReadShare != nil {
		t.Errorf("cache_read_share per bucket: %d points", len(cache.Series))
	}
	if strings.Contains(got, "cache_hit_rate") {
		t.Error("the old cache_hit_rate field is back")
	}
	if strings.Contains(got, "cost_usd") {
		t.Error("cache json carries dollar fields")
	}
}

func TestChartWindowErrors(t *testing.T) {
	cfg := seedChartCorpus(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bad since", []string{"spend", "--since", "yesterday"}, "--since"},
		{"empty window", []string{"spend", "--since", "2026-10-10", "--until", "2026-10-01"}, "window is empty"},
		{"zero days", []string{"spend", "--days", "0"}, "--days"},
		{"too fine for width", []string{"spend", "--days", "30", "--gran", "1h", "--width", "80"}, "more than"},
		{"bad colour", []string{"spend", "--color", "rainbow"}, "--color"},
		{"bad gran", []string{"spend", "--gran", "2d"}, "gran"},
		// The misaligned 5-minute edge: the point cap admits it (Points is
		// exactly 2000) but its grid is 2001 buckets, so there is no grid
		// and a sub-day axis cannot be data-bounded. Refused at a width
		// where only the missing grid can refuse; the message must not
		// suggest --width.
		{"misaligned 5m edge", []string{"spend", "--gran", "5m", "--since", "2026-10-01T00:02:30Z", "--until", "2026-10-07T22:41:30Z", "--width", "5000"}, "most a chart axis holds"},
		{"misaligned 5m edge, cache-share", []string{"cache-share", "--gran", "5m", "--since", "2026-10-01T00:02:30Z", "--until", "2026-10-07T22:41:30Z", "--width", "5000"}, "most a chart axis holds"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := runChartCmd(t, "", append(c.args, "--config", cfg)...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want it to mention %q", err, c.want)
			}
		})
	}
	// --json is not limited by the width.
	if _, err := runChartCmd(t, "", "spend", "--config", cfg, "--days", "30", "--gran", "1h", "--width", "80", "--json"); err != nil {
		t.Errorf("--json with a fine --gran: %v", err)
	}
}

// TestChartAutoGranularity: auto never goes finer than the dashboard's
// Auto, and coarsens to fit the width.
func TestChartAutoGranularity(t *testing.T) {
	cases := []struct {
		days     int
		capacity int
		json     bool
		want     string
	}{
		{1, 71, false, "1h"},  // dashboard Auto is 1h; 25 points fit
		{1, 20, false, "1d"},  // 25 hours do not fit 20 columns
		{7, 71, false, "1d"},  // 169 hours do not fit
		{7, 71, true, "1h"},   // --json keeps the dashboard Auto
		{30, 71, false, "1d"}, // day buckets
		{365, 71, false, "1w"},
	}
	prev, prevZone := chartNow, chartSystemZone
	chartNow = func() time.Time { return chartTestEnd }
	chartSystemZone = func() (*time.Location, string) { return time.UTC, "UTC" }
	t.Cleanup(func() { chartNow, chartSystemZone = prev, prevZone })
	for _, c := range cases {
		w, err := resolveChartWindow(&chartFlags{days: c.days, gran: "auto", jsonOut: c.json}, c.capacity)
		if err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		if string(w.spec.Gran) != c.want || !w.spec.Auto {
			t.Errorf("%+v: gran %s auto %v", c, w.spec.Gran, w.spec.Auto)
		}
	}
}

func TestSystemZone(t *testing.T) {
	cases := []struct {
		name     string
		tz       string
		set      bool
		wantName string
		wantUTC  bool
	}{
		{"TZ names a zone", "Asia/Kolkata", true, "Asia/Kolkata", false},
		{"TZ with a leading colon", ":Europe/Berlin", true, "Europe/Berlin", false},
		{"empty TZ is UTC, as Go reads it", "", true, "UTC", true},
		{"unknown TZ keeps time.Local, unnamed", "Mars/Base", true, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("TZ", c.tz)
			loc, name := systemZone()
			if name != c.wantName {
				t.Errorf("name %q want %q", name, c.wantName)
			}
			if (loc == time.UTC) != c.wantUTC {
				t.Errorf("loc %v, want UTC=%v", loc, c.wantUTC)
			}
		})
	}
}

func TestChartZoneFlag(t *testing.T) {
	prev := chartSystemZone
	t.Cleanup(func() { chartSystemZone = prev })
	chartSystemZone = func() (*time.Location, string) { return time.FixedZone("X", 3600), "" }
	if _, name, err := chartZone(""); err != nil || name != "local" {
		t.Errorf("unnamed system zone: %q %v", name, err)
	}
	if _, name, err := chartZone("America/New_York"); err != nil || name != "America/New_York" {
		t.Errorf("--tz: %q %v", name, err)
	}
	if _, _, err := chartZone("Mars/Base"); err == nil || !strings.Contains(err.Error(), "--tz") {
		t.Errorf("unknown --tz: %v", err)
	}
	for _, v := range []string{"local", "LOCAL"} {
		loc, name, err := chartZone(v)
		if err != nil || name != "local" || loc.String() != "X" {
			t.Errorf("--tz %s: %v %q %v", v, loc, name, err)
		}
	}
	chartSystemZone = func() (*time.Location, string) { return time.UTC, "UTC" }
	if _, name, err := chartZone("local"); err != nil || name != "UTC" {
		t.Errorf("--tz local with a named system zone: %q %v", name, err)
	}
}

// TestChartWindowTZRoundTrips: the window.tz an unnamed system zone yields
// ("local") is accepted back as --tz and gives the same series.
func TestChartWindowTZRoundTrips(t *testing.T) {
	cfg := seedChartCorpus(t)
	kiri, err := time.LoadLocation("Pacific/Kiritimati")
	if err != nil {
		t.Fatal(err)
	}
	type doc struct {
		Window struct {
			TZ string `json:"tz"`
		} `json:"window"`
		Series []struct {
			Bucket      string `json:"bucket"`
			TotalTokens int64  `json:"total_tokens"`
		} `json:"series"`
	}
	run := func(extra ...string) (doc, string) {
		args := append([]string{"spend", "--config", cfg, "--since", "2026-10-01T00:00:00Z", "--until", "2026-10-31T00:00:00Z", "--json"}, extra...)
		out, err := runChartCmdZone(t, func() (*time.Location, string) { return kiri, "" }, args...)
		if err != nil {
			t.Fatal(err)
		}
		var d doc
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			t.Fatal(err)
		}
		return d, out
	}
	first, _ := run()
	if first.Window.TZ != "local" {
		t.Fatalf("window.tz %q, want local for an unnamed system zone", first.Window.TZ)
	}
	again, _ := run("--tz", first.Window.TZ)
	if again.Window.TZ != first.Window.TZ || len(again.Series) != len(first.Series) {
		t.Fatalf("round trip: %q %d vs %q %d", again.Window.TZ, len(again.Series), first.Window.TZ, len(first.Series))
	}
	for i := range first.Series {
		if first.Series[i] != again.Series[i] {
			t.Errorf("bucket %d: %+v vs %+v", i, first.Series[i], again.Series[i])
		}
	}
}

// TestChartZoneMovesBucketsNotTotals: over one window (RFC3339 bounds, so
// the instants match), bucketing in another zone moves turns between day
// buckets while the window total stays the same. This is the agreement
// docs/cli-chart.md promises: totals always, buckets when zones match.
func TestChartZoneMovesBucketsNotTotals(t *testing.T) {
	cfg := seedChartCorpus(t)
	type doc struct {
		Window struct {
			TZ string `json:"tz"`
		} `json:"window"`
		Series []struct {
			Bucket      string `json:"bucket"`
			TotalTokens int64  `json:"total_tokens"`
		} `json:"series"`
	}
	run := func(zone string) (doc, int64) {
		args := []string{"spend", "--config", cfg, "--since", "2026-10-01T00:00:00Z", "--until", "2026-10-31T00:00:00Z", "--json"}
		if zone != "" {
			args = append(args, "--tz", zone)
		}
		out, err := runChartCmd(t, "", args...)
		if err != nil {
			t.Fatal(err)
		}
		var d doc
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			t.Fatal(err)
		}
		var sum int64
		for _, p := range d.Series {
			sum += p.TotalTokens
		}
		return d, sum
	}
	utc, utcSum := run("")
	far, farSum := run("Pacific/Kiritimati") // UTC+14: 10:30Z lands on the next local day
	if utc.Window.TZ != "UTC" || far.Window.TZ != "Pacific/Kiritimati" {
		t.Fatalf("tz %q / %q", utc.Window.TZ, far.Window.TZ)
	}
	if utcSum != farSum || utcSum == 0 {
		t.Errorf("window totals differ: %d vs %d", utcSum, farSum)
	}
	byKey := map[string]int64{}
	for _, p := range utc.Series {
		byKey[p.Bucket] = p.TotalTokens
	}
	moved := false
	for _, p := range far.Series {
		if byKey[p.Bucket] != p.TotalTokens {
			moved = true
		}
	}
	if !moved {
		t.Error("buckets did not move with the zone")
	}
}

// TestChartWidthCountsRendererSlots: the width check counts the grid slots
// the renderer is handed (timebucket.Slots), not timebucket.Points, which
// overcounts an aligned window by one and undercounts a week-straddling
// one by one.
func TestChartWidthCountsRendererSlots(t *testing.T) {
	cfg := seedChartCorpus(t)
	window := []string{"--config", cfg, "--since", "2026-10-01", "--until", "2026-10-31", "--color", "never"}
	// Width 39 leaves 30 plot columns: exactly the 30 day buckets.
	if capacity := 39 - 9; capacity != 30 {
		t.Fatalf("gutter changed: capacity %d", capacity)
	}
	for _, args := range [][]string{
		{"spend", "--width", "39", "--gran", "1d"},
		{"spend", "--width", "39"},
		{"models", "--width", "39"},
	} {
		out, err := runChartCmd(t, "", append(args, window...)...)
		if err != nil {
			t.Fatalf("%v: a window at capacity must draw: %v", args, err)
		}
		if !strings.Contains(out, "per day") || !strings.Contains(out, "(30 buckets)") {
			t.Errorf("%v: want 30 day buckets:\n%s", args, out)
		}
	}

	prev, prevZone := chartNow, chartSystemZone
	chartNow = func() time.Time { return chartTestEnd }
	chartSystemZone = func() (*time.Location, string) { return time.UTC, "UTC" }
	t.Cleanup(func() { chartNow, chartSystemZone = prev, prevZone })
	cases := []struct {
		name      string
		since     string
		until     string
		gran      string
		capacity  int
		wantSlots int
		wantErr   bool
	}{
		// Points(30d, 1d) = 31, but the aligned grid is 30.
		{"aligned days at capacity", "2026-10-01", "2026-10-31", "1d", 30, 30, false},
		// Sunday 2026-10-04 plus 30 days touches 6 Monday-start weeks;
		// Points says 5.
		{"week-straddling window over capacity", "2026-10-04", "2026-11-03", "1w", 5, 6, true},
		{"week-straddling window at capacity", "2026-10-04", "2026-11-03", "1w", 6, 6, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, err := resolveChartWindow(&chartFlags{since: c.since, until: c.until, gran: c.gran}, c.capacity)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, want error %v", err, c.wantErr)
			}
			if err != nil {
				return
			}
			if n := chartSlotCount(w.spec); n != c.wantSlots {
				t.Errorf("slots %d want %d", n, c.wantSlots)
			}
		})
	}
}

// TestChartSlotCountWithoutGrid: a window the point cap lets through whose
// grid still exceeds the cap (Points says exactly 2000, the misaligned grid
// touches 2001 buckets, so Spec.Grid is nil) must count as too wide, not
// zero; the old count of 0 let a sparse database draw its data buckets
// side by side.
func TestChartSlotCountWithoutGrid(t *testing.T) {
	since := time.Date(2026, 10, 1, 0, 2, 30, 0, time.UTC)
	until := since.Add(1999*5*time.Minute + 4*time.Minute)
	spec, err := timebucket.Resolve(timebucket.Request{Gran: "5m", TZ: "UTC", Since: since, Until: until, Now: until})
	if err != nil {
		t.Fatalf("the cap must let this window through: %v", err)
	}
	if g := spec.Grid(time.Time{}); g != nil {
		t.Fatalf("precondition: want no grid, got %d buckets", len(g))
	}
	if n := chartSlotCount(spec); n <= timebucket.MaxPoints {
		t.Errorf("chartSlotCount = %d, want more than %d", n, timebucket.MaxPoints)
	}
	prev, prevZone := chartNow, chartSystemZone
	chartNow = func() time.Time { return until }
	chartSystemZone = func() (*time.Location, string) { return time.UTC, "UTC" }
	t.Cleanup(func() { chartNow, chartSystemZone = prev, prevZone })
	f := &chartFlags{since: since.Format(time.RFC3339), until: until.Format(time.RFC3339), gran: "5m"}
	if _, err := resolveChartWindow(f, 1_000_000); err == nil {
		t.Error("a window with no grid must be refused however wide the chart")
	}
	f.jsonOut = true
	if _, err := resolveChartWindow(f, 1_000_000); err != nil {
		t.Errorf("--json is not limited by the width: %v", err)
	}
	// A normal window keeps its exact grid length.
	day, err := timebucket.Resolve(timebucket.Request{Gran: "1d", TZ: "UTC", Since: chartTestEnd.Add(-30 * 24 * time.Hour), Until: chartTestEnd})
	if err != nil {
		t.Fatal(err)
	}
	if n := chartSlotCount(day); n != 30 {
		t.Errorf("30 aligned days: %d slots", n)
	}
}

// TestChartDefaultZoneIsSystemZone: with no --tz the command buckets in the
// injected system zone (not UTC, not $TZ read on its own): window.tz is the
// system zone's name and the series equals an explicit --tz of that zone,
// and differs from UTC's.
func TestChartDefaultZoneIsSystemZone(t *testing.T) {
	cfg := seedChartCorpus(t)
	t.Setenv("TZ", "UTC") // must not matter: the injected system zone decides
	kiri, err := time.LoadLocation("Pacific/Kiritimati")
	if err != nil {
		t.Fatal(err)
	}
	system := func() (*time.Location, string) { return kiri, "Pacific/Kiritimati" }
	type doc struct {
		Window struct {
			TZ string `json:"tz"`
		} `json:"window"`
		Series []struct {
			Bucket      string `json:"bucket"`
			TotalTokens int64  `json:"total_tokens"`
		} `json:"series"`
	}
	run := func(zone func() (*time.Location, string), extra ...string) doc {
		args := append([]string{"spend", "--config", cfg, "--since", "2026-10-01T00:00:00Z", "--until", "2026-10-31T00:00:00Z", "--json"}, extra...)
		out, err := runChartCmdZone(t, zone, args...)
		if err != nil {
			t.Fatal(err)
		}
		var d doc
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	def := run(system)
	if def.Window.TZ != "Pacific/Kiritimati" {
		t.Fatalf("default window.tz %q, want the system zone", def.Window.TZ)
	}
	explicit := run(func() (*time.Location, string) { return time.UTC, "UTC" }, "--tz", "Pacific/Kiritimati")
	utc := run(func() (*time.Location, string) { return time.UTC, "UTC" })
	same, differsFromUTC := len(def.Series) == len(explicit.Series), false
	for i := range def.Series {
		if i >= len(explicit.Series) || def.Series[i] != explicit.Series[i] {
			same = false
		}
		if i >= len(utc.Series) || def.Series[i] != utc.Series[i] {
			differsFromUTC = true
		}
	}
	if !same {
		t.Error("default-zone series differs from an explicit --tz of the system zone")
	}
	if !differsFromUTC {
		t.Error("default-zone series equals UTC's: the system zone did not reach the buckets")
	}
}

// TestChartDataBoundedLongWindows: a day or week window over the 2000-bucket
// cap is drawn from the earliest data bucket (what costseries returns), as
// before the round-2 grid check, and is refused only when even that axis is
// over the cap (no width helps, so --width is not suggested) or does not
// fit the width (then it is).
func TestChartDataBoundedLongWindows(t *testing.T) {
	cfg := seedChartCorpus(t)
	draws := []struct {
		name string
		args []string
		want string
	}{
		{"1d over 2500 days", []string{"spend", "--gran", "1d", "--days", "2500"}, "30 buckets from the first data"},
		{"1d since 2015", []string{"spend", "--gran", "1d", "--since", "2015-01-01"}, "30 buckets from the first data; the window starts 2015-01-01"},
		{"1w since 1980", []string{"spend", "--gran", "1w", "--since", "1980-01-01"}, "from the first data"},
		{"models 1d since 2015", []string{"models", "--gran", "1d", "--since", "2015-01-01"}, "30 buckets from the first data"},
		{"cache-share 1d since 2015", []string{"cache-share", "--gran", "1d", "--since", "2015-01-01"}, "30 buckets from the first data"},
		{"auto since 1980 picks data-bounded weeks", []string{"spend", "--since", "1980-01-01"}, "per week"},
	}
	for _, c := range draws {
		t.Run(c.name, func(t *testing.T) {
			out, err := runChartCmd(t, "", append(c.args, "--config", cfg, "--width", "80", "--color", "never")...)
			if err != nil {
				t.Fatalf("must draw: %v", err)
			}
			if !strings.Contains(out, c.want) {
				t.Errorf("want %q in:\n%s", c.want, out)
			}
		})
	}

	// A stray 2015 row makes even the data-bounded day axis ~4,300 buckets.
	old := chartCorpusTurns()[0]
	old.ts = time.Date(2015, 3, 1, 12, 0, 0, 0, time.UTC)
	stray := seedChartCorpusWith(t, []chartTurn{old})
	refusals := []struct {
		name      string
		args      []string
		want      string
		wantWidth bool
	}{
		{"days from a 2015 row: over the cap", []string{"spend", "--gran", "1d", "--since", "2010-01-01"}, "from the earliest data in this window are more than 2000 points", false},
		{"models days from a 2015 row: over the cap", []string{"models", "--gran", "1d", "--since", "2010-01-01"}, "from the earliest data in this window are more than 2000 points", false},
		{"weeks from a 2015 row: too wide", []string{"spend", "--gran", "1w", "--since", "2010-01-01"}, "more than 71 columns can draw", true},
		{"auto since 2015: weekly too wide", []string{"spend", "--since", "2015-01-01"}, "more than 71 columns can draw", true},
	}
	for _, c := range refusals {
		t.Run(c.name, func(t *testing.T) {
			_, err := runChartCmd(t, "", append(c.args, "--config", stray, "--width", "80")...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if got := strings.Contains(err.Error(), "--width"); got != c.wantWidth {
				t.Errorf("suggests --width = %v, want %v: %v", got, c.wantWidth, err)
			}
		})
	}
	// --json is never limited by the width or the axis cap.
	if _, err := runChartCmd(t, "", "spend", "--config", stray, "--gran", "1d", "--since", "2010-01-01", "--json"); err != nil {
		t.Errorf("--json: %v", err)
	}
}

// TestChartRefusalMessages: --width is suggested exactly when a wider
// terminal would draw the chart.
func TestChartRefusalMessages(t *testing.T) {
	if e := chartNoGrid(timebucket.Day, true).Error(); strings.Contains(e, "--width") {
		t.Errorf("no-grid refusal suggests --width: %s", e)
	}
	if e := chartNoGrid(timebucket.Min5, false).Error(); strings.Contains(e, "--width") || !strings.Contains(e, "over this window") {
		t.Errorf("no-grid refusal: %s", e)
	}
	if e := chartTooWide(timebucket.Week, 300, 71).Error(); !strings.Contains(e, "--width") {
		t.Errorf("too-wide refusal must suggest --width: %s", e)
	}
}
