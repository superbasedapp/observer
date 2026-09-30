package timebucket

import (
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	MaxPoints int `json:"max_points"`
	Table     []struct {
		Gran          string `json:"gran"`
		StepMS        int64  `json:"step_ms"`
		AutoMaxSpanMS int64  `json:"auto_max_span_ms"`
		AlwaysAllowed bool   `json:"always_allowed"`
	} `json:"table"`
	Choose []struct {
		Name   string `json:"name"`
		SpanMS *int64 `json:"span_ms"`
		Want   string `json:"want"`
	} `json:"choose"`
	Points []struct {
		SpanMS int64  `json:"span_ms"`
		Gran   string `json:"gran"`
		Want   int    `json:"want"`
	} `json:"points"`
	Allowed []struct {
		Name   string   `json:"name"`
		SpanMS *int64   `json:"span_ms"`
		Want   []string `json:"want"`
	} `json:"allowed"`
}

func loadFixture(t *testing.T) fixture {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "shared", "lib", "granularity.fixture.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

func spanOf(ms *int64) time.Duration {
	if ms == nil {
		return Unbounded
	}
	return time.Duration(*ms) * time.Millisecond
}

// TestFixtureParity pins the Go table and rules to the ONE fixture the TS
// mirror (shared/lib/granularity.ts) is also tested against.
func TestFixtureParity(t *testing.T) {
	f := loadFixture(t)
	if f.MaxPoints != MaxPoints {
		t.Fatalf("max_points: fixture %d, Go %d", f.MaxPoints, MaxPoints)
	}
	if len(f.Table) != len(Table) {
		t.Fatalf("table rows: fixture %d, Go %d", len(f.Table), len(Table))
	}
	for i, row := range f.Table {
		g := Table[i]
		if string(g.Gran) != row.Gran || g.Step.Milliseconds() != row.StepMS ||
			g.AutoMaxSpan.Milliseconds() != row.AutoMaxSpanMS || g.AlwaysAllowed != row.AlwaysAllowed {
			t.Errorf("table row %d: Go %+v, fixture %+v", i, g, row)
		}
	}
	for _, c := range f.Choose {
		if got := Choose(spanOf(c.SpanMS)); string(got) != c.Want {
			t.Errorf("Choose(%s) = %s, want %s", c.Name, got, c.Want)
		}
	}
	for _, c := range f.Points {
		if got := Points(time.Duration(c.SpanMS)*time.Millisecond, Granularity(c.Gran)); got != c.Want {
			t.Errorf("Points(%dms, %s) = %d, want %d", c.SpanMS, c.Gran, got, c.Want)
		}
	}
	for _, c := range f.Allowed {
		got := []string{}
		for _, g := range Allowed(spanOf(c.SpanMS)) {
			got = append(got, string(g))
		}
		if !reflect.DeepEqual(got, c.Want) {
			t.Errorf("Allowed(%s) = %v, want %v", c.Name, got, c.Want)
		}
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want Granularity
		ok   bool
	}{
		{"", "", true},
		{"auto", "", true},
		{"AUTO", "", true},
		{"5m", Min5, true},
		{"1h", Hour, true},
		{"hour", Hour, true},
		{"day", Day, true},
		{"1d", Day, true},
		{"1w", Week, true},
		{"week", Week, true},
		{"2h", "", false},
		{"month", "", false},
	}
	for _, c := range cases {
		got, ok := Parse(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Parse(%q) = %q,%v want %q,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestValidateCap(t *testing.T) {
	cases := []struct {
		name string
		g    Granularity
		span time.Duration
		cap  bool
	}{
		{"5m over 1h", Min5, time.Hour, false},
		{"5m over 7d", Min5, 7 * 24 * time.Hour, true},
		{"1h over 83d", Hour, 83 * 24 * time.Hour, false},
		{"1h over 84d", Hour, 84 * 24 * time.Hour, true},
		{"1h unbounded", Hour, Unbounded, true},
		{"1d unbounded", Day, Unbounded, false},
		{"1w unbounded", Week, Unbounded, false},
	}
	for _, c := range cases {
		err := Validate(c.g, c.span)
		var ce *CapError
		if got := errors.As(err, &ce); got != c.cap {
			t.Errorf("%s: cap error = %v (%v), want %v", c.name, got, err, c.cap)
		}
	}
	if err := Validate("2h", time.Hour); !errors.Is(err, ErrUnknownGranularity) {
		t.Errorf("unknown gran: %v", err)
	}
}

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	l, err := time.LoadLocation(name)
	if err != nil {
		t.Skipf("zone %s unavailable: %v", name, err)
	}
	return l
}

func TestFloor(t *testing.T) {
	ist := mustLoc(t, "Asia/Kolkata")
	la := mustLoc(t, "America/Los_Angeles")
	lh := mustLoc(t, "Australia/Lord_Howe")
	cases := []struct {
		name string
		in   string
		g    Granularity
		loc  *time.Location
		want string // RFC3339 in loc
	}{
		{"utc hour", "2026-09-29T14:37:12Z", Hour, time.UTC, "2026-09-29T14:00:00Z"},
		{"utc 5m", "2026-09-29T14:37:12Z", Min5, time.UTC, "2026-09-29T14:35:00Z"},
		{"utc day", "2026-09-29T14:37:12Z", Day, time.UTC, "2026-09-29T00:00:00Z"},
		{"utc week (Tue -> Mon)", "2026-09-29T14:37:12Z", Week, time.UTC, "2026-09-28T00:00:00Z"},
		{"utc week on Monday", "2026-09-28T00:00:00Z", Week, time.UTC, "2026-09-28T00:00:00Z"},
		{"utc week on Sunday", "2026-10-04T23:59:59Z", Week, time.UTC, "2026-09-28T00:00:00Z"},
		// IST +5:30: hour buckets start at :30 UTC.
		{"ist hour", "2026-09-29T14:37:12Z", Hour, ist, "2026-09-29T20:00:00+05:30"},
		{"ist hour just before", "2026-09-29T14:29:59Z", Hour, ist, "2026-09-29T19:00:00+05:30"},
		{"ist 5m", "2026-09-29T14:37:12Z", Min5, ist, "2026-09-29T20:05:00+05:30"},
		// 2026-09-29T20:00Z is 01:30 IST on the 30th: the IST day differs from UTC.
		{"ist day across UTC midnight", "2026-09-29T20:00:00Z", Day, ist, "2026-09-30T00:00:00+05:30"},
		{"ist week", "2026-10-04T20:00:00Z", Week, ist, "2026-10-05T00:00:00+05:30"},
		// LA spring forward 2026-03-08 02:00 PST -> 03:00 PDT (10:00Z).
		{"la hour after spring forward", "2026-03-08T10:30:00Z", Hour, la, "2026-03-08T03:00:00-07:00"},
		{"la hour before spring forward", "2026-03-08T09:59:00Z", Hour, la, "2026-03-08T01:00:00-08:00"},
		{"la day on spring-forward day", "2026-03-08T20:00:00Z", Day, la, "2026-03-08T00:00:00-08:00"},
		// LA fall back 2026-11-01 02:00 PDT -> 01:00 PST (09:00Z): two 01:00 buckets.
		{"la first 01:00", "2026-11-01T08:30:00Z", Hour, la, "2026-11-01T01:00:00-07:00"},
		{"la second 01:00", "2026-11-01T09:30:00Z", Hour, la, "2026-11-01T01:00:00-08:00"},
		// Lord Howe falls back 30 minutes (2026-04-05 02:00 +11 -> 01:30
		// +10:30 at 15:00Z): the half hour after the change is a bucket of
		// its own, never folded into the 01:00 +11 bucket before it.
		{"lord howe hour before fall back", "2026-04-04T14:30:00Z", Hour, lh, "2026-04-05T01:00:00+11:00"},
		{"lord howe hour at fall back", "2026-04-04T15:00:00Z", Hour, lh, "2026-04-05T01:30:00+10:30"},
		{"lord howe hour after fall back", "2026-04-04T15:29:00Z", Hour, lh, "2026-04-05T01:30:00+10:30"},
		{"lord howe next whole hour", "2026-04-04T15:30:00Z", Hour, lh, "2026-04-05T02:00:00+10:30"},
		// ... and springs forward 30 minutes (2026-10-04 02:00 +10:30 ->
		// 02:30 +11 at 15:30Z).
		{"lord howe hour at spring forward", "2026-10-03T15:30:00Z", Hour, lh, "2026-10-04T02:30:00+11:00"},
		{"lord howe 5m at spring forward", "2026-10-03T15:32:00Z", Min5, lh, "2026-10-04T02:30:00+11:00"},
		{"lord howe day", "2026-04-04T15:00:00Z", Day, lh, "2026-04-05T00:00:00+11:00"},
	}
	for _, c := range cases {
		in, _ := time.Parse(time.RFC3339, c.in)
		got := Floor(in, c.g, c.loc).Format(time.RFC3339)
		if got != c.want {
			t.Errorf("%s: Floor = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestGridIST(t *testing.T) {
	ist := mustLoc(t, "Asia/Kolkata")
	since, _ := time.Parse(time.RFC3339, "2026-09-29T00:00:00Z") // 05:30 IST
	until := since.Add(24 * time.Hour)
	g, ok := Grid(since, until, Day, ist, MaxPoints)
	if !ok || len(g) != 2 {
		t.Fatalf("IST day grid over a UTC day = %v (ok=%v), want 2 local days", g, ok)
	}
	if Key(g[0], Day, ist) != "2026-09-29" || Key(g[1], Day, ist) != "2026-09-30" {
		t.Errorf("IST day keys = %s, %s", Key(g[0], Day, ist), Key(g[1], Day, ist))
	}
	h, _ := Grid(since, until, Hour, ist, MaxPoints)
	if len(h) != 25 { // starts at 05:00 IST (partial), ends at 05:00 IST next day (partial)
		t.Errorf("IST hour grid len = %d, want 25", len(h))
	}
	if !strings.HasSuffix(Key(h[0], Hour, ist), ":00:00+05:30") {
		t.Errorf("IST hour key = %s", Key(h[0], Hour, ist))
	}
}

func TestGridDSTCrossing(t *testing.T) {
	la := mustLoc(t, "America/Los_Angeles")
	// The local day 2026-11-01 (fall back) holds 25 hours, 2026-03-08 holds 23.
	fb := time.Date(2026, 11, 1, 0, 0, 0, 0, la)
	g, _ := Grid(fb, time.Date(2026, 11, 2, 0, 0, 0, 0, la), Hour, la, MaxPoints)
	if len(g) != 25 {
		t.Errorf("fall-back day hour grid = %d buckets, want 25", len(g))
	}
	keys := map[string]bool{}
	for _, b := range g {
		keys[Key(b, Hour, la)] = true
	}
	if len(keys) != 25 {
		t.Errorf("fall-back hour keys not distinct: %d", len(keys))
	}
	sf := time.Date(2026, 3, 8, 0, 0, 0, 0, la)
	g2, _ := Grid(sf, time.Date(2026, 3, 9, 0, 0, 0, 0, la), Hour, la, MaxPoints)
	if len(g2) != 23 {
		t.Errorf("spring-forward day hour grid = %d buckets, want 23", len(g2))
	}
	// A week of days across the change: 7 distinct local midnights.
	d, _ := Grid(time.Date(2026, 3, 5, 0, 0, 0, 0, la), time.Date(2026, 3, 12, 0, 0, 0, 0, la), Day, la, MaxPoints)
	if len(d) != 7 {
		t.Fatalf("day grid across DST = %d, want 7", len(d))
	}
	for _, b := range d {
		if b.Hour() != 0 || b.Minute() != 0 {
			t.Errorf("day bucket not at local midnight: %s", b)
		}
	}
}

// TestFloorNextGridConsistency walks every minute of two DST-crossing
// windows in zones with whole-hour, 30-minute (Lord Howe), 45-minute
// (Chatham) and 2-hour (Troll) offset changes, and off-hour standard
// offsets (IST, Nepal, Newfoundland): every t floors to a grid bucket b with
// b <= t < Next(b), and the grid strictly increases (no overlapping or
// duplicate buckets).
func TestFloorNextGridConsistency(t *testing.T) {
	zones := []string{
		"America/New_York", "Europe/London", "Asia/Kolkata", "Asia/Kathmandu",
		"Australia/Lord_Howe", "Australia/Adelaide", "America/St_Johns", "Pacific/Chatham",
		"America/Santiago", "Asia/Beirut", "Africa/Casablanca", "Antarctica/Troll",
	}
	windows := [][2]time.Time{
		{time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)},
		{time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)},
	}
	for _, z := range zones {
		loc := mustLoc(t, z)
		for _, w := range windows {
			for _, g := range []Granularity{Min5, Hour, Day, Week} {
				grid, ok := Grid(w[0], w[1], g, loc, 100000)
				if !ok {
					t.Fatalf("%s %s: grid over the cap", z, g)
				}
				in := make(map[int64]bool, len(grid))
				for i, b := range grid {
					in[b.Unix()] = true
					if i > 0 && !b.After(grid[i-1]) {
						t.Errorf("%s %s: grid not increasing at %v", z, g, b)
					}
				}
				bad := 0
				for tt := w[0]; tt.Before(w[1]); tt = tt.Add(time.Minute) {
					b := Floor(tt, g, loc)
					if b.After(tt) || !Next(b, g, loc).After(tt) || (!in[b.Unix()] && !b.Before(w[0])) {
						bad++
						if bad <= 3 {
							t.Errorf("%s %s: t=%s floor=%s next=%s inGrid=%v", z, g, tt.Format(time.RFC3339),
								b.In(loc).Format(time.RFC3339), Next(b, g, loc).In(loc).Format(time.RFC3339), in[b.Unix()])
						}
					}
				}
			}
		}
	}
}

func TestGridCap(t *testing.T) {
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, ok := Grid(since, since.Add(7*24*time.Hour), Min5, time.UTC, MaxPoints); ok {
		t.Error("5m grid over 7d should exceed the cap")
	}
	if g, ok := Grid(since, since.Add(time.Hour), Min5, time.UTC, MaxPoints); !ok || len(g) != 12 {
		t.Errorf("aligned 1h at 5m = %d buckets (ok=%v), want 12", len(g), ok)
	}
}

func TestResolve(t *testing.T) {
	now := time.Date(2026, 9, 29, 14, 23, 10, 0, time.UTC)
	cases := []struct {
		name     string
		req      Request
		want     Granularity
		auto     bool
		tz       string
		fallback bool
		err      bool
	}{
		{"auto 1h", Request{Since: now.Add(-time.Hour), Now: now}, Min5, true, "UTC", false, false},
		{"auto 12h", Request{Since: now.Add(-12 * time.Hour), Now: now}, Hour, true, "UTC", false, false},
		{"auto 30d", Request{Since: now.Add(-30 * 24 * time.Hour), Now: now}, Day, true, "UTC", false, false},
		{"auto unbounded", Request{Now: now}, Week, true, "UTC", false, false},
		{"legacy bucket=hour", Request{LegacyBucket: "hour", Since: now.Add(-24 * time.Hour), Now: now}, Hour, false, "UTC", false, false},
		{"gran wins over legacy", Request{Gran: "1d", LegacyBucket: "hour", Since: now.Add(-24 * time.Hour), Now: now}, Day, false, "UTC", false, false},
		{"tz honoured", Request{Gran: "1h", TZ: "Asia/Kolkata", Since: now.Add(-24 * time.Hour), Now: now}, Hour, false, "Asia/Kolkata", false, false},
		{"unknown tz falls back", Request{Gran: "1h", TZ: "Mars/Olympus", Since: now.Add(-24 * time.Hour), Now: now}, Hour, false, "UTC", true, false},
		{"Local refused", Request{Gran: "1h", TZ: "Local", Since: now.Add(-24 * time.Hour), Now: now}, Hour, false, "UTC", true, false},
		{"5m over 30d is a 400, never coarsened", Request{Gran: "5m", Since: now.Add(-30 * 24 * time.Hour), Now: now}, "", false, "", false, true},
		{"bad token", Request{Gran: "2h", Now: now}, "", false, "", false, true},
		{"daily-only surface: auto 1h window -> 1d", Request{Since: now.Add(-time.Hour), Now: now, Allowed: []Granularity{Day, Week}}, Day, true, "UTC", false, false},
		{"daily-only surface: auto 1y -> 1w", Request{Since: now.Add(-365 * 24 * time.Hour), Now: now, Allowed: []Granularity{Day, Week}}, Week, true, "UTC", false, false},
		{"daily-only surface refuses 1h", Request{Gran: "1h", Since: now.Add(-time.Hour), Now: now, Allowed: []Granularity{Day, Week}}, "", false, "", false, true},
	}
	for _, c := range cases {
		sp, err := Resolve(c.req)
		if c.err {
			var re *RequestError
			if !errors.As(err, &re) {
				t.Errorf("%s: want *RequestError, got %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if sp.Gran != c.want || sp.Auto != c.auto || sp.TZ != c.tz || sp.TZFallback != c.fallback {
			t.Errorf("%s: got gran=%s auto=%v tz=%s fallback=%v", c.name, sp.Gran, sp.Auto, sp.TZ, sp.TZFallback)
		}
	}
}

func TestSpecGridClampsUnboundedToData(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	sp, err := Resolve(Request{Gran: "1d", Since: now.Add(-36500 * 24 * time.Hour), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if g := sp.Grid(time.Time{}); len(g) != 0 {
		t.Errorf("no data -> no grid, got %d", len(g))
	}
	g := sp.Grid(now.Add(-10 * 24 * time.Hour))
	if len(g) != 11 {
		t.Errorf("100y window with 10 days of data -> %d buckets, want 11", len(g))
	}
	// A stray decades-old row: the data-bounded grid would exceed the cap,
	// so there is no zero-fill grid (the caller emits data buckets only).
	if g := sp.Grid(now.Add(-60 * 365 * 24 * time.Hour)); g != nil {
		t.Errorf("data-bounded grid over the cap: got %d buckets, want nil", len(g))
	}
	// A 7d span measured a few microseconds late is still a 7d span.
	sp7, _ := Resolve(Request{Since: now.Add(-7*24*time.Hour - 3*time.Microsecond), Now: now})
	if sp7.Gran != Hour {
		t.Errorf("7d window a hair over 7d: Auto = %s, want 1h", sp7.Gran)
	}
	sp2, _ := Resolve(Request{Since: now.Add(-time.Hour), Now: now})
	if g := sp2.Grid(time.Time{}); len(g) != 12 {
		t.Errorf("aligned 1h window at 5m -> %d buckets, want 12 (zero-filled even with no data)", len(g))
	}
	m := sp2.Meta()
	if m["bucket"] != "5m" || m["bucket_ms"] != int64(300000) || m["tz"] != "UTC" || m["since"] == "" {
		t.Errorf("meta = %v", m)
	}
}

// TestSlotChoice pins Spec.Slot's table walk: the coarsest UTC slot that
// lies wholly inside one bucket for every zone period of the window.
func TestSlotChoice(t *testing.T) {
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		gran string
		tz   string
		span time.Duration // 0 = unbounded
		want int64
	}{
		{"utc day", "1d", "UTC", 30 * 24 * time.Hour, 86400},
		{"utc week", "1w", "UTC", 365 * 24 * time.Hour, 86400},
		{"utc hour", "1h", "UTC", 24 * time.Hour, 3600},
		{"utc 5m", "5m", "UTC", time.Hour, 300},
		{"new york day across fall back", "1d", "America/New_York", 30 * 24 * time.Hour, 3600},
		{"new york hour", "1h", "America/New_York", 7 * 24 * time.Hour, 3600},
		{"ist day", "1d", "Asia/Kolkata", 30 * 24 * time.Hour, 900},
		{"ist hour", "1h", "Asia/Kolkata", 24 * time.Hour, 900},
		{"nepal hour", "1h", "Asia/Kathmandu", 24 * time.Hour, 900},
		{"ist 5m", "5m", "Asia/Kolkata", time.Hour, 300},
		{"lord howe day over a year (30-min DST)", "1d", "Australia/Lord_Howe", 365 * 24 * time.Hour, 900},
		{"ist all time", "1w", "Asia/Kolkata", 0, 900},
		// London is +0 in winter: a window wholly in GMT gets UTC-day slots.
		{"london winter day", "1d", "Europe/London", 7 * 24 * time.Hour, 86400},
		{"london across the change", "1d", "Europe/London", 30 * 24 * time.Hour, 3600},
	}
	for _, c := range cases {
		var since time.Time
		if c.span > 0 {
			since = now.Add(-c.span)
		}
		sp, err := Resolve(Request{Gran: c.gran, TZ: c.tz, Since: since, Now: now})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := sp.Slot().Seconds; got != c.want {
			t.Errorf("%s: slot = %ds, want %ds", c.name, got, c.want)
		}
	}
}

// TestSlotBucketIsExact is the regression for the SQL offset-at-until
// approximation (day buckets near midnight on the far side of a DST change
// landed on the wrong local day): for every minute of DST-crossing windows,
// the bucket recovered from the minute's UTC SLOT label equals the exact
// Floor of the minute itself.
func TestSlotBucketIsExact(t *testing.T) {
	type win struct{ since, until time.Time }
	wins := []win{
		{time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC), time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)},
		{time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)},
	}
	zones := []string{
		"UTC", "America/New_York", "Europe/London", "Asia/Kolkata", "Asia/Kathmandu",
		"Australia/Lord_Howe", "Pacific/Chatham", "America/St_Johns", "Antarctica/Troll",
	}
	for _, z := range zones {
		for _, w := range wins {
			for _, g := range []string{"5m", "1h", "1d", "1w"} {
				since := w.since
				if g == "5m" {
					since = w.until.Add(-6 * 24 * time.Hour) // under the 2000-point cap
				}
				sp, err := Resolve(Request{Gran: g, TZ: z, Since: since, Until: w.until, Now: w.until})
				if err != nil {
					t.Fatalf("%s %s: %v", z, g, err)
				}
				sl := sp.Slot()
				moved := 0
				for tt := since; tt.Before(w.until); tt = tt.Add(time.Minute) {
					start := time.Unix(floorDiv(tt.Unix(), sl.Seconds)*sl.Seconds, 0).UTC()
					b, ok := sl.Bucket(start.Format(sl.row.layout))
					if !ok || !b.Equal(sp.Floor(tt)) {
						moved++
						if moved <= 3 {
							t.Errorf("%s %s slot %ds: t=%s slot bucket %s, exact %s", z, g, sl.Seconds,
								tt.Format(time.RFC3339), sp.Key(b), sp.KeyOf(tt))
						}
					}
				}
			}
		}
	}
}

func TestSlotLabels(t *testing.T) {
	sl := UTCDaySlot()
	if b, ok := sl.Bucket("2026-09-29"); !ok || !b.Equal(time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("UTC day slot = %v %v", b, ok)
	}
	for _, bad := range []string{"", "2026-09-2", "2026-09-29T1", "garbage"} {
		if _, ok := sl.Bucket(bad); ok && bad != "" {
			t.Errorf("day slot parsed %q", bad)
		}
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	sp, _ := Resolve(Request{Gran: "1h", TZ: "Asia/Kolkata", Since: now.Add(-24 * time.Hour), Now: now})
	q := sp.Slot()
	if q.Seconds != 900 {
		t.Fatalf("IST hour slot = %d", q.Seconds)
	}
	// 14:30Z..14:44Z is the 20:00 IST hour.
	if b, ok := q.Bucket("2026-09-29T14:30"); !ok || sp.Key(b) != "2026-09-29T20:00:00+05:30" {
		t.Errorf("IST quarter bucket = %s %v", sp.Key(b), ok)
	}
	// The SQLite rendering's label is the integer slot index.
	if b, ok := q.IndexBucket(time.Date(2026, 9, 29, 14, 44, 0, 0, time.UTC).Unix()/900, true); !ok || sp.Key(b) != "2026-09-29T20:00:00+05:30" {
		t.Errorf("IST quarter bucket from a slot index = %s %v", sp.Key(b), ok)
	}
	if _, ok := q.IndexBucket(0, false); ok {
		t.Error("a NULL slot index (unreadable timestamp) must be excluded")
	}
	// The label a short / malformed timestamp produces never parses.
	for _, bad := range []string{"2026-09-2600", "2026-09-26", "", "2026-09-26T1x:00"} {
		if _, ok := q.Bucket(bad); ok {
			t.Errorf("quarter slot parsed %q", bad)
		}
	}
	for _, c := range []struct{ col, want string }{
		{q.TextExpr("ts"), "(substr(ts,1,14) || CASE WHEN substr(ts,15,2) < '15' THEN '00' WHEN substr(ts,15,2) < '30' THEN '15' WHEN substr(ts,15,2) < '45' THEN '30' ELSE '45' END)"},
		{UTCDaySlot().TextExpr("ts"), "substr(ts,1,10)"},
		{UTCDaySlot().SQLiteExpr("ts"), "(unixepoch(ts) / 86400)"},
		{q.SQLiteExpr("ts"), "(unixepoch(ts) / 900)"},
	} {
		if c.col != c.want {
			t.Errorf("expr = %s, want %s", c.col, c.want)
		}
	}
	if strings.Contains(q.TextExpr("ts"), "CAST") {
		t.Error("TextExpr must not cast (PostgreSQL rejects a cast of a malformed minute)")
	}
}

// TestLoadZoneUsesEmbeddedTZData proves a named zone resolves with no
// usable zone database on disk: the child process runs with ZONEINFO
// pointed at an empty directory (time reads ZONEINFO once, so the check
// runs in a fresh process). On a host without a system database (Windows,
// distroless) only the embedded time/tzdata copy can satisfy it;
// TestTZDataEmbedded pins the import structurally for hosts that have one.
func TestLoadZoneUsesEmbeddedTZData(t *testing.T) {
	if os.Getenv("TIMEBUCKET_TZ_CHILD") == "1" {
		for _, z := range []string{"Asia/Kolkata", "America/New_York", "Australia/Lord_Howe"} {
			loc, resolved, fellBack := LoadZone(z)
			if fellBack || resolved != z || loc == time.UTC {
				t.Fatalf("LoadZone(%q) = %v, %q, fellBack=%v; want the named zone", z, loc, resolved, fellBack)
			}
		}
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestLoadZoneUsesEmbeddedTZData$", "-test.count=1")
	cmd.Env = append(os.Environ(), "TIMEBUCKET_TZ_CHILD=1", "ZONEINFO="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child with an empty ZONEINFO failed: %v\n%s", err, out)
	}
}

// TestTZDataEmbedded pins the time/tzdata import in this package (see
// tzdata.go): removing it silently turns every chart on a host without a
// zone database into UTC buckets.
func TestTZDataEmbedded(t *testing.T) {
	af, err := parser.ParseFile(token.NewFileSet(), "tzdata.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range af.Imports {
		if strings.Trim(imp.Path.Value, `"`) == "time/tzdata" {
			return
		}
	}
	t.Fatal("tzdata.go must import time/tzdata")
}

// TestResolveAutoCaps pins Request.AutoCaps: Auto is raised to the cap's
// granularity only for a window over OverSpan; an explicit choice and a
// window within the span are untouched; a cap never makes Auto finer.
func TestResolveAutoCaps(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	caps := []AutoCap{{OverSpan: 48 * time.Hour, Gran: Day}}
	cases := []struct {
		name string
		gran string
		span time.Duration
		want Granularity
	}{
		{"within span keeps hour", "", 48 * time.Hour, Hour},
		{"over span raises to day", "", 72 * time.Hour, Day},
		{"7d raises to day", "", 7 * 24 * time.Hour, Day},
		{"explicit hour untouched", "1h", 7 * 24 * time.Hour, Hour},
		{"coarser auto untouched", "", 365 * 24 * time.Hour, Week},
		{"short window keeps 5m", "", time.Hour, Min5},
	}
	for _, c := range cases {
		sp, err := Resolve(Request{Gran: c.gran, Since: now.Add(-c.span), Now: now, AutoCaps: caps})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if sp.Gran != c.want {
			t.Errorf("%s: %s, want %s", c.name, sp.Gran, c.want)
		}
	}
}
