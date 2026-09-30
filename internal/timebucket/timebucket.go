package timebucket

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// Granularity is one chart bucket width.
type Granularity string

// The granularity vocabulary. The string values are the wire tokens (the
// `gran` query param and the `bucket` field every time-series response
// echoes).
const (
	Min5 Granularity = "5m"
	Hour Granularity = "1h"
	Day  Granularity = "1d"
	Week Granularity = "1w"
)

// Auto is the request token meaning "let Choose pick from the span".
const Auto = "auto"

// MaxPoints is the point cap: a granularity is allowed for a span only when
// the grid it produces holds at most this many buckets. Day and week are
// always allowed (Rule.AlwaysAllowed) - their grids are clamped to the data
// instead (see Spec.Grid).
const MaxPoints = 2000

// Rule is one row of the granularity table.
type Rule struct {
	Gran Granularity
	// Step is the nominal bucket width (a DST day is still reported as 24h;
	// flooring itself is calendar-exact, see Floor).
	Step time.Duration
	// AutoMaxSpan is the largest window span Auto assigns this granularity
	// to (inclusive). Zero means unbounded (the last row).
	AutoMaxSpan time.Duration
	// AlwaysAllowed exempts the granularity from the point cap.
	AlwaysAllowed bool
}

// Table is THE granularity table, finest first (CLAUDE.md #5: decision
// logic is a data table walked top-down). shared/lib/granularity.ts mirrors
// it; granularity.fixture.json pins both.
var Table = []Rule{
	{Gran: Min5, Step: 5 * time.Minute, AutoMaxSpan: 3 * time.Hour},
	{Gran: Hour, Step: time.Hour, AutoMaxSpan: 7 * 24 * time.Hour},
	{Gran: Day, Step: 24 * time.Hour, AutoMaxSpan: 180 * 24 * time.Hour, AlwaysAllowed: true},
	{Gran: Week, Step: 7 * 24 * time.Hour, AlwaysAllowed: true},
}

// Unbounded is the span used for a window with no lower bound.
const Unbounded = time.Duration(math.MaxInt64)

func rule(g Granularity) (Rule, bool) {
	for _, r := range Table {
		if r.Gran == g {
			return r, true
		}
	}
	return Rule{}, false
}

// aliases maps the accepted spellings (including the legacy `bucket=day|
// hour` values the pre-granularity endpoints took) to a granularity.
var aliases = map[string]Granularity{
	"5m": Min5, "5min": Min5, "minute5": Min5,
	"1h": Hour, "hour": Hour, "h": Hour,
	"1d": Day, "day": Day, "d": Day,
	"1w": Week, "week": Week, "w": Week,
}

// Parse resolves a wire token. ok is false for an unknown token. An empty
// token or "auto" returns ("", true): the caller should Choose.
func Parse(s string) (g Granularity, ok bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == Auto {
		return "", true
	}
	g, ok = aliases[s]
	return g, ok
}

// Valid reports whether g is in the table.
func (g Granularity) Valid() bool { _, ok := rule(g); return ok }

// Step returns g's nominal bucket width (0 for an unknown granularity).
func (g Granularity) Step() time.Duration { r, _ := rule(g); return r.Step }

// Millis returns Step in milliseconds (the `bucket_ms` response field).
func (g Granularity) Millis() int64 { return g.Step().Milliseconds() }

// SubDay reports whether g is finer than a day.
func (g Granularity) SubDay() bool { return g == Min5 || g == Hour }

// Choose picks the Auto granularity for a window span: the first table row
// whose AutoMaxSpan covers it.
func Choose(span time.Duration) Granularity {
	for _, r := range Table {
		if r.AutoMaxSpan == 0 || span <= r.AutoMaxSpan {
			return r.Gran
		}
	}
	return Table[len(Table)-1].Gran
}

// Points returns the most buckets a window of this span can touch at g:
// floor(span/step)+1 (a window that does not start on a bucket boundary
// touches a partial bucket at each end). An unbounded span returns
// math.MaxInt.
func Points(span time.Duration, g Granularity) int {
	step := g.Step()
	if step <= 0 || span < 0 {
		return 0
	}
	if span == Unbounded {
		return math.MaxInt
	}
	return int(span/step) + 1
}

// Allowed lists the granularities a span permits, finest first.
func Allowed(span time.Duration) []Granularity {
	out := make([]Granularity, 0, len(Table))
	for _, r := range Table {
		if r.AlwaysAllowed || Points(span, r.Gran) <= MaxPoints {
			out = append(out, r.Gran)
		}
	}
	return out
}

// CapError is the typed refusal of a granularity that would exceed the
// point cap for the requested span. Handlers render it as a 400.
type CapError struct {
	Gran   Granularity
	Span   time.Duration
	Points int
	Max    int
}

func (e *CapError) Error() string {
	span := "an unbounded window"
	if e.Span != Unbounded {
		span = "a " + e.Span.Round(time.Minute).String() + " window"
	}
	return fmt.Sprintf("granularity %s over %s needs more than %d points (max %d); choose a coarser granularity or a shorter window",
		e.Gran, span, e.Max, e.Max)
}

// ErrUnknownGranularity is returned for a token Parse does not know.
var ErrUnknownGranularity = errors.New("unknown granularity (want auto, 5m, 1h, 1d or 1w)")

// Validate refuses g for span when its grid would exceed MaxPoints. It
// never coarsens: the caller gets a *CapError and says so.
func Validate(g Granularity, span time.Duration) error {
	r, ok := rule(g)
	if !ok {
		return ErrUnknownGranularity
	}
	if r.AlwaysAllowed {
		return nil
	}
	if p := Points(span, g); p > MaxPoints {
		return &CapError{Gran: g, Span: span, Points: p, Max: MaxPoints}
	}
	return nil
}

// Floor returns the start of the bucket holding t, in loc.
//
// Sub-day buckets floor on the absolute timeline shifted by the zone's
// offset AT t, so an off-hour zone (IST +5:30) gets buckets at :30 UTC and
// a DST fall-back hour yields two distinct buckets (both labelled 01:00).
// Day buckets are local calendar days; week buckets start on Monday.
func Floor(t time.Time, g Granularity, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	t = t.In(loc)
	switch g {
	case Min5, Hour:
		_, off := t.Zone()
		step := int64(g.Step() / time.Second)
		u := t.Unix() + int64(off)
		fl := floorDiv(u, step)*step - int64(off)
		// A zone change that is not a multiple of the step (Lord Howe's
		// 30-minute DST shift under hour buckets) would otherwise floor t
		// to an instant BEFORE the change, i.e. into the previous
		// offset's grid, overlapping the bucket before it. A zone period
		// always starts a new bucket, so the bucket never reaches back
		// across its own offset change.
		if zs, _ := t.ZoneBounds(); !zs.IsZero() && fl < zs.Unix() {
			fl = zs.Unix()
		}
		return time.Unix(fl, 0).In(loc)
	case Week:
		y, m, d := t.Date()
		back := (int(t.Weekday()) + 6) % 7 // Monday = 0
		return time.Date(y, m, d-back, 0, 0, 0, 0, loc)
	default: // Day
		y, m, d := t.Date()
		return time.Date(y, m, d, 0, 0, 0, 0, loc)
	}
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if (a%b != 0) && ((a < 0) != (b < 0)) {
		q--
	}
	return q
}

// Next returns the start of the bucket after the one starting at start.
func Next(start time.Time, g Granularity, loc *time.Location) time.Time {
	if loc == nil {
		loc = time.UTC
	}
	switch g {
	case Min5, Hour:
		step := g.Step()
		n := Floor(start.Add(step), g, loc)
		if !n.After(start) {
			n = Floor(start.Add(2*step), g, loc)
		}
		// An offset change inside (start, n) starts a bucket of its own
		// (see Floor), so the next bucket begins there.
		if _, ze := start.In(loc).ZoneBounds(); !ze.IsZero() && ze.After(start) && ze.Before(n) {
			n = ze.In(loc)
		}
		return n
	case Week:
		s := start.In(loc)
		y, m, d := s.Date()
		return Floor(time.Date(y, m, d+7, 12, 0, 0, 0, loc), Week, loc)
	default:
		s := start.In(loc)
		y, m, d := s.Date()
		return Floor(time.Date(y, m, d+1, 12, 0, 0, 0, loc), Day, loc)
	}
}

// Grid returns the bucket starts covering [since, until) at g in loc,
// oldest first. It returns ok=false (and nil) when the grid would exceed
// max buckets, so a caller never builds an unbounded slice.
func Grid(since, until time.Time, g Granularity, loc *time.Location, max int) (grid []time.Time, ok bool) {
	if !g.Valid() || !until.After(since) {
		return nil, true
	}
	last := until.Add(-time.Nanosecond)
	for b := Floor(since, g, loc); !b.After(last); b = Next(b, g, loc) {
		if len(grid) >= max {
			return nil, false
		}
		grid = append(grid, b)
	}
	return grid, true
}

// Key renders a bucket start as its wire key: the local calendar date
// ("2026-09-29") for day and week buckets, RFC3339 with the zone offset for
// sub-day buckets ("2026-09-29T14:00:00+05:30"; "...Z" in UTC, which is
// byte-identical to the pre-granularity hour keys).
func Key(start time.Time, g Granularity, loc *time.Location) string {
	if loc == nil {
		loc = time.UTC
	}
	start = start.In(loc)
	if g.SubDay() {
		return start.Format(time.RFC3339)
	}
	return start.Format("2006-01-02")
}

// LoadZone resolves an IANA zone name. An empty, unknown or malformed name
// falls back to UTC; fellBack reports that so the response can say so.
func LoadZone(name string) (loc *time.Location, resolved string, fellBack bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return time.UTC, "UTC", false
	}
	// "Local" would silently mean the SERVER's zone; refuse it.
	if len(name) > 64 || name == "Local" || strings.ContainsAny(name, "\\\x00") || strings.Contains(name, "..") {
		return time.UTC, "UTC", true
	}
	l, err := time.LoadLocation(name)
	if err != nil {
		return time.UTC, "UTC", true
	}
	return l, l.String(), false
}
