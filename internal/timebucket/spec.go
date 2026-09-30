package timebucket

import (
	"fmt"
	"time"
)

// Request is the transport-neutral input a handler resolves: the raw
// `gran` (or legacy `bucket`) token, the raw `tz` name and the window the
// handler already resolved.
type Request struct {
	// Gran is the `gran` query value ("", "auto", "5m", "1h", "1d", "1w").
	Gran string
	// LegacyBucket is the pre-granularity `bucket=day|hour` value, honoured
	// only when Gran is empty.
	LegacyBucket string
	// TZ is the viewer's IANA zone name.
	TZ string
	// Since is the window's inclusive lower bound; zero = unbounded.
	Since time.Time
	// Until is the window's exclusive upper bound; zero = now.
	Until time.Time
	// Now is the clock (zero = time.Now()).
	Now time.Time
	// Allowed optionally restricts the granularities a surface can serve
	// (a chart fed by a day-grained summary passes {Day, Week}). Empty
	// means the whole table. Auto picks the finest allowed granularity at
	// or above Choose's answer.
	Allowed []Granularity
	// AutoCaps optionally coarsens Auto for this surface (never an explicit
	// choice): the first row whose OverSpan the window exceeds raises a
	// finer Auto answer to its Gran. A surface whose sub-day buckets cost
	// materially more than its day buckets (the org spend series: raw rows
	// vs the daily summary) caps Auto without taking the finer choice away.
	AutoCaps []AutoCap
}

// AutoCap is one per-surface Auto cap row: for a window longer than
// OverSpan, Auto picks nothing finer than Gran.
type AutoCap struct {
	OverSpan time.Duration
	Gran     Granularity
}

// Spec is a resolved bucket request.
type Spec struct {
	Gran Granularity
	// Auto reports that the caller asked for Auto (or nothing).
	Auto bool
	Loc  *time.Location
	// TZ is the zone actually used ("UTC" on fallback).
	TZ string
	// TZFallback reports that the requested zone was unknown and UTC was
	// used instead.
	TZFallback bool
	// Since / Until are the window bounds; Until is never zero (now when
	// the request had none).
	Since, Until time.Time
}

// RequestError is a caller error (bad token, over the cap, a granularity
// the surface cannot serve). Handlers render it as a 400.
type RequestError struct{ Err error }

func (e *RequestError) Error() string { return e.Err.Error() }
func (e *RequestError) Unwrap() error { return e.Err }

// Span returns the window span, or Unbounded when Since is zero.
func (s Spec) Span() time.Duration { return span(s.Since, s.Until) }

func span(since, until time.Time) time.Duration {
	if since.IsZero() {
		return Unbounded
	}
	if d := until.Sub(since); d > 0 {
		return d
	}
	return 0
}

// Resolve turns a Request into a Spec. Errors are *RequestError.
func Resolve(req Request) (Spec, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	until := req.Until
	if until.IsZero() {
		until = now
	}
	loc, tz, fellBack := LoadZone(req.TZ)
	sp := Spec{Loc: loc, TZ: tz, TZFallback: fellBack, Since: req.Since, Until: until.UTC()}
	if !sp.Since.IsZero() {
		sp.Since = sp.Since.UTC()
	}

	token := req.Gran
	if token == "" {
		token = req.LegacyBucket
	}
	g, ok := Parse(token)
	if !ok {
		return Spec{}, &RequestError{Err: fmt.Errorf("gran %q: %w", token, ErrUnknownGranularity)}
	}
	allowed := func(x Granularity) bool {
		if len(req.Allowed) == 0 {
			return true
		}
		for _, a := range req.Allowed {
			if a == x {
				return true
			}
		}
		return false
	}
	// Round to the second: a handler that resolved `since = now - 7d`
	// a few microseconds before Resolve read the clock must still see a 7d
	// span (Auto's edges are inclusive), exactly as the SPA does.
	w := span(sp.Since, sp.Until)
	if w != Unbounded {
		w = w.Round(time.Second)
	}
	if g == "" {
		sp.Auto = true
		g = Choose(w)
		if !allowed(g) {
			// Walk down the table from Choose's answer to the first
			// granularity this surface serves (never finer than Auto).
			picked := Granularity("")
			seen := false
			for _, r := range Table {
				if r.Gran == g {
					seen = true
				}
				if seen && allowed(r.Gran) {
					picked = r.Gran
					break
				}
			}
			if picked == "" {
				picked = req.Allowed[len(req.Allowed)-1]
			}
			g = picked
		}
		for _, c := range req.AutoCaps {
			if w > c.OverSpan {
				if g.Step() < c.Gran.Step() {
					g = c.Gran
				}
				break
			}
		}
	} else if !allowed(g) {
		return Spec{}, &RequestError{Err: fmt.Errorf("granularity %s is not available for this chart (daily data only)", g)}
	}
	if err := Validate(g, w); err != nil {
		return Spec{}, &RequestError{Err: err}
	}
	sp.Gran = g
	return sp, nil
}

// Floor floors t into this spec's bucket.
func (s Spec) Floor(t time.Time) time.Time { return Floor(t, s.Gran, s.Loc) }

// Key renders a bucket start as its wire key.
func (s Spec) Key(start time.Time) string { return Key(start, s.Gran, s.Loc) }

// KeyOf floors t and renders its bucket key.
func (s Spec) KeyOf(t time.Time) string { return s.Key(s.Floor(t)) }

// Grid returns the zero-fill grid, oldest first. When the window's own grid
// fits MaxPoints it spans the whole window. When it does not (an
// always-allowed day/week granularity over an "all" window), it starts at
// the earliest bucket that holds data (earliest; zero = no data, so no
// grid) - zero-filling a century of empty days is noise, not honesty. If
// even the data-bounded grid exceeds MaxPoints (a stray decades-old
// timestamp), there is no zero-fill grid at all (nil): the caller emits
// its data buckets only, so the point cap still bounds the response.
func (s Spec) Grid(earliest time.Time) []time.Time {
	if !s.Since.IsZero() {
		if g, ok := Grid(s.Since, s.Until, s.Gran, s.Loc, MaxPoints); ok {
			return g
		}
	}
	if earliest.IsZero() {
		return nil
	}
	from := earliest
	if !s.Since.IsZero() && from.Before(s.Since) {
		from = s.Since
	}
	g, ok := Grid(from, s.Until, s.Gran, s.Loc, MaxPoints)
	if !ok {
		return nil
	}
	return g
}

// Meta returns the response metadata every time-series response echoes:
// bucket, bucket_ms, tz (+ tz_fallback when the requested zone was not
// usable), gran_auto, since, until.
func (s Spec) Meta() map[string]any {
	m := map[string]any{
		"bucket":    string(s.Gran),
		"bucket_ms": s.Gran.Millis(),
		"tz":        s.TZ,
		"gran_auto": s.Auto,
		"until":     s.Until.UTC().Format(time.RFC3339),
		"since":     "",
	}
	if !s.Since.IsZero() {
		m["since"] = s.Since.UTC().Format(time.RFC3339)
	}
	if s.TZFallback {
		m["tz_fallback"] = true
	}
	return m
}
