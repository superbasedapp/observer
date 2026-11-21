package timebucket

import (
	"sort"
	"time"
)

// This file holds the zero-fill and keying helpers every time-series
// consumer shares: the node dashboard's handlers and `observer chart` call
// the same functions, so a bucket on the CLI is the bucket the dashboard
// draws (one owner per metric; the helpers used to live unexported in
// internal/intelligence/dashboard/granularity.go).

// ParseStoredTS parses a stored row timestamp (RFC3339 / RFC3339Nano, or
// SQLite's "YYYY-MM-DD HH:MM:SS" UTC form).
func ParseStoredTS(ts string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02 15:04:05", ts); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// StoredKeyer returns a func mapping a stored timestamp string to its bucket
// key under spec (the cost engine's Options.BucketKey). Every granularity is
// at least five minutes wide and every real zone offset is a whole number of
// minutes, so all timestamps in one UTC minute share a bucket; the keyer
// memoizes on that minute prefix, which keeps a 200k-row window to a map
// lookup per row. A timestamp that does not parse keeps its date prefix (the
// pre-granularity behaviour) rather than vanishing. The returned func is not
// safe for concurrent use.
func StoredKeyer(spec Spec) func(ts string) string {
	memo := map[string]string{}
	return func(ts string) string {
		minute := ""
		if len(ts) >= 17 && ts[len(ts)-1] == 'Z' {
			minute = ts[:16]
			if k, ok := memo[minute]; ok {
				return k
			}
		}
		t, ok := ParseStoredTS(ts)
		if !ok {
			if len(ts) >= 10 {
				return ts[:10]
			}
			return ts
		}
		k := spec.KeyOf(t)
		if minute != "" && len(memo) < 1<<16 {
			memo[minute] = k
		}
		return k
	}
}

// GridSlot is one bucket of a response's ordered, zero-filled axis.
type GridSlot struct {
	Key string
	T   time.Time
}

// Slots returns the ordered buckets a series must emit: the spec's
// zero-fill grid plus any data bucket outside it (a row stamped exactly at
// the window edge, or an unparseable key, is never dropped). data maps a
// bucket key to its bucket start (zero time when unknown).
func Slots(spec Spec, data map[string]time.Time) []GridSlot {
	var earliest time.Time
	for _, t := range data {
		if !t.IsZero() && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	grid := spec.Grid(earliest)
	out := make([]GridSlot, 0, len(grid)+len(data))
	seen := make(map[string]bool, len(grid))
	for _, b := range grid {
		k := spec.Key(b)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, GridSlot{Key: k, T: b})
	}
	for k, t := range data {
		if !seen[k] {
			seen[k] = true
			out = append(out, GridSlot{Key: k, T: t})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].T.Equal(out[j].T) {
			return out[i].T.Before(out[j].T)
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// KeyStart recovers a bucket key's start instant (keys come from spec.Key,
// or a legacy date prefix). Zero when it does not parse.
func KeyStart(spec Spec, key string) time.Time {
	if t, err := time.Parse(time.RFC3339, key); err == nil {
		return t
	}
	if t, err := time.ParseInLocation("2006-01-02", key, spec.Loc); err == nil {
		return spec.Floor(t.Add(12 * time.Hour))
	}
	return time.Time{}
}
