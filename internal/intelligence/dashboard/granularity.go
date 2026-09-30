package dashboard

// Chart time granularity - the dashboard's one seam onto internal/timebucket
// (docs/plans/chart-time-granularity-plan-2026-09-29.md).
//
// Every time-series handler resolves its window through windowRange and then
// its bucket through bucketSpec: `gran` (auto|5m|1h|1d|1w; the legacy
// `bucket=day|hour` is still honoured when `gran` is absent) and `tz` (the
// viewer's IANA zone; unknown -> UTC, echoed). A granularity that would
// exceed the 2000-point cap is a typed 400, never a silent coarsening. The
// handler then keys rows with the spec, zero-fills the grid (bucketSlots) and
// merges spec.Meta() (bucket, bucket_ms, tz, gran_auto, since, until) into its
// response. The analytics response cache keys on the canonical query, so
// gran / tz / bucket are part of every cached route's key by construction.

import (
	"errors"
	"net/http"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/timebucket"
)

// bucketSpec resolves the request's granularity + viewer zone against the
// already-resolved window. allowed optionally restricts the granularities
// the surface can serve.
func bucketSpec(r *http.Request, since, until time.Time, allowed ...timebucket.Granularity) (timebucket.Spec, error) {
	q := r.URL.Query()
	return timebucket.Resolve(timebucket.Request{
		Gran:         q.Get("gran"),
		LegacyBucket: q.Get("bucket"),
		TZ:           q.Get("tz"),
		Since:        since,
		Until:        until,
		Allowed:      allowed,
	})
}

// writeBucketErr renders a bucketSpec error: a *timebucket.RequestError is
// the caller's fault (400, code granularity); anything else is a 500.
func writeBucketErr(w http.ResponseWriter, err error) {
	var re *timebucket.RequestError
	if errors.As(err, &re) {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": re.Error(), "code": "granularity"})
		return
	}
	writeErr(w, err)
}

// parseStoredTS parses a stored row timestamp (RFC3339 / RFC3339Nano, or
// SQLite's "YYYY-MM-DD HH:MM:SS" UTC form).
func parseStoredTS(ts string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02 15:04:05", ts); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// tsBucketKeyer returns the cost engine's Options.BucketKey for spec: the
// stored timestamp string -> its bucket key. Every granularity is at least
// five minutes wide and every real zone offset is a whole number of minutes,
// so all timestamps in one UTC minute share a bucket; the keyer memoizes on
// that minute prefix, which keeps a 200k-row window to a map lookup per row.
// A timestamp that does not parse keeps its date prefix (the pre-granularity
// behaviour) rather than vanishing.
func tsBucketKeyer(spec timebucket.Spec) func(ts string) string {
	memo := map[string]string{}
	return func(ts string) string {
		minute := ""
		if len(ts) >= 17 && ts[len(ts)-1] == 'Z' {
			minute = ts[:16]
			if k, ok := memo[minute]; ok {
				return k
			}
		}
		t, ok := parseStoredTS(ts)
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

// bucketSlot is one zero-fill grid bucket.
type bucketSlot struct {
	Key string
	T   time.Time
}

// bucketSlots returns the ordered buckets a response must emit: the spec's
// zero-fill grid plus any data bucket outside it (a row stamped exactly at
// the window edge, or an unparseable key, is never dropped). data maps a
// bucket key to its bucket start (zero time when unknown).
func bucketSlots(spec timebucket.Spec, data map[string]time.Time) []bucketSlot {
	var earliest time.Time
	for _, t := range data {
		if !t.IsZero() && (earliest.IsZero() || t.Before(earliest)) {
			earliest = t
		}
	}
	grid := spec.Grid(earliest)
	out := make([]bucketSlot, 0, len(grid)+len(data))
	seen := make(map[string]bool, len(grid))
	for _, b := range grid {
		k := spec.Key(b)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, bucketSlot{Key: k, T: b})
	}
	for k, t := range data {
		if !seen[k] {
			seen[k] = true
			out = append(out, bucketSlot{Key: k, T: t})
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

// keyStart recovers a bucket key's start instant (keys come from
// spec.Key, or a legacy date prefix). Zero when it does not parse.
func keyStart(spec timebucket.Spec, key string) time.Time {
	if t, err := time.Parse(time.RFC3339, key); err == nil {
		return t
	}
	if t, err := time.ParseInLocation("2006-01-02", key, spec.Loc); err == nil {
		return spec.Floor(t.Add(12 * time.Hour))
	}
	return time.Time{}
}

// millis renders a bucket start as the `t` field (epoch ms; 0 when unknown).
func millis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// withBucketMeta merges spec.Meta() into a response map. The meta fields
// (bucket, bucket_ms, tz, gran_auto, since, until) are authoritative; the
// handler's other fields (`days`, `metric`, ...) are kept as they were.
func withBucketMeta(spec timebucket.Spec, resp map[string]any) map[string]any {
	for k, v := range spec.Meta() {
		resp[k] = v
	}
	return resp
}
