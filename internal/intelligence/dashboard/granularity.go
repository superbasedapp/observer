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

// tsBucketKeyer returns the cost engine's Options.BucketKey for spec: the
// stored timestamp string -> its bucket key (timebucket.StoredKeyer, shared
// with `observer chart`).
func tsBucketKeyer(spec timebucket.Spec) func(ts string) string {
	return timebucket.StoredKeyer(spec)
}

// bucketSlot is one zero-fill grid bucket.
type bucketSlot = timebucket.GridSlot

// bucketSlots returns the ordered buckets a response must emit
// (timebucket.Slots: the zero-fill grid plus any data bucket outside it).
func bucketSlots(spec timebucket.Spec, data map[string]time.Time) []bucketSlot {
	return timebucket.Slots(spec, data)
}

// keyStart recovers a bucket key's start instant (timebucket.KeyStart).
func keyStart(spec timebucket.Spec, key string) time.Time { return timebucket.KeyStart(spec, key) }

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
