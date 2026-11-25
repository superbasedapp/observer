package openai

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Shared vocabulary of the OpenAI drivers.
const (
	// Tool is the registry tool the Platform activity surfaces report on
	// (a segment: the Platform APIs have no Codex dimension, EA-F11).
	Tool = "codex"
	// LegacyOrgKey is the ownership key of the legacy codexanalytics
	// poller's openai_org surface, which reads the usage and cost endpoints.
	LegacyOrgKey = "codexanalytics.openai_org"

	day = 24 * time.Hour
	// settleLag widens every report request back so a day's last hours are
	// read again after they settle (recent buckets revise, catalog).
	settleLag = 2 * time.Hour
	// ReportBucketLimit is the documented maximum of daily buckets per page
	// on the usage endpoints (1d: default 7, maximum 31; costs allow 180).
	ReportBucketLimit = 31
	// ReportMaxWindow keeps one run's daily buckets inside one page.
	ReportMaxWindow = 28 * day
	// ListPageLimit is the documented maximum page size of the list
	// endpoints (audit logs and users: 1 to 100).
	ListPageLimit = 100
)

// adminAuth is the documented Admin API auth: an Admin key as a bearer token.
var adminAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

// cursorRE bounds an opaque next_page token or last_id before it is sent back.
var cursorRE = regexp.MustCompile(`^[A-Za-z0-9_=+/.:-]{1,512}$`)

// bucketPage is the usage and costs envelope: object page, data buckets,
// has_more and next_page (sent back as page).
type bucketPage[R any] struct {
	Data     *[]bucket[R] `json:"data"`
	HasMore  *bool        `json:"has_more"`
	NextPage *string      `json:"next_page"`
}

type bucket[R any] struct {
	StartTime *json.Number `json:"start_time"`
	EndTime   *json.Number `json:"end_time"`
	Results   *[]R         `json:"results"`
}

// envelope checks the bucket page paging contract and returns the next cursor.
func envelope[R any](surface vs.SurfaceID, r vendorapi.Response, doc *bucketPage[R]) (string, error) {
	if r.Status != 200 {
		return "", vendorapi.Drift(surface, "status %d is not the documented 200", r.Status)
	}
	if err := vendorapi.DecodeNumbers(r.Body, doc); err != nil {
		return "", vendorapi.Drift(surface, "body does not decode as the documented page")
	}
	if doc.Data == nil || doc.HasMore == nil {
		return "", vendorapi.Drift(surface, "required field data or has_more is missing")
	}
	if !*doc.HasMore {
		return "", nil
	}
	if doc.NextPage == nil || !cursorRE.MatchString(*doc.NextPage) {
		return "", vendorapi.Drift(surface, "has_more is true without a usable next_page")
	}
	return *doc.NextPage, nil
}

// bucketInterval reads a daily bucket's Unix-second bounds. The fact interval
// is the whole UTC day, so a partial current-day bucket is the provisional
// value of that day and a later restatement replaces it.
func bucketInterval[R any](surface vs.SurfaceID, i int, b bucket[R]) (time.Time, time.Time, error) {
	if b.StartTime == nil || b.EndTime == nil {
		return time.Time{}, time.Time{}, vendorapi.Drift(surface, "data[%d] misses start_time or end_time", i)
	}
	s, err1 := b.StartTime.Int64()
	e, err2 := b.EndTime.Int64()
	if err1 != nil || err2 != nil {
		return time.Time{}, time.Time{}, vendorapi.Drift(surface, "data[%d] bounds are not Unix seconds", i)
	}
	start, end := time.Unix(s, 0).UTC(), time.Unix(e, 0).UTC()
	if !start.Equal(start.Truncate(day)) || !end.After(start) || end.Sub(start) > day {
		return time.Time{}, time.Time{}, vendorapi.Drift(surface, "data[%d] is not a daily bucket", i)
	}
	return start, start.Add(day), nil
}

// reportQuery is the query of a daily bucket report: start_time from UTC
// midnight of the window start moved back by settleLag, end_time the window
// end, both Unix seconds.
func reportQuery(surface vs.SurfaceID, w vendorapi.Window, cursor string) (map[string][]string, error) {
	if w.From.IsZero() || !w.To.After(w.From) {
		return nil, fmt.Errorf("%s: a non-empty window is required", surface)
	}
	start := w.From.UTC().Add(-settleLag).Truncate(day)
	q := map[string][]string{
		"start_time":   {strconv.FormatInt(start.Unix(), 10)},
		"end_time":     {strconv.FormatInt(w.To.UTC().Unix(), 10)},
		"bucket_width": {"1d"},
		"limit":        {strconv.Itoa(ReportBucketLimit)},
	}
	if cursor != "" {
		if !cursorRE.MatchString(cursor) {
			return nil, fmt.Errorf("%s: cursor is not an opaque page token", surface)
		}
		q["page"] = []string{cursor}
	}
	return q, nil
}

// listDoc is the list envelope of the audit-log and users endpoints.
type listDoc[T any] struct {
	Data    *[]T    `json:"data"`
	HasMore *bool   `json:"has_more"`
	LastID  *string `json:"last_id"`
}

// listEnvelope checks a list page and returns its next cursor (last_id).
func listEnvelope[T any](surface vs.SurfaceID, r vendorapi.Response, doc *listDoc[T]) (string, error) {
	if r.Status != 200 {
		return "", vendorapi.Drift(surface, "status %d is not the documented 200", r.Status)
	}
	if err := vendorapi.DecodeNumbers(r.Body, doc); err != nil {
		return "", vendorapi.Drift(surface, "body does not decode as the documented list")
	}
	if doc.Data == nil || doc.HasMore == nil {
		return "", vendorapi.Drift(surface, "required field data or has_more is missing")
	}
	if !*doc.HasMore {
		return "", nil
	}
	if doc.LastID == nil || !cursorRE.MatchString(*doc.LastID) {
		return "", vendorapi.Drift(surface, "has_more is true without a usable last_id")
	}
	return *doc.LastID, nil
}

// listQuery adds the limit and the after cursor of a list request.
func listQuery(surface vs.SurfaceID, cursor string) (map[string][]string, error) {
	q := map[string][]string{"limit": {strconv.Itoa(ListPageLimit)}}
	if cursor != "" {
		if !cursorRE.MatchString(cursor) {
			return nil, fmt.Errorf("%s: cursor is not an object id", surface)
		}
		q["after"] = []string{cursor}
	}
	return q, nil
}

// count reads a non-negative JSON integer in micro-units.
func count(n *json.Number) (int64, bool) {
	if n == nil {
		return 0, false
	}
	v, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return vendorapi.CountMicros(v)
}

// unixRFC3339 renders an optional Unix-second timestamp as RFC 3339.
func unixRFC3339(n *json.Number) (string, bool) {
	if n == nil {
		return "", true
	}
	v, err := n.Int64()
	if err != nil || v < 0 {
		return "", false
	}
	return time.Unix(v, 0).UTC().Format(time.RFC3339), true
}
