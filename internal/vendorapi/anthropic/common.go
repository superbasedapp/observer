package anthropic

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Shared vocabulary of the Anthropic drivers.
const (
	// APIVersion is the anthropic-version header every Admin API example sends.
	APIVersion = "2023-06-01"
	// Tool is the registry tool the Console activity surfaces report on. The
	// usage and cost reports cover the org's whole API-key traffic, so their
	// coverage stays a segment (never complete for the tool, plan 7.2).
	Tool = "claude-code"
	// day is the width of every bucket these drivers request.
	day = 24 * time.Hour
	// settleLag widens every request back by the documented freshness
	// (usage and cost within about 5 minutes, Claude Code analytics up to 1
	// hour) plus margin, so the last hours of a day are re-read after they
	// settle and the provisional value is replaced.
	settleLag = 2 * time.Hour
)

// adminAuth is the documented Admin API auth: the key as the whole value of
// X-Api-Key (catalog auth kind header_key).
var adminAuth = vendorapi.AuthContract{Kind: vs.AuthHeaderKey, Scheme: vendorapi.SchemeRawHeader, Header: "X-Api-Key"}

func headers() map[string]string { return map[string]string{"anthropic-version": APIVersion} }

// cursorRE bounds an opaque next_page or last_id cursor before it is sent
// back as a query value.
var cursorRE = regexp.MustCompile(`^[A-Za-z0-9_=+/.:-]{1,512}$`)

// reportDoc is the report envelope of the usage, cost and Claude Code
// reports: data, has_more and next_page (an opaque token sent back as page).
type reportDoc[T any] struct {
	Data     *[]T    `json:"data"`
	HasMore  *bool   `json:"has_more"`
	NextPage *string `json:"next_page"`
}

// envelope checks the paging contract of a report page and returns its next
// cursor ("" on the terminal page).
func envelope[T any](surface vs.SurfaceID, r vendorapi.Response, doc *reportDoc[T]) (string, error) {
	if r.Status != 200 {
		return "", vendorapi.Drift(surface, "status %d is not the documented 200", r.Status)
	}
	if err := vendorapi.DecodeNumbers(r.Body, doc); err != nil {
		return "", vendorapi.Drift(surface, "body does not decode as the documented report")
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

// pageQuery adds a validated cursor as the page parameter.
func pageQuery(surface vs.SurfaceID, q map[string][]string, cursor string) error {
	if cursor == "" {
		return nil
	}
	if !cursorRE.MatchString(cursor) {
		return fmt.Errorf("%s: cursor is not an opaque page token", surface)
	}
	q["page"] = []string{cursor}
	return nil
}

// bucketWindow is the request window of a daily report: from UTC midnight of
// the window start (moved back by settleLag) to the window end.
func bucketWindow(surface vs.SurfaceID, w vendorapi.Window) (time.Time, time.Time, error) {
	if w.From.IsZero() || !w.To.After(w.From) {
		return time.Time{}, time.Time{}, fmt.Errorf("%s: a non-empty window is required", surface)
	}
	start := w.From.UTC().Add(-settleLag).Truncate(day)
	return start, w.To.UTC(), nil
}

// bucketInterval reads one daily bucket's bounds. A bucket starts at UTC
// midnight and ends after its start, at most one day later; the fact
// interval is always the whole day, so a partial current-day bucket lands as
// the provisional value of that day and a later run's restatement replaces
// it (decide.MergeFact) instead of adding a second interval.
func bucketInterval(surface vs.SurfaceID, i int, startS, endS *string) (time.Time, time.Time, error) {
	if startS == nil || endS == nil {
		return time.Time{}, time.Time{}, vendorapi.Drift(surface, "data[%d] misses starting_at or ending_at", i)
	}
	start, err1 := time.Parse(time.RFC3339Nano, *startS)
	end, err2 := time.Parse(time.RFC3339Nano, *endS)
	if err1 != nil || err2 != nil {
		return time.Time{}, time.Time{}, vendorapi.Drift(surface, "data[%d] bounds are not RFC 3339", i)
	}
	start, end = start.UTC(), end.UTC()
	if !start.Equal(start.Truncate(day)) || !end.After(start) || end.Sub(start) > day {
		return time.Time{}, time.Time{}, vendorapi.Drift(surface, "data[%d] is not a daily bucket", i)
	}
	return start, start.Add(day), nil
}

// count reads a non-negative JSON integer and returns it in micro-units.
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
