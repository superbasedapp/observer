package openhands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Shared vocabulary of the OpenHands drivers.
const (
	// Tool is the tool the OpenHands Cloud surfaces report on. No capture
	// adapter or registry row exists for it yet; the node connector (lane
	// CA-B2) owns that mapping.
	Tool = "openhands"
	// PageSize is the documented maximum page size of both search routes
	// (limit, default 100, max 100).
	PageSize = 100
	// maxBodyText caps a free-text snapshot value (a title) below
	// vendorapi.MaxAttrValue.
	maxBodyText = 256
)

// bearerAuth is the documented Cloud auth: "Authorization: Bearer <Cloud API
// key>" (reference OH01).
var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

var (
	// pageIDRE bounds an opaque next_page_id before it is sent back.
	pageIDRE = regexp.MustCompile(`^[A-Za-z0-9_=+/.:-]{1,512}$`)
	// idRE bounds a conversation or event id.
	idRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
)

func drift(surface vs.SurfaceID, format string, a ...any) error {
	return fmt.Errorf("%w: %s: "+format, append([]any{vendorapi.ErrSchemaDrift, surface}, a...)...)
}

func decode(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	return dec.Decode(v)
}

// page is the V1 search envelope: items (required) and next_page_id (null
// on the last page).
type page[T any] struct {
	Items      *[]T    `json:"items"`
	NextPageID *string `json:"next_page_id"`
}

// envelope checks one search page's paging contract and returns its next
// cursor ("" on the last page).
func envelope[T any](surface vs.SurfaceID, r vendorapi.Response, doc *page[T]) (string, error) {
	if r.Status != 200 {
		return "", drift(surface, "status %d is not the documented 200", r.Status)
	}
	if err := decode(r.Body, doc); err != nil {
		return "", drift(surface, "body does not decode as the documented page")
	}
	if doc.Items == nil {
		return "", drift(surface, "required field items is missing")
	}
	if doc.NextPageID == nil || *doc.NextPageID == "" {
		return "", nil
	}
	if !pageIDRE.MatchString(*doc.NextPageID) {
		return "", drift(surface, "next_page_id is not an opaque page id")
	}
	if *doc.NextPageID == r.Cursor {
		return "", drift(surface, "next_page_id repeats the page the request asked for")
	}
	return *doc.NextPageID, nil
}

// pageQuery adds the page size and a validated page_id.
func pageQuery(surface vs.SurfaceID, q map[string][]string, cursor string) error {
	q["limit"] = []string{strconv.Itoa(PageSize)}
	if cursor == "" {
		return nil
	}
	if !pageIDRE.MatchString(cursor) {
		return fmt.Errorf("%s: cursor is not an opaque next_page_id", surface)
	}
	q["page_id"] = []string{cursor}
	return nil
}

// windowQuery adds a half-open [From, To) filter on field as RFC 3339
// field__gte and field__lt. A zero window adds nothing (a full listing); a
// half or inverted window is refused.
func windowQuery(surface vs.SurfaceID, q map[string][]string, field string, w vendorapi.Window) error {
	switch {
	case w.From.IsZero() && w.To.IsZero():
		return nil
	case w.From.IsZero() || !w.To.After(w.From):
		return fmt.Errorf("%s: a window needs both bounds, From before To", surface)
	}
	q[field+"__gte"] = []string{w.From.UTC().Format(time.RFC3339)}
	q[field+"__lt"] = []string{w.To.UTC().Format(time.RFC3339)}
	return nil
}

// isoLayouts are the timestamp spellings accepted, most specific first. The
// SDK serializes event timestamps without a zone (Python isoformat of a
// naive datetime); a zoneless value is read as UTC (Inferred).
var isoLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"}

// isoTime reads an ISO 8601 timestamp into UTC.
func isoTime(s *string) (time.Time, bool) {
	if s == nil || *s == "" {
		return time.Time{}, false
	}
	for _, layout := range isoLayouts {
		if t, err := time.Parse(layout, *s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// capText cuts text at a rune boundary within max bytes.
func capText(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

func str(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// num is a JSON number kept as its literal text; it refuses a quoted value
// (a number turned string is a type change, plan 12A.5). A JSON null leaves
// a *num nil.
type num string

// UnmarshalJSON accepts a bare JSON number only.
func (n *num) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("openhands: %.16q is not a JSON number", b)
	}
	*n = num(b)
	return nil
}

// count reads an optional whole non-negative count (0 when absent).
func count(n *num) (int64, bool) {
	if n == nil {
		return 0, true
	}
	v, err := strconv.ParseInt(string(*n), 10, 64)
	return v, err == nil && v >= 0
}
