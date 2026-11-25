package cognition

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Shared vocabulary of the Cognition drivers.
const (
	// Tool is the registry tool the Devin enterprise surfaces report on.
	Tool = "devin"
	// PageSize is the documented maximum of the v3 cursor pages (first,
	// 1 to 200).
	PageSize = 200
	day      = 24 * time.Hour
)

// bearerAuth is the documented v3 auth: a service-user credential (prefix
// cog_) as "Authorization: Bearer" (securitySchemes.bearerAuth).
var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

// cursorRE bounds an opaque end_cursor before it is sent back as "after".
var cursorRE = regexp.MustCompile(`^[A-Za-z0-9_=+/.:-]{1,512}$`)

// paginated is the v3 cursor envelope (PaginatedResponse[T]): items
// (required), has_next_page (default false) and end_cursor (null on the last
// page).
type paginated[T any] struct {
	Items       *[]T    `json:"items"`
	HasNextPage *bool   `json:"has_next_page"`
	EndCursor   *string `json:"end_cursor"`
}

// envelope checks the paging contract of one v3 page and returns its next
// cursor ("" on the terminal page). A missing has_next_page reads as its
// documented default, false.
func envelope[T any](surface vs.SurfaceID, r vendorapi.Response, doc *paginated[T]) (string, error) {
	if r.Status != 200 {
		return "", vendorapi.Drift(surface, "status %d is not the documented 200", r.Status)
	}
	if err := vendorapi.DecodeNumbers(r.Body, doc); err != nil {
		return "", vendorapi.Drift(surface, "body does not decode as the documented paginated response")
	}
	if doc.Items == nil {
		return "", vendorapi.Drift(surface, "required field items is missing")
	}
	if doc.HasNextPage == nil || !*doc.HasNextPage {
		return "", nil
	}
	if doc.EndCursor == nil || !cursorRE.MatchString(*doc.EndCursor) {
		return "", vendorapi.Drift(surface, "has_next_page is true without a usable end_cursor")
	}
	if r.Cursor != "" && *doc.EndCursor == r.Cursor {
		return "", vendorapi.Drift(surface, "end_cursor repeats the cursor the page was asked with")
	}
	return *doc.EndCursor, nil
}

// pageQuery adds the documented page size and a validated cursor as after.
func pageQuery(surface vs.SurfaceID, q map[string][]string, cursor string) error {
	q["first"] = []string{strconv.Itoa(PageSize)}
	if cursor == "" {
		return nil
	}
	if !cursorRE.MatchString(cursor) {
		return fmt.Errorf("%s: cursor is not an opaque end_cursor", surface)
	}
	q["after"] = []string{cursor}
	return nil
}

// num is a JSON number kept as its literal text. Unlike json.Number it
// refuses a quoted value: a number the vendor starts sending as a string is a
// type change, so the page fails as schema drift (plan 12A.5). A JSON null
// leaves a *num nil.
type num string

// UnmarshalJSON accepts a bare JSON number only.
func (n *num) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || (b[0] != '-' && (b[0] < '0' || b[0] > '9')) {
		return fmt.Errorf("cognition: %.16q is not a JSON number", b)
	}
	*n = num(b)
	return nil
}

// unixSeconds reads a v3 integer timestamp as Unix seconds (the unit the
// reference documents for time_after and time_before; that response
// timestamps share it is Inferred). A value that is not a whole number, is
// negative or is beyond year 9999 is refused.
func unixSeconds(n *num) (time.Time, bool) {
	if n == nil {
		return time.Time{}, false
	}
	v, err := strconv.ParseInt(string(*n), 10, 64)
	if err != nil || v < 0 || v > 253402300799 {
		return time.Time{}, false
	}
	return time.Unix(v, 0).UTC(), true
}

// acuMicros reads a non-negative ACU amount (a JSON number) in micro-ACUs.
func acuMicros(n *num) (int64, bool) {
	if n == nil {
		return 0, false
	}
	v, ok := vendorapi.DecimalMicros(string(*n), 0)
	if !ok || v < 0 {
		return 0, false
	}
	return v, true
}
