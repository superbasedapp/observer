package warp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Shared vocabulary of the Warp drivers.
const (
	// APIBase is the path prefix of every route: the OpenAPI server is
	// https://app.warp.dev/api/v1.
	APIBase = "/api/v1"
	// ParamRunID is the connection parameter naming one run (the per-run
	// surfaces).
	ParamRunID = "run_id"
	// PageSize is the page size the runs list asks for (the documented
	// range is 1 to 500, default 20).
	PageSize = 100
	// ExecutionRemote is the only execution_location the runs list asks for:
	// "Executed by a remote/cloud worker". LOCAL runs ran in the user's own
	// Warp app.
	ExecutionRemote = "REMOTE"
	// ExecutionLocal is the documented value of a run executed locally.
	ExecutionLocal = "LOCAL"

	// contract is the pinned source every surface's contract version names.
	contract = "warpdotdev/docs@4aa3f12 developers/agent-api-openapi.yaml"
)

// bearerAuth is the documented auth: components.securitySchemes.bearerAuth,
// "Authentication via a Warp API key or a supported Warp-issued user token".
var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

var (
	// cursorRE bounds an opaque page cursor before it is sent back.
	cursorRE = regexp.MustCompile(`^[A-Za-z0-9_=+/.:~-]{1,512}$`)
	// idRE bounds a run, conversation, step, message or action id (the
	// documented ids are UUIDs; the bound is wider on purpose).
	idRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	// tokenRE bounds a vendor enum or name before it lands as a token.
	tokenRE = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
)

func drift(surface vs.SurfaceID, format string, a ...any) error {
	return fmt.Errorf("%w: %s: "+format, append([]any{vendorapi.ErrSchemaDrift, surface}, a...)...)
}

func decode(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	return dec.Decode(v)
}

// status200 refuses any status but the documented 200.
func status200(surface vs.SurfaceID, r vendorapi.Response) error {
	if r.Status != 200 {
		return drift(surface, "status %d is not the documented 200", r.Status)
	}
	return nil
}

// runPath builds /api/v1/agent/runs/{runId}<suffix> from a validated run id.
func runPath(surface vs.SurfaceID, p vendorapi.Params, suffix string) (string, error) {
	id := p[ParamRunID]
	if !idRE.MatchString(id) {
		return "", fmt.Errorf("%s: parameter %s is missing or not a run id", surface, ParamRunID)
	}
	return APIBase + "/agent/runs/" + url.PathEscape(id) + suffix, nil
}

// rfc3339 reads an RFC 3339 timestamp into UTC.
func rfc3339(s *string) (time.Time, bool) {
	if s == nil || *s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
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
		return fmt.Errorf("warp: %.16q is not a JSON number", b)
	}
	*n = num(b)
	return nil
}

// counter reads an optional whole non-negative count. present is false for
// an absent or null counter (the schema: "Absent or null means unmeasured,
// not zero"); ok is false for a value that is not a count.
func counter(n *num) (v int64, present, ok bool) {
	if n == nil {
		return 0, false, true
	}
	v, err := strconv.ParseInt(string(*n), 10, 64)
	return v, true, err == nil && v >= 0
}

// amount reads an optional non-negative amount (a JSON double: a credit
// count or US dollars) as micros of its unit.
func amount(n *num) (v int64, present, ok bool) {
	if n == nil {
		return 0, false, true
	}
	v, ok = vendorapi.FloatMicros(string(*n))
	return v, true, ok && v >= 0
}
