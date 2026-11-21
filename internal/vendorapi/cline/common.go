package cline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// Shared vocabulary of the Cline Cloud drivers.
const (
	// Tool is the tool a Cline cloud session lands under: the same tool id
	// as the local VS Code extension (CA-D1: where a session ran is
	// execution_location, not a new tool id).
	Tool = "cline"
	// ParamSessionID names the cloud session a status or history request
	// reads (the outer "ses-..." id).
	ParamSessionID = "session_id"
	// SourceCommit is the github.com/cline/cline commit the VS Code
	// extension source was read at (2026-11-01).
	SourceCommit = "a6507a62a147db4a35e27f4294589742ccac5060"
	// SourcePackage is the npm package whose type declarations and compiled
	// client define the session API shapes.
	SourcePackage = "@cline/core@0.2.0"
)

// bearerAuth is the client's auth: "Authorization: Bearer <token>"
// (@cline/core 0.2.0 CloudSessionApi.request). An app.cline.bot API key
// ("sk_...", Account > API Keys) is accepted as the token on all three
// reads (live check 2026-11-02).
var bearerAuth = vendorapi.AuthContract{Kind: vs.AuthBearer, Scheme: vendorapi.SchemeBearer, Header: "Authorization"}

// idRE bounds a session, task or message id. Cloud session ids are
// "ses-..." (apps/vscode/src/shared/cloud/cloud-sessions.ts
// isPersistedCloudSessionId); the rule admits any plain id so a format
// change is not refused, only an unsafe one.
var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// ValidID reports whether s may be used as a session id in a request path.
func ValidID(s string) bool { return idRE.MatchString(s) }

func drift(surface vs.SurfaceID, format string, a ...any) error {
	return fmt.Errorf("%w: %s: "+format, append([]any{vendorapi.ErrSchemaDrift, surface}, a...)...)
}

// decode decodes a JSON body with numbers kept as literals.
func decode(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	return dec.Decode(v)
}

// isNull reports whether a body is the JSON literal null (the node egress
// answers a 404 the connector declares absent with it).
func isNull(body []byte) bool { return string(bytes.TrimSpace(body)) == "null" }

// checkStatus refuses any status but the documented 200.
func checkStatus(surface vs.SurfaceID, r vendorapi.Response) error {
	if r.Status != 200 {
		return drift(surface, "status %d is not the documented 200", r.Status)
	}
	return nil
}

// isoTime reads an ISO 8601 timestamp (JavaScript Date.toISOString) into
// UTC; ok is false for a value that does not parse.
func isoTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// putTime sets an optional ISO timestamp as RFC 3339 seconds; a value that
// does not parse is drift. ok reports success.
func putTime(body map[string]string, key string, v *string) bool {
	if v == nil || *v == "" {
		return true
	}
	t, ok := isoTime(*v)
	if !ok {
		return false
	}
	body[key] = t.Format(time.RFC3339)
	return true
}

// putShort sets an optional id-shaped value, refusing an over-long one.
func putShort(body map[string]string, key string, v *string) bool {
	if v == nil || *v == "" {
		return true
	}
	if len(*v) > vendorapi.MaxIDLen {
		return false
	}
	body[key] = *v
	return true
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
		return fmt.Errorf("cline: %.16q is not a JSON number", b)
	}
	*n = num(b)
	return nil
}

// count reads a present count as a whole non-negative number.
func count(n *num) (int64, bool) {
	v, err := strconv.ParseInt(string(*n), 10, 64)
	return v, err == nil && v >= 0
}
