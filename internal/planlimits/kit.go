package planlimits

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// kit.go holds the small, pure helpers every driver uses: request builders
// for the common auth shapes and a tolerant JSON reader. A driver stays a
// plan function plus a parse function; these keep each one short.

// --- request builders ---------------------------------------------------------

// AuthStyle is how a secret travels in a request.
type AuthStyle int

// Auth styles.
const (
	AuthBearer AuthStyle = iota // Authorization: Bearer <secret>
	AuthHeader                  // <Header>: <secret>
	AuthCookie                  // Cookie: <secret> (a pasted browser session)
)

// authHeaders builds the secret header map for one auth style. name is the
// header for AuthHeader.
func authHeaders(style AuthStyle, name, secret string) map[string]string {
	switch style {
	case AuthHeader:
		return map[string]string{name: secret}
	case AuthCookie:
		return map[string]string{"Cookie": SessionCookie(secret)}
	default:
		return bearer(secret)
	}
}

// SessionCookie normalises a pasted browser session: a full "Cookie: a=b"
// line, a bare "a=b; c=d" header value, or a cURL copy's -H value all become
// the header value. Control characters are dropped so a paste can never
// inject a second header.
func SessionCookie(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(strings.ToLower(s), "cookie:"); i >= 0 {
		s = s[i+len("cookie:"):]
	}
	return cleanPaste(s)
}

// cleanPaste trims quotes and spaces and drops control characters.
func cleanPaste(s string) string {
	s = strings.Trim(strings.TrimSpace(s), ` '"`)
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// SessionBearer normalises a pasted bearer token: "Authorization: Bearer x",
// "Bearer x" and "x" all become "x".
func SessionBearer(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(strings.ToLower(s), "authorization:"); i >= 0 {
		s = strings.TrimSpace(s[i+len("authorization:"):])
	}
	if strings.HasPrefix(strings.ToLower(s), "bearer ") {
		s = strings.TrimSpace(s[len("bearer "):])
	}
	return cleanPaste(s)
}

// keyedGET returns a Plan function for one GET to u carrying secret key in
// the given style. Extra plain headers ride along.
func keyedGET(u, secretKey string, style AuthStyle, headerName string, extra map[string]string) func(PlanInput) ([]Request, error) {
	return func(in PlanInput) ([]Request, error) {
		k, err := secret(in, secretKey)
		if err != nil {
			return nil, err
		}
		h := map[string]string{"Accept": "application/json"}
		for n, v := range extra {
			h[n] = v
		}
		return []Request{{Key: "main", Kind: ReqHTTP, Method: "GET", URL: u, Header: h, SecretHeaders: authHeaders(style, headerName, k)}}, nil
	}
}

// --- tolerant JSON reading ------------------------------------------------------

// J is a decoded JSON value with path helpers. Every getter returns ok=false
// for a missing, null or wrongly typed value: unknown is never zero.
type J struct{ v any }

// ParseJ decodes a JSON body. A body that is not JSON is a shape error.
func ParseJ(body []byte) (J, error) {
	var v any
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return J{}, shapeErr("json", err)
	}
	return J{v}, nil
}

// At walks a dotted path ("data.balance", "items.0.used"). A numeric segment
// indexes an array.
func (j J) At(path string) J {
	cur := j.v
	if path == "" {
		return j
	}
	for _, seg := range strings.Split(path, ".") {
		switch c := cur.(type) {
		case map[string]any:
			cur = c[seg]
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(c) {
				return J{}
			}
			cur = c[i]
		default:
			return J{}
		}
	}
	return J{cur}
}

// Exists reports whether the value is present and not null.
func (j J) Exists() bool { return j.v != nil }

// Num reads a number or a numeric string.
func (j J) Num() (float64, bool) {
	switch v := j.v.(type) {
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case float64:
		return v, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "%")), 64)
		return f, err == nil
	}
	return 0, false
}

// NumP reads a number into a pointer; nil when unknown.
func (j J) NumP() *float64 {
	if f, ok := j.Num(); ok {
		return &f
	}
	return nil
}

// Str reads a string (a number is rendered as its literal).
func (j J) Str() (string, bool) {
	switch v := j.v.(type) {
	case string:
		return v, true
	case json.Number:
		return v.String(), true
	}
	return "", false
}

// Bool reads a boolean.
func (j J) Bool() (bool, bool) {
	b, ok := j.v.(bool)
	return b, ok
}

// Arr returns the elements of an array; nil when not an array.
func (j J) Arr() []J {
	a, ok := j.v.([]any)
	if !ok {
		return nil
	}
	out := make([]J, len(a))
	for i, v := range a {
		out[i] = J{v}
	}
	return out
}

// Keys returns an object's keys, sorted; nil when not an object.
func (j J) Keys() []string {
	m, ok := j.v.(map[string]any)
	if !ok {
		return nil
	}
	return sortedKeys(m)
}

// First returns the first path that exists.
func (j J) First(paths ...string) J {
	for _, p := range paths {
		if v := j.At(p); v.Exists() {
			return v
		}
	}
	return J{}
}

// Micros reads a decimal money amount (a number or a string) into integer
// micros without float rounding for strings. scale is the power of ten the
// amount is already in (2 for cents).
func (j J) Micros(scale int) (int64, bool) {
	switch v := j.v.(type) {
	case json.Number:
		m, err := MicrosFromDecimal(v.String(), scale)
		return m, err == nil
	case string:
		m, err := MicrosFromDecimal(strings.TrimPrefix(strings.TrimSpace(v), "$"), scale)
		return m, err == nil
	case float64:
		m, err := MicrosFromDecimal(strconv.FormatFloat(v, 'f', -1, 64), scale)
		return m, err == nil
	}
	return 0, false
}

// Time reads a time from an RFC 3339 string or an epoch number. Epoch values
// above 1e12 are taken as milliseconds, otherwise seconds.
func (j J) Time() *time.Time {
	if s, ok := j.v.(string); ok {
		if t := parseISO(s); t != nil {
			return t
		}
		if t, err := time.Parse("2006-01-02", s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	f, ok := j.Num()
	if !ok || f <= 0 {
		return nil
	}
	if f > 1e12 {
		t := time.UnixMilli(int64(f)).UTC()
		return &t
	}
	return unixPtr(int64(f))
}

// --- window builders -------------------------------------------------------------

// PercentWindow builds a percent window from a 0..100 used percentage.
func PercentWindow(key string, usedPercent float64, reset *time.Time, length time.Duration) Window {
	w := Window{Key: key, Unit: UnitPercent, UsedFrac: fracFromPercent(usedPercent), ResetsAt: reset}
	if length > 0 {
		w.Length = dur(length)
	}
	return w
}

// AmountWindow builds an amount window from any two of used, limit and
// remaining (pointers; nil is unknown). ok=false when no reading results.
func AmountWindow(key string, unit Unit, used, limit, remaining *float64, reset *time.Time, length time.Duration) (Window, bool) {
	w := Window{Key: key, Unit: unit, Used: used, Limit: limit, Remaining: remaining, ResetsAt: reset}
	if w.Used == nil && limit != nil && remaining != nil {
		w.Used = F(*limit - *remaining)
	}
	if w.Remaining == nil && limit != nil && w.Used != nil {
		w.Remaining = F(max(*limit-*w.Used, 0))
	}
	if limit != nil && *limit > 0 && w.Used != nil {
		w.UsedFrac = F(min(max(*w.Used / *limit, 0), 2))
	}
	if length > 0 {
		w.Length = dur(length)
	}
	if w.Used == nil && w.Remaining == nil && w.Limit == nil {
		return Window{}, false
	}
	return w, true
}

// requireAny returns a shape error naming what when the snapshot has no
// numbers at all.
func requireAny(s Snapshot, what string) error {
	if len(s.Windows)+len(s.Balances)+len(s.Spend) == 0 && s.Status == StatusOK {
		return shapeErr(fmt.Sprintf("%s: no readings", what), nil)
	}
	return nil
}
