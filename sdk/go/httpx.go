package superbased

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const userAgent = "superbased-sdk-go"

// response is the outcome of one control call. status 0 means no HTTP answer
// (a transport failure or a timeout, see err).
type response struct {
	status  int
	body    any // decoded JSON (numbers as json.Number), or nil
	headers http.Header
	err     string
	raw     []byte
}

func (r *response) ok() bool { return r.status >= 200 && r.status < 300 }

func (r *response) header(name string) string {
	if r.headers == nil {
		return ""
	}
	return r.headers.Get(name)
}

// obj is the body as a JSON object (nil when it is not one).
func (r *response) obj() map[string]any {
	m, _ := r.body.(map[string]any)
	return m
}

// errorCode is the SDK control API error envelope's "error" field, or "".
func (r *response) errorCode() string {
	if m := r.obj(); m != nil {
		if s, ok := m["error"].(string); ok {
			return s
		}
	}
	return ""
}

func (r *response) describe() string {
	if r.status == 0 {
		if r.err != "" {
			return r.err
		}
		return "no response"
	}
	out := fmt.Sprintf("HTTP %d", r.status)
	if code := r.errorCode(); code != "" {
		out += " " + code
	}
	if m := r.obj(); m != nil {
		if msg, ok := m["message"].(string); ok && msg != "" {
			out += ": " + msg
		}
	}
	return out
}

// isLoopbackURL reports whether raw's host is 127.0.0.0/8, ::1 or localhost.
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// queryParam is one query parameter (kept in order).
type queryParam struct{ k, v string }

func joinURL(base, path string, query []queryParam) string {
	out := strings.TrimRight(base, "/") + path
	q := url.Values{}
	var order []string
	for _, p := range query {
		if p.v == "" {
			continue
		}
		if _, ok := q[p.k]; !ok {
			order = append(order, p.k)
		}
		q.Add(p.k, p.v)
	}
	if len(order) > 0 {
		parts := make([]string, 0, len(order))
		for _, k := range order {
			for _, v := range q[k] {
				parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
			}
		}
		out += "?" + strings.Join(parts, "&")
	}
	return out
}

var (
	transportMu   sync.Mutex
	transports    = map[bool]http.RoundTripper{}
	testTransport func(loopback bool) http.RoundTripper // tests capture requests here
)

// transportFor is the round tripper for a call: a loopback call never goes
// through an HTTP(S)_PROXY from the environment; a remote call honours it.
func transportFor(loopback bool) http.RoundTripper {
	transportMu.Lock()
	defer transportMu.Unlock()
	if testTransport != nil {
		return testTransport(loopback)
	}
	if t, ok := transports[loopback]; ok {
		return t
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	if loopback {
		t.Proxy = nil
	} else {
		t.Proxy = http.ProxyFromEnvironment
	}
	transports[loopback] = t
	return t
}

// clientFor is an http.Client that never follows a redirect: a credential is
// never forwarded to a host the caller did not name.
func clientFor(rawURL string, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport:     transportFor(isLoopbackURL(rawURL)),
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func decodeJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	return v
}

// marshalCompact is compact JSON without HTML escaping.
func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// doRequest is one HTTP call with a JSON body (when given) and a JSON answer.
// It never returns an error: a failure is a response with status 0.
func doRequest(ctx context.Context, method, rawURL string, body any, headers map[string]string, timeout time.Duration) *response {
	if ctx == nil {
		ctx = context.Background()
	}
	if timeout <= 0 {
		timeout = time.Millisecond
	}
	var rd io.Reader
	if body != nil {
		b, err := marshalCompact(body)
		if err != nil {
			return &response{err: "the request body is not JSON: " + err.Error()}
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return &response{err: err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := clientFor(rawURL, timeout).Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return &response{err: fmt.Sprintf("timeout after %s (%v)", timeout, err)}
		}
		return &response{err: err.Error()}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return &response{status: resp.StatusCode, body: decodeJSON(raw), headers: resp.Header, raw: raw}
}

// --- loose JSON readers ---------------------------------------------------------

func jsonStr(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

// jsonInt reads an integer (json.Number or a Go number); ok false otherwise.
func jsonInt(v any) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	}
	return 0, false
}

// jsonFloat reads a number (never a bool).
func jsonFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// jsonText renders a scalar id the way Python's str() would ("" for nil).
func jsonText(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	default:
		return fmt.Sprint(t)
	}
}
