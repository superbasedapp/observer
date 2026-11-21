package superbased

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace/noop"
)

// contractDir is sdk/contract (SUPERBASED_CONTRACT_DIR when the suite runs on
// a copy of the package).
func contractDir() string {
	if d := os.Getenv("SUPERBASED_CONTRACT_DIR"); d != "" {
		return d
	}
	return filepath.Join("..", "contract")
}

// setup isolates one test: SDK state, the environment, the global provider
// and the log capture. Discovery is off unless the test turns it on.
func setup(t *testing.T) *logCapture {
	t.Helper()
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		for _, p := range []string{"SUPERBASED_", "OTEL_", "OBSERVER_CAPTURE", "ANTHROPIC_OPEN_TELEMETRY"} {
			if strings.HasPrefix(k, p) {
				t.Setenv(k, "")
				os.Unsetenv(k)
			}
		}
	}
	t.Setenv("SUPERBASED_DISCOVER", "0")
	resetForTests()
	otel.SetTracerProvider(noop.NewTracerProvider())
	lc := &logCapture{}
	SetLogger(slog.New(lc))
	t.Cleanup(func() {
		resetForTests()
		SetLogger(nil)
		transportMu.Lock()
		testTransport = nil
		transportMu.Unlock()
	})
	return lc
}

// logCapture is a slog handler that keeps every record.
type logCapture struct {
	mu    sync.Mutex
	lines []string
	warns []string
}

func (l *logCapture) Enabled(context.Context, slog.Level) bool { return true }
func (l *logCapture) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, r.Message)
	if r.Level >= slog.LevelWarn {
		l.warns = append(l.warns, r.Message)
	}
	return nil
}
func (l *logCapture) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logCapture) WithGroup(string) slog.Handler      { return l }

func (l *logCapture) warnings(contains string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, w := range l.warns {
		if strings.Contains(w, contains) {
			out = append(out, w)
		}
	}
	return out
}

// stubReq is one request a stub saw.
type stubReq struct {
	Method, Path, Query string
	Headers             http.Header
	Body                map[string]any
	Raw                 []byte
}

type stubAnswer func(stubReq) (int, any, map[string]string)

// stub is a scripted HTTP server: reply sets the default answer, route
// answers one method and path (query ignored). An OTLP export with no route
// gets the default status and an empty body.
type stub struct {
	srv      *httptest.Server
	URL      string
	mu       sync.Mutex
	requests []stubReq
	routes   map[string]stubAnswer
	status   int
	body     any
	headers  map[string]string
	delay    time.Duration
}

func newStub(t *testing.T) *stub {
	s := &stub{routes: map[string]stubAnswer{}, status: 200, body: map[string]any{}}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	s.URL = s.srv.URL
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stub) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	req := stubReq{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Headers: r.Header.Clone(), Raw: raw}
	var body map[string]any
	if json.Unmarshal(raw, &body) == nil {
		req.Body = body
	}
	s.mu.Lock()
	s.requests = append(s.requests, req)
	status, out, headers, delay := s.status, s.body, s.headers, s.delay
	hit := s.routes[r.Method+" "+r.URL.Path]
	s.mu.Unlock()
	otlp := strings.HasSuffix(r.URL.Path, "/v1/traces") && hit == nil
	if hit != nil {
		status, out, headers = hit(req)
	}
	if delay > 0 {
		time.Sleep(delay)
	}
	for k, v := range headers {
		w.Header().Set(k, v)
	}
	w.WriteHeader(status)
	if otlp {
		return
	}
	if b, ok := out.([]byte); ok {
		_, _ = w.Write(b)
		return
	}
	b, _ := json.Marshal(out)
	_, _ = w.Write(b)
}

func (s *stub) reply(body any, status int, headers map[string]string) {
	s.mu.Lock()
	s.body, s.status, s.headers = body, status, headers
	s.mu.Unlock()
}

func (s *stub) setDelay(d time.Duration) {
	s.mu.Lock()
	s.delay = d
	s.mu.Unlock()
}

func (s *stub) route(method, path string, fn stubAnswer) {
	s.mu.Lock()
	s.routes[method+" "+path] = fn
	s.mu.Unlock()
}

func (s *stub) routeBody(method, path string, body any) {
	s.route(method, path, func(stubReq) (int, any, map[string]string) { return 200, body, nil })
}

func (s *stub) seen(path string) []stubReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []stubReq
	for _, r := range s.requests {
		if path == "" || r.Path == path {
			out = append(out, r)
		}
	}
	return out
}

// deadURL is a loopback URL nothing listens on.
func deadURL(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return "http://" + addr
}

// captured is a RoundTripper that records each request and answers a clean
// verdict, so nothing is dialled.
type captured struct {
	mu    sync.Mutex
	calls []capturedCall
}

type capturedCall struct {
	URL      string
	Headers  http.Header
	Body     map[string]any
	Loopback bool
}

func (c *captured) install() {
	transportMu.Lock()
	testTransport = func(loopback bool) http.RoundTripper {
		return rtFunc(func(r *http.Request) (*http.Response, error) {
			raw, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			c.mu.Lock()
			c.calls = append(c.calls, capturedCall{r.URL.String(), r.Header.Clone(), body, loopback})
			c.mu.Unlock()
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(bytes.NewReader([]byte(`{"allowed": true, "decision": "allow"}`))), Request: r}, nil
		})
	}
	transportMu.Unlock()
}

func (c *captured) last() capturedCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[len(c.calls)-1]
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// loadSection reads one section of sdk-behaviour-cases.json.
func loadSection(t *testing.T, name string) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(contractDir(), "sdk-behaviour-cases.json"))
	if err != nil {
		t.Skipf("sdk/contract is not present: %v", err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	var sec map[string]json.RawMessage
	if err := json.Unmarshal(all[name], &sec); err != nil {
		t.Fatalf("section %s: %v", name, err)
	}
	return sec
}

// cases decodes a section's cases into T.
func cases[T any](t *testing.T, name string) []T {
	t.Helper()
	var out []T
	if err := json.Unmarshal(loadSection(t, name)["cases"], &out); err != nil {
		t.Fatalf("section %s cases: %v", name, err)
	}
	return out
}
