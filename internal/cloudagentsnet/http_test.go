package cloudagentsnet

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respond(status int, body string, hdr http.Header) *http.Response {
	if hdr == nil {
		hdr = http.Header{}
	}
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: hdr}
}

func TestDefaultTableAllowsNoOtherHost(t *testing.T) {
	c := New(Options{})
	for _, u := range []string{"https://api.github.com/user", "https://chatgpt.com/backend-api/x", "https://api.cursor.com.evil.io/v1/agents"} {
		if cloudagents.ClassOf(c.CheckURL(u)) != cloudagents.ErrHostNotAllowed {
			t.Errorf("%s allowed: only the API rows' exact hosts are in the table", u)
		}
	}
	called := false
	c = New(Options{HTTP: &http.Client{Transport: rtFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return respond(200, "{}", nil), nil
	})}})
	cur, _ := cloudagents.ConnectorByID(cloudagents.ConnectorCursorCloud)
	req := cloudagents.Request{Connector: cur.ID, Op: cloudagents.OpList, URL: "https://api.github.com/user", Auth: cur.Auth}
	if _, err := c.Call(context.Background(), req, "k"); cloudagents.ClassOf(err) != cloudagents.ErrHostNotAllowed || called {
		t.Fatalf("refused URL reached the transport: %v called=%v", err, called)
	}
}

// getForTest drives readJSON (the response classifier every API call goes
// through) against a test-only host. There is deliberately no exported
// equivalent: production egress is Call/Stream, bound to the connector row.
func getForTest(c *Client, raw string, headers map[string]string) ([]byte, error) {
	if err := c.CheckURL(raw); err != nil {
		return nil, err
	}
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.readJSON(ctx, req, cloudagents.OpList, nil)
}

func TestCheckURL(t *testing.T) {
	c := New(Options{APIHosts: []string{"api.example.com"}})
	cases := map[string]bool{
		"https://api.example.com/v1/x":      true,
		"https://API.example.com:443/v1":    true,
		"http://api.example.com/v1":         false,
		"https://api.example.com:8443/v1":   false,
		"https://u:p@api.example.com/v1":    false,
		"https://api.example.com/v1#frag":   false,
		"https://api.example.com.evil.io/x": false,
		"https://evil.io/api.example.com":   false,
		"::not a url":                       false,
	}
	for u, ok := range cases {
		if err := c.CheckURL(u); (err == nil) != ok {
			t.Errorf("%s: err=%v want ok=%v", u, err, ok)
		}
	}
}

func TestReadJSONClassifiesResponses(t *testing.T) {
	var gotAuth string
	tr := rtFunc(func(r *http.Request) (*http.Response, error) {
		gotAuth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/ok":
			return respond(200, `{"ok":true}`, nil), nil
		case "/redirect":
			return respond(302, "", http.Header{"Location": {"https://evil.io/steal"}}), nil
		case "/denied":
			return respond(401, "bad key sk-secret", nil), nil
		case "/slow":
			return respond(429, "", nil), nil
		case "/big":
			return respond(200, strings.Repeat("x", MaxOutput+1), nil), nil
		}
		return respond(503, "", nil), nil
	})
	c := New(Options{APIHosts: []string{"api.example.com"}, HTTP: &http.Client{Transport: tr}})
	hdr := map[string]string{"Authorization": "Bearer sk-secret"}
	b, err := getForTest(c, "https://api.example.com/ok", hdr)
	if err != nil || string(b) != `{"ok":true}` || gotAuth != "Bearer sk-secret" {
		t.Fatalf("ok: %s %v %q", b, err, gotAuth)
	}
	cases := map[string]cloudagents.ErrorClass{
		"/redirect": cloudagents.ErrHostNotAllowed,
		"/denied":   cloudagents.ErrNotSignedIn,
		"/slow":     cloudagents.ErrRateLimited,
		"/big":      cloudagents.ErrOverCap,
		"/down":     cloudagents.ErrServerError,
	}
	for path, want := range cases {
		_, err := getForTest(c, "https://api.example.com"+path, hdr)
		if cloudagents.ClassOf(err) != want {
			t.Errorf("%s: %v want %s", path, err, want)
		}
		if err != nil && strings.Contains(err.Error(), "sk-secret") {
			t.Errorf("%s: secret leaked: %v", path, err)
		}
	}
}

// TestClassifyStatus: one case per status rule row. A vendor 5xx is
// server_error (retried next pass), never unreachable, which is kept for a
// real network failure.
func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		status int
		want   cloudagents.ErrorClass
	}{
		{301, cloudagents.ErrHostNotAllowed},
		{302, cloudagents.ErrHostNotAllowed},
		{401, cloudagents.ErrNotSignedIn},
		{429, cloudagents.ErrRateLimited},
		{403, cloudagents.ErrPermissionDenied},
		{404, cloudagents.ErrPermissionDenied},
		{500, cloudagents.ErrServerError},
		{502, cloudagents.ErrServerError},
		{503, cloudagents.ErrServerError},
		{504, cloudagents.ErrServerError},
		{400, cloudagents.ErrFailed},
		{418, cloudagents.ErrFailed},
	}
	for _, tc := range cases {
		if got := ClassifyStatus(tc.status); got != tc.want {
			t.Errorf("ClassifyStatus(%d) = %s want %s", tc.status, got, tc.want)
		}
	}
}

// TestNetworkFailureIsUnreachable: a transport error (no answer at all)
// stays unreachable, distinct from a vendor 5xx.
func TestNetworkFailureIsUnreachable(t *testing.T) {
	tr := rtFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("dial tcp: connection refused") })
	c := New(Options{APIHosts: []string{"api.example.com"}, HTTP: &http.Client{Transport: tr}})
	_, err := getForTest(c, "https://api.example.com/x", nil)
	if cloudagents.ClassOf(err) != cloudagents.ErrUnreachable {
		t.Fatalf("network failure: %v", err)
	}
}

// TestAPITimeoutDefaults: an HTTPS call gets at least 90 s by default (the
// Cursor usage read took up to 37 s live), the CLI keeps 45 s, and a test's
// single Timeout still caps both.
func TestAPITimeoutDefaults(t *testing.T) {
	cases := []struct {
		name          string
		o             Options
		cli, api, hcl time.Duration
	}{
		{"defaults", Options{}, DefaultTimeout, DefaultAPITimeout, DefaultAPITimeout},
		{"one cap", Options{Timeout: 5 * time.Second}, 5 * time.Second, 5 * time.Second, 5 * time.Second},
		{"api cap", Options{APITimeout: 2 * time.Minute}, DefaultTimeout, 2 * time.Minute, 2 * time.Minute},
	}
	for _, tc := range cases {
		c := New(tc.o)
		if c.timeout != tc.cli || c.apiTimeout != tc.api || c.http.Timeout != tc.hcl {
			t.Errorf("%s: cli %s api %s http %s", tc.name, c.timeout, c.apiTimeout, c.http.Timeout)
		}
	}
	if DefaultAPITimeout < 90*time.Second {
		t.Errorf("DefaultAPITimeout %s is below 90 s", DefaultAPITimeout)
	}
}
