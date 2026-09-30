package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestAPIMCPAccessStatus pins GET /api/mcp-access/status (Agent Access
// P10): one case per handler branch - no seam wired, the seam's body passed
// through with ?verify=1 forwarded, a seam error, and a non-GET method.
func TestAPIMCPAccessStatus(t *testing.T) {
	t.Parallel()
	type seamCall struct {
		called bool
		verify bool
	}
	cases := []struct {
		name       string
		seam       func(call *seamCall) func(context.Context, bool) (any, error)
		method     string
		path       string
		wantCode   int
		wantSub    string
		wantCalled bool
		wantVerify bool
	}{
		{
			name: "no seam: honest unavailable body, never a 404", method: "GET", path: "/api/mcp-access/status",
			wantCode: 200, wantSub: `"available":false`,
		},
		{
			name: "seam body passed through, polled read skips the chain walk",
			seam: func(call *seamCall) func(context.Context, bool) (any, error) {
				return func(_ context.Context, verify bool) (any, error) {
					call.called, call.verify = true, verify
					return map[string]any{"available": true, "status": map[string]any{"enabled": true}}, nil
				}
			},
			method: "GET", path: "/api/mcp-access/status", wantCode: 200, wantSub: `"enabled":true`, wantCalled: true,
		},
		{
			name: "verify=1 is forwarded",
			seam: func(call *seamCall) func(context.Context, bool) (any, error) {
				return func(_ context.Context, verify bool) (any, error) {
					call.called, call.verify = true, verify
					return map[string]any{"available": true}, nil
				}
			},
			method: "GET", path: "/api/mcp-access/status?verify=1", wantCode: 200, wantSub: `"available":true`, wantCalled: true, wantVerify: true,
		},
		{
			name: "seam error is a 500 with the error",
			seam: func(call *seamCall) func(context.Context, bool) (any, error) {
				return func(context.Context, bool) (any, error) {
					call.called = true
					return nil, errors.New("boom")
				}
			},
			method: "GET", path: "/api/mcp-access/status", wantCode: 500, wantSub: "mcp access status: boom", wantCalled: true,
		},
		{
			name: "read-only: POST refused before the seam runs",
			seam: func(call *seamCall) func(context.Context, bool) (any, error) {
				return func(context.Context, bool) (any, error) {
					call.called = true
					return map[string]any{}, nil
				}
			},
			method: "POST", path: "/api/mcp-access/status", wantCode: 405,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var call seamCall
			opts := Options{}
			if tc.seam != nil {
				opts.MCPAccessStatus = tc.seam(&call)
			}
			s := newRemoteTestServer(t, opts)
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantCode, rec.Body)
			}
			if tc.wantSub != "" && !strings.Contains(rec.Body.String(), tc.wantSub) {
				t.Fatalf("body %s lacks %q", rec.Body, tc.wantSub)
			}
			if call.called != tc.wantCalled || call.verify != tc.wantVerify {
				t.Fatalf("seam called=%v verify=%v, want %v/%v", call.called, call.verify, tc.wantCalled, tc.wantVerify)
			}
			if tc.seam == nil {
				var body mcpAccessUnavailable
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Available || body.Reason != mcpAccessNotWiredReason {
					t.Fatalf("unavailable body %s (%v)", rec.Body, err)
				}
			}
		})
	}
}

// TestMCPAccessStatusIsASecurityViewRoute: the route is classified View and
// belongs to the Security nav section, so an organization that hides the
// Security page hides it too (governance.go).
func TestMCPAccessStatusIsASecurityViewRoute(t *testing.T) {
	t.Parallel()
	s := newRemoteTestServer(t, Options{})
	_, capMap, sectionMap := s.registerRoutes(nil)
	if capMap["/api/mcp-access/status"] != CapabilityView {
		t.Fatalf("capability %s, want view", capMap["/api/mcp-access/status"])
	}
	if sectionMap["/api/mcp-access/status"] != SectionSecurity {
		t.Fatalf("section %v, want security", sectionMap["/api/mcp-access/status"])
	}
}

// TestMCPAccessUnavailableMatchesFixture pins the VS Code / web fixture of
// the no-seam body to what the handler actually answers.
func TestMCPAccessUnavailableMatchesFixture(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "vscode", "test", "fixtures", "agentAccess", "unavailable.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want, got map[string]any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	s := newRemoteTestServer(t, Options{})
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/api/mcp-access/status", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("handler body %v != fixture %v", got, want)
	}
}
