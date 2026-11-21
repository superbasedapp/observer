package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAPIPromptJudgeStatus pins GET /api/guard/prompt/judge (lane adm-p2):
// no seam answers the honest unavailable body, a wired seam's body passes
// through, an error is a 500, and the read is a Security view route.
func TestAPIPromptJudgeStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		seam     func(context.Context) (any, error)
		method   string
		wantCode int
		wantSub  string
	}{
		{name: "no seam", method: "GET", wantCode: 200, wantSub: `"available":false`},
		{
			name: "seam body passed through", method: "GET", wantCode: 200, wantSub: `"active":true`,
			seam: func(context.Context) (any, error) { return map[string]any{"available": true, "active": true}, nil },
		},
		{
			name: "seam error", method: "GET", wantCode: 500, wantSub: "prompt judge status: boom",
			seam: func(context.Context) (any, error) { return nil, errors.New("boom") },
		},
		{
			name: "read-only", method: "POST", wantCode: 405,
			seam: func(context.Context) (any, error) { return map[string]any{}, nil },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newRemoteTestServer(t, Options{PromptJudgeStatus: tc.seam})
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, httptest.NewRequest(tc.method, "/api/guard/prompt/judge", nil))
			if rec.Code != tc.wantCode {
				t.Fatalf("status %d, want %d: %s", rec.Code, tc.wantCode, rec.Body)
			}
			if tc.wantSub != "" && !strings.Contains(rec.Body.String(), tc.wantSub) {
				t.Fatalf("body %s lacks %q", rec.Body, tc.wantSub)
			}
			if tc.seam == nil {
				var body mcpAccessUnavailable
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Reason != promptJudgeNotWiredReason {
					t.Fatalf("unavailable body %s (%v)", rec.Body, err)
				}
			}
		})
	}
	s := newRemoteTestServer(t, Options{})
	_, capMap, sectionMap := s.registerRoutes(nil)
	if capMap["/api/guard/prompt/judge"] != CapabilityView || sectionMap["/api/guard/prompt/judge"] != SectionSecurity.WithTab("prompt-guard") {
		t.Fatalf("capability %v section %v", capMap["/api/guard/prompt/judge"], sectionMap["/api/guard/prompt/judge"])
	}
}
