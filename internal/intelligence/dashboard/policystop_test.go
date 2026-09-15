package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// fakePolicyStopProvider is a table-driven-friendly test double: keyed by
// handle, returns a canned (PolicyStop, ok) pair.
type fakePolicyStopProvider struct {
	byHandle map[string]PolicyStop
}

func (f *fakePolicyStopProvider) PolicyStopForHandle(_ context.Context, handle string) (PolicyStop, bool) {
	if f == nil {
		return PolicyStop{}, false
	}
	stop, ok := f.byHandle[handle]
	return stop, ok
}

func TestPolicyStop_DisplayMessage(t *testing.T) {
	cases := []struct {
		name string
		stop PolicyStop
		want string
	}{
		{
			name: "terminated with rule and reason",
			stop: PolicyStop{RuleID: "B-602", Decision: "terminated", Reason: "daily spend accounting is unavailable; cannot verify the configured budget"},
			want: "Stopped by organization policy (B-602): daily spend accounting is unavailable; cannot verify the configured budget",
		},
		{
			name: "killed with rule, no reason",
			stop: PolicyStop{RuleID: "B-621", Decision: "killed"},
			want: "Stopped by organization policy (B-621)",
		},
		{
			name: "policy_unavailable never claims a stop",
			stop: PolicyStop{RuleID: "B-602", Decision: "policy_unavailable", Reason: "pricing document unknown"},
			want: "Organization policy check failed; process was not stopped by the daemon: pricing document unknown",
		},
		{
			name: "unknown decision falls to the honest non-stopping message",
			stop: PolicyStop{Decision: "fence_rejected"},
			want: "Organization policy check failed; process was not stopped by the daemon",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.stop.DisplayMessage(); got != tc.want {
				t.Errorf("DisplayMessage() = %q, want %q", got, tc.want)
			}
		})
	}
}

func newPolicyStopTestServer(t *testing.T, status TerminalStatusProvider, stop PolicyStopProvider) *Server {
	t.Helper()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{DB: database, TerminalStatus: status, PolicyStop: stop})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHandleTerminalStatus_MergesPolicyStop(t *testing.T) {
	at := time.Date(2026, 9, 14, 12, 1, 0, 0, time.UTC)
	statusP := &fakeStatusProvider{found: true, res: TerminalStatusResult{
		Status: "exited", Evidence: "exit frame", Confidence: "trusted",
	}}
	stopP := &fakePolicyStopProvider{byHandle: map[string]PolicyStop{
		"HANDLE-1": {RuleID: "B-602", Decision: "terminated", Reason: "budget unavailable", At: at},
	}}
	s := newPolicyStopTestServer(t, statusP, stopP)

	req := httptest.NewRequest(http.MethodGet, "/api/terminal/HANDLE-1/status", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out TerminalStatusResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.PolicyStop == nil {
		t.Fatal("expected policy_stop to be populated")
	}
	if out.PolicyStop.RuleID != "B-602" || out.PolicyStop.Decision != "terminated" {
		t.Errorf("PolicyStop = %+v, unexpected", out.PolicyStop)
	}
}

func TestHandleTerminalStatus_OmitsPolicyStopWhenNoneFound(t *testing.T) {
	statusP := &fakeStatusProvider{found: true, res: TerminalStatusResult{
		Status: "exited", Evidence: "exit frame", Confidence: "trusted",
	}}
	// No matching handle in the fake provider's map -> ok=false.
	stopP := &fakePolicyStopProvider{byHandle: map[string]PolicyStop{}}
	s := newPolicyStopTestServer(t, statusP, stopP)

	req := httptest.NewRequest(http.MethodGet, "/api/terminal/HANDLE-1/status", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var out TerminalStatusResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.PolicyStop != nil {
		t.Errorf("PolicyStop = %+v, want nil (no matching audit row)", out.PolicyStop)
	}
}

func TestHandleTerminalStatus_NilPolicyStopSeamOmitsField(t *testing.T) {
	statusP := &fakeStatusProvider{found: true, res: TerminalStatusResult{
		Status: "exited", Evidence: "exit frame", Confidence: "trusted",
	}}
	// A nil PolicyStop seam (the pre-arc / unmanaged-node state) must behave
	// exactly as before this arc: the field is simply absent.
	s := newPolicyStopTestServer(t, statusP, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/terminal/HANDLE-1/status", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if bodyHasPolicyStopKey(rec.Body.Bytes()) {
		t.Errorf("expected no policy_stop key in the response body: %s", rec.Body.String())
	}
}

func bodyHasPolicyStopKey(body []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	_, ok := raw["policy_stop"]
	return ok
}
