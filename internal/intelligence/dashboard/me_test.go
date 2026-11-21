package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

func TestMeRoutes(t *testing.T) {
	srv := &Server{}
	cases := []struct {
		name    string
		method  string
		target  string
		handler http.HandlerFunc
		status  int
		check   func(t *testing.T, body map[string]any)
	}{
		{"tool accounts, no database", "GET", "/api/me/tool-accounts", srv.handleMeToolAccounts, 200, func(t *testing.T, b map[string]any) {
			if tools, ok := b["tools"].([]any); !ok || len(tools) != 0 {
				t.Errorf("tools = %v", b["tools"])
			}
		}},
		{"tool accounts, wrong method", "POST", "/api/me/tool-accounts", srv.handleMeToolAccounts, 405, nil},
		{"machine, not enrolled", "GET", "/api/me/machine", srv.handleMeMachine, 200, func(t *testing.T, b map[string]any) {
			if b["org_bound"] == true {
				t.Error("org_bound without an enrolment")
			}
			if _, leaked := b["machine_id"]; leaked {
				t.Error("raw id field present")
			}
		}},
		{"credentials, listed without touching the keychain", "GET", "/api/me/credentials", srv.handleMeCredentials, 200, func(t *testing.T, b map[string]any) {
			if b["checked"] != false {
				t.Error("checked should be false")
			}
			rows, _ := b["services"].([]any)
			if len(rows) == 0 {
				t.Fatal("no services")
			}
			for _, r := range rows {
				if r.(map[string]any)["presence"] != "not_checked" {
					t.Errorf("row = %v", r)
				}
			}
		}},
		{"credentials, checked", "GET", "/api/me/credentials?check=1", srv.handleMeCredentials, 200, func(t *testing.T, b map[string]any) {
			if b["checked"] != true {
				t.Error("checked should be true")
			}
			for _, r := range b["services"].([]any) {
				p := r.(map[string]any)["presence"]
				if p == "not_checked" {
					t.Errorf("row left unchecked: %v", r)
				}
				if strings.Contains(strings.ToLower(toJSON(r)), "secret") {
					t.Errorf("row mentions a value: %v", r)
				}
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler(rec, httptest.NewRequest(tc.method, tc.target, nil))
			if rec.Code != tc.status {
				t.Fatalf("status %d, want %d", rec.Code, tc.status)
			}
			if tc.check == nil {
				return
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			tc.check(t, body)
		})
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// TestMeAggregateShare: without the component's seam the route says the
// feature is not in this build; with it, the seam's values come back and a
// missing receipt leaves consented_at out.
func TestMeAggregateShare(t *testing.T) {
	get := func(srv *Server) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		srv.handleMeAggregateShare(rec, httptest.NewRequest("GET", "/api/me/aggregate-share", nil))
		if rec.Code != 200 {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		var b map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	if b := get(&Server{}); b["available"] != false {
		t.Errorf("no seam: body = %v", b)
	}
	off := &Server{opts: Options{AggregateShareStatus: func(context.Context) (dashapi.AggregateShareStatus, error) {
		return dashapi.AggregateShareStatus{Status: "disabled"}, nil
	}}}
	b := get(off)
	if b["available"] != true || b["enabled"] != false || b["status"] != "disabled" {
		t.Errorf("off: body = %v", b)
	}
	if _, ok := b["consented_at"]; ok {
		t.Error("consented_at present without a receipt")
	}
	at := time.Date(2026, 11, 7, 8, 0, 0, 0, time.UTC)
	on := &Server{opts: Options{AggregateShareStatus: func(context.Context) (dashapi.AggregateShareStatus, error) {
		return dashapi.AggregateShareStatus{Enabled: true, Status: "valid", ConsentedAt: at, Actor: "cli", SchemaVersion: 1}, nil
	}}}
	if b := get(on); b["status"] != "valid" || b["consented_at"] != "2026-11-07T08:00:00Z" || b["actor"] != "cli" {
		t.Errorf("on: body = %v", b)
	}
	rec := httptest.NewRecorder()
	off.handleMeAggregateShare(rec, httptest.NewRequest("POST", "/api/me/aggregate-share", nil))
	if rec.Code != 405 {
		t.Errorf("POST status %d", rec.Code)
	}
}

// TestMeMachineEnrolledIsOrgBound: on an enrolled machine the fingerprint is
// the org-salted value the org holds, and it differs from the display-only
// value shown before enrolment.
func TestMeMachineEnrolledIsOrgBound(t *testing.T) {
	get := func(srv *Server) map[string]any {
		t.Helper()
		rr := httptest.NewRecorder()
		srv.handleMeMachine(rr, httptest.NewRequest(http.MethodGet, "/api/me/machine", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		var b map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		return b
	}
	enrolled := get(&Server{opts: Options{OrgClient: &fakeEnrolment{state: orgclient.EnrolmentState{Enrolled: true, OrgID: "org-test-1"}}}})
	solo := get(&Server{})
	if enrolled["source"] == "none" {
		t.Skip("no machine identity source on this host")
	}
	if enrolled["org_bound"] != true {
		t.Errorf("org_bound = %v, want true", enrolled["org_bound"])
	}
	if enrolled["fingerprint"] == "" || enrolled["fingerprint"] == solo["fingerprint"] {
		t.Errorf("enrolled fingerprint %v must be set and differ from the solo one %v", enrolled["fingerprint"], solo["fingerprint"])
	}
}
