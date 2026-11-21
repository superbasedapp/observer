package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/planechoice"
)

// fakeApps is a daemon-side AI Apps runtime stand-in.
type fakeApps struct {
	status   planechoice.AppsStatus
	report   planechoice.EnableReport
	enabled  int
	disabled int
}

func (a *fakeApps) bind(s *Server) {
	s.SetApps(
		func(context.Context) planechoice.AppsStatus { return a.status },
		func(context.Context) planechoice.EnableReport {
			a.enabled++
			if a.report.OK {
				a.status.On, a.status.ConfiguredOn = true, true
			}
			return a.report
		},
		func(context.Context) (string, error) {
			a.disabled++
			if a.status.Component == planechoice.ComponentBlocked {
				return "", errors.New("pinned")
			}
			return "AI Apps is set to off. It stops at the next start of the daemon.", nil
		},
	)
}

func (f *firstRunFixture) post(t *testing.T, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	req := armLocalWrite(httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
	f.server.Handler().ServeHTTP(rr, req)
	return rr
}

func TestFirstRunPlaneWithoutAppsSeams(t *testing.T) {
	f := newFirstRunFixture(t, true)
	r := f.get(t)
	if r.Apps.Component != planechoice.ComponentUnknown || r.Apps.HotEnable || r.Apps.Available.Available {
		t.Fatalf("apps without seams: %+v", r.Apps)
	}
	if r.Plane.Row != 4 || r.Plane.Track != planechoice.TrackCoding || !r.Plane.Ask {
		t.Fatalf("fresh machine without seams: %+v", r.Plane)
	}
	if r.Apps.Consent.Sentence != "Stays on this machine." {
		t.Fatalf("consent: %+v", r.Apps.Consent)
	}
}

// TestFirstRunPlaneRows: each row of the four-row table, as /api/firstrun
// serves it from real stored state and fake daemon facts.
func TestFirstRunPlaneRows(t *testing.T) {
	cases := []struct {
		name    string
		history bool
		intent  string
		on      bool
		row     int
		track   planechoice.Track
	}{
		{"history and AI Apps on: both", true, "", true, 1, planechoice.TrackBoth},
		{"apps intent: apps", false, "apps", false, 2, planechoice.TrackApps},
		{"history only: coding with the offer", true, "", false, 3, planechoice.TrackCoding},
		{"nothing: coding with the switch", false, "", false, 4, planechoice.TrackCoding},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFirstRunFixture(t, true)
			a := &fakeApps{status: planechoice.AppsStatus{InBuild: true, Component: planechoice.ComponentAvailable, On: tc.on, HotEnable: true}}
			a.bind(f.server)
			if tc.history {
				f.seedSession(t, "s1", "tool-done", "/p/one")
			}
			if tc.intent != "" {
				if code := f.postSeen(t, `{"intent":"`+tc.intent+`","intent_source":"connect"}`); code != http.StatusOK {
					t.Fatalf("intent post: %d", code)
				}
			}
			r := f.get(t)
			if r.Plane.Row != tc.row || r.Plane.Track != tc.track {
				t.Fatalf("plane: %+v", r.Plane)
			}
			if tc.row == 3 && !r.Plane.OfferApps {
				t.Fatal("row 3 without the AI Apps offer")
			}
		})
	}
}

func TestFirstRunBriefCarriesPlane(t *testing.T) {
	f := newFirstRunFixture(t, true)
	a := &fakeApps{status: planechoice.AppsStatus{InBuild: true, Component: planechoice.ComponentAbsent}}
	a.bind(f.server)
	var r firstRunResponse
	getModelJSON(t, f.server, "/api/firstrun?brief=1", &r)
	if r.Plane.AppsAvailable.Available || r.Plane.AppsAvailable.Reason != "not_in_build" || r.Plane.OfferApps {
		t.Fatalf("absent component: %+v", r.Plane)
	}
}

func TestFocusAndIntentWrites(t *testing.T) {
	f := newFirstRunFixture(t, true)
	if code := f.postSeen(t, `{"focus":"apps"}`); code != http.StatusOK {
		t.Fatalf("focus: %d", code)
	}
	f.seedSession(t, "s1", "tool-done", "/p/one")
	a := &fakeApps{status: planechoice.AppsStatus{InBuild: true, Component: planechoice.ComponentAvailable}}
	a.bind(f.server)
	if r := f.get(t); r.Plane.Focus != planechoice.ChoiceApps || r.Plane.Track != planechoice.TrackApps {
		t.Fatalf("stored apps on a coder's machine: %+v", r.Plane)
	}
	if code := f.postSeen(t, `{"focus":""}`); code != http.StatusOK {
		t.Fatalf("clear focus: %d", code)
	}
	if r := f.get(t); r.Plane.Focus != "" || r.Plane.Track != planechoice.TrackCoding {
		t.Fatalf("cleared: %+v", r.Plane)
	}
	for _, bad := range []string{
		`{"focus":"everything"}`,
		`{"intent":"apps","intent_source":"web"}`,
		`{"intent":"../apps","intent_source":"connect"}`,
		`{"intent":"apps"}`,
	} {
		if code := f.postSeen(t, bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", bad, code)
		}
	}
	// First intent wins.
	if code := f.postSeen(t, `{"intent":"coding","intent_source":"for_link"}`); code != http.StatusOK {
		t.Fatal(code)
	}
	if code := f.postSeen(t, `{"intent":"apps","intent_source":"connect"}`); code != http.StatusOK {
		t.Fatal(code)
	}
	if r := f.get(t); r.Plane.Intent != planechoice.ChoiceCoding || r.Plane.IntentSource != planechoice.SourceForLink {
		t.Fatalf("intent: %+v", r.Plane)
	}
}

func TestAppsEnableWithoutSeamIs501(t *testing.T) {
	f := newFirstRunFixture(t, true)
	if rr := f.post(t, "/api/apps/enable", `{}`); rr.Code != http.StatusNotImplemented {
		t.Fatalf("code %d", rr.Code)
	}
}

func TestAppsEnableRecordsIntentAndReportsOutcome(t *testing.T) {
	f := newFirstRunFixture(t, true)
	a := &fakeApps{
		status: planechoice.AppsStatus{InBuild: true, Component: planechoice.ComponentAvailable, HotEnable: true},
		report: planechoice.ClassifyEnable(planechoice.EnableFacts{
			InBuild: true, Component: planechoice.ComponentActive,
			Receiver: planechoice.Receiver{State: planechoice.ReceiverListening, HTTPAddr: "127.0.0.1:4318"},
		}),
	}
	a.bind(f.server)
	rr := f.post(t, "/api/apps/enable", `{"source":"cli"}`)
	if rr.Code != http.StatusOK || a.enabled != 1 {
		t.Fatalf("enable: %d %s", rr.Code, rr.Body.String())
	}
	var rep planechoice.EnableReport
	if err := json.Unmarshal(rr.Body.Bytes(), &rep); err != nil || !rep.OK || rep.Outcome != planechoice.OutcomeOn {
		t.Fatalf("report: %+v %v", rep, err)
	}
	r := f.get(t)
	if r.Plane.Intent != planechoice.ChoiceApps || r.Plane.IntentSource != planechoice.SourceAppsOn || r.Plane.Track != planechoice.TrackApps {
		t.Fatalf("after enable: %+v", r.Plane)
	}
	if rr := f.post(t, "/api/apps/enable", `{"source":"phone"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown source: %d", rr.Code)
	}
}

func TestAppsEnableBindFailureIsConflictAndRecordsNoIntent(t *testing.T) {
	f := newFirstRunFixture(t, true)
	a := &fakeApps{
		status: planechoice.AppsStatus{InBuild: true, Component: planechoice.ComponentAvailable, HotEnable: true},
		report: planechoice.ClassifyEnable(planechoice.EnableFacts{
			InBuild: true, Component: planechoice.ComponentActive,
			Receiver: planechoice.Receiver{State: planechoice.ReceiverBindFailed, HTTPAddr: "127.0.0.1:4318", Error: "address already in use"},
		}),
	}
	a.bind(f.server)
	rr := f.post(t, "/api/apps/enable", `{}`)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "http_addr") {
		t.Fatalf("bind failure: %d %s", rr.Code, rr.Body.String())
	}
	if r := f.get(t); r.Plane.Intent != "" {
		t.Fatalf("a failed enable recorded an intent: %+v", r.Plane)
	}
}

func TestAppsEnableNeedsConfirmToken(t *testing.T) {
	f := newFirstRunFixture(t, true)
	(&fakeApps{}).bind(f.server)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/apps/enable", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	f.server.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("code %d", rr.Code)
	}
}

func TestAppsDisableIsNextStart(t *testing.T) {
	f := newFirstRunFixture(t, true)
	a := &fakeApps{status: planechoice.AppsStatus{InBuild: true, Component: planechoice.ComponentActive, On: true}}
	a.bind(f.server)
	rr := f.post(t, "/api/apps/disable", `{"source":"cli"}`)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"effective":"next_start"`) {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}
}

func TestAppsStatusCarriesConsentAndToken(t *testing.T) {
	f := newFirstRunFixture(t, true)
	a := &fakeApps{status: planechoice.AppsStatus{
		InBuild: true, Component: planechoice.ComponentActive, On: true,
		Consent:     planechoice.ConsentFacts{Enrolled: true, Org: "Acme", Tiers: []string{"traces"}},
		LatestTrace: &planechoice.LatestTrace{TraceID: "abc", Name: "answer"},
	}}
	a.bind(f.server)
	var out struct {
		firstRunApps
		ConfirmToken string `json:"confirm_token"`
	}
	getModelJSON(t, f.server, "/api/apps/status", &out)
	if out.Consent.Sentence != "Also sent to Acme (trace structure)." || out.ConfirmToken == "" || out.LatestTrace == nil {
		t.Fatalf("status: %+v", out)
	}
}
