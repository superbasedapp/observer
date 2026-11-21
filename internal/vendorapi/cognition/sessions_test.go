package cognition

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/testsupport/vendormock"
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
)

var sessionParams = vendorapi.Params{ParamOrgID: "org_synth01", ParamSessionID: "devin-synth0001"}

func sessResp(body []byte, cursor string) vendorapi.Response {
	return vendorapi.Response{
		Status: 200, Origin: "https://api.devin.ai:443", Body: body, Cursor: cursor, Params: sessionParams,
	}
}

// TestOrgSessionsParseCorpus: one snapshot per session; an ACU usage row only
// where acus_consumed is reported (absent is never zero); the creator is the
// user, else the service user.
func TestOrgSessionsParseCorpus(t *testing.T) {
	p, err := parseOrgSessions(sessResp(fixture(t, SurfaceOrgSessions, "normal_page.json"), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Snapshots) != 2 || len(p.Usage) != 1 || p.SourceRecords != 2 || p.NextCursor != "synthsession0002" {
		t.Fatalf("snapshots %d usage %d records %d next %q", len(p.Snapshots), len(p.Usage), p.SourceRecords, p.NextCursor)
	}
	s := p.Snapshots[0]
	want := map[string]string{
		"status": "running", "created_at": "2026-10-30T09:00:00Z", "updated_at": "2026-10-30T09:40:00Z",
		"title": "Fix the flaky login test", "url": "https://app.devin.ai/sessions/devin-synth0001",
		"origin": "webapp", "org_id": "org_synth01", "user_id": "user_synth0001", "child_session_count": "1",
		"pull_request_count": "1", "pr_url": "https://github.com/acme/widget/pull/42", "pr_state": "open",
		"on_demand_usage_usd": "0",
	}
	if s.Class != SessionClass || s.Subject != "devin-synth0001" || len(s.Body) != len(want) {
		t.Fatalf("snapshot %+v", s)
	}
	for k, v := range want {
		if s.Body[k] != v {
			t.Errorf("body[%s] = %q, want %q", k, s.Body[k], v)
		}
	}
	u := p.Usage[0]
	updated := time.Date(2026, 10, 30, 9, 40, 0, 0, time.UTC)
	if u.JoinValue != "devin-synth0001" || u.ChargedUnit != UnitACU || u.ChargedMicros != 3_750_000 ||
		u.IdentityKind != "user_id" || u.Identity != "user_synth0001" || !u.At.Equal(updated) ||
		u.Revision != updated.Unix() || u.SessionRef != "devin-synth0001" || u.InputTokens != 0 {
		t.Fatalf("usage %+v", u)
	}
	s2 := p.Snapshots[1]
	if s2.Body["service_user_id"] != "service_user_synth01" || s2.Body["parent_session_id"] != "devin-synth0001" ||
		s2.Body["automation_id"] != "automation-synth01" || s2.Body["pull_request_count"] != "0" {
		t.Fatalf("snapshot 1 %+v", s2)
	}
	if _, ok := s2.Body["user_id"]; ok {
		t.Error("a null user_id landed")
	}
	last, err := parseOrgSessions(sessResp(fixture(t, SurfaceOrgSessions, "last_page.json"), "synthsession0002"))
	if err != nil || last.NextCursor != "" || len(last.Snapshots) != 1 || len(last.Usage) != 1 || last.Usage[0].Identity != "user_synth0002" {
		t.Fatalf("last page %+v %v", last, err)
	}
}

func TestSessionMessagesParseCorpus(t *testing.T) {
	p, err := parseSessionMessages(sessResp(fixture(t, SurfaceSessionMessages, "normal_page.json"), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Content) != 3 || p.NextCursor != "synthmessage0003" || len(canaryMessages(p)) != 0 {
		t.Fatalf("content %d next %q", len(p.Content), p.NextCursor)
	}
	c0, c1 := p.Content[0], p.Content[1]
	if c0.Role != "prompt" || c0.ItemID != "event_synth_0001" || c0.IdentityKind != "user_id" || c0.Identity != "user_synth0001" ||
		c0.SessionRef != "devin-synth0001" || !c0.At.Equal(time.Date(2026, 10, 30, 9, 0, 5, 0, time.UTC)) ||
		!strings.HasPrefix(c0.Text, "Please fix") {
		t.Fatalf("message 0 %+v", c0)
	}
	if c1.Role != "response" || c1.Identity != "" || c1.Truncated {
		t.Fatalf("message 1 %+v", c1)
	}
	// An undocumented source is not landed and trips the canary.
	odd, err := parseSessionMessages(sessResp([]byte(`{"items":[{"event_id":"e1","source":"system","message":"x",
		"created_at":1793350800}],"has_next_page":false,"end_cursor":null}`), ""))
	if err != nil || len(odd.Content) != 0 || len(canaryMessages(odd)) != 1 {
		t.Fatalf("unknown source %+v %v", odd, err)
	}
	// An over-long message is cut at the cap and marked.
	long := `{"items":[{"event_id":"e1","source":"devin","message":"` + strings.Repeat("é", vendorapi.MaxContentBytes) +
		`","created_at":1793350800}],"has_next_page":false,"end_cursor":null}`
	cut, err := parseSessionMessages(sessResp([]byte(long), ""))
	if err != nil || !cut.Content[0].Truncated || len(cut.Content[0].Text) > vendorapi.MaxContentBytes {
		t.Fatalf("long message %v", err)
	}
	if err := vendorapi.Validate(cut); err != nil {
		t.Fatalf("cut page does not validate: %v", err)
	}
}

func TestSessionBuildContract(t *testing.T) {
	from := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	req, err := buildOrgSessions(sessionParams, vendorapi.Window{From: from, To: from.Add(48 * time.Hour)}, "")
	if err != nil || req.Method != "GET" || req.Path != "/v3/organizations/org_synth01/sessions" ||
		req.Query["updated_after"][0] != "1793232000" || req.Query["updated_before"][0] != "1793404800" ||
		req.Query["first"][0] != "200" || req.Query["after"] != nil {
		t.Fatalf("sessions request %+v %v", req, err)
	}
	all, err := buildOrgSessions(sessionParams, vendorapi.Window{}, "synthsession0002")
	if err != nil || all.Query["updated_after"] != nil || all.Query["after"][0] != "synthsession0002" {
		t.Fatalf("unwindowed request %+v %v", all, err)
	}
	msg, err := buildSessionMessages(sessionParams, vendorapi.Window{}, "")
	if err != nil || msg.Path != "/v3/organizations/org_synth01/sessions/devin-synth0001/messages" || msg.Query["first"][0] != "200" {
		t.Fatalf("messages request %+v %v", msg, err)
	}
	for name, err := range map[string]error{
		"no org":           errOf(buildOrgSessions(nil, vendorapi.Window{}, "")),
		"org injection":    errOf(buildOrgSessions(vendorapi.Params{ParamOrgID: "a/../b"}, vendorapi.Window{}, "")),
		"half window":      errOf(buildOrgSessions(sessionParams, vendorapi.Window{From: from}, "")),
		"inverted window":  errOf(buildOrgSessions(sessionParams, vendorapi.Window{From: from, To: from.Add(-time.Hour)}, "")),
		"bad cursor":       errOf(buildOrgSessions(sessionParams, vendorapi.Window{}, "bad cursor!")),
		"no session":       errOf(buildSessionMessages(vendorapi.Params{ParamOrgID: "org_synth01"}, vendorapi.Window{}, "")),
		"session slash":    errOf(buildSessionMessages(vendorapi.Params{ParamOrgID: "o", ParamSessionID: "a/b"}, vendorapi.Window{}, "")),
		"messages no org":  errOf(buildSessionMessages(vendorapi.Params{ParamSessionID: "devin-1"}, vendorapi.Window{}, "")),
		"messages bad cur": errOf(buildSessionMessages(sessionParams, vendorapi.Window{}, "bad cursor!")),
	} {
		if err == nil {
			t.Errorf("%s: build accepted", name)
		}
	}
}

func errOf(_ vendorapi.Request, err error) error { return err }

// TestSessionFieldPolicy (plan 12A.5): missing required fields, wrong JSON
// types, repeated keys, bad timestamps, negative or quoted amounts and a
// paging contract break fail the page as schema drift.
func TestSessionFieldPolicy(t *testing.T) {
	sess := func(b string) error { _, err := parseOrgSessions(sessResp([]byte(b), "")); return err }
	msgs := func(b string) error { _, err := parseSessionMessages(sessResp([]byte(b), "")); return err }
	env := func(items string) string { return `{"items":[` + items + `],"has_next_page":false,"end_cursor":null}` }
	ok := `{"session_id":"devin-1","status":"running","created_at":1793350800}`
	okMsg := `{"event_id":"e1","source":"user","message":"hi","created_at":1793350800}`
	for name, err := range map[string]error{
		"items missing":         sess(`{"has_next_page":false}`),
		"flag type":             sess(`{"items":[],"has_next_page":"true","end_cursor":"x"}`),
		"next without cursor":   sess(`{"items":[],"has_next_page":true,"end_cursor":null}`),
		"session id missing":    sess(env(`{"status":"running","created_at":1793350800}`)),
		"session repeated":      sess(env(ok + "," + ok)),
		"status missing":        sess(env(`{"session_id":"devin-1","created_at":1793350800}`)),
		"created quoted":        sess(env(`{"session_id":"devin-1","status":"r","created_at":"1793350800"}`)),
		"updated negative":      sess(env(`{"session_id":"devin-1","status":"r","created_at":1793350800,"updated_at":-5}`)),
		"acus negative":         sess(env(`{"session_id":"devin-1","status":"r","created_at":1793350800,"acus_consumed":-1}`)),
		"acus quoted":           sess(env(`{"session_id":"devin-1","status":"r","created_at":1793350800,"acus_consumed":"2"}`)),
		"on demand negative":    sess(env(`{"session_id":"devin-1","status":"r","created_at":1793350800,"on_demand_usage":-0.5}`)),
		"pull requests object":  sess(env(`{"session_id":"devin-1","status":"r","created_at":1793350800,"pull_requests":{}}`)),
		"message id missing":    msgs(env(`{"source":"user","message":"hi","created_at":1793350800}`)),
		"message repeated":      msgs(env(okMsg + "," + okMsg)),
		"message text missing":  msgs(env(`{"event_id":"e1","source":"user","created_at":1793350800}`)),
		"message time missing":  msgs(env(`{"event_id":"e1","source":"user","message":"hi"}`)),
		"message text not text": msgs(env(`{"event_id":"e1","source":"user","message":5,"created_at":1793350800}`)),
	} {
		if !isDrift(err) {
			t.Errorf("%s: err %v, want schema drift", name, err)
		}
	}
	noSession := sessResp([]byte(env(okMsg)), "")
	noSession.Params = vendorapi.Params{ParamOrgID: "org_synth01"}
	if _, err := parseSessionMessages(noSession); !isDrift(err) {
		t.Errorf("messages without a session parameter: %v", err)
	}
	if _, err := parseOrgSessions(vendorapi.Response{Status: 404, Body: []byte(`{}`)}); !isDrift(err) {
		t.Errorf("non-200: %v", err)
	}
}

// TestSessionDriversContract pins both drivers to their catalog rows and
// corpus ledgers (node-consumed: they have no org driver-table entry).
func TestSessionDriversContract(t *testing.T) {
	for _, d := range []vendorapi.Driver{OrgSessions(), SessionMessages()} {
		vendormock.CheckDriverContract(t, d)
		if !d.ClosedDTO || d.Tool != Tool || d.Auth.Scheme != vendorapi.SchemeBearer {
			t.Errorf("%s: driver %+v", d.Surface, d)
		}
	}
}

// TestSessionConformance runs the shared conformance suite against both
// drivers through the pure adapter.
func TestSessionConformance(t *testing.T) {
	for _, d := range []vendorapi.Driver{OrgSessions(), SessionMessages()} {
		d := d
		t.Run(string(d.Surface), func(t *testing.T) { vendormock.RunPure(t, d, sessionParams, vendorapi.Window{}) })
	}
}
