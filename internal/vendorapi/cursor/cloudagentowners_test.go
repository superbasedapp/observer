package cursor

import (
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/testsupport/vendormock"
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
)

// TestCloudAgentMetaParsesCorpus (lane CA-C8): the documented API Key Info
// example lands one cursor.cloud_agent_key snapshot of a user key with the
// numeric user id and the folded e-mail; the key name and the user's names
// never land.
func TestCloudAgentMetaParsesCorpus(t *testing.T) {
	p, err := parseCloudAgentMeta(cloudResp(cloudFixture(t, SurfaceCloudAgentMeta, "normal_page.json"), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Snapshots) != 1 {
		t.Fatalf("snapshots %+v", p.Snapshots)
	}
	s := p.Snapshots[0]
	want := map[string]string{"key_kind": KeyKindUser, "user_id": "42", "user_email": "developer@example.com"}
	if s.Class != CloudAgentKeyClass || s.Subject != CloudAgentKeySubject || len(s.Body) != len(want) {
		t.Fatalf("snapshot %+v", s)
	}
	for k, v := range want {
		if s.Body[k] != v {
			t.Errorf("body[%s] = %q, want %q", k, s.Body[k], v)
		}
	}
}

// TestParseKeyInfoKinds: one case per key-kind outcome. Only a body naming a
// positive user id AND an address-shaped e-mail is a user key; anything else
// names no user (never a guess), and a body that does not decode is drift.
func TestParseKeyInfoKinds(t *testing.T) {
	cases := []struct {
		name, body string
		kind       string
		id         int64
		email      string
		err        bool
	}{
		{"user key", `{"userId":7,"userEmail":"Dev@Corp.example"}`, KeyKindUser, 7, "Dev@Corp.example", false},
		{"no user id (a service-account key is expected here)", `{"apiKeyName":"ci","userEmail":"bot@corp.example"}`, KeyKindNoUser, 0, "bot@corp.example", false},
		{"zero user id", `{"userId":0,"userEmail":"dev@corp.example"}`, KeyKindNoUser, 0, "dev@corp.example", false},
		{"user id without e-mail", `{"userId":9}`, KeyKindNoUser, 9, "", false},
		{"e-mail not shaped like an address", `{"userId":9,"userEmail":"not an address"}`, KeyKindNoUser, 9, "not an address", false},
		{"two @ signs", `{"userId":9,"userEmail":"a@b@corp.example"}`, KeyKindNoUser, 9, "a@b@corp.example", false},
		{"terminal escape in the e-mail", `{"userId":9,"userEmail":"dev\u001b[2J@corp.example"}`, KeyKindNoUser, 9, "dev\x1b[2J@corp.example", false},
		{"bidi override in the e-mail", `{"userId":9,"userEmail":"dev\u202E@corp.example"}`, KeyKindNoUser, 9, "dev\u202E@corp.example", false},
		{"empty object", `{}`, KeyKindNoUser, 0, "", false},
		{"not JSON", `<html>`, "", 0, "", true},
		{"a quoted user id", `{"userId":"7","userEmail":"dev@corp.example"}`, "", 0, "", true},
	}
	for _, c := range cases {
		got, err := ParseKeyInfo([]byte(c.body))
		if (err != nil) != c.err {
			t.Errorf("%s: err %v", c.name, err)
			continue
		}
		if c.err {
			if !errors.Is(err, vendorapi.ErrSchemaDrift) {
				t.Errorf("%s: error is not schema drift: %v", c.name, err)
			}
			continue
		}
		if got.Kind != c.kind || got.UserID != c.id || got.Email != c.email {
			t.Errorf("%s: got %+v", c.name, got)
		}
	}
	// A no-user key lands its kind only: no id, no e-mail.
	p, err := parseCloudAgentMeta(cloudResp([]byte(`{"apiKeyName":"ci","userEmail":"bot@corp.example"}`), ""))
	if err != nil || len(p.Snapshots) != 1 || len(p.Snapshots[0].Body) != 1 || p.Snapshots[0].Body["key_kind"] != KeyKindNoUser {
		t.Fatalf("no-user page %+v %v", p, err)
	}
	if _, err := parseCloudAgentMeta(vendorapi.Response{Status: 500, Body: []byte(`{}`)}); !errors.Is(err, vendorapi.ErrSchemaDrift) {
		t.Errorf("non-200: %v", err)
	}
	if _, err := buildCloudAgentMeta(nil, vendorapi.Window{}, "2"); err == nil {
		t.Error("a second page of the key-info document was built")
	}
	if r, err := buildCloudAgentMeta(nil, vendorapi.Window{}, ""); err != nil || r.Method != "GET" || r.Path != "/v1/me" || r.Body != nil {
		t.Errorf("request %+v %v", r, err)
	}
}

// TestCloudAgentOwnersParsesCorpus: the cloud-filtered usage events land one
// owner snapshot per (cloudAgentId, identity): two events of one agent by the
// same member (different case) are one owner, a run-id cloudAgentId lands as
// stated, and a service-account event lands its account id even though it
// also carries the account's address. No usage row, token or cent lands.
func TestCloudAgentOwnersParsesCorpus(t *testing.T) {
	p, err := parseCloudAgentOwners(cloudResp(cloudFixture(t, SurfaceCloudAgentOwners, "normal_page.json"), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Usage) != 0 || len(p.Facts) != 0 || p.SourceRecords != 4 || p.NextCursor != "2" {
		t.Fatalf("page usage %d facts %d records %d next %q", len(p.Usage), len(p.Facts), p.SourceRecords, p.NextCursor)
	}
	want := []map[string]string{
		{"cloud_agent_id": "bc-00000000-0000-4000-8000-000000000001", "identity_kind": OwnerKindEmail, "identity": "developer@company.com"},
		{"cloud_agent_id": "run-00000000-0000-4000-8000-0000000000aa", "identity_kind": OwnerKindEmail, "identity": "admin@company.com"},
		{"cloud_agent_id": "bc-00000000-0000-4000-8000-000000000002", "identity_kind": OwnerKindServiceAccount, "identity": "sa_abc123"},
	}
	if len(p.Snapshots) != len(want) {
		t.Fatalf("snapshots %+v", p.Snapshots)
	}
	for i, w := range want {
		s := p.Snapshots[i]
		if s.Class != CloudAgentOwnerClass || s.Subject != OwnerSubject(w["cloud_agent_id"], w["identity_kind"], w["identity"]) ||
			len(s.Body) != len(w) {
			t.Fatalf("snapshot %d %+v", i, s)
		}
		for k, v := range w {
			if s.Body[k] != v {
				t.Errorf("snapshot %d body[%s] = %q, want %q", i, k, s.Body[k], v)
			}
		}
	}
	last, err := parseCloudAgentOwners(cloudResp(cloudFixture(t, SurfaceCloudAgentOwners, "last_page.json"), "2"))
	if err != nil || last.NextCursor != "" || len(last.Snapshots) != 1 {
		t.Fatalf("last page %+v %v", last, err)
	}
	// The digest separates identities: two members of one agent are two rows.
	if OwnerSubject("bc-1", OwnerKindEmail, "a@x.example") == OwnerSubject("bc-1", OwnerKindEmail, "b@x.example") {
		t.Error("two identities share a subject")
	}
}

// TestCloudAgentOwnersFieldPolicy: an event naming nobody and a malformed id
// fail the page as drift; an event without a cloudAgentId is skipped; the
// usage-events envelope rules apply.
func TestCloudAgentOwnersFieldPolicy(t *testing.T) {
	env := func(events string) []byte {
		return []byte(`{"usageEvents":[` + events + `],"pagination":{"currentPage":1,"hasNextPage":false}}`)
	}
	ok := `{"timestamp":"1","model":"m","userEmail":"a@corp.example","cloudAgentId":"bc-1"}`
	cases := []struct {
		name  string
		body  []byte
		drift bool
		snaps int
	}{
		{"one owner", env(ok), false, 1},
		{"no cloudAgentId is skipped", env(`{"timestamp":"1","model":"m","userEmail":"a@corp.example"}`), false, 0},
		{"names nobody", env(`{"timestamp":"1","model":"m","cloudAgentId":"bc-1"}`), true, 0},
		{"an id with a slash", env(`{"timestamp":"1","model":"m","userEmail":"a@corp.example","cloudAgentId":"bc/../x"}`), true, 0},
		{"a quoted flag", env(`{"timestamp":"1","model":"m","userEmail":"a@corp.example","cloudAgentId":"bc-1","isHeadless":"true"}`), true, 0},
		{"missing pagination", []byte(`{"usageEvents":[]}`), true, 0},
		{"missing events", []byte(`{"pagination":{"currentPage":1,"hasNextPage":false}}`), true, 0},
	}
	for _, c := range cases {
		p, err := parseCloudAgentOwners(cloudResp(c.body, ""))
		if c.drift {
			if !errors.Is(err, vendorapi.ErrSchemaDrift) {
				t.Errorf("%s: want drift, got %v", c.name, err)
			}
			continue
		}
		if err != nil || len(p.Snapshots) != c.snaps {
			t.Errorf("%s: %d snapshots, %v", c.name, len(p.Snapshots), err)
		}
	}
}

// TestCloudAgentOwnersBuildsTheHostingBody: the request is the usage-events
// POST with the closed hosting filter, page-numbered, at most 30 days.
func TestCloudAgentOwnersBuildsTheHostingBody(t *testing.T) {
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	w := vendorapi.Window{From: from, To: from.Add(24 * time.Hour)}
	r, err := buildCloudAgentOwners(nil, w, "3")
	want := vendorapi.EpochRangePageHosting{
		StartMillis: from.UnixMilli(), EndMillis: from.Add(24*time.Hour).UnixMilli() - 1, Page: 3, PageSize: UsagePageSize,
		HostingType: vendorapi.HostingCloud,
	}
	if err != nil || r.Method != "POST" || r.Path != "/teams/filtered-usage-events" || r.Body != want {
		t.Fatalf("request %+v %v", r, err)
	}
	if _, err := buildCloudAgentOwners(nil, vendorapi.Window{From: from, To: from.Add(31 * 24 * time.Hour)}, ""); err == nil {
		t.Error("a window above 30 days was built")
	}
	if _, err := buildCloudAgentOwners(nil, w, "page-two"); err == nil {
		t.Error("a non-numeric cursor was built")
	}
}

// TestCloudAgentOwnerDriversContract pins both lane CA-C8 drivers to their
// catalog rows and corpus ledgers. The key-info driver also runs the pure
// conformance suite; the owner driver is a POST, which the pure adapter does
// not send, so its conformance runs through the real runner
// (TestOrgSeatsConformance in internal/orgserver/vendorconn/runner).
func TestCloudAgentOwnerDriversContract(t *testing.T) {
	for _, d := range []vendorapi.Driver{CloudAgentMeta(), CloudAgentOwners()} {
		vendormock.CheckDriverContract(t, d)
		if !d.ClosedDTO || d.Tool != Tool || d.Auth.Scheme != vendorapi.SchemeBasicUser || d.LegacyPoller != "" {
			t.Errorf("%s: driver %+v", d.Surface, d)
		}
	}
	vendormock.RunPure(t, CloudAgentMeta(), nil, vendorapi.Window{})
}
