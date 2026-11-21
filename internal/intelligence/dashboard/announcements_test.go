package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/announce"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newAnnouncementServer builds a Server over a throwaway DB. The
// announcements endpoint touches no tables — the DB exists only because
// New requires one.
func newAnnouncementServer(t *testing.T) http.Handler {
	t.Helper()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Options{DB: database})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.Handler()
}

// getAnnouncements issues the request and decodes the response.
func getAnnouncements(t *testing.T, h http.Handler) (int, string, announcementsResponse) {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/announcements", nil))
	body := rr.Body.String()
	var decoded announcementsResponse
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &decoded); err != nil {
			t.Fatalf("decode %q: %v", body, err)
		}
	}
	return rr.Code, body, decoded
}

// stubAnnouncements swaps both package-level seams for the duration of
// one test.
func stubAnnouncements(t *testing.T, now time.Time, set []announce.Announcement) {
	t.Helper()
	prevSrc, prevNow := releaseAnnouncementSource, announcementNow
	releaseAnnouncementSource = func() []announce.Announcement { return set }
	announcementNow = func() time.Time { return now }
	t.Cleanup(func() {
		releaseAnnouncementSource, announcementNow = prevSrc, prevNow
	})
}

// TestAnnouncements_EmptyIsArrayNotNull pins the contract the banner
// depends on: no announcements must serialize as [], never null (a null
// would land as `.announcements.length` on undefined in the frontend).
//
// The empty set is INJECTED rather than inherited from the compiled-in
// release set. It used to rely on that set being empty, which made the
// test pass by coincidence — and fail the moment a release actually
// authored an announcement, which is a normal thing to do and not a
// regression in the contract under test.
func TestAnnouncements_EmptyIsArrayNotNull(t *testing.T) {
	stubAnnouncements(t, time.Now().UTC(), nil)
	h := newAnnouncementServer(t)
	code, body, got := getAnnouncements(t, h)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if strings.TrimSpace(body) != `{"announcements":[]}` {
		t.Errorf("body = %q, want {\"announcements\":[]}", strings.TrimSpace(body))
	}
	if got.Announcements == nil {
		t.Error("decoded announcements = nil, want empty slice")
	}
}

// TestAnnouncements_ServesLiveAndFiltersExpired covers the endpoint's
// only real behaviour: expired rows never reach the wire, live ones do,
// and the order is the merge order (critical first).
func TestAnnouncements_ServesLiveAndFiltersExpired(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	mk := func(id string, sev announce.Severity, expiresIn time.Duration) announce.Announcement {
		return announce.Announcement{
			ID:        id,
			Severity:  sev,
			Title:     "t " + id,
			Body:      "b " + id,
			ExpiresAt: now.Add(expiresIn).Format(time.RFC3339),
			Source:    announce.SourceRelease,
		}
	}
	stubAnnouncements(t, now, []announce.Announcement{
		mk("live-info", announce.SeverityInfo, 24*time.Hour),
		mk("expired", announce.SeverityCritical, -time.Second),
		mk("live-critical", announce.SeverityCritical, time.Hour),
	})

	h := newAnnouncementServer(t)
	code, body, got := getAnnouncements(t, h)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if strings.Contains(body, "expired") {
		t.Errorf("expired announcement leaked onto the wire: %s", body)
	}
	if len(got.Announcements) != 2 {
		t.Fatalf("got %d announcements, want 2: %s", len(got.Announcements), body)
	}
	if got.Announcements[0].ID != "live-critical" {
		t.Errorf("first announcement = %q, want live-critical (severity order)", got.Announcements[0].ID)
	}
	if got.Announcements[1].ID != "live-info" {
		t.Errorf("second announcement = %q, want live-info", got.Announcements[1].ID)
	}
	// Wire keys are the §1 contract shared with the frontend and the
	// later org rail — assert the JSON names, not just the struct.
	for _, key := range []string{`"id"`, `"severity"`, `"title"`, `"body"`, `"expires_at"`, `"source"`} {
		if !strings.Contains(body, key) {
			t.Errorf("body missing wire key %s: %s", key, body)
		}
	}
}

// TestAnnouncements_InvalidRowsDropped proves the endpoint degrades to
// "no banner" rather than serving a malformed one — the property that
// matters once rail R3 feeds it decoded wire data.
func TestAnnouncements_InvalidRowsDropped(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	stubAnnouncements(t, now, []announce.Announcement{
		{ID: "no-expiry", Severity: announce.SeverityInfo, Title: "t", Body: "b", Source: announce.SourceRelease},
		{
			ID: "bad-url", Severity: announce.SeverityInfo, Title: "t", Body: "b",
			URL:       "http://insecure.example/notes",
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
			Source:    announce.SourceRelease,
		},
	})

	h := newAnnouncementServer(t)
	code, body, got := getAnnouncements(t, h)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(got.Announcements) != 0 {
		t.Errorf("invalid announcements served: %s", body)
	}
}

// newAnnouncementServerWithOrg builds a Server over a throwaway DB with
// the org rail configured per orgEnabled, and returns the handler plus
// the store so a test can seed the node-local org cache (migration 076)
// the way the push loop would.
//
// The org rail also requires CURRENT enrolment, so an enrolled
// EnrolmentService double is wired in — the state every one of these
// tests is describing.
func newAnnouncementServerWithOrg(t *testing.T, orgEnabled bool) (http.Handler, *store.Store) {
	t.Helper()
	return newAnnouncementServerWithOrgEnrolment(t, orgEnabled, enrolledService())
}

// enrolledService is the EnrolmentService double for "this node is
// enrolled right now".
func enrolledService() EnrolmentService {
	return &fakeEnrolment{state: orgclient.EnrolmentState{
		Enrolled: true, OrgID: "org-1", OrgName: "Acme",
	}}
}

// newAnnouncementServerWithOrgEnrolment is the same builder with the
// enrolment seam left to the caller (nil = solo-local install, where
// cmd/observer leaves Options.OrgClient a nil interface).
func newAnnouncementServerWithOrgEnrolment(t *testing.T, orgEnabled bool, oc EnrolmentService) (http.Handler, *store.Store) {
	t.Helper()
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	opts := Options{
		DB:        database,
		Dashboard: config.DashboardConfig{OrgAnnouncements: orgEnabled},
	}
	if oc != nil {
		opts.OrgClient = oc
	}
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s.Handler(), store.New(database)
}

// seedOrgAnnouncement writes the node-local cache row exactly as
// orgclient.FetchOrgAnnouncement would after verifying a signed doc.
// The hash/signature columns are not read by the dashboard (verification
// happened at fetch time, once) so they carry placeholder values.
func seedOrgAnnouncement(t *testing.T, s *store.Store, body string) {
	t.Helper()
	if err := s.UpsertOrgAnnouncement(context.Background(), store.OrgAnnouncementRow{
		Version: 1, Body: body, BodyHash: "hash", Signature: "sig",
		ServerPubkey: "pk", ReceivedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertOrgAnnouncement: %v", err)
	}
}

// orgBody renders one org announcement as the §1 document body.
func orgBody(t *testing.T, id string, expiresAt time.Time) string {
	t.Helper()
	body, err := announce.Encode([]announce.Announcement{{
		ID:        id,
		Severity:  announce.SeverityNotice,
		Title:     "Fleet notice " + id,
		Body:      "From your org admin.",
		ExpiresAt: expiresAt.Format(time.RFC3339),
		Source:    announce.SourceOrg,
	}})
	if err != nil {
		t.Fatalf("announce.Encode: %v", err)
	}
	return body
}

// TestAnnouncements_OrgRailMergesWithRelease is rail R3's headline: the
// cached org document appears alongside the compiled-in release set, in
// the merged order, tagged source "org".
func TestAnnouncements_OrgRailMergesWithRelease(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	stubAnnouncements(t, now, []announce.Announcement{{
		ID:        "release-one",
		Severity:  announce.SeverityInfo,
		Title:     "release title",
		Body:      "release body",
		ExpiresAt: now.Add(48 * time.Hour).Format(time.RFC3339),
		Source:    announce.SourceRelease,
	}})

	h, s := newAnnouncementServerWithOrg(t, true)
	seedOrgAnnouncement(t, s, orgBody(t, "org-one", now.Add(24*time.Hour)))

	code, body, got := getAnnouncements(t, h)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(got.Announcements) != 2 {
		t.Fatalf("got %d announcements, want 2 (release + org): %s", len(got.Announcements), body)
	}
	// notice > info, so the org announcement leads.
	if got.Announcements[0].ID != "org-one" || got.Announcements[0].Source != announce.SourceOrg {
		t.Errorf("first = %+v, want org-one tagged source org", got.Announcements[0])
	}
	if got.Announcements[1].ID != "release-one" {
		t.Errorf("second = %q, want release-one", got.Announcements[1].ID)
	}
}

// TestAnnouncements_OrgSourceIsForced pins that provenance is decided by
// which cache the row came from, not by a string inside the body. A
// document claiming "release" still renders as org content.
func TestAnnouncements_OrgSourceIsForced(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	stubAnnouncements(t, now, nil)
	h, s := newAnnouncementServerWithOrg(t, true)
	seedOrgAnnouncement(t, s, `{"id":"liar","severity":"info","title":"t","body":"b",`+
		`"expires_at":"`+now.Add(time.Hour).Format(time.RFC3339)+`","source":"release"}`)

	_, body, got := getAnnouncements(t, h)
	if len(got.Announcements) != 1 {
		t.Fatalf("got %d announcements, want 1: %s", len(got.Announcements), body)
	}
	if got.Announcements[0].Source != announce.SourceOrg {
		t.Errorf("source = %q, want org", got.Announcements[0].Source)
	}
}

// TestAnnouncements_OrgRailDisabled pins the node operator's opt-out:
// with [dashboard].org_announcements = false the cached document is not
// read at all, while the release rail is untouched.
func TestAnnouncements_OrgRailDisabled(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	stubAnnouncements(t, now, nil)
	h, s := newAnnouncementServerWithOrg(t, false)
	seedOrgAnnouncement(t, s, orgBody(t, "org-one", now.Add(24*time.Hour)))

	code, body, got := getAnnouncements(t, h)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(got.Announcements) != 0 {
		t.Errorf("org announcement served with the rail disabled: %s", body)
	}
}

// TestAnnouncements_OrgDegradesSilently pins every "nothing to show"
// leg: no cache row (solo install), a retraction (empty body), and an
// undecodable body must each yield the release set alone — never a 500,
// because a broken banner input must not take the endpoint down.
func TestAnnouncements_OrgDegradesSilently(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		seed func(t *testing.T, s *store.Store)
	}{
		{"no cache row (solo install)", func(*testing.T, *store.Store) {}},
		{"retraction (empty body)", func(t *testing.T, s *store.Store) { seedOrgAnnouncement(t, s, "") }},
		{"undecodable body", func(t *testing.T, s *store.Store) { seedOrgAnnouncement(t, s, "{not json") }},
		{"body announcement fails §1", func(t *testing.T, s *store.Store) {
			seedOrgAnnouncement(t, s, `{"id":"no-expiry","severity":"info","title":"t","body":"b","source":"org"}`)
		}},
		{"expired org announcement", func(t *testing.T, s *store.Store) {
			seedOrgAnnouncement(t, s, orgBody(t, "stale", now.Add(-time.Hour)))
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stubAnnouncements(t, now, nil)
			h, s := newAnnouncementServerWithOrg(t, true)
			tc.seed(t, s)
			code, body, got := getAnnouncements(t, h)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (degrade, never fault): %s", code, body)
			}
			if len(got.Announcements) != 0 {
				t.Errorf("served %s, want nothing", body)
			}
		})
	}
}

// TestAnnouncements_OrgArrayBodyIsSupported pins the forward-compatible
// document shape: an ARRAY body is merged just like a single object, so
// a future multi-announcement composer needs no node change.
func TestAnnouncements_OrgArrayBodyIsSupported(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	stubAnnouncements(t, now, nil)
	h, s := newAnnouncementServerWithOrg(t, true)
	seedOrgAnnouncement(t, s, "["+
		orgBody(t, "org-a", now.Add(24*time.Hour))+","+
		orgBody(t, "org-b", now.Add(12*time.Hour))+"]")

	_, body, got := getAnnouncements(t, h)
	if len(got.Announcements) != 2 {
		t.Fatalf("got %d announcements, want 2: %s", len(got.Announcements), body)
	}
	if got.Announcements[0].ID != "org-a" || got.Announcements[1].ID != "org-b" {
		t.Errorf("order = %v, want [org-a org-b] (later expiry first)",
			[]string{got.Announcements[0].ID, got.Announcements[1].ID})
	}
}

// TestAnnouncements_ReleaseWinsIdCollision pins the rail order: Merge
// keeps the FIRST occurrence of an id and release is source 0, so an org
// admin cannot displace one of our announcements by reusing its id.
func TestAnnouncements_ReleaseWinsIdCollision(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	stubAnnouncements(t, now, []announce.Announcement{{
		ID:        "shared-id",
		Severity:  announce.SeverityInfo,
		Title:     "the real one",
		Body:      "from the release",
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		Source:    announce.SourceRelease,
	}})
	h, s := newAnnouncementServerWithOrg(t, true)
	seedOrgAnnouncement(t, s, orgBody(t, "shared-id", now.Add(48*time.Hour)))

	_, body, got := getAnnouncements(t, h)
	if len(got.Announcements) != 1 {
		t.Fatalf("got %d announcements, want 1: %s", len(got.Announcements), body)
	}
	if got.Announcements[0].Source != announce.SourceRelease {
		t.Errorf("source = %q, want release (first source wins an id collision)", got.Announcements[0].Source)
	}
}

// TestAnnouncements_OrgRequiresCurrentEnrolment is security finding 3
// leg (b). The cache row is deleted on unenrolment
// (store.DeleteEnrolment), so this handler should never SEE a stale row
// — which is exactly why it must also refuse to render one. A row that
// outlives its enrolment by any route the delete does not cover (a
// crash between writes, a restored DB, a future unenrol path that
// forgets) would otherwise let an org the operator has LEFT keep
// speaking into their dashboard.
//
// Each case seeds a perfectly valid, unexpired org announcement and
// varies only the enrolment state.
func TestAnnouncements_OrgRequiresCurrentEnrolment(t *testing.T) {
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		service EnrolmentService
		want    int
	}{
		{"not enrolled (unenrolled node, row left behind)", &fakeEnrolment{state: orgclient.EnrolmentState{Enrolled: false}}, 0},
		{"no org client at all (solo-local install)", nil, 0},
		{"enrolment lookup fails", &fakeEnrolment{statusErr: errors.New("db gone")}, 0},
		{"enrolled", enrolledService(), 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stubAnnouncements(t, now, nil)
			h, s := newAnnouncementServerWithOrgEnrolment(t, true, tc.service)
			seedOrgAnnouncement(t, s, orgBody(t, "org-one", now.Add(24*time.Hour)))

			code, body, got := getAnnouncements(t, h)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (degrade, never fault): %s", code, body)
			}
			if len(got.Announcements) != tc.want {
				t.Errorf("served %d announcements, want %d: %s", len(got.Announcements), tc.want, body)
			}
		})
	}
}

// TestAnnouncements_PlatformScoped pins U-01: an announcement scoped to
// another operating system never reaches this machine's banner, and the
// platforms key rides the wire for the frontend's own rail.
func TestAnnouncements_PlatformScoped(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	mk := func(id string, platforms ...string) announce.Announcement {
		return announce.Announcement{
			ID: id, Severity: announce.SeverityNotice, Title: "t " + id, Body: "b " + id,
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Source: announce.SourceRelease,
			Platforms: platforms,
		}
	}
	stubAnnouncements(t, now, []announce.Announcement{mk("mac-only", "darwin"), mk("linux-only", "linux"), mk("everywhere")})
	prev := announcementGOOS
	announcementGOOS = func() string { return "linux" }
	t.Cleanup(func() { announcementGOOS = prev })

	code, body, got := getAnnouncements(t, newAnnouncementServer(t))
	if code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	var ids []string
	for _, a := range got.Announcements {
		ids = append(ids, a.ID)
	}
	if strings.Join(ids, ",") != "everywhere,linux-only" && strings.Join(ids, ",") != "linux-only,everywhere" {
		t.Fatalf("ids = %v, want linux-only and everywhere: %s", ids, body)
	}
	if !strings.Contains(body, `"platforms":["linux"]`) {
		t.Errorf("platforms key missing from the wire: %s", body)
	}
}
