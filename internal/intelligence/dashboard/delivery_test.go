//go:build !sbo_omit_remote

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeDeliveryService records calls and answers from fields.
type fakeDeliveryService struct {
	calls   []string
	connErr error
	link    delivery.ProviderLink
	lastReq dashapi.DeliveryConnectRequest
}

func (f *fakeDeliveryService) Connect(_ context.Context, req dashapi.DeliveryConnectRequest) (delivery.ProviderLink, error) {
	f.calls = append(f.calls, "connect")
	f.lastReq = req
	return f.link, f.connErr
}

func (f *fakeDeliveryService) TestLink(_ context.Context, id int64) (delivery.ProviderLink, error) {
	f.calls = append(f.calls, "test:"+itoa64(id))
	return f.link, nil
}

func (f *fakeDeliveryService) Disconnect(_ context.Context, id int64) error {
	f.calls = append(f.calls, "disconnect:"+itoa64(id))
	return nil
}

func (f *fakeDeliveryService) DeleteMirror(_ context.Context, id int64) error {
	f.calls = append(f.calls, "mirror:"+itoa64(id))
	return nil
}

func (f *fakeDeliveryService) MirrorUsage(context.Context) (int64, int64, []delivery.Mirror, error) {
	f.calls = append(f.calls, "usage")
	return 10 << 20, 2048 << 20, []delivery.Mirror{{ID: 3, URL: "https://gitlab.com/acme/app.git", SizeBytes: 10 << 20, Status: "ok"}}, nil
}

func (f *fakeDeliveryService) CheckProject(_ context.Context, id int64) (dashapi.DeliveryCheckResult, error) {
	f.calls = append(f.calls, "check:"+itoa64(id))
	return dashapi.DeliveryCheckResult{Reevaluated: true, Repos: []dashapi.DeliveryCheckRepo{{RemoteName: "origin", Status: "ok"}}}, nil
}

// doConfirm sends a confirm-token request with any method.
func doConfirm(t *testing.T, h http.Handler, method, path, body string, ck *http.Cookie, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	if ck != nil {
		req.AddCookie(ck)
		req.Header.Set(remoteConfirmHeader, token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// seedDelivery lands the fixture's sha1 through a merged GitHub PR.
func seedDelivery(t *testing.T, s *Server, projectID int64) (linkID, prID int64) {
	t.Helper()
	ctx := context.Background()
	st := store.New(s.db())
	now := time.Now().UTC().Truncate(time.Second)
	if err := st.UpsertProjectRemote(ctx, delivery.Remote{
		ProjectID: projectID, Name: "origin", URL: "https://github.com/acme/app.git", DefaultBranch: "main",
		FetchHeadAt: now.Add(-2 * time.Hour), ObservedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	linkID, err := st.CreateProviderLink(ctx, delivery.ProviderLink{
		Provider: delivery.ProviderGitHub, Host: "github.com", AuthMode: "token", KeyName: "link.k.token",
		AccountLogin: "dev", Status: "ok", LastOKAt: now, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	prID, err = st.UpsertPullRequest(ctx, delivery.PullRequest{
		LinkID: linkID, Provider: delivery.ProviderGitHub, Host: "github.com", RepoSlug: "acme/app", Number: 41,
		Title: "feat: login button", URL: "https://github.com/acme/app/pull/41", State: delivery.PRMerged,
		MergeMethod: delivery.MergeSquash, CreatedAt: now.Add(-90 * time.Minute), MergedAt: now.Add(-30 * time.Minute), FetchedAt: now,
	}, []delivery.PRCommit{{SHA: "sha1", Position: 0}})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := st.LoadProjectCommits(ctx, projectID, now.Add(-24*time.Hour), now.Add(time.Hour), 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("commits = %+v, %v", rows, err)
	}
	if err := st.UpsertCommitLandings(ctx, []delivery.Landing{{
		CommitID: rows[0].ID, Status: delivery.StatusLanded, Kind: delivery.KindSquash, Confidence: delivery.ConfExact,
		PRID: prID, PRNumber: 41, RuleID: "P1", RuleVersion: delivery.RuleVersion, Source: delivery.SourceProvider,
		LandedAt: now.Add(-30 * time.Minute), LandedAtSource: delivery.LandedAtProvider, EvaluatedAt: now, SessionIDs: []string{"sess1"},
	}}); err != nil {
		t.Fatal(err)
	}
	return linkID, prID
}

// TestAPIProjectDelivery pins the Delivery tab read: provider source, the
// PR with its AI commit, owner session and prompt, metrics known, funnel.
func TestAPIProjectDelivery(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	s.opts.Delivery = config.DeliveryConfig{Local: true, PollMinutes: 10}
	seedDelivery(t, s, projectID)
	h := s.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/2000000000/delivery", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown project: %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/delivery", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got dashapi.APIProjectDelivery
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Source.Kind != "provider" || !got.ProviderLinked || got.Source.DefaultBranch != "main" || got.Source.AccountLogin != "dev" {
		t.Fatalf("source = %+v linked=%v", got.Source, got.ProviderLinked)
	}
	if got.LinkProblem != nil || got.CanCheck {
		t.Fatalf("link problem %+v / can_check %v", got.LinkProblem, got.CanCheck)
	}
	if len(got.PullRequests) != 1 {
		t.Fatalf("PRs = %+v", got.PullRequests)
	}
	pr := got.PullRequests[0]
	if pr.Number != 41 || pr.State != "merged" || pr.Stale || len(pr.AICommits) != 1 || pr.MergeSeconds != 3600 {
		t.Fatalf("PR = %+v", pr)
	}
	c := pr.AICommits[0]
	if c.SHA != "sha1" || c.Status != "landed" || c.Kind != "squash" || c.OwnerSessionID != "sess1" ||
		c.Prompt == nil || c.Prompt.Preview != "add login button" {
		t.Fatalf("PR commit = %+v (prompt %+v)", c, c.Prompt)
	}
	if len(pr.Sessions) != 1 || pr.Sessions[0] != "sess1" {
		t.Fatalf("PR sessions = %v", pr.Sessions)
	}
	sum := got.Summary
	if sum.AICommits != 1 || !sum.AcceptedWorkRate.Known || sum.AcceptedWorkRate.Value != 1 ||
		!sum.PRMergeRate.Known || !sum.OpenMergeable.Known || sum.OpenMergeable.Value != 0 || sum.LandedSquash != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	if !sum.Funnel.Known || sum.Funnel.EditedPrompts != 2 || sum.Funnel.Committed != 1 || sum.Funnel.Landed != 1 || sum.Funnel.InPR != 1 {
		t.Fatalf("funnel = %+v", sum.Funnel)
	}
	if len(got.NotInPR) != 0 || got.NotInPRTotal != 0 {
		t.Fatalf("not in PR = %+v", got.NotInPR)
	}
}

// TestAPIProjectDeliveryLocalOnly: no link means PR metrics are unknown,
// never zero, and the source is the user's own fetches.
func TestAPIProjectDeliveryLocalOnly(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	ctx := context.Background()
	st := store.New(s.db())
	now := time.Now().UTC()
	if err := st.UpsertProjectRemote(ctx, delivery.Remote{ProjectID: projectID, Name: "origin", URL: "https://gitlab.com/acme/app.git", DefaultBranch: "main", FetchHeadAt: now.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.LoadProjectCommits(ctx, projectID, now.Add(-24*time.Hour), now.Add(time.Hour), 10)
	if err := st.UpsertCommitLandings(ctx, []delivery.Landing{{CommitID: rows[0].ID, Status: delivery.StatusPushed, RuleID: "L6", RuleVersion: 1, EvaluatedAt: now}}); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/project/"+itoa64(projectID)+"/delivery", nil))
	var got dashapi.APIProjectDelivery
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Source.Kind != "user_refs" || got.ProviderLinked || !got.MirrorEligible {
		t.Fatalf("source = %+v linked=%v eligible=%v", got.Source, got.ProviderLinked, got.MirrorEligible)
	}
	if got.Summary.PRMergeRate.Known || got.Summary.PRMergeRate.UnknownReason != delivery.UnknownNoProvider || got.Summary.OpenMergeable.Known {
		t.Fatalf("PR metrics should be unknown: %+v", got.Summary)
	}
	if got.NotInPRTotal != 1 || got.NotInPR[0].Status != "pushed" {
		t.Fatalf("not in PR = %+v", got.NotInPR)
	}
}

// TestAPISessionDelivery pins GET /api/session/{id}/delivery.
func TestAPISessionDelivery(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	seedDelivery(t, s, projectID)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/sess1/delivery", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	var got dashapi.APISessionDelivery
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ProjectID != projectID || !got.ProviderLinked || got.DefaultBranch != "main" || len(got.Rows) != 1 {
		t.Fatalf("session delivery = %+v", got)
	}
	r := got.Rows[0]
	if !r.Evaluated || r.Landing == nil || r.Landing.Status != "landed" || r.PR == nil || r.PR.Number != 41 || !r.Owner {
		t.Fatalf("row = %+v", r)
	}
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/session/no-such/delivery", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown session: %d", rr.Code)
	}
}

// TestDeliveryWriteRoutes is the table of every write route: 403 without
// the confirm token, 503 with no service, then the service call it makes.
func TestDeliveryWriteRoutes(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	h := s.Handler()
	ck, token := getConfirm(t, h)
	pid := itoa64(projectID)
	cases := []struct {
		name, method, path, body, wantCall string
	}{
		{"connect", http.MethodPost, "/api/delivery/links", `{"provider":"github","host":"github.com","auth_mode":"token","token":"tok"}`, "connect"},
		{"test", http.MethodPost, "/api/delivery/links/7/test", "{}", "test:7"},
		{"disconnect", http.MethodDelete, "/api/delivery/links/7", "{}", "disconnect:7"},
		{"delete mirror", http.MethodDelete, "/api/delivery/mirrors/3", "{}", "mirror:3"},
		{"check now", http.MethodPost, "/api/project/" + pid + "/delivery/check", "{}", "check:" + pid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s.opts.DeliveryService = nil
			if rec := doConfirm(t, h, tc.method, tc.path, tc.body, nil, ""); rec.Code != http.StatusForbidden {
				t.Fatalf("no token: %d %s", rec.Code, rec.Body.String())
			}
			if rec := doConfirm(t, h, tc.method, tc.path, tc.body, ck, token); rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("no service: %d %s", rec.Code, rec.Body.String())
			}
			f := &fakeDeliveryService{link: delivery.ProviderLink{ID: 7, Provider: delivery.ProviderGitHub, Host: "github.com", AuthMode: "token", KeyName: "link.secret.token", Status: "ok"}}
			s.opts.DeliveryService = f
			rec := doConfirm(t, h, tc.method, tc.path, tc.body, ck, token)
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d body=%s", rec.Code, rec.Body.String())
			}
			if len(f.calls) != 1 || f.calls[0] != tc.wantCall {
				t.Fatalf("calls = %v, want %s", f.calls, tc.wantCall)
			}
			if strings.Contains(rec.Body.String(), "link.secret.token") || strings.Contains(rec.Body.String(), `"tok"`) {
				t.Fatalf("response leaks a secret or key name: %s", rec.Body.String())
			}
		})
	}
	s.opts.DeliveryService = nil
}

// TestDeliveryConnectErrorMapping: a service error carries its status and
// closed kind to the page.
func TestDeliveryConnectErrorMapping(t *testing.T) {
	s, _, _, _, _ := seedProjectsFixture(t)
	h := s.Handler()
	ck, token := getConfirm(t, h)
	cases := []struct {
		err        *dashapi.DeliveryError
		wantStatus int
	}{
		{&dashapi.DeliveryError{Status: http.StatusConflict, Kind: "no_keychain", Message: "no keychain"}, http.StatusConflict},
		{&dashapi.DeliveryError{Status: http.StatusUnprocessableEntity, Kind: "auth_failed", Message: "refused"}, http.StatusUnprocessableEntity},
		{&dashapi.DeliveryError{Status: http.StatusBadRequest, Kind: "invalid", Message: "bad host"}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		s.opts.DeliveryService = &fakeDeliveryService{connErr: tc.err}
		rec := doConfirm(t, h, http.MethodPost, "/api/delivery/links", `{"provider":"github","auth_mode":"gh_cli"}`, ck, token)
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != tc.wantStatus || body["kind"] != tc.err.Kind {
			t.Fatalf("%s: status %d body %v", tc.err.Kind, rec.Code, body)
		}
	}
}

// TestDeliverySettingsRoute pins the schedule rule (0 or at least 30
// minutes) and that turning the mirror off clears the schedule.
func TestDeliverySettingsRoute(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	h := s.Handler()
	ck, token := getConfirm(t, h)
	path := "/api/project/" + itoa64(projectID) + "/delivery/settings"
	cases := []struct {
		body         string
		wantStatus   int
		wantMirror   bool
		wantSchedule int
	}{
		{`{"mirror_enabled":true,"schedule_minutes":10}`, http.StatusBadRequest, false, 0},
		{`{"mirror_enabled":true,"schedule_minutes":20000}`, http.StatusBadRequest, false, 0},
		{`{"mirror_enabled":true,"schedule_minutes":60}`, http.StatusOK, true, 60},
		{`{"mirror_enabled":true,"schedule_minutes":0}`, http.StatusOK, true, 0},
		{`{"mirror_enabled":false,"schedule_minutes":60}`, http.StatusOK, false, 0},
	}
	for _, tc := range cases {
		rec := doConfirm(t, h, http.MethodPut, path, tc.body, ck, token)
		if rec.Code != tc.wantStatus {
			t.Fatalf("%s: status %d body=%s", tc.body, rec.Code, rec.Body.String())
		}
		if rec.Code != http.StatusOK {
			continue
		}
		var got dashapi.APIDeliverySettings
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.MirrorEnabled != tc.wantMirror || got.ScheduleMinutes != tc.wantSchedule {
			t.Fatalf("%s: settings = %+v", tc.body, got)
		}
	}
	if rec := doConfirm(t, h, http.MethodPut, path, `{"mirror_enabled":true}`, nil, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("no token: %d", rec.Code)
	}
}

// TestDeliveryReadRoutes pins the link and mirror lists: no secret, the
// served repository count, and the cap with no service wired.
func TestDeliveryReadRoutes(t *testing.T) {
	s, _, projectID, _, _ := seedProjectsFixture(t)
	s.opts.Delivery = config.DeliveryConfig{PollMinutes: 10, MirrorCapMB: 2048}
	seedDelivery(t, s, projectID)
	h := s.Handler()

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/delivery/links", nil))
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "link.k.token") {
		t.Fatalf("links: %d %s", rr.Code, rr.Body.String())
	}
	var links dashapi.APIDeliveryLinksResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &links); err != nil {
		t.Fatal(err)
	}
	if links.ServiceAvailable || links.PollMinutes != 10 || len(links.Links) != 1 || links.Links[0].Repos != 1 || links.Links[0].AccountLogin != "dev" {
		t.Fatalf("links = %+v", links)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/delivery/mirrors", nil))
	var mirrors dashapi.APIDeliveryMirrorsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &mirrors); err != nil {
		t.Fatal(err)
	}
	if mirrors.CapBytes != 2048<<20 || len(mirrors.Mirrors) != 0 {
		t.Fatalf("mirrors = %+v", mirrors)
	}
	s.opts.DeliveryService = &fakeDeliveryService{}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/delivery/mirrors", nil))
	if err := json.Unmarshal(rr.Body.Bytes(), &mirrors); err != nil {
		t.Fatal(err)
	}
	if !mirrors.ServiceAvailable || mirrors.UsedBytes != 10<<20 || len(mirrors.Mirrors) != 1 {
		t.Fatalf("mirrors via service = %+v", mirrors)
	}
	s.opts.DeliveryService = nil
}
