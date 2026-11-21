package deliverynet

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
)

const testToken = "github_pat_SEEDEDsecretVALUE123"

// fixture reads a Phase 0 GitHub fixture.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "delivery", "github", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

// tlsServer starts an httptest TLS server and a Client whose transport
// dials it for ANY host, so request URLs keep the real api.github.com (or
// GHES) host and the production allow-list stays in force.
func tlsServer(t *testing.T, h http.Handler, o Options) (*Client, *int64) {
	t.Helper()
	var hits int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	tr.TLSClientConfig.ServerName = "example.com"
	tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	o.HTTP = &http.Client{Transport: tr, Timeout: 5 * time.Second}
	return New(o), &hits
}

func tokenAuth() Auth { return Auth{Mode: AuthToken, Host: GitHubDotCom, Token: testToken} }

func TestUserSendsBearerAndReadsLogin(t *testing.T) {
	c, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "api.github.com" || r.URL.Path != "/user" {
			t.Errorf("unexpected request %s %s", r.Host, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("Authorization = %q", got)
		}
		w.Header().Set("X-OAuth-Scopes", "repo, read:org")
		_, _ = w.Write([]byte(`{"login":"octo"}`))
	}), Options{})
	acct, err := c.User(context.Background(), tokenAuth())
	if err != nil {
		t.Fatal(err)
	}
	if acct.Login != "octo" || acct.Scopes != "repo, read:org" {
		t.Fatalf("got %+v", acct)
	}
}

func TestRedirectIsNeverFollowed(t *testing.T) {
	var followed int64
	c, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repositories/") {
			atomic.AddInt64(&followed, 1)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.Redirect(w, r, "https://api.github.com/repositories/42/pulls/7", http.StatusMovedPermanently)
	}), Options{})
	_, err := c.PullRequest(context.Background(), tokenAuth(), "old/name", 7)
	if KindOf(err) != KindRepoMoved {
		t.Fatalf("kind = %q, want repo_moved (err %v)", KindOf(err), err)
	}
	if followed != 0 {
		t.Fatalf("redirect target was requested %d times", followed)
	}
}

func TestHostNotOnAllowListIsRefusedBeforeAnyRequest(t *testing.T) {
	c, hits := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"login":"x"}`))
	}), Options{GHESHosts: []string{"ghe.corp.example"}})
	for _, host := range []string{"evil.example", "gitlab.com", "api.github.com.evil.example"} {
		_, err := c.User(context.Background(), Auth{Mode: AuthToken, Host: host, Token: testToken})
		if KindOf(err) != KindHostNotAllowed {
			t.Errorf("host %s: kind = %q", host, KindOf(err))
		}
	}
	if *hits != 0 {
		t.Fatalf("server saw %d requests for refused hosts", *hits)
	}
	// A declared GHES host is allowed, under /api/v3.
	c2, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "ghe.corp.example" || r.URL.Path != "/api/v3/user" {
			t.Errorf("GHES request %s %s", r.Host, r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"login":"corp"}`))
	}), Options{GHESHosts: []string{"GHE.corp.example"}})
	if acct, err := c2.User(context.Background(), Auth{Mode: AuthToken, Host: "ghe.corp.example", Token: testToken}); err != nil || acct.Login != "corp" {
		t.Fatalf("GHES: %+v %v", acct, err)
	}
}

func TestCheckURL(t *testing.T) {
	c := New(Options{GHESHosts: []string{"ghe.example"}})
	cases := []struct {
		url string
		ok  bool
	}{
		{"https://api.github.com/user", true},
		{"https://api.github.com:443/user", true},
		{"https://ghe.example/api/v3/user", true},
		{"http://api.github.com/user", false},
		{"https://api.github.com:8443/user", false},
		{"https://tok@api.github.com/user", false},
		{"https://github.com/user", false},
		{"https://evil.example/user", false},
		{"https://api.github.com/user#x", false},
	}
	for _, tc := range cases {
		err := c.CheckURL(tc.url)
		if (err == nil) != tc.ok {
			t.Errorf("CheckURL(%s) err=%v want ok=%v", tc.url, err, tc.ok)
		}
	}
}

func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		status int
		rl     bool
		want   Kind
	}{
		{301, false, KindRepoMoved},
		{307, false, KindRepoMoved},
		{401, false, KindAuthFailed},
		{403, true, KindRateLimited},
		{429, false, KindRateLimited},
		{403, false, KindAuthFailed},
		{404, false, KindNotFound},
		{422, false, KindUnprocessable},
		{502, false, KindUnreachable},
		{418, false, KindWrongShape},
	}
	for _, tc := range cases {
		if got := ClassifyStatus(tc.status, tc.rl); got != tc.want {
			t.Errorf("ClassifyStatus(%d,%v)=%s want %s", tc.status, tc.rl, got, tc.want)
		}
	}
}

func TestCommitPulls422MeansNotInRepo(t *testing.T) {
	body := fixture(t, "commit_pulls_unknown_sha_422.json")
	c, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write(body)
	}), Options{})
	prs, inRepo, err := c.CommitPulls(context.Background(), tokenAuth(), "cli/cli", "0123456789abcdef0123456789abcdef01234567")
	if err != nil || inRepo || len(prs) != 0 {
		t.Fatalf("got prs=%v inRepo=%v err=%v", prs, inRepo, err)
	}
}

func TestCommitPullsMergedFromFixture(t *testing.T) {
	body := fixture(t, "commit_pulls_merged.json")
	c, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/cli/cli/commits/1b0eb4096d53d0c8c35f76cf2aad62529083d93d/pulls" {
			t.Errorf("path %s", r.URL.Path)
		}
		_, _ = w.Write(body)
	}), Options{})
	prs, inRepo, err := c.CommitPulls(context.Background(), tokenAuth(), "cli/cli", "1b0eb4096d53d0c8c35f76cf2aad62529083d93d")
	if err != nil || !inRepo || len(prs) != 1 {
		t.Fatalf("got %v %v %v", prs, inRepo, err)
	}
	p := prs[0]
	if p.Number != 14706 || p.State != delivery.PRMerged || p.MergeCommitSHA != "59e9f78eacdf2554f8534d166808c3e9b8c7ebcb" {
		t.Fatalf("pr = %+v", p)
	}
	if p.Provider != delivery.ProviderGitHub || p.Host != GitHubDotCom || p.RepoSlug != "cli/cli" || p.URL != "https://github.com/cli/cli/pull/14706" {
		t.Fatalf("identity = %+v", p)
	}
	if p.MergedAt.IsZero() || p.CreatedAt.IsZero() {
		t.Fatalf("times not parsed: %+v", p)
	}
}

// openPRServer serves the open/unstable PR and its readiness evidence.
func openPRServer(t *testing.T, pullFixture string) http.Handler {
	pull := fixture(t, pullFixture)
	checks := fixture(t, "check_runs_mixed.json")
	status := fixture(t, "combined_status_empty.json")
	reviews := fixture(t, "reviews_commented.json")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/check-runs"):
			_, _ = w.Write(checks)
		case strings.HasSuffix(r.URL.Path, "/status"):
			_, _ = w.Write(status)
		case strings.HasSuffix(r.URL.Path, "/reviews"):
			_, _ = w.Write(reviews)
		case strings.Contains(r.URL.Path, "/pulls/"):
			_, _ = w.Write(pull)
		default:
			http.NotFound(w, r)
		}
	})
}

func TestPullRequestOpenUnstableIsReadyWithFacet(t *testing.T) {
	c, hits := tlsServer(t, openPRServer(t, "pull_open_unstable.json"), Options{})
	p, err := c.PullRequest(context.Background(), tokenAuth(), "cli/cli", 14678)
	if err != nil {
		t.Fatal(err)
	}
	if p.State != delivery.PROpen || p.Readiness != delivery.ReadyToMerge {
		t.Fatalf("state %s readiness %s", p.State, p.Readiness)
	}
	if p.Facets.Checks != "nonrequired_failing" {
		t.Fatalf("facets %+v", p.Facets)
	}
	if p.MergeCommitSHA != "" {
		t.Fatalf("an open PR's test merge commit must not be kept: %s", p.MergeCommitSHA)
	}
	if p.HeadSHA != "ea5512228b30fe38b68b18232acc4dc8f29acd3a" || p.BaseRef == "" {
		t.Fatalf("head/base %+v", p)
	}
	if *hits != 4 {
		t.Fatalf("hits = %d, want 4 (pull, check-runs, status, reviews)", *hits)
	}
}

func TestPullRequestDraftBeforeMergeableState(t *testing.T) {
	c, _ := tlsServer(t, openPRServer(t, "pull_draft_clean.json"), Options{})
	p, err := c.PullRequest(context.Background(), tokenAuth(), "cli/cli", 14679)
	if err != nil {
		t.Fatal(err)
	}
	if p.State != delivery.PRDraft {
		t.Fatalf("state %s, want draft", p.State)
	}
}

func TestPullRequestMergedFetchesNoReadiness(t *testing.T) {
	c, hits := tlsServer(t, openPRServer(t, "pull_merged_mergecommit.json"), Options{})
	p, err := c.PullRequest(context.Background(), tokenAuth(), "cli/cli", 14706)
	if err != nil {
		t.Fatal(err)
	}
	if p.State != delivery.PRMerged || p.MergeCommitSHA == "" {
		t.Fatalf("pr %+v", p)
	}
	if *hits != 1 {
		t.Fatalf("hits = %d, want 1", *hits)
	}
}

func TestPullCommitsPagesAndCaps(t *testing.T) {
	var pages int64
	c, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&pages, 1)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		var b strings.Builder
		b.WriteString("[")
		for i := 0; i < perPage; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `{"sha":"%040x"}`, page*1000+i)
		}
		b.WriteString("]")
		_, _ = w.Write([]byte(b.String()))
	}), Options{})
	got, err := c.PullCommits(context.Background(), tokenAuth(), "o/r", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != MaxPRCommits || pages != 3 {
		t.Fatalf("len=%d pages=%d", len(got), pages)
	}
	if got[249].Position != 249 {
		t.Fatalf("position %d", got[249].Position)
	}
	// The merged fixture: two commits.
	body := fixture(t, "pull_commits_merged.json")
	c2, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }), Options{})
	got, err = c2.PullCommits(context.Background(), tokenAuth(), "cli/cli", 14706)
	if err != nil || len(got) != 2 || got[1].SHA != "1b0eb4096d53d0c8c35f76cf2aad62529083d93d" {
		t.Fatalf("got %v %v", got, err)
	}
}

func TestConditionalRequestReusesETag(t *testing.T) {
	c, hits := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(`{"login":"octo"}`))
	}), Options{})
	for i := 0; i < 2; i++ {
		acct, err := c.User(context.Background(), tokenAuth())
		if err != nil || acct.Login != "octo" {
			t.Fatalf("call %d: %+v %v", i, acct, err)
		}
	}
	if *hits != 2 {
		t.Fatalf("hits %d", *hits)
	}
}

func TestRateLimitBlocksUntilReset(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	reset := now.Add(10 * time.Minute)
	c, hits := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		w.WriteHeader(http.StatusForbidden)
	}), Options{Now: func() time.Time { return now }})
	_, err := c.User(context.Background(), tokenAuth())
	if KindOf(err) != KindRateLimited || !ResetOf(err).Equal(reset) {
		t.Fatalf("err %v reset %v", err, ResetOf(err))
	}
	_, err = c.User(context.Background(), tokenAuth())
	if KindOf(err) != KindRateLimited || *hits != 1 {
		t.Fatalf("second call sent a request (hits %d) or wrong kind %v", *hits, err)
	}
	// A 200 that spends the last request blocks the next call as well.
	c2, hits2 := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
		_, _ = w.Write([]byte(`{"login":"octo"}`))
	}), Options{Now: func() time.Time { return now }})
	if _, err := c2.User(context.Background(), tokenAuth()); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.User(context.Background(), tokenAuth()); KindOf(err) != KindRateLimited || *hits2 != 1 {
		t.Fatalf("hits %d err %v", *hits2, err)
	}
}

func TestBodyCapAndShape(t *testing.T) {
	big := strings.Repeat("x", MaxBody+10)
	c, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(big)) }), Options{})
	if _, err := c.User(context.Background(), tokenAuth()); KindOf(err) != KindWrongShape {
		t.Fatalf("kind %v", KindOf(err))
	}
	c2, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`not json`)) }), Options{})
	if _, err := c2.User(context.Background(), tokenAuth()); KindOf(err) != KindWrongShape {
		t.Fatalf("kind %v", KindOf(err))
	}
}

func TestTokenNeverInErrors(t *testing.T) {
	for _, st := range []int{401, 403, 404, 500, 301} {
		c, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "https://evil.example/")
			w.WriteHeader(st)
			_, _ = w.Write([]byte(`{"message":"` + testToken + `"}`))
		}), Options{})
		_, err := c.User(context.Background(), tokenAuth())
		if err == nil || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), "evil.example") {
			t.Fatalf("status %d: err %v", st, err)
		}
	}
}

func TestInputValidationRefusesBeforeRequest(t *testing.T) {
	c, hits := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`[]`)) }), Options{})
	ctx := context.Background()
	if _, _, err := c.CommitPulls(ctx, tokenAuth(), "../etc", "abcdef1"); KindOf(err) != KindInvalid {
		t.Errorf("slug: %v", err)
	}
	if _, _, err := c.CommitPulls(ctx, tokenAuth(), "o/r", "HEAD;rm"); KindOf(err) != KindInvalid {
		t.Errorf("sha: %v", err)
	}
	if _, err := c.PullRequest(ctx, tokenAuth(), "o/r", 0); KindOf(err) != KindInvalid {
		t.Errorf("number: %v", err)
	}
	if _, err := c.User(ctx, Auth{Mode: AuthToken, Host: GitHubDotCom}); KindOf(err) != KindAuthFailed {
		t.Errorf("empty token: %v", err)
	}
	if *hits != 0 {
		t.Fatalf("hits %d", *hits)
	}
}

// TestPullsForHeadQueriesByHeadBranch (lane CA-C5): the head= query names
// the repository owner and the branch, a returned PR whose head ref is
// another branch is dropped, and the head ref is kept on the PR.
func TestPullsForHeadQueriesByHeadBranch(t *testing.T) {
	var gotQuery string
	c, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/app/pulls" {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
		  {"number": 7, "state": "closed", "merged_at": "2026-11-01T10:00:00Z", "merge_commit_sha": "3333333333333333333333333333333333333333",
		   "head": {"sha": "1111111111111111111111111111111111111111", "ref": "cursor/fix-a"}, "base": {"ref": "main"}, "user": {"login": "cursor[bot]"}},
		  {"number": 8, "state": "open", "head": {"sha": "2222222222222222222222222222222222222222", "ref": "other"}, "base": {"ref": "main"}}
		]`))
	}), Options{})
	prs, err := c.PullsForHead(context.Background(), tokenAuth(), "acme/app", "cursor/fix-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "head=acme%3Acursor%2Ffix-a") || !strings.Contains(gotQuery, "state=all") {
		t.Fatalf("query %q", gotQuery)
	}
	if len(prs) != 1 || prs[0].Number != 7 || prs[0].HeadRef != "cursor/fix-a" || prs[0].State != delivery.PRMerged {
		t.Fatalf("prs %+v", prs)
	}
	if _, err := c.PullsForHead(context.Background(), tokenAuth(), "acme/app", "bad branch"); KindOf(err) != KindInvalid {
		t.Fatalf("bad branch err = %v", err)
	}
}
