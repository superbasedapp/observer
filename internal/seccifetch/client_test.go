package seccifetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

func TestNewRefusesUnsafeURLs(t *testing.T) {
	for _, u := range []string{
		"http://org.example.com", "ftp://x", "https://user:pw@org.example.com", "https://org.example.com?x=1", "org.example.com", "",
	} {
		if _, err := New(u, "cred"); !errors.Is(err, ErrBaseURL) {
			t.Errorf("%q: err = %v", u, err)
		}
	}
	for _, u := range []string{"https://org.example.com/", "http://127.0.0.1:8443", "http://[::1]:1", "http://localhost:9"} {
		if _, err := New(u, "cred"); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
	if _, err := New("https://org.example.com", " "); !errors.Is(err, ErrRefused) {
		t.Errorf("empty credential: %v", err)
	}
}

// fakeClock advances only when the client sleeps.
type fakeClock struct{ now time.Time }

func (f *fakeClock) client(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	c, err := New(srv.URL, "ci-cred")
	if err != nil {
		t.Fatal(err)
	}
	c.Now = func() time.Time { return f.now }
	c.Sleep = func(_ context.Context, d time.Duration) error { f.now = f.now.Add(d); return nil }
	return c
}

func lookupBody(t *testing.T, states ...string) []byte {
	t.Helper()
	ans := orgcontract.CILookupAnswer{OrgID: "org-1", AnsweredAt: "2026-10-22T12:00:00Z"}
	ca := orgcontract.CILookupCommitAnswer{SHA: strings.Repeat("1", 40), Records: []orgcontract.CILookupRecord{}}
	for _, s := range states {
		ca.Records = append(ca.Records, orgcontract.CILookupRecord{RecordDigest: "d", State: s})
	}
	ans.Commits = []orgcontract.CILookupCommitAnswer{ca}
	body, _ := json.Marshal(ans)
	b, _ := json.Marshal(orgcontract.CISignedDocument{Body: body, IssuerKeyID: "k", Signature: "s"})
	return b
}

var oneCommit = orgcontract.CILookupRequest{Commits: []orgcontract.CILookupCommit{{SHA: strings.Repeat("1", 40)}}}

// TestLookupWaitBounded: the fetch job asks again with backoff while the
// answer is not settled, and stops at the wait with the last answer.
func TestLookupWaitBounded(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ci-cred" || r.URL.Path != orgcontract.CILookupPath || r.Method != http.MethodPost {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		calls.Add(1)
		_, _ = w.Write(lookupBody(t, orgcontract.ChangeIngestPending))
	}))
	defer srv.Close()
	clk := &fakeClock{now: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	c := clk.client(t, srv)
	start := clk.now
	res := c.LookupWait(context.Background(), oneCommit, 180*time.Second)
	if res.Settled || res.Doc == nil || res.LastErr != nil {
		t.Fatalf("res = %+v", res)
	}
	if got := clk.now.Sub(start); got != 180*time.Second {
		t.Fatalf("waited %s, want exactly the 180s bound", got)
	}
	// 5 + 10 + 20 + 30*4 = 155, then a 25s remainder: 9 lookups.
	if res.Attempts != 9 || calls.Load() != 9 {
		t.Fatalf("attempts %d calls %d", res.Attempts, calls.Load())
	}
}

// TestLookupWaitSettles: an answer whose every commit has a final record
// ends the wait at once.
func TestLookupWaitSettles(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(lookupBody(t, orgcontract.ChangeIngestCountersigned))
	}))
	defer srv.Close()
	clk := &fakeClock{now: time.Now()}
	res := clk.client(t, srv).LookupWait(context.Background(), oneCommit, 180*time.Second)
	if !res.Settled || res.Attempts != 3 || res.LastErr != nil {
		t.Fatalf("res = %+v", res)
	}
}

// TestLookupWaitStopsOnRefusal: a 4xx (a wrong or revoked credential, a
// server without the CI check) is not retried.
func TestLookupWaitStopsOnRefusal(t *testing.T) {
	for code, want := range map[int]error{http.StatusForbidden: ErrRefused, http.StatusNotFound: ErrNotSupported} {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":"wrong_scope","message":"not echoed"}`))
		}))
		clk := &fakeClock{now: time.Now()}
		res := clk.client(t, srv).LookupWait(context.Background(), oneCommit, 180*time.Second)
		srv.Close()
		if !errors.Is(res.LastErr, want) || calls.Load() != 1 || res.Doc != nil {
			t.Errorf("%d: res = %+v calls %d", code, res, calls.Load())
		}
		if strings.Contains(res.LastErr.Error(), "not echoed") {
			t.Errorf("%d: free text echoed: %v", code, res.LastErr)
		}
	}
}

func TestSettled(t *testing.T) {
	two := orgcontract.CILookupRequest{Commits: []orgcontract.CILookupCommit{{SHA: strings.Repeat("1", 40)}, {SHA: strings.Repeat("2", 40)}}}
	cases := []struct {
		name string
		doc  []byte
		req  orgcontract.CILookupRequest
		want bool
	}{
		{"countersigned", lookupBody(t, orgcontract.ChangeIngestCountersigned), oneCommit, true},
		{"refused is final", lookupBody(t, orgcontract.ChangeIngestReplay), oneCommit, true},
		{"pending", lookupBody(t, orgcontract.ChangeIngestCountersigned, orgcontract.ChangeIngestPending), oneCommit, false},
		{"no record", lookupBody(t), oneCommit, false},
		{"a commit not answered", lookupBody(t, orgcontract.ChangeIngestCountersigned), two, false},
		{"garbage", []byte("{"), oneCommit, false},
	}
	for _, c := range cases {
		if got := Settled(c.doc, c.req); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestPolicyWait(t *testing.T) {
	body, _ := json.Marshal(orgcontract.CIPolicy{WaitSeconds: 42})
	doc, _ := json.Marshal(orgcontract.CISignedDocument{Body: body})
	if PolicyWait(doc) != 42 || PolicyWait([]byte("x")) != -1 {
		t.Fatal("PolicyWait")
	}
}

// TestDriverPinned: a driver whose bytes are the pin is kept; any other
// bytes are refused.
func TestDriverPinned(t *testing.T) {
	payload := []byte("engine bytes")
	sum := sha256.Sum256(payload)
	pin := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != orgcontract.CIContentPath+"security.engine/opengrep" || r.URL.Query().Get("os") != "linux" || r.URL.Query().Get("arch") != "amd64" {
			http.Error(w, `{"error":"not_mirrored"}`, http.StatusNotFound)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer srv.Close()
	c, err := New(srv.URL, "ci-cred")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := c.Driver(context.Background(), "security.engine", "opengrep", "linux", "amd64", pin, &buf); err != nil || !bytes.Equal(buf.Bytes(), payload) {
		t.Fatalf("pinned driver refused: %v", err)
	}
	if _, err := c.Driver(context.Background(), "security.engine", "opengrep", "linux", "amd64", strings.Repeat("0", 64), &bytes.Buffer{}); !errors.Is(err, ErrDigest) {
		t.Fatalf("wrong pin: %v", err)
	}
	if _, err := c.Driver(context.Background(), "security.engine", "../x", "linux", "amd64", pin, &bytes.Buffer{}); !errors.Is(err, ErrRefused) {
		t.Fatalf("path in name: %v", err)
	}
	if _, err := c.Driver(context.Background(), "security.engine", "other", "linux", "amd64", pin, &bytes.Buffer{}); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("not mirrored: %v", err)
	}
}

// TestNoRedirect: a redirect is not followed, so the credential never
// reaches another host.
func TestNoRedirect(t *testing.T) {
	var hit atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer srv.Close()
	c, err := New(srv.URL, "ci-cred")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Policy(context.Background()); err == nil || hit.Load() {
		t.Fatalf("redirect followed: %v %v", err, hit.Load())
	}
}
