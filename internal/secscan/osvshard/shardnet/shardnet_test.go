package shardnet

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestAllowListIsOneHost(t *testing.T) {
	t.Parallel()
	if got := AllowedHosts(); len(got) != 1 || got[0] != "shards.superbased.app" {
		t.Fatalf("AllowedHosts = %v", got)
	}
	c := New(Options{})
	for _, u := range []string{"https://superbased.app/npm/obj/x", "http://shards.superbased.app/x", "https://example.com/x"} {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if _, err := c.http.Transport.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "allow-list") {
			t.Errorf("%s: %v", u, err)
		}
	}
}

func TestValidPath(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"npm/index/" + digest + ".json", "GitHub-Actions/obj/" + digest + ".json.gz", "Ubuntu-24.04-LTS/obj/" + digest + ".json.gz"} {
		if !validPath(ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, no := range []string{"", "npm", "npm/obj/" + digest, "npm/obj/" + strings.ToUpper(digest) + ".json.gz", "../npm/obj/" + digest + ".json.gz", "npm/other/" + digest + ".json", "npm/index/lodash.json", "npm/index/" + digest + ".json?name=lodash"} {
		if validPath(no) {
			t.Errorf("%s accepted", no)
		}
	}
}

func TestFetch(t *testing.T) {
	t.Parallel()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if ua := r.Header.Get("User-Agent"); ua != UserAgent {
			t.Errorf("User-Agent %q", ua)
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/npm/obj/"):
			_, _ = w.Write([]byte("0123456789"))
		case strings.HasPrefix(r.URL.Path, "/redir/"):
			http.Redirect(w, r, "https://example.com/", http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/busy/"):
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(Options{BaseURL: srv.URL, Backoff: time.Millisecond, Retries: 2})
	ctx := context.Background()
	b, err := c.Fetch(ctx, "npm/obj/"+digest+".json.gz", 10)
	if err != nil || string(b) != "0123456789" {
		t.Fatalf("fetch: %q %v", b, err)
	}
	if _, err := c.Fetch(ctx, "npm/obj/"+digest+".json.gz", 9); err == nil {
		t.Fatal("a body over the cap was accepted")
	}
	if _, err := c.Fetch(ctx, "redir/obj/"+digest+".json.gz", 10); err == nil {
		t.Fatal("a redirect was followed")
	}
	if _, err := c.Fetch(ctx, "npm/index/"+digest+".json", 10); err == nil {
		t.Fatal("a 404 was accepted")
	}
	before := hits.Load()
	if _, err := c.Fetch(ctx, "busy/obj/"+digest+".json.gz", 10); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("429: %v", err)
	}
	if n := hits.Load() - before; n != 3 {
		t.Fatalf("a persistent 429 was tried %d times, want 3", n)
	}
	before = hits.Load()
	if _, err := c.Fetch(ctx, "npm/obj/lodash.json.gz", 10); err == nil || hits.Load() != before {
		t.Fatal("a path naming a package was sent")
	}
	if _, err := c.Fetch(ctx, "npm/obj/"+digest+".json.gz", 0); err == nil {
		t.Fatal("a zero cap was accepted")
	}
}
