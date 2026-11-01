package opengrepnet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fake serves every allow-listed host from one TLS test server.
func fake(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	eps := map[string]string{}
	for _, host := range AllowedHosts() {
		eps[host] = srv.URL
	}
	return New(Options{Transport: srv.Client().Transport, Endpoints: eps})
}

func TestDownloadFollowsRedirectsOnlyWithinTheAllowList(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 1000)
	sum := sha256.Sum256(body)
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			http.Redirect(w, r, "https://"+AssetsHost+"/asset", http.StatusFound)
		case "/asset":
			_, _ = w.Write(body)
		case "/evil":
			http.Redirect(w, r, "https://evil.example/asset", http.StatusFound)
		case "/plain":
			http.Redirect(w, r, "http://"+AssetsHost+"/asset", http.StatusFound)
		case "/feedhost":
			http.Redirect(w, r, "https://"+FeedHost+"/asset", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "https://"+ReleaseHost+"/loop", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	var buf bytes.Buffer
	n, digest, err := c.Download(ctx, "https://"+ReleaseHost+"/ok", 2000, &buf)
	if err != nil || n != 1000 || digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("download: %d %s %v", n, digest, err)
	}
	for _, path := range []string{"/evil", "/plain", "/loop", "/missing"} {
		if _, _, err := c.Download(ctx, "https://"+ReleaseHost+path, 2000, &bytes.Buffer{}); err == nil {
			t.Errorf("%s was followed", path)
		}
	}
	if _, _, err := c.Download(ctx, "https://"+ReleaseHost+"/ok", 999, &bytes.Buffer{}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over the cap: %v", err)
	}
	for _, raw := range []string{"https://evil.example/x", "http://github.com/x", "https://github.com:8443/x", "https://" + FeedHost + "/x"} {
		if _, _, err := c.Download(ctx, raw, 2000, &bytes.Buffer{}); err == nil {
			t.Errorf("%s was fetched", raw)
		}
	}
}

func TestFetchFeedFileKindsAndCaps(t *testing.T) {
	c := fake(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/security.rule_pack/manifest.json"):
			_, _ = w.Write([]byte("{}"))
		case strings.HasSuffix(r.URL.Path, "/big"):
			_, _ = w.Write(bytes.Repeat([]byte("y"), 100))
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	if b, err := c.FetchFeedFile(ctx, "security.rule_pack", "manifest.json", 0); err != nil || string(b) != "{}" {
		t.Fatalf("feed: %q %v", b, err)
	}
	if _, err := c.FetchFeedFile(ctx, "security.engine", "manifest.json", 0); !errors.Is(err, ErrNotPublished) {
		t.Errorf("not published: %v", err)
	}
	if _, err := c.FetchFeedFile(ctx, "security.rule_pack", "big", 10); !errors.Is(err, ErrTooLarge) {
		t.Errorf("cap: %v", err)
	}
	for _, kind := range []string{"security.malicious_packages", "security.osv_export", ""} {
		if _, err := c.FetchFeedFile(ctx, kind, "manifest.json", 0); err == nil {
			t.Errorf("kind %q fetched", kind)
		}
	}
	for _, file := range []string{"../x", "a/b", "", ".."} {
		if _, err := c.FetchFeedFile(ctx, "security.rule_pack", file, 0); err == nil {
			t.Errorf("file %q fetched", file)
		}
	}
}
