package trivynet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

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

// TestDownloadStaysOnTheAllowList: a redirect is followed only to an
// allow-listed https host; a body over the cap, a non-200 or a URL that is
// not a github.com release URL is refused.
func TestDownloadStaysOnTheAllowList(t *testing.T) {
	body := bytes.Repeat([]byte("t"), 1000)
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
		case "/loop":
			http.Redirect(w, r, "https://"+ReleaseHost+"/loop", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	n, digest, err := c.Download(ctx, "https://"+ReleaseHost+"/ok", 2000, &bytes.Buffer{})
	if err != nil || n != 1000 || digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("download: %d %s %v", n, digest, err)
	}
	for _, p := range []string{"/evil", "/plain", "/loop", "/missing"} {
		if _, _, err := c.Download(ctx, "https://"+ReleaseHost+p, 2000, &bytes.Buffer{}); err == nil {
			t.Errorf("%s was followed", p)
		}
	}
	if _, _, err := c.Download(ctx, "https://"+ReleaseHost+"/ok", 999, &bytes.Buffer{}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("over the cap: %v", err)
	}
	for _, raw := range []string{"http://github.com/ok", "https://" + AssetsHost + "/asset", "https://api.github.com/x", "https://github.com:8443/x"} {
		if _, _, err := c.Download(ctx, raw, 2000, &bytes.Buffer{}); err == nil {
			t.Errorf("%s was fetched", raw)
		}
	}
}
