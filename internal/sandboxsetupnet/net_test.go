package sandboxsetupnet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
)

// fake serves every allow-listed host from one TLS test server; no request
// ever leaves the machine.
func fake(t *testing.T, timeout time.Duration, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	eps := map[string]string{}
	for _, host := range AllowedHosts() {
		eps[host] = srv.URL
	}
	return New(Options{Transport: srv.Client().Transport, Endpoints: eps, Timeout: timeout})
}

func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

const assetURL = "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static"

func TestDownloadFollowsRedirectsWithinTheAllowList(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 1000)
	var seen []string
	c := fake(t, 0, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Host+" ua="+r.Header.Get("User-Agent")+" cookie="+r.Header.Get("Cookie"))
		switch r.URL.Path {
		case "/cloud-hypervisor/cloud-hypervisor/releases/download/v54.0/cloud-hypervisor-static":
			http.SetCookie(w, &http.Cookie{Name: "track", Value: "1"})
			http.Redirect(w, r, "https://"+AssetsHost+"/asset", http.StatusFound)
		case "/asset":
			_, _ = w.Write(body)
		default:
			http.NotFound(w, r)
		}
	})
	var out bytes.Buffer
	n, digest, err := c.Download(context.Background(), assetURL, 1000, &out)
	if err != nil || n != 1000 || digest != sum(body) || !bytes.Equal(out.Bytes(), body) {
		t.Fatalf("Download = %d, %s, %v", n, digest, err)
	}
	if len(seen) != 2 {
		t.Fatalf("requests = %v", seen)
	}
	for _, s := range seen {
		if !strings.Contains(s, "ua="+UserAgent) || !strings.HasSuffix(s, "cookie=") {
			t.Errorf("request %q: want the Observer User-Agent and no cookie", s)
		}
	}
}

func TestDownloadRefusesURLsOutsideTheLane(t *testing.T) {
	c := fake(t, 0, func(w http.ResponseWriter, r *http.Request) { t.Errorf("request reached the server: %s", r.URL) })
	for _, raw := range []string{
		"http://github.com/a",
		"https://github.com:8443/a",
		"https://evil.example/a",
		"https://user:secret@github.com/a",
		"https://api.github.com/a",
		"ftp://github.com/a",
		"::not a url",
	} {
		t.Run(raw, func(t *testing.T) {
			_, _, err := c.Download(context.Background(), raw, 10, &bytes.Buffer{})
			if !errors.Is(err, ErrNotAllowed) {
				t.Errorf("Download(%q) = %v, want ErrNotAllowed", raw, err)
			}
			if strings.Contains(fmt.Sprint(err), "secret") {
				t.Errorf("error leaks user info: %v", err)
			}
		})
	}
	if !Allowed("https://github.com:443/a") || Allowed("https://github.com:444/a") {
		t.Error("port 443 rule")
	}
}

func TestDownloadRefusesRedirectsOutsideTheLane(t *testing.T) {
	for _, loc := range []string{
		"https://evil.example/x",
		"http://" + AssetsHost + "/x",
		"https://" + AssetsHost + ":8443/x",
	} {
		t.Run(loc, func(t *testing.T) {
			c := fake(t, 0, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/x" {
					t.Errorf("redirect target reached: %s", r.URL)
				}
				http.Redirect(w, r, loc, http.StatusFound)
			})
			if _, _, err := c.Download(context.Background(), assetURL, 10, &bytes.Buffer{}); !errors.Is(err, ErrNotAllowed) {
				t.Errorf("Download = %v, want ErrNotAllowed", err)
			}
		})
	}
}

func TestDownloadTooManyRedirects(t *testing.T) {
	c := fake(t, 0, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+ObjectsHost+"/loop", http.StatusFound)
	})
	if _, _, err := c.Download(context.Background(), assetURL, 10, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("Download = %v", err)
	}
}

func TestDownloadCaps(t *testing.T) {
	big := bytes.Repeat([]byte("y"), 101)
	t.Run("declared length over the cap", func(t *testing.T) {
		c := fake(t, 0, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(big) })
		var out bytes.Buffer
		if _, _, err := c.Download(context.Background(), assetURL, 100, &out); !errors.Is(err, ErrTooLarge) || out.Len() != 0 {
			t.Errorf("Download = %v (wrote %d)", err, out.Len())
		}
	})
	t.Run("streamed body over the cap", func(t *testing.T) {
		c := fake(t, 0, func(w http.ResponseWriter, r *http.Request) {
			w.(http.Flusher).Flush() // chunked: no declared length
			_, _ = w.Write(big)
		})
		n, _, err := c.Download(context.Background(), assetURL, 100, &bytes.Buffer{})
		if !errors.Is(err, ErrTooLarge) || n > 101 {
			t.Errorf("Download = %d, %v", n, err)
		}
	})
	t.Run("bad limit", func(t *testing.T) {
		c := fake(t, 0, func(w http.ResponseWriter, r *http.Request) { t.Error("request sent") })
		if _, _, err := c.Download(context.Background(), assetURL, 0, &bytes.Buffer{}); !errors.Is(err, ErrBadLimit) {
			t.Errorf("Download = %v", err)
		}
	})
}

func TestDownloadNon200(t *testing.T) {
	c := fake(t, 0, func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
	if _, _, err := c.Download(context.Background(), assetURL, 10, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("Download = %v", err)
	}
}

func TestDownloadTimeout(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	c := fake(t, 50*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	start := time.Now()
	_, _, err := c.Download(context.Background(), assetURL, 10, &bytes.Buffer{})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 10*time.Second {
		t.Errorf("Download = %v after %s", err, time.Since(start))
	}
}

func TestTransportRefusesDirectRequests(t *testing.T) {
	a := allowList{base: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("base transport reached for %s", r.URL)
		return nil, errors.New("unreachable")
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://evil.example/", nil)
	if _, err := a.RoundTrip(req); !errors.Is(err, ErrNotAllowed) {
		t.Errorf("RoundTrip = %v", err)
	}
}

func TestClientKeepsNoCookies(t *testing.T) {
	if New(Options{}).http.Jar != nil {
		t.Error("the lane's client has a cookie jar")
	}
}

func TestRedactHidesProxyCredentials(t *testing.T) {
	err := redact(fmt.Errorf("proxyconnect tcp: http://alice:s3cret@proxy.internal:3128: %w", context.Canceled))
	if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "alice") || !errors.Is(err, context.Canceled) {
		t.Errorf("redact = %v", err)
	}
	plain := errors.New("no credentials here")
	if redact(plain) != plain { //nolint:errorlint // identity: redact must hand back the very same error value
		t.Error("redact changed an error with no user info")
	}
}

// TestEveryGroundedPinIsOnTheLane: each compiled pin's URL is one this lane
// may fetch, so a pin can never name a host outside the allow-list.
func TestEveryGroundedPinIsOnTheLane(t *testing.T) {
	ps := sandboxsetup.Pins()
	if len(ps) == 0 {
		t.Fatal("no compiled pins")
	}
	for _, p := range ps {
		if p.URL == "" || !Allowed(p.URL) {
			t.Errorf("pin %s/%s/%s url %q is not on the lane", p.ID, p.GOOS, p.GOARCH, p.URL)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
