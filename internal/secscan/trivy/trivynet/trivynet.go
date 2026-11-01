package trivynet

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"
)

// The allow-listed hosts.
const (
	ReleaseHost  = "github.com"
	AssetsHost   = "release-assets.githubusercontent.com"
	ObjectsHost  = "objects.githubusercontent.com"
	maxRedirects = 5
)

// AllowedHosts is the exact host allow-list.
func AllowedHosts() []string { return []string{ReleaseHost, AssetsHost, ObjectsHost} }

// Options tunes New. The zero value is the production client.
type Options struct {
	// Transport replaces the base transport (tests only); the scheme and
	// host checks still apply.
	Transport http.RoundTripper
	// Endpoints maps an allow-listed host to a test server's base URL
	// (tests only).
	Endpoints map[string]string
}

// Client is the lane.
type Client struct{ http *http.Client }

// ErrTooLarge is a body over its cap.
var ErrTooLarge = errors.New("trivynet: the response is over its cap")

// New returns the lane's client.
func New(o Options) *Client {
	base := o.Transport
	if base == nil {
		base = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
		}
	}
	return &Client{http: &http.Client{
		Transport: allowList{base: base, endpoints: o.Endpoints},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("trivynet: too many redirects")
			}
			if !allowed(req.URL) {
				return fmt.Errorf("trivynet: a redirect to %s://%s is refused", req.URL.Scheme, req.URL.Hostname())
			}
			return nil
		},
	}}
}

func allowed(u *url.URL) bool {
	return u.Scheme == "https" && slices.Contains(AllowedHosts(), u.Hostname()) && (u.Port() == "" || u.Port() == "443")
}

type allowList struct {
	base      http.RoundTripper
	endpoints map[string]string
}

func (a allowList) RoundTrip(r *http.Request) (*http.Response, error) {
	if !allowed(r.URL) {
		return nil, fmt.Errorf("trivynet: %s://%s is not on the allow-list", r.URL.Scheme, r.URL.Host)
	}
	if ep, ok := a.endpoints[r.URL.Hostname()]; ok {
		t, err := url.Parse(ep)
		if err != nil {
			return nil, err
		}
		r2 := r.Clone(r.Context())
		r2.URL.Scheme, r2.URL.Host = t.Scheme, t.Host
		r2.Host = t.Host
		return a.base.RoundTrip(r2)
	}
	return a.base.RoundTrip(r)
}

// Download streams the asset at raw into w, at most limit bytes, and
// returns the byte count and the hex sha256 of what it wrote. A body over
// limit, a non-200 answer or a refused host is an error; the caller
// discards whatever reached w.
func (c *Client) Download(ctx context.Context, raw string, limit int64, w io.Writer) (int64, string, error) {
	u, err := url.Parse(raw)
	if err != nil || !allowed(u) || u.Hostname() != ReleaseHost {
		return 0, "", fmt.Errorf("trivynet: %q is not a release URL on the allow-list", raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "superbased-observer")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("trivynet.Download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("trivynet.Download: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return 0, "", ErrTooLarge
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return n, "", fmt.Errorf("trivynet.Download: %w", err)
	}
	if n > limit {
		return n, "", ErrTooLarge
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}
