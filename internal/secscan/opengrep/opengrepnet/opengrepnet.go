package opengrepnet

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
	"strings"
	"time"
)

// The allow-listed hosts.
const (
	ReleaseHost  = "github.com"
	AssetsHost   = "release-assets.githubusercontent.com"
	ObjectsHost  = "objects.githubusercontent.com"
	FeedHost     = "superbased.app"
	maxRedirects = 5
	// MaxFeedBytes caps one feed file (a rule pack bundle is far smaller).
	MaxFeedBytes = 16 << 20
)

// FeedKinds are the only content kinds this lane fetches.
var FeedKinds = []string{"security.rule_pack", "security.engine"}

// AllowedHosts is the exact host allow-list.
func AllowedHosts() []string { return []string{ReleaseHost, AssetsHost, ObjectsHost, FeedHost} }

// Options tunes New. The zero value is the production client.
type Options struct {
	// Transport replaces the base transport (tests only); the scheme and
	// host checks still apply.
	Transport http.RoundTripper
	// Endpoints maps an allow-listed host to a test server's base URL
	// (tests only): the request still names the allow-listed host first.
	Endpoints map[string]string
}

// Client is the lane.
type Client struct {
	http      *http.Client
	endpoints map[string]string
}

// ErrNotPublished is a 404 or 410 from the feed.
var ErrNotPublished = errors.New("opengrepnet: the feed file is not published")

// ErrTooLarge is a body over its cap.
var ErrTooLarge = errors.New("opengrepnet: the response is over its cap")

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
	c := &Client{endpoints: o.Endpoints}
	c.http = &http.Client{
		Transport: allowList{base: base, endpoints: o.Endpoints},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("opengrepnet: too many redirects")
			}
			if !allowed(req.URL) {
				return fmt.Errorf("opengrepnet: a redirect to %s://%s is refused", req.URL.Scheme, req.URL.Hostname())
			}
			return nil
		},
	}
	return c
}

// allowed reports whether u is HTTPS to an allow-listed host.
func allowed(u *url.URL) bool {
	return u.Scheme == "https" && slices.Contains(AllowedHosts(), u.Hostname()) && (u.Port() == "" || u.Port() == "443")
}

// allowList refuses any request that is not HTTPS to an allow-listed host,
// and, in tests only, sends an allow-listed host to its test endpoint.
type allowList struct {
	base      http.RoundTripper
	endpoints map[string]string
}

func (a allowList) RoundTrip(r *http.Request) (*http.Response, error) {
	if !allowed(r.URL) {
		return nil, fmt.Errorf("opengrepnet: %s://%s is not on the allow-list", r.URL.Scheme, r.URL.Host)
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
// limit, a non-200 answer or a refused host writes an error; the caller
// discards whatever reached w.
func (c *Client) Download(ctx context.Context, raw string, limit int64, w io.Writer) (int64, string, error) {
	u, err := url.Parse(raw)
	if err != nil || !allowed(u) || u.Hostname() == FeedHost {
		return 0, "", fmt.Errorf("opengrepnet: %q is not a release URL on the allow-list", raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", "superbased-observer")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("opengrepnet.Download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("opengrepnet.Download: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return 0, "", ErrTooLarge
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return n, "", fmt.Errorf("opengrepnet.Download: %w", err)
	}
	if n > limit {
		return n, "", ErrTooLarge
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// FeedURL is the vendor content feed's URL for a kind's file (the layout
// the install gate's feed uses).
func FeedURL(kind, file string) string {
	return "https://" + FeedHost + "/api/security/v1/content/" + url.PathEscape(kind) + "/" + url.PathEscape(file)
}

// FetchFeedFile downloads one file of a code-rules content kind from the
// vendor feed, capped at limit (0: MaxFeedBytes).
func (c *Client) FetchFeedFile(ctx context.Context, kind, file string, limit int64) ([]byte, error) {
	if !slices.Contains(FeedKinds, kind) {
		return nil, fmt.Errorf("opengrepnet: %q is not a code rules kind", kind)
	}
	if file == "" || strings.ContainsAny(file, "/\\") || file == "." || file == ".." {
		return nil, fmt.Errorf("opengrepnet: bad feed file %q", file)
	}
	if limit <= 0 || limit > MaxFeedBytes {
		limit = MaxFeedBytes
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, FeedURL(kind, file), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "superbased-observer")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("opengrepnet.FetchFeedFile: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		return nil, fmt.Errorf("opengrepnet: %s/%s: %w", kind, file, ErrNotPublished)
	default:
		return nil, fmt.Errorf("opengrepnet: %s/%s: HTTP %d", kind, file, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("opengrepnet.FetchFeedFile: %w", err)
	}
	if int64(len(b)) > limit {
		return nil, ErrTooLarge
	}
	return b, nil
}
