package sandboxsetupnet

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
	"regexp"
	"slices"
	"time"
)

// The allow-listed hosts.
const (
	// ReleaseHost serves the release download URL a pin names.
	ReleaseHost = "github.com"
	// AssetsHost is where a release download redirects today.
	AssetsHost = "release-assets.githubusercontent.com"
	// ObjectsHost is where older release downloads redirect.
	ObjectsHost = "objects.githubusercontent.com"
)

// UserAgent names Observer on every request.
const UserAgent = "superbased-observer (sandbox setup)"

// DefaultTimeout bounds one whole transfer when Options.Timeout is zero.
const DefaultTimeout = 15 * time.Minute

const maxRedirects = 5

// Errors, matched with errors.Is.
var (
	// ErrNotAllowed is a URL or redirect outside the lane: not HTTPS, not
	// port 443, carrying user info, or to a host not in the list.
	ErrNotAllowed = errors.New("sandboxsetupnet: the URL is not on the allow-list")
	// ErrTooLarge is a body over its cap.
	ErrTooLarge = errors.New("sandboxsetupnet: the response is over its cap")
	// ErrBadLimit is a cap that is not positive.
	ErrBadLimit = errors.New("sandboxsetupnet: the size cap must be positive")
)

// AllowedHosts is the exact host allow-list.
func AllowedHosts() []string { return []string{ReleaseHost, AssetsHost, ObjectsHost} }

// Allowed reports whether raw is a URL this lane may fetch: HTTPS, port 443
// (or none), no user info, to an allow-listed host.
func Allowed(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && allowed(u)
}

func allowed(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.User == nil &&
		slices.Contains(AllowedHosts(), u.Hostname()) && (u.Port() == "" || u.Port() == "443")
}

// Options tunes New. The zero value is the production client.
type Options struct {
	// Transport replaces the base transport (tests only); the scheme, host
	// and port checks still apply to every request.
	Transport http.RoundTripper
	// Endpoints maps an allow-listed host to a test server's base URL (tests
	// only): the request still names the allow-listed host first.
	Endpoints map[string]string
	// Timeout bounds one whole transfer (0: DefaultTimeout).
	Timeout time.Duration
}

// Client is the lane.
type Client struct {
	http    *http.Client
	timeout time.Duration
}

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
			MaxIdleConns:          2,
			IdleConnTimeout:       30 * time.Second,
		}
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		timeout: timeout,
		http: &http.Client{
			// Jar nil: no cookie is stored or sent.
			Transport: allowList{base: base, endpoints: o.Endpoints},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return errors.New("sandboxsetupnet: too many redirects")
				}
				if !allowed(req.URL) {
					return fmt.Errorf("%w: a redirect to %s://%s", ErrNotAllowed, req.URL.Scheme, req.URL.Hostname())
				}
				return nil
			},
		},
	}
}

// allowList refuses any request that is not HTTPS to an allow-listed host on
// port 443, and, in tests only, sends an allow-listed host to its test
// endpoint.
type allowList struct {
	base      http.RoundTripper
	endpoints map[string]string
}

// RoundTrip implements http.RoundTripper.
func (a allowList) RoundTrip(r *http.Request) (*http.Response, error) {
	if !allowed(r.URL) {
		return nil, fmt.Errorf("%w: %s://%s", ErrNotAllowed, r.URL.Scheme, r.URL.Hostname())
	}
	r.Header.Del("Cookie")
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

// userInfo matches the user info of any URL in an error string.
var userInfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@`)

// redact strips user info (a proxy credential) from err's text.
func redact(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	r := userInfo.ReplaceAllString(s, "${1}[redacted]@")
	if r == s {
		return err
	}
	return redactedError{msg: r, err: err}
}

// redactedError keeps errors.Is working while showing only the redacted text.
type redactedError struct {
	msg string
	err error
}

func (e redactedError) Error() string { return e.msg }
func (e redactedError) Unwrap() error { return e.err }

// Download streams the asset at raw into w, at most limit bytes, and
// returns the byte count and the lowercase hex sha256 of what it wrote. A
// URL outside the lane, a non-200 answer, a body over limit or a timeout
// returns an error; the caller discards whatever reached w.
func (c *Client) Download(ctx context.Context, raw string, limit int64, w io.Writer) (int64, string, error) {
	if limit <= 0 {
		return 0, "", ErrBadLimit
	}
	u, err := url.Parse(raw)
	if err != nil || !allowed(u) {
		return 0, "", fmt.Errorf("%w: %s", ErrNotAllowed, safeURL(raw))
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return 0, "", fmt.Errorf("sandboxsetupnet.Download: %w", redact(err))
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("sandboxsetupnet.Download: %w", redact(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, "", fmt.Errorf("sandboxsetupnet.Download: HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return 0, "", fmt.Errorf("sandboxsetupnet.Download: %d bytes declared, cap %d: %w", resp.ContentLength, limit, ErrTooLarge)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return n, "", fmt.Errorf("sandboxsetupnet.Download: %w", redact(err))
	}
	if n > limit {
		return n, "", fmt.Errorf("sandboxsetupnet.Download: over the %d byte cap: %w", limit, ErrTooLarge)
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

// safeURL is raw for an error message, with any user info redacted.
func safeURL(raw string) string {
	return userInfo.ReplaceAllString(raw, "${1}[redacted]@")
}
