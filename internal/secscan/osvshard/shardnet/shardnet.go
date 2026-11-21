package shardnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvshardkey"
)

// Host is the lane's one allow-listed host.
const Host = osvdb.RemoteShardHost

// UserAgent is sent on every request: the product, nothing about the node.
const UserAgent = "superbased-observer"

// ErrRateLimited is a 429 that stayed one after the retries.
var ErrRateLimited = errors.New("shardnet: rate limited")

// Options tunes New. The zero value is the production client.
type Options struct {
	// Transport replaces the base transport (tests only); the host and
	// scheme checks still apply.
	Transport http.RoundTripper
	// BaseURL redirects the host to a test server (tests only: loopback).
	BaseURL string
	// Retries is how many times a 429 or 503 is retried (default 2).
	Retries int
	// Backoff is the first retry's wait (default 1 s, doubled each time).
	Backoff time.Duration
}

// Client is the lane.
type Client struct {
	http    *http.Client
	base    string
	retries int
	backoff time.Duration
}

// New returns the lane's client.
func New(o Options) *Client {
	base := o.Transport
	if base == nil {
		base = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          8,
			MaxIdleConnsPerHost:   8,
			IdleConnTimeout:       30 * time.Second,
		}
	}
	u := o.BaseURL
	if u == "" {
		u = "https://" + Host
	}
	retries := o.Retries
	if retries <= 0 {
		retries = 2
	}
	backoff := o.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	return &Client{
		http: &http.Client{
			Transport: allowList{base: base, test: o.BaseURL != ""},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("shardnet: redirects are refused")
			},
			Timeout: 2 * time.Minute,
		},
		base:    strings.TrimRight(u, "/"),
		retries: retries,
		backoff: backoff,
	}
}

// AllowedHosts is the exact host allow-list.
func AllowedHosts() []string { return []string{Host} }

// allowList refuses any request that is not HTTPS to the allow-listed host.
type allowList struct {
	base http.RoundTripper
	test bool
}

func (a allowList) RoundTrip(r *http.Request) (*http.Response, error) {
	host := r.URL.Hostname()
	ok := host == Host
	if a.test && (host == "127.0.0.1" || host == "localhost") {
		ok = true
	}
	if !ok || (r.URL.Scheme != "https" && !a.test) {
		return nil, fmt.Errorf("shardnet: %s://%s is not on the allow-list", r.URL.Scheme, host)
	}
	return a.base.RoundTrip(r)
}

// validPath admits exactly the two object shapes of the shard bucket
// (osvshardkey.ParseObjectPath, the one path check).
func validPath(p string) bool { return osvshardkey.ValidObjectPath(p) }

// Fetch GETs one object (osvshard.Fetcher) and refuses anything but a 200
// of at most max bytes. A 429 or 503 is retried with back-off, at most
// Options.Retries times; one that persists answers ErrRateLimited.
func (c *Client) Fetch(ctx context.Context, path string, max int64) ([]byte, error) {
	if !validPath(path) {
		return nil, fmt.Errorf("shardnet: bad object path %q", path)
	}
	if max <= 0 || max > osvshardkey.MaxShardBytes {
		return nil, fmt.Errorf("shardnet: %s: size %d out of range", path, max)
	}
	wait := c.backoff
	for attempt := 0; ; attempt++ {
		b, status, err := c.get(ctx, path, max)
		if err == nil {
			return b, nil
		}
		if (status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable) || attempt >= c.retries {
			if status == http.StatusTooManyRequests {
				return nil, fmt.Errorf("%w: %s", ErrRateLimited, path)
			}
			return nil, err
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
		wait *= 2
	}
}

func (c *Client) get(ctx context.Context, path string, max int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/"+path, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("shardnet: %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("shardnet: %s: HTTP %d", path, resp.StatusCode)
	}
	if resp.ContentLength > max {
		return nil, resp.StatusCode, fmt.Errorf("shardnet: %s: %d bytes, over %d", path, resp.ContentLength, max)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("shardnet: %s: %w", path, err)
	}
	if int64(len(b)) > max {
		return nil, resp.StatusCode, fmt.Errorf("shardnet: %s: over %d bytes", path, max)
	}
	return b, resp.StatusCode, nil
}
