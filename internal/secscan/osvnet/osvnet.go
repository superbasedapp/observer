package osvnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

// The allow-listed hosts.
const (
	BucketHost = "osv-vulnerabilities.storage.googleapis.com"
	APIHost    = "api.osv.dev"
	// FeedHost serves SuperBased's signed mirror of the OSV exports (the
	// security.osv_export content kind: a base and a cumulative delta per
	// ecosystem, static feed mirroring plan sections 6 and 7).
	FeedHost = "superbased.app"
)

// Options tunes New. The zero value is the production client.
type Options struct {
	// Transport replaces the base transport (tests only); the host and
	// scheme checks still apply.
	Transport http.RoundTripper
	// BucketURL redirects the bucket host to a test server (tests only).
	BucketURL string
	// FeedURL redirects the feed host to a test server (tests only).
	FeedURL string
}

// Client is the lane.
type Client struct {
	http      *http.Client
	bucketURL string
	feedURL   string
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
			MaxIdleConns:          4,
			IdleConnTimeout:       30 * time.Second,
		}
	}
	bucket := o.BucketURL
	if bucket == "" {
		bucket = "https://" + BucketHost
	}
	feed := o.FeedURL
	if feed == "" {
		feed = "https://" + FeedHost
	}
	return &Client{
		http: &http.Client{
			Transport: allowList{base: base, test: o.BucketURL != "" || o.FeedURL != ""},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("osvnet: redirects are refused")
			},
		},
		bucketURL: strings.TrimRight(bucket, "/"),
		feedURL:   strings.TrimRight(feed, "/"),
	}
}

// AllowedHosts is the exact host allow-list.
func AllowedHosts() []string { return []string{BucketHost, APIHost, FeedHost} }

// allowList refuses any request that is not HTTPS to an allow-listed host.
type allowList struct {
	base http.RoundTripper
	test bool
}

func (a allowList) RoundTrip(r *http.Request) (*http.Response, error) {
	host := r.URL.Hostname()
	ok := false
	for _, h := range AllowedHosts() {
		if host == h {
			ok = true
		}
	}
	if a.test && (host == "127.0.0.1" || host == "localhost") {
		ok = true
	}
	if !ok || (r.URL.Scheme != "https" && !a.test) {
		return nil, fmt.Errorf("osvnet: %s://%s is not on the allow-list", r.URL.Scheme, host)
	}
	return a.base.RoundTrip(r)
}

// HTTPClient is the client handed to SCALIBR's osvdev enricher (api.osv.dev
// only, by the allow-list).
func (c *Client) HTTPClient() *http.Client { return c.http }

// validEco keeps the ecosystem one path segment once escaped: the store's
// one name rule (osvdb.ValidEcosystem), which admits the space of
// "GitHub Actions" (sent as %20, url.PathEscape) and nothing that could
// leave the segment.
func validEco(eco string) bool { return osvdb.ValidEcosystem(eco) }

func (c *Client) exportURL(eco string) (string, error) {
	if !validEco(eco) {
		return "", fmt.Errorf("osvnet: bad ecosystem %q", eco)
	}
	return c.bucketURL + "/" + url.PathEscape(eco) + "/all.zip", nil
}

func metaOf(resp *http.Response) osvdb.Meta {
	m := osvdb.Meta{LastModified: resp.Header.Get("Last-Modified"), Size: -1}
	for _, v := range resp.Header.Values("X-Goog-Hash") {
		for _, part := range strings.Split(v, ",") {
			if k, val, ok := strings.Cut(strings.TrimSpace(part), "="); ok && k == "crc32c" {
				m.CRC32C = val
			}
		}
	}
	if n, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil {
		m.Size = n
	}
	return m
}

// Head returns one export's metadata.
func (c *Client) Head(ctx context.Context, eco string) (osvdb.Meta, error) {
	u, err := c.exportURL(eco)
	if err != nil {
		return osvdb.Meta{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return osvdb.Meta{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return osvdb.Meta{}, fmt.Errorf("osvnet.Head: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return osvdb.Meta{}, fmt.Errorf("osvnet.Head: %s: HTTP %d", eco, resp.StatusCode)
	}
	return metaOf(resp), nil
}

// Get streams one export. The caller closes the body.
func (c *Client) Get(ctx context.Context, eco string) (osvdb.Meta, io.ReadCloser, error) {
	u, err := c.exportURL(eco)
	if err != nil {
		return osvdb.Meta{}, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return osvdb.Meta{}, nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return osvdb.Meta{}, nil, fmt.Errorf("osvnet.Get: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return osvdb.Meta{}, nil, fmt.Errorf("osvnet.Get: %s: HTTP %d", eco, resp.StatusCode)
	}
	return metaOf(resp), resp.Body, nil
}
