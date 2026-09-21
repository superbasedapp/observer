package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// maxFeedBodyBytes bounds the response body a single fetch will read. The
// public feed is a few dozen model rows; a body larger than this is a
// misconfiguration or a hostile endpoint, and reading it unbounded would let an
// endpoint exhaust the node's memory. The org pricing rail's maxOrgDocBytes is
// the precedent; this value is generous for the envelope shape.
const maxFeedBodyBytes = 4 << 20 // 4 MiB

// defaultTimeout bounds one fetch end to end. The feed is an optional,
// opt-in convenience; a hung endpoint must never wedge the command that drives
// it.
const defaultTimeout = 30 * time.Second

// Typed transport errors. The gate and the sync ladder map each to "refuse the
// body, keep the previously applied prices": the feed is fail-open, so a
// transport failure is never fatal and never clears the cache.
var (
	// ErrBadURL — the configured feed URL is empty or not an absolute http(s)
	// URL. Caught before any network attempt.
	ErrBadURL = errors.New("pricingfeed/client: feed URL is empty or not an absolute http(s) URL")
	// ErrTransport — the request could not be completed (DNS, dial, TLS,
	// timeout, context cancel).
	ErrTransport = errors.New("pricingfeed/client: feed request failed")
	// ErrStatus — the server answered with a status that is neither 200 nor
	// 304.
	ErrStatus = errors.New("pricingfeed/client: feed server returned an unexpected status")
	// ErrDecode — the 200 body is not a decodable feed envelope (truncated,
	// not JSON, or over the size bound).
	ErrDecode = errors.New("pricingfeed/client: feed body is not a decodable envelope")
)

// Result is one fetch outcome. Exactly one of NotModified / (a decoded
// Envelope) is meaningful: on a 304 NotModified is true and Envelope is zero;
// on a 200 NotModified is false and Envelope carries the decoded body (still
// UNVERIFIED — the caller verifies).
type Result struct {
	Envelope    pricingfeed.Envelope
	NotModified bool
	// Raw is the VERBATIM 200 response body the Envelope was decoded from (nil on
	// a 304). It is threaded through the gate to store.SavePricingFeedRaw so the
	// persisted copy is the bytes that verified, not a typed re-marshal that would
	// drop a field this build does not model and freeze the node on the next
	// restart (N1 / P2-0).
	Raw []byte
}

// Fetcher performs the feed GET. It is an interface so the gate can inject a
// test double and so a caller can supply a pre-configured *http.Client (proxy,
// custom timeout). The default implementation is [New].
type Fetcher interface {
	Fetch(ctx context.Context, feedURL, lastDigest string) (Result, error)
}

// httpFetcher is the production Fetcher over a bounded *http.Client.
type httpFetcher struct {
	hc *http.Client
}

// New returns the default HTTP-backed Fetcher. A nil hc gets a client with
// defaultTimeout; pass your own to override the transport or timeout.
func New(hc *http.Client) Fetcher {
	if hc == nil {
		hc = &http.Client{Timeout: defaultTimeout}
	}
	return &httpFetcher{hc: hc}
}

// Fetch issues GET feedURL with an If-None-Match of lastDigest (when non-empty)
// and returns the decoded envelope, a not-modified signal, or a typed error.
//
// The body is read through an io.LimitReader so a hostile or misconfigured
// endpoint cannot exhaust memory. No verification happens here — the caller
// (the gate) runs pricingfeed.Verify against the compiled key set before
// trusting the result.
func (f *httpFetcher) Fetch(ctx context.Context, feedURL, lastDigest string) (Result, error) {
	u, err := url.Parse(strings.TrimSpace(feedURL))
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Result{}, fmt.Errorf("%w: %q", ErrBadURL, feedURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrTransport, err)
	}
	req.Header.Set("Accept", "application/json")
	if d := strings.TrimSpace(lastDigest); d != "" {
		// The feed's ETag IS its content digest (the body names no org/subject
		// and is cacheable), so a conditional request short-circuits to 304 when
		// the publisher has not re-signed.
		req.Header.Set("If-None-Match", etagOf(d))
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrTransport, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return Result{NotModified: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("%w: %d", ErrStatus, resp.StatusCode)
	}
	// Read the body into memory (bounded) BEFORE decoding so the exact received
	// bytes can be persisted verbatim. Verification runs over env.rawRows, which
	// UnmarshalJSON populates from these same bytes, so the bytes we keep are the
	// bytes the caller verifies (N1 / P2-0).
	raw, rerr := io.ReadAll(io.LimitReader(resp.Body, maxFeedBodyBytes))
	if rerr != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrDecode, rerr)
	}
	var env pricingfeed.Envelope
	if derr := json.Unmarshal(raw, &env); derr != nil {
		return Result{}, fmt.Errorf("%w: %w", ErrDecode, derr)
	}
	return Result{Envelope: env, Raw: raw}, nil
}

// etagOf renders a digest as a (weak-tolerant) quoted ETag value. A publisher
// that sends a bare digest and one that quotes it both round-trip: the server
// compares the digest substring, and quoting is the HTTP-correct form for the
// If-None-Match header.
func etagOf(digest string) string {
	d := strings.TrimSpace(digest)
	if strings.HasPrefix(d, `"`) || strings.HasPrefix(d, `W/`) {
		return d
	}
	return `"` + d + `"`
}
