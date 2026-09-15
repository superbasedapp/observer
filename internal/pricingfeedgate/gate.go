package pricingfeedgate

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
	"github.com/marmutapp/superbased-observer/internal/pricingfeed/client"
)

// Options configure one gate fetch.
type Options struct {
	// URL is the feed endpoint (the resolved [pricing.feed].url). Required.
	URL string
	// LastDigest is the content digest of the feed this node last applied, sent
	// as If-None-Match so an unchanged feed short-circuits to NotModified.
	// Empty on a cold node forces a full fetch.
	LastDigest string
	// Keys is the vendor key set to verify against. Zero value means
	// pricingfeed.CompiledKeySet() — the keys this build ships. A test injects a
	// throwaway set. A key set with no keys makes every body fail closed
	// (ErrCannotVerify), never "accept anything".
	Keys pricingfeed.KeySet
	// HTTPClient overrides the transport/timeout. Nil uses the lane default.
	// Ignored when Fetcher is set.
	HTTPClient *http.Client
	// Fetcher overrides the network lane entirely (tests inject a double). Nil
	// uses the production HTTP fetcher built from HTTPClient.
	Fetcher client.Fetcher
}

// Result is one gate outcome. On a 304, NotModified is true and Envelope is
// zero. On a verified 200, NotModified is false and Envelope is the verified
// feed body ready to apply.
type Result struct {
	Envelope    pricingfeed.Envelope
	NotModified bool
}

// ErrCannotVerify is returned when the build ships no usable vendor key (empty
// compiled set, or an injected empty set). It is FAIL-CLOSED: a node that
// cannot verify must never apply a feed body, and must never treat "no key" as
// "no verification needed".
var ErrCannotVerify = fmt.Errorf("pricingfeedgate: no vendor key available to verify the feed (fail closed)")

// Fetch pulls the public feed through the isolated network lane and VERIFIES a
// 200 body before returning it. It is the ONE entry point cmd/observer reaches
// the network through.
//
// The contract, fail-open on transport and fail-closed on trust:
//
//   - transport error / unexpected status / undecodable body -> the lane's
//     typed error, unwrapped; the caller keeps its cached prices.
//   - 304 Not Modified -> Result{NotModified: true}, nil.
//   - 200 with a body that FAILS pricingfeed.Verify (unsigned, mis-signed,
//     tampered digest, unsupported schema, unknown key, malformed rows) -> that
//     verification error; the caller keeps its cached prices.
//   - 200 with a body that verifies -> Result{Envelope: <verified>}, nil.
func Fetch(ctx context.Context, opts Options) (Result, error) {
	keys := opts.Keys
	if keys.Len() == 0 {
		keys = pricingfeed.CompiledKeySet()
	}
	if keys.Len() == 0 {
		// A build with no compiled key material can verify nothing; refuse
		// rather than fetch, so an unverifiable body is never even decoded into
		// a position where a later change could forget to check it.
		return Result{}, ErrCannotVerify
	}

	fetcher := opts.Fetcher
	if fetcher == nil {
		fetcher = client.New(opts.HTTPClient)
	}
	res, err := fetcher.Fetch(ctx, opts.URL, opts.LastDigest)
	if err != nil {
		return Result{}, err
	}
	if res.NotModified {
		return Result{NotModified: true}, nil
	}
	if verr := pricingfeed.Verify(res.Envelope, keys); verr != nil {
		return Result{}, verr
	}
	return Result{Envelope: res.Envelope}, nil
}

// IsTransportError reports whether err returned by [Fetch] is a NETWORK-LANE
// transport failure (connection/status/decode/bad-URL) rather than a
// trust/verification refusal. It lives here, on the seam, so a caller can
// classify a fetch outcome WITHOUT importing the isolated network lane itself —
// which the egress pin forbids for everything but this package.
func IsTransportError(err error) bool {
	return errors.Is(err, client.ErrTransport) ||
		errors.Is(err, client.ErrStatus) ||
		errors.Is(err, client.ErrDecode) ||
		errors.Is(err, client.ErrBadURL)
}
