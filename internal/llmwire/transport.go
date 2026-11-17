package llmwire

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MaxResponseBytes is the default cap on how much of a response body is read.
const MaxResponseBytes = 4 << 20

// AuthStyle selects the header that carries the credential.
type AuthStyle int

const (
	// AuthBearer sends "Authorization: Bearer <key>" (the default).
	AuthBearer AuthStyle = iota
	// AuthAPIKey sends "api-key: <key>" (Azure OpenAI).
	AuthAPIKey
)

// authRule is one row of the auth-header table.
type authRule struct {
	header string
	prefix string
}

var authRules = map[AuthStyle]authRule{
	AuthBearer: {header: "Authorization", prefix: authScheme},
	AuthAPIKey: {header: "api-key"},
}

// RetryOn is a set of failure kinds a RetryPolicy retries.
type RetryOn uint8

const (
	// RetryTransport retries a failed round trip (never a cancelled context).
	RetryTransport RetryOn = 1 << iota
	// RetryServerError retries a 5xx response.
	RetryServerError
)

// RetryPolicy bounds how often a failed call is repeated. The zero value makes
// one attempt.
type RetryPolicy struct {
	// Retries is the number of ADDITIONAL attempts after the first.
	Retries int
	// On selects which failures are retried.
	On RetryOn
	// Backoff is the pause before each retry.
	Backoff time.Duration
	// Wait pauses for d or until ctx ends; nil uses a real timer. Tests inject
	// a no-delay Wait.
	Wait func(ctx context.Context, d time.Duration) error
}

// retryRule is one row of the retry decision table: the policy retries when
// any row whose failure kind is enabled matches.
type retryRule struct {
	on    RetryOn
	match func(transportFailed bool, status int) bool
}

var retryRules = []retryRule{
	{RetryTransport, func(tf bool, _ int) bool { return tf }},
	{RetryServerError, func(tf bool, st int) bool { return !tf && st >= 500 }},
}

func (p RetryPolicy) shouldRetry(attempt int, transportFailed bool, status int) bool {
	if attempt >= p.Retries {
		return false
	}
	for _, r := range retryRules {
		if p.On&r.on != 0 && r.match(transportFailed, status) {
			return true
		}
	}
	return false
}

func (p RetryPolicy) wait(ctx context.Context) error {
	if p.Wait != nil {
		return p.Wait(ctx, p.Backoff)
	}
	t := time.NewTimer(p.Backoff)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// TransportError is a failed round trip or body read, returned in place of
// ErrTimeout or a wrapped error when WithRawErrors is set, so the caller can
// phrase it. Err is the underlying cause (net/http's *url.Error, a context
// error, ...).
type TransportError struct{ Err error }

func (e *TransportError) Error() string { return "llmwire: transport: " + e.Err.Error() }

// Unwrap exposes the cause.
func (e *TransportError) Unwrap() error { return e.Err }

// Option tunes a Client. Defaults keep the behaviour of a plain NewClient.
type Option func(*Client)

// WithRetry sets the retry policy (default: none).
func WithRetry(p RetryPolicy) Option { return func(c *Client) { c.retry = p } }

// WithMaxResponseBytes caps the response body read (default MaxResponseBytes);
// n <= 0 is ignored.
func WithMaxResponseBytes(n int64) Option {
	return func(c *Client) {
		if n > 0 {
			c.maxBytes = n
		}
	}
}

// WithHeaders adds fixed headers to every request. They are applied before
// Content-Type and the credential, which therefore win.
func WithHeaders(h map[string]string) Option {
	return func(c *Client) {
		c.headers = make(map[string]string, len(h))
		for k, v := range h {
			c.headers[k] = v
		}
	}
}

// WithAuth selects the credential header (default AuthBearer).
func WithAuth(s AuthStyle) Option { return func(c *Client) { c.auth = s } }

// WithRawErrors makes every non-2xx answer a *StatusError (no ErrQuota or
// ErrTimeout mapping) carrying the status and the full capped body, and every
// transport or read failure a *TransportError, so the caller formats its own
// error text.
func WithRawErrors() Option { return func(c *Client) { c.raw = true } }

// Client performs chat completions over a caller-supplied HTTP client. It is
// the only HTTP code in the package. Build the *http.Client with
// internal/netguard; Client never creates one.
type Client struct {
	http     *http.Client
	retry    RetryPolicy
	maxBytes int64
	headers  map[string]string
	auth     AuthStyle
	raw      bool
}

// NewClient wraps an SSRF-guarded HTTP client. A nil client is refused so a
// forgotten wiring can never fall back to http.DefaultClient.
func NewClient(h *http.Client, opts ...Option) (*Client, error) {
	if h == nil {
		return nil, errors.New("llmwire: an *http.Client from internal/netguard is required")
	}
	c := &Client{http: h, maxBytes: MaxResponseBytes}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Complete sends one request to baseURL, authenticating with apiKey (empty
// sends no header, for a keyless loopback model), and decodes the reply. See
// CompleteAt for the errors.
func (c *Client) Complete(ctx context.Context, baseURL, apiKey string, req Request) (Response, error) {
	return c.CompleteAt(ctx, Endpoint(baseURL), apiKey, req)
}

// CompleteAt is Complete against a full endpoint URL, for dialects whose URL
// is not base+ChatPath (Azure deployments). Errors are ErrQuota, ErrTimeout, a
// *StatusError, ErrDecode/ErrNoChoices, or a wrapped transport error; with
// WithRawErrors they are *StatusError and *TransportError instead. Retries
// follow the client's RetryPolicy.
func (c *Client) CompleteAt(ctx context.Context, endpoint, apiKey string, req Request) (Response, error) {
	body, err := EncodeRequest(req)
	if err != nil {
		return Response{}, err
	}
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			if werr := c.retry.wait(ctx); werr != nil {
				return Response{}, c.transportErr(werr)
			}
		}
		raw, status, terr := c.roundTrip(ctx, endpoint, apiKey, body)
		failed := terr != nil
		if failed && ctx.Err() != nil {
			return Response{}, c.transportErr(terr)
		}
		if c.retry.shouldRetry(attempt, failed, status) {
			continue
		}
		if failed {
			return Response{}, c.transportErr(terr)
		}
		if status < 200 || status >= 300 {
			if c.raw {
				return Response{}, &StatusError{StatusCode: status, Class: ClassifyStatus(status), Body: string(raw)}
			}
			return Response{}, ErrorFor(status, raw)
		}
		return DecodeResponse(raw)
	}
}

// roundTrip performs one HTTP exchange and returns the capped body.
func (c *Client) roundTrip(ctx context.Context, endpoint, apiKey string, body []byte) ([]byte, int, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("build request: %w", err)
	}
	for k, v := range c.headers {
		httpReq.Header.Set(k, v)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if k := strings.TrimSpace(apiKey); k != "" {
		rule := authRules[c.auth]
		httpReq.Header.Set(rule.header, rule.prefix+k)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return raw, resp.StatusCode, nil
}

// transportErr maps a failed exchange onto the client's error vocabulary.
func (c *Client) transportErr(err error) error {
	if c.raw {
		return &TransportError{Err: err}
	}
	if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
		return ErrTimeout
	}
	return fmt.Errorf("llmwire: transport: %w", err)
}

// authScheme prefixes the credential in the Authorization header.
const authScheme = "Bearer "

func isTimeout(err error) bool {
	var te interface{ Timeout() bool }
	return errors.As(err, &te) && te.Timeout()
}
