package paddleapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/seatbilling"
)

// SandboxBaseURL is Paddle's sandbox API.
const SandboxBaseURL = "https://sandbox-api.paddle.com"

// LiveBaseURL is Paddle's live API (E1.6; wave 17 paddle-live). A client is
// only ever built for it with a live key (KeyEnvironment), and only when the
// deployment's SBCI_PADDLE_ENV is live (cmd/observer-cloud).
const LiveBaseURL = "https://api.paddle.com"

// APIVersion is the Paddle-Version header value.
const APIVersion = "1"

// maxResponse bounds a response body (bytes).
const maxResponse = 1 << 20

// The two Paddle environments a key or a base URL belongs to.
const (
	EnvSandbox = "sandbox"
	EnvLive    = "live"
)

// Doer sends one request (an *http.Client in production, a test server's
// client in tests).
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client calls Paddle's subscriptions and customer portal APIs.
type Client struct {
	base string
	key  string
	http Doer
}

// Errors.
var (
	// ErrBaseURL means the base URL is not one this package may call.
	ErrBaseURL = errors.New("paddleapi: base URL is not Paddle's sandbox or live API, or a loopback test server")
	// ErrKeyEnvironment means the key belongs to another Paddle environment
	// than the base URL (a sandbox key against the live API, a live key
	// against the sandbox, or a key with no environment prefix at all).
	ErrKeyEnvironment = errors.New("paddleapi: the API key is not a key of the base URL's Paddle environment")
	// ErrEnvironment means an environment name other than sandbox or live.
	ErrEnvironment = errors.New("paddleapi: environment must be sandbox or live")
	// ErrSubscriptionID means the id is not a Paddle subscription id.
	ErrSubscriptionID = errors.New("paddleapi: not a Paddle subscription id")
	// ErrCustomerID means the id is not a Paddle customer id.
	ErrCustomerID = errors.New("paddleapi: not a Paddle customer id")
	// ErrNoKey means the client has no API key.
	ErrNoKey = errors.New("paddleapi: no API key")
	// errNoEntity means a 2xx answer carried no data.
	errNoEntity = errors.New("no entity in the body")
)

// keyPrefixes maps a Paddle API key prefix to its environment (Paddle
// Billing keys are pdl_live_apikey_... and pdl_sdbx_apikey_...).
var keyPrefixes = []struct{ prefix, env string }{
	{"pdl_live_", EnvLive},
	{"pdl_sdbx_", EnvSandbox},
}

// KeyEnvironment returns the Paddle environment a key belongs to, by its
// prefix, or "" for a key with no known prefix. It never returns or logs the
// key.
func KeyEnvironment(key string) string {
	for _, p := range keyPrefixes {
		if strings.HasPrefix(key, p.prefix) {
			return p.env
		}
	}
	return ""
}

// BaseURLFor returns the Paddle API base URL of an environment.
func BaseURLFor(env string) (string, error) {
	switch env {
	case EnvSandbox:
		return SandboxBaseURL, nil
	case EnvLive:
		return LiveBaseURL, nil
	}
	return "", fmt.Errorf("paddleapi.BaseURLFor(%q): %w", env, ErrEnvironment)
}

// baseRule is one row of the base URL table: the first match allows. env is
// the Paddle environment a key must belong to ("" for a loopback test
// server, which takes any non-empty key).
type baseRule struct {
	name  string
	env   string
	allow func(u *url.URL) bool
}

func baseRules() []baseRule {
	return []baseRule{
		{name: "sandbox", env: EnvSandbox, allow: func(u *url.URL) bool { return u.String() == SandboxBaseURL }},
		{name: "live", env: EnvLive, allow: func(u *url.URL) bool { return u.String() == LiveBaseURL }},
		{name: "loopback test server", allow: func(u *url.URL) bool {
			h := u.Hostname()
			return (u.Scheme == "http" || u.Scheme == "https") && (h == "127.0.0.1" || h == "::1" || h == "localhost") && u.Path == ""
		}},
	}
}

// New returns a client for base with key. It refuses a base URL outside the
// table, an empty key, and a key of another environment than the base URL's.
func New(base, key string, doer Doer) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("paddleapi.New: %w", ErrBaseURL)
	}
	var rule *baseRule
	for _, r := range baseRules() {
		if r.allow(u) {
			rule = &r
			break
		}
	}
	if rule == nil {
		return nil, fmt.Errorf("paddleapi.New: %q: %w", base, ErrBaseURL)
	}
	if key == "" {
		return nil, fmt.Errorf("paddleapi.New: %w", ErrNoKey)
	}
	if rule.env != "" && KeyEnvironment(key) != rule.env {
		return nil, fmt.Errorf("paddleapi.New: %s API: %w", rule.name, ErrKeyEnvironment)
	}
	if doer == nil {
		return nil, fmt.Errorf("paddleapi.New: no HTTP client")
	}
	return &Client{base: strings.TrimRight(base, "/"), key: key, http: doer}, nil
}

// paddleID reports a Paddle entity id: prefix and 26 lower-case letters or
// digits.
func paddleID(id, prefix string) bool {
	rest, ok := strings.CutPrefix(id, prefix)
	if !ok || len(rest) != 26 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// ValidCustomerID reports a Paddle customer id: "ctm_" and 26 lower-case
// letters or digits.
func ValidCustomerID(id string) bool { return paddleID(id, "ctm_") }

// ValidSubscriptionID reports a Paddle subscription id: "sub_" and 26
// lower-case letters or digits.
func ValidSubscriptionID(id string) bool { return paddleID(id, "sub_") }

// APIError is a non-2xx answer, decoded from Paddle's error envelope.
type APIError struct {
	// HTTPStatus is the response status code.
	HTTPStatus int
	// Type, Code and Detail are Paddle's error fields.
	Type   string
	Code   string
	Detail string
	// RequestID is Paddle's request id, for support.
	RequestID string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("paddleapi: HTTP %d %s/%s: %s (request %s)", e.HTTPStatus, e.Type, e.Code, e.Detail, e.RequestID)
}

// Retryable reports a rate limit or a server-side failure.
func (e *APIError) Retryable() bool {
	return e.HTTPStatus == http.StatusTooManyRequests || e.HTTPStatus >= 500
}

// wireSubscription is the part of Paddle's subscription entity read here.
type wireSubscription struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	BillingCycle struct {
		Interval  string `json:"interval"`
		Frequency int    `json:"frequency"`
	} `json:"billing_cycle"`
	CurrentBillingPeriod *struct {
		StartsAt string `json:"starts_at"`
		EndsAt   string `json:"ends_at"`
	} `json:"current_billing_period"`
	Items []struct {
		Status   string `json:"status"`
		Quantity int64  `json:"quantity"`
		Price    struct {
			ID string `json:"id"`
		} `json:"price"`
	} `json:"items"`
}

// envelope is Paddle's response envelope: data (the entity) or error, and
// the request id.
type envelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Type   string `json:"type"`
		Code   string `json:"code"`
		Detail string `json:"detail"`
	} `json:"error"`
	Meta struct {
		RequestID string `json:"request_id"`
	} `json:"meta"`
}

func (w wireSubscription) subscription() seatbilling.Subscription {
	s := seatbilling.Subscription{ID: w.ID, Status: w.Status, Interval: w.BillingCycle.Interval}
	if w.BillingCycle.Frequency != 1 && w.BillingCycle.Interval == "month" {
		// A multi-month cycle is not the monthly-in-arrears plan.
		s.Interval = fmt.Sprintf("%d %s", w.BillingCycle.Frequency, w.BillingCycle.Interval)
	}
	if p := w.CurrentBillingPeriod; p != nil {
		s.PeriodStart, s.PeriodEnd = p.StartsAt, p.EndsAt
	}
	for _, it := range w.Items {
		s.Items = append(s.Items, seatbilling.Item{PriceID: it.Price.ID, Quantity: it.Quantity})
	}
	return s
}

// call sends one request to path (already validated by the caller) and
// returns the envelope's data. A non-2xx answer is an *APIError. The key
// goes only into the Authorization header.
func (c *Client) call(ctx context.Context, method, path string, body []byte) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, fmt.Errorf("paddleapi: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Paddle-Version", APIVersion)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("paddleapi: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("paddleapi: read response: %w", err)
	}
	if len(raw) > maxResponse {
		return nil, fmt.Errorf("paddleapi: response over %d bytes", maxResponse)
	}
	var env envelope
	decodeErr := json.Unmarshal(raw, &env)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{HTTPStatus: resp.StatusCode, RequestID: env.Meta.RequestID}
		if decodeErr == nil && env.Error != nil {
			ae.Type, ae.Code, ae.Detail = env.Error.Type, env.Error.Code, env.Error.Detail
		}
		return nil, ae
	}
	if decodeErr != nil || len(env.Data) == 0 || string(env.Data) == "null" {
		return nil, fmt.Errorf("paddleapi: HTTP %d: %w", resp.StatusCode, errNoEntity)
	}
	return env.Data, nil
}

// do sends one subscription request: method on /subscriptions/{id} plus
// suffix ("" or "/cancel") and returns the subscription Paddle answers.
func (c *Client) do(ctx context.Context, method, id, suffix string, body []byte) (seatbilling.Subscription, error) {
	if !ValidSubscriptionID(id) {
		return seatbilling.Subscription{}, fmt.Errorf("paddleapi: %w", ErrSubscriptionID)
	}
	data, err := c.call(ctx, method, "/subscriptions/"+id+suffix, body)
	if err != nil {
		if errors.Is(err, errNoEntity) {
			return seatbilling.Subscription{}, fmt.Errorf("paddleapi: no subscription in the body: %w", err)
		}
		return seatbilling.Subscription{}, err
	}
	var w wireSubscription
	if err := json.Unmarshal(data, &w); err != nil {
		return seatbilling.Subscription{}, fmt.Errorf("paddleapi: decode subscription: %w", err)
	}
	if w.ID != id {
		return seatbilling.Subscription{}, fmt.Errorf("paddleapi: asked for %s, answered %s", id, w.ID)
	}
	return w.subscription(), nil
}

// GetSubscription reads one subscription (seatbilling.API).
func (c *Client) GetSubscription(ctx context.Context, id string) (seatbilling.Subscription, error) {
	return c.do(ctx, http.MethodGet, id, "", nil)
}

// UpdateSubscriptionItems sends the item update (seatbilling.API).
func (c *Client) UpdateSubscriptionItems(ctx context.Context, id string, req seatbilling.UpdateRequest) (seatbilling.Subscription, error) {
	body, err := req.Encode()
	if err != nil {
		return seatbilling.Subscription{}, fmt.Errorf("paddleapi: %w", err)
	}
	return c.do(ctx, http.MethodPatch, id, "", body)
}

// cancelNowBody is the cancel request: effective immediately, so the
// subscription stops at once instead of renewing to the period's end (an
// org deletion has already waited out its cooling-off window).
var cancelNowBody = []byte(`{"effective_from":"immediately"}`)

// StatusCanceled is the status of a canceled subscription.
const StatusCanceled = "canceled"

// CancelSubscription cancels the subscription now (POST
// /subscriptions/{id}/cancel with effective_from "immediately"; plan 07
// M6.9, the org deletion's cancel_billing step) and returns Paddle's answer.
// Paddle refuses to cancel a subscription that is already canceled; the
// caller reads the subscription to tell that apart (the deletion's billing
// seam reads it before and after). It needs an API key with the
// subscription write permission.
func (c *Client) CancelSubscription(ctx context.Context, id string) (seatbilling.Subscription, error) {
	return c.do(ctx, http.MethodPost, id, "/cancel", cancelNowBody)
}

// PortalSession is a Paddle customer portal session: the authenticated
// links Paddle mints for one customer (POST /customers/{id}/portal-sessions).
// Every link is checked to be an https link on paddle.com before it is
// returned. The links are short-lived and carry a token; they are handed to
// the signed-in browser and never stored or logged.
type PortalSession struct {
	// Overview is the portal's home: subscriptions, payment methods and the
	// invoices Paddle issued (Paddle is the merchant of record).
	Overview string
	// Subscriptions are the deep links for the subscriptions asked for.
	Subscriptions []PortalSubscriptionLinks
}

// PortalSubscriptionLinks are one subscription's deep links.
type PortalSubscriptionLinks struct {
	ID                  string
	Cancel              string
	UpdatePaymentMethod string
}

type wirePortalSession struct {
	CustomerID string `json:"customer_id"`
	URLs       struct {
		General struct {
			Overview string `json:"overview"`
		} `json:"general"`
		Subscriptions []struct {
			ID                              string `json:"id"`
			CancelSubscription              string `json:"cancel_subscription"`
			UpdateSubscriptionPaymentMethod string `json:"update_subscription_payment_method"`
		} `json:"subscriptions"`
	} `json:"urls"`
}

// portalLinkOK reports an https link on paddle.com or a subdomain of it
// (customer-portal.paddle.com, sandbox-customer-portal.paddle.com).
func portalLinkOK(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "paddle.com" || strings.HasSuffix(h, ".paddle.com")
}

// CreatePortalSession mints a customer portal session for customerID,
// with deep links for subscriptionIDs (each must be the customer's; Paddle
// refuses otherwise). It needs an API key with the customer portal session
// write permission.
func (c *Client) CreatePortalSession(ctx context.Context, customerID string, subscriptionIDs []string) (PortalSession, error) {
	if !ValidCustomerID(customerID) {
		return PortalSession{}, fmt.Errorf("paddleapi: %w", ErrCustomerID)
	}
	ids := make([]string, 0, len(subscriptionIDs))
	for _, id := range subscriptionIDs {
		if !ValidSubscriptionID(id) {
			return PortalSession{}, fmt.Errorf("paddleapi: %w", ErrSubscriptionID)
		}
		ids = append(ids, id)
	}
	body, err := json.Marshal(map[string][]string{"subscription_ids": ids})
	if err != nil {
		return PortalSession{}, fmt.Errorf("paddleapi: encode portal session: %w", err)
	}
	data, err := c.call(ctx, http.MethodPost, "/customers/"+customerID+"/portal-sessions", body)
	if err != nil {
		return PortalSession{}, err
	}
	var w wirePortalSession
	if err := json.Unmarshal(data, &w); err != nil {
		return PortalSession{}, fmt.Errorf("paddleapi: decode portal session: %w", err)
	}
	if w.CustomerID != customerID {
		return PortalSession{}, fmt.Errorf("paddleapi: asked for a session of %s, answered %s", customerID, w.CustomerID)
	}
	if !portalLinkOK(w.URLs.General.Overview) {
		return PortalSession{}, errors.New("paddleapi: the portal session's overview link is not an https paddle.com link")
	}
	out := PortalSession{Overview: w.URLs.General.Overview}
	for _, s := range w.URLs.Subscriptions {
		l := PortalSubscriptionLinks{ID: s.ID}
		if portalLinkOK(s.CancelSubscription) {
			l.Cancel = s.CancelSubscription
		}
		if portalLinkOK(s.UpdateSubscriptionPaymentMethod) {
			l.UpdatePaymentMethod = s.UpdateSubscriptionPaymentMethod
		}
		out.Subscriptions = append(out.Subscriptions, l)
	}
	return out, nil
}
