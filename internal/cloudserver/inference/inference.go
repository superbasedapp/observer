package inference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors the executors classify on. Every provider client maps its
// own failures onto these so the worker's retry and park decisions never
// depend on which provider answered.
var (
	// ErrQuota is a provider quota or rate-limit response (HTTP 429, or a
	// provider's own overloaded signal).
	ErrQuota = errors.New("inference: provider quota/rate-limit (429)")
	// ErrTimeout is a provider-call timeout or deadline.
	ErrTimeout = errors.New("inference: provider call timed out")
	// ErrPersistenceViolation means a call that must not be persisted came
	// back indicating it was (the Foundry responses_store_false dialect). A
	// hard, terminal failure.
	ErrPersistenceViolation = errors.New("inference: response indicated persistence (store:false violated)")
	// ErrUnsupportedDialect is a dialect no wired provider speaks.
	ErrUnsupportedDialect = errors.New("inference: unsupported dialect")
)

// ProviderError is a non-2xx, non-quota provider HTTP response. Body is the
// PROVIDER's error document (never session evidence); callers truncate it
// before it reaches a ledger.
type ProviderError struct {
	StatusCode int
	Body       string
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("inference: provider status %d: %s", e.StatusCode, Truncate(e.Body, 256))
}

// Request is one bounded structured-output completion. The body is built by
// the provider client from these fields only: a caller cannot add tools,
// persistence flags or sampling parameters.
type Request struct {
	// Endpoint is the provider base URL from the resolved route snapshot.
	Endpoint string
	// Deployment is the route's deployment: an Azure deployment name for the
	// Foundry dialects, the public model id (e.g. "claude-haiku-5-5") for the
	// Anthropic dialect.
	Deployment string
	// APIVersion is the provider API version from the route snapshot.
	APIVersion string
	// APIKey is the credential, passed EXPLICITLY by the caller (the worker's
	// credential-absence gate resolved it). Never read from an ambient source.
	APIKey string
	// Dialect selects the API surface (and therefore the provider).
	Dialect Dialect
	// System is the system instruction (evidence-as-data framing).
	System string
	// User is the user message (the delimited evidence).
	User string
	// SchemaName names the strict structured-output schema.
	SchemaName string
	// Schema is the JSON schema for strict structured output.
	Schema json.RawMessage
	// MaxOutputTokens caps the completion (on the Anthropic dialect it also
	// covers adaptive thinking).
	MaxOutputTokens int
	// Timeout bounds the single call; zero means the client's default.
	Timeout time.Duration
}

// Usage is the provider-reported token accounting for one call, split the way
// the pricing table prices it. Input EXCLUDES cache reads and cache writes.
type Usage struct {
	Input      int64
	Output     int64
	CacheRead  int64
	CacheWrite int64
}

// PromptTokens is every prompt-side token the provider processed (uncached,
// cache-read and cache-write), which is the figure recorded as tokens_in.
func (u Usage) PromptTokens() int64 { return u.Input + u.CacheRead + u.CacheWrite }

// Response is the parsed provider result. Content is the model's JSON text
// (the structured output the caller unmarshals into a result).
type Response struct {
	Content   string
	TokensIn  int64
	TokensOut int64
	// Usage is the per-bucket split behind TokensIn/TokensOut. A client that
	// cannot split (Foundry chat completions) leaves the cache buckets zero and
	// puts every prompt token in Input.
	Usage Usage
	// Model is the model id the provider reports having served, when it
	// reports one ("" otherwise).
	Model string
	// FinishReason is the provider's stop reason, normalized across dialects:
	// FinishLength when the answer was cut at MaxOutputTokens, FinishRefusal
	// (with an optional ":<category>" suffix) when the provider's safety
	// systems declined, otherwise the provider's value verbatim. DIAGNOSTIC
	// only: a truncated or refused answer is not valid JSON, which the caller
	// already rejects as invalid output; this lets the attempt ledger say why.
	FinishReason string
}

// FinishLength is the normalized FinishReason of an answer cut at the
// request's MaxOutputTokens.
const FinishLength = "length"

// FinishRefusal prefixes the normalized FinishReason of a provider refusal.
const FinishRefusal = "refusal"

// Truncated reports whether the answer was cut at the output-token cap.
func (r Response) Truncated() bool { return r.FinishReason == FinishLength }

// Refused reports whether the provider's safety systems declined the call.
func (r Response) Refused() bool {
	return r.FinishReason == FinishRefusal || strings.HasPrefix(r.FinishReason, FinishRefusal+":")
}

// Provider is the seam every executor calls: one bounded, non-agentic,
// non-retrying structured-output completion.
type Provider interface {
	Complete(ctx context.Context, req Request) (Response, error)
}

// Router dispatches each request to the provider wired for its dialect. A
// dialect with no wired provider fails with ErrUnsupportedDialect, so a route
// pointing at a provider this process was not configured for can never fall
// through to a different one.
type Router struct {
	providers map[Dialect]Provider
}

// NewRouter builds a router over a dialect -> provider table. Entries with an
// unknown dialect or a nil provider are ignored (fail closed: such a dialect
// stays unsupported).
func NewRouter(providers map[Dialect]Provider) *Router {
	m := make(map[Dialect]Provider, len(providers))
	for d, p := range providers {
		if p == nil {
			continue
		}
		if _, ok := SpecFor(string(d)); !ok {
			continue
		}
		m[d] = p
	}
	return &Router{providers: m}
}

// Supports reports whether a provider is wired for the dialect.
func (r *Router) Supports(d Dialect) bool {
	if r == nil {
		return false
	}
	_, ok := r.providers[d]
	return ok
}

// Complete dispatches on the request's dialect.
func (r *Router) Complete(ctx context.Context, req Request) (Response, error) {
	if r == nil {
		return Response{}, fmt.Errorf("%w: no router", ErrUnsupportedDialect)
	}
	p, ok := r.providers[req.Dialect]
	if !ok {
		return Response{}, fmt.Errorf("%w: %q", ErrUnsupportedDialect, req.Dialect)
	}
	return p.Complete(ctx, req)
}

var _ Provider = (*Router)(nil)

// Truncate bounds a diagnostic string.
func Truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// FakeProvider is a scripted Provider for executor, corpora and proving-lane
// tests. It is not safe for concurrent use (an executor makes one call at a
// time).
type FakeProvider struct {
	// Func, when set, fully controls the response.
	Func func(ctx context.Context, req Request) (Response, error)
	// Response/Err are used when Func is nil.
	Response Response
	Err      error
	// Requests records every request for assertions (e.g. evidence-as-data
	// framing, store:false forcing).
	Requests []Request
}

// Complete returns the scripted response, recording the request.
func (f *FakeProvider) Complete(ctx context.Context, req Request) (Response, error) {
	f.Requests = append(f.Requests, req)
	if f.Func != nil {
		return f.Func(ctx, req)
	}
	return f.Response, f.Err
}

var _ Provider = (*FakeProvider)(nil)
