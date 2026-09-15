// Package providerext is the PLUGGABLE provider-adapter contract for the AI
// gateway plus its first two native-protocol instances, Bedrock and Vertex
// (Plane B dual-mode gateway design 2026-08-29 §2.5, HG6; P6). It restores the
// full R4 "any inference provider" claim by turning a provider KIND into a
// pluggable adapter row — auth shape, request-path mapping, and usage
// extraction — rather than a hardcoded switch.
//
// OWNERSHIP: this is a NEW subpackage created for the P6b lane; it does NOT edit
// any of the P4/P6a-owned files under internal/aigateway (the closed
// parserForKind map, gwhttp/dispatch.go's attachAuth/kindDefaultPath switches,
// handler.go's pre-dial refusal). It is DECOUPLED by design: it defines its own
// small contract types so it never depends on the concurrently-evolving core
// types, and it is consumed at gateway WIRING time (see the doc.go
// "Integration" note) via the existing Handler.Dialer injection seam.
//
// One STOP-AND-REPORT coupling remains and is documented, not performed: the
// core's ParserForKind refuses an unknown kind BEFORE the dialer runs
// (handler.go), so wiring bedrock/vertex end-to-end needs one P4-side change —
// ParserForKind (or the pre-dial refusal) must consult an injected external
// adapter registry. This package provides exactly the registry that change
// would consult.
package providerext

import (
	"fmt"
	"net/http"
	"strings"
)

// Native provider kinds this package adds to the gateway vocabulary. They are
// DISTINCT from the six closed openai/anthropic-family kinds in
// internal/orgserver/llmprovider (which speak the OpenAI/Anthropic wire); these
// require a native endpoint/auth/request/stream adapter.
const (
	KindBedrock = "bedrock"
	KindVertex  = "vertex"
)

// AuthKind declares HOW an adapter attaches credentials to an upstream request.
type AuthKind string

const (
	// AuthOAuthBearer attaches `Authorization: Bearer <cred>` — a GCP access
	// token for Vertex, for example.
	AuthOAuthBearer AuthKind = "oauth_bearer" //nolint:gosec // G101: auth-kind identifier, not a credential
	// AuthSigV4 signs the request with AWS Signature V4 (Bedrock). SigV4 needs
	// region/service/time, so it is delegated to an injected Signer.
	AuthSigV4 AuthKind = "sigv4"
	// AuthAPIKey attaches a provider-specific API-key header.
	AuthAPIKey AuthKind = "api_key"
)

// Usage is the adapter's normalized token extraction. It intentionally mirrors
// the core's usage shape by VALUE (four token counts) without importing the
// core package, so this contract does not couple to the P6a-owned core.
type Usage struct {
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CacheReadTokens  int64 `json:"cache_read_tokens"`
	CacheWriteTokens int64 `json:"cache_write_tokens"`
}

// Signer signs a request for an auth kind that needs more than a static header
// (AWS SigV4). It is injected at wiring time so this package takes no AWS SDK
// dependency; the gateway supplies a signer bound to the upstream's region and
// credentials.
type Signer interface {
	// Sign mutates req in place to carry a valid signature for cred.
	Sign(req *http.Request, cred string) error
}

// ProviderAdapter is one pluggable provider row: it declares its kind, its auth
// shape, how a logical request maps to the provider's URL path, and how to pull
// token usage from a response. This is the §2.5 "pluggable endpoint/auth/
// request/stream-response adapter contract".
type ProviderAdapter interface {
	// Kind is the upstream kind this adapter serves (KindBedrock, KindVertex…).
	Kind() string
	// AuthKind declares the credential-attachment shape.
	AuthKind() AuthKind
	// BuildURL maps the upstream base URL + model + stream flag to the full
	// request URL the gateway dials.
	BuildURL(baseURL, model string, stream bool) string
	// AttachAuth attaches the credential to req. For AuthSigV4, signer MUST be
	// non-nil (the gateway supplies it); for header-based kinds signer is ignored.
	AttachAuth(req *http.Request, cred string, signer Signer) error
	// ExtractUsage parses token usage from a (buffered, non-streaming) response
	// body. ok is false when the body carries no recognisable usage block.
	ExtractUsage(body []byte) (Usage, bool)
}

// Registry is the injected set of pluggable adapters the gateway consults for a
// native kind. It is what a P4-side ParserForKind change would look up.
type Registry struct {
	adapters map[string]ProviderAdapter
}

// NewRegistry builds a registry from the given adapters. A duplicate kind is an
// error (two adapters for one kind is a wiring mistake).
func NewRegistry(adapters ...ProviderAdapter) (*Registry, error) {
	r := &Registry{adapters: make(map[string]ProviderAdapter, len(adapters))}
	for _, a := range adapters {
		k := normKind(a.Kind())
		if k == "" {
			return nil, fmt.Errorf("providerext.NewRegistry: adapter with empty kind")
		}
		if _, dup := r.adapters[k]; dup {
			return nil, fmt.Errorf("providerext.NewRegistry: duplicate adapter for kind %q", k)
		}
		r.adapters[k] = a
	}
	return r, nil
}

// DefaultRegistry is the registry of the shipped native adapters (Bedrock +
// Vertex). Wiring code passes this into the gateway.
func DefaultRegistry() *Registry {
	r, _ := NewRegistry(NewBedrockAdapter(), NewVertexAdapter())
	return r
}

// Lookup returns the adapter for a kind (case/space-insensitive), or ok=false.
func (r *Registry) Lookup(kind string) (ProviderAdapter, bool) {
	if r == nil {
		return nil, false
	}
	a, ok := r.adapters[normKind(kind)]
	return a, ok
}

// Kinds returns the registered kinds (sorted-insensitive not guaranteed; small
// set). Used by drift tests and by the admin surface to list pluggable kinds.
func (r *Registry) Kinds() []string {
	if r == nil {
		return nil
	}
	out := make([]string, 0, len(r.adapters))
	for k := range r.adapters {
		out = append(out, k)
	}
	return out
}

// Has reports whether a kind is a registered pluggable adapter.
func (r *Registry) Has(kind string) bool {
	_, ok := r.Lookup(kind)
	return ok
}

func normKind(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
