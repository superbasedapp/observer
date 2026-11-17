package hostapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// HTTP methods, spelled here so the pure core does not import net/http.
const (
	methodGet  = "GET"
	methodPost = "POST"
	methodPut  = "PUT"
)

// Request is one host-API request before signing: the route from
// platformcontract, the raw query (empty for every outbox verb) and the body.
type Request struct {
	// Method is the HTTP method.
	Method string
	// Path is the escaped path below the host's origin (platformcontract.BasePath...).
	Path string
	// RawQuery is the query without the "?".
	RawQuery string
	// Body is the JSON body (empty for GET).
	Body []byte
}

// Queued is an outbox row as the dispatcher claimed it.
type Queued struct {
	// OrgID is the org (and tenant) id.
	OrgID string
	// Verb is the queued verb.
	Verb Verb
	// IdempotencyKey is the row key.
	IdempotencyKey string
	// LifecycleGen is the row's generation.
	LifecycleGen int64
	// Payload is the row's payload JSON.
	Payload []byte
}

// CreateExtras is what a create_tenant request needs beyond its payload, read
// at send time by an injected resolver: the owner identity (through the
// worker's narrow definer lookups, W14-D2), the first signed entitlement
// document (the document signer's output), and the org's current slug and
// kind (a pooled host routes by slug and refuses a create without one).
type CreateExtras struct {
	// OwnerSub is the owner's WorkOS subject; the host binds the owner by it.
	OwnerSub string
	// OwnerEmail is the owner's address, a display hint only.
	OwnerEmail string
	// OwnerEmailVerified is true only when the control plane vouches for
	// OwnerEmail. W14-D2 sends it false (L-31 is unruled).
	OwnerEmailVerified bool
	// Entitlements is the first signed entitlement document.
	Entitlements pc.EntitlementDocument
	// Slug is the org's current slug ("" omits it from the request).
	Slug string
	// Kind is the org's kind ("" omits it: the host reads team).
	Kind pc.OrgKind
}

// Observed is what a verified success body says about the tenant.
type Observed struct {
	// HasState is true when the answer reported a state and generation.
	HasState bool
	// State is the tenant state now in force on the host.
	State pc.TenantState
	// LifecycleGen is the generation now in force on the host.
	LifecycleGen int64
}

// verdict is a verb's reading of a verified success body.
type verdict struct {
	observed     Observed
	createFailed bool
}

// errBadResponse means a verified success body is not the verb's answer.
var errBadResponse = errors.New("hostapi: response is not the verb's answer")

// verbSpec is one row of the outbox verb table.
type verbSpec struct {
	verb   Verb
	method string
	// needsExtras is true when building the request needs CreateExtras.
	needsExtras bool
	// build turns the queued row into the contract request value and its
	// path. Any error is a bad intent: the row can never become a request.
	build func(q Queued, x CreateExtras) (path string, body any, err error)
	// judge reads a verified success body.
	judge func(q Queued, body []byte) (verdict, error)
}

// verbTable is the outbox verb table, one row per mutating platformcontract
// verb, walked top-down by verb. Export, enrolment tokens and role grants have
// no row and must never get one (platformcontract "Scope").
var verbTable = []verbSpec{
	{
		verb: VerbCreateTenant, method: methodPost, needsExtras: true,
		build: func(q Queued, x CreateExtras) (string, any, error) {
			var p CreatePayload
			if err := decodePayload(q, &p, func() string { return p.TenantID }); err != nil {
				return "", nil, err
			}
			if x.Kind != "" && !x.Kind.Valid() {
				return "", nil, errors.New("create extras: unknown org kind")
			}
			r := pc.CreateTenantRequest{
				IdempotencyKey: q.IdempotencyKey, TenantID: p.TenantID, Name: p.Name,
				OwnerSub: x.OwnerSub, OwnerEmail: x.OwnerEmail, OwnerEmailVerified: x.OwnerEmailVerified,
				Entitlements: x.Entitlements, Slug: x.Slug, Kind: x.Kind,
			}
			return pc.PathTenants, r, r.Validate()
		},
		judge: func(q Queued, body []byte) (verdict, error) {
			var r pc.CreateTenantResponse
			if err := json.Unmarshal(body, &r); err != nil || r.TenantID != q.OrgID || !r.Outcome.Valid() || !r.State.Valid() {
				return verdict{}, errBadResponse
			}
			return verdict{
				observed:     Observed{HasState: true, State: r.State, LifecycleGen: r.LifecycleGen},
				createFailed: r.Outcome == pc.CreateFailed,
			}, nil
		},
	},
	{
		verb: VerbSetState, method: methodPut,
		build: func(q Queued, _ CreateExtras) (string, any, error) {
			var p StatePayload
			if err := decodePayload(q, &p, func() string { return p.TenantID }); err != nil {
				return "", nil, err
			}
			r := pc.SetStateRequest{TenantID: p.TenantID, State: p.State, LifecycleGen: q.LifecycleGen}
			return pc.PathTenantState(p.TenantID), r, r.Validate()
		},
		judge: func(_ Queued, body []byte) (verdict, error) {
			var r pc.SetStateResponse
			if err := json.Unmarshal(body, &r); err != nil || !r.State.Valid() || r.LifecycleGen < 0 {
				return verdict{}, errBadResponse
			}
			// Applied=false is success: the host already holds a newer
			// generation (design 4.6, "State intents").
			return verdict{observed: Observed{HasState: true, State: r.State, LifecycleGen: r.LifecycleGen}}, nil
		},
	},
	{
		verb: VerbSetEntitlements, method: methodPut,
		build: func(q Queued, _ CreateExtras) (string, any, error) {
			var p EntitlementsPayload
			if err := decodePayload(q, &p, func() string { return p.TenantID }); err != nil {
				return "", nil, err
			}
			r := pc.SetEntitlementsRequest{TenantID: p.TenantID, Document: p.Document}
			return pc.PathTenantEntitlements(p.TenantID), r, r.Validate()
		},
		judge: func(_ Queued, body []byte) (verdict, error) {
			var r pc.SetEntitlementsResponse
			if err := json.Unmarshal(body, &r); err != nil || r.Version < 0 {
				return verdict{}, errBadResponse
			}
			return verdict{}, nil
		},
	},
	{
		verb: VerbMembersDeactivate, method: methodPost,
		build: func(q Queued, _ CreateExtras) (string, any, error) {
			var p DeactivatePayload
			if err := decodePayload(q, &p, func() string { return p.TenantID }); err != nil {
				return "", nil, err
			}
			r := pc.DeactivateMemberRequest{TenantID: p.TenantID, Sub: p.Sub, IdempotencyKey: q.IdempotencyKey}
			return pc.PathTenantMembersDeactivate(p.TenantID), r, r.Validate()
		},
		judge: func(_ Queued, body []byte) (verdict, error) {
			var r pc.DeactivateMemberResponse
			if err := json.Unmarshal(body, &r); err != nil {
				return verdict{}, errBadResponse
			}
			return verdict{}, nil
		},
	},
	{
		verb: VerbEvict, method: methodPost,
		build: func(q Queued, _ CreateExtras) (string, any, error) {
			var p EvictPayload
			if err := decodePayload(q, &p, func() string { return p.TenantID }); err != nil {
				return "", nil, err
			}
			r := pc.EvictRequest{TenantID: p.TenantID, LifecycleGen: q.LifecycleGen}
			return pc.PathTenantEvict(p.TenantID), r, r.Validate()
		},
		judge: func(_ Queued, body []byte) (verdict, error) {
			var r pc.EvictResponse
			if err := json.Unmarshal(body, &r); err != nil {
				return verdict{}, errBadResponse
			}
			return verdict{}, nil
		},
	},
}

// specFor returns the verb table row for v.
func specFor(v Verb) (*verbSpec, bool) {
	for i := range verbTable {
		if verbTable[i].verb == v {
			return &verbTable[i], true
		}
	}
	return nil, false
}

// NeedsCreateExtras reports whether building v's request needs CreateExtras.
func NeedsCreateExtras(v Verb) bool {
	s, ok := specFor(v)
	return ok && s.needsExtras
}

// Build turns a queued row into its contract request. Every error wraps
// ErrBadIntent: the row cannot become a valid request, so it is parked, never
// sent.
func Build(q Queued, x CreateExtras) (Request, error) {
	s, ok := specFor(q.Verb)
	if !ok {
		return Request{}, fmt.Errorf("hostapi.Build: unknown verb %q: %w", q.Verb, ErrBadIntent)
	}
	if !validPathID(q.OrgID) || needAll(q.IdempotencyKey) != nil {
		return Request{}, fmt.Errorf("hostapi.Build: %w", ErrBadIntent)
	}
	path, v, err := s.build(q, x)
	if err != nil {
		return Request{}, fmt.Errorf("hostapi.Build: %s: %w: %w", q.Verb, ErrBadIntent, err)
	}
	body, err := json.Marshal(v)
	if err != nil {
		return Request{}, fmt.Errorf("hostapi.Build: %s: %w: %w", q.Verb, ErrBadIntent, err)
	}
	return Request{Method: s.method, Path: path, Body: body}, nil
}

// decodePayload unmarshals the row payload into p and requires its tenant id
// to be the row's org id.
func decodePayload(q Queued, p any, tenant func() string) error {
	if err := json.Unmarshal(q.Payload, p); err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	if tenant() != q.OrgID {
		return errors.New("payload tenant_id is not the row's org")
	}
	return nil
}

// validPathID reports whether id is safe as one path segment: non-empty and
// made of ASCII letters, digits, '-', '_' and '.' only (org ids are UUIDs).
func validPathID(id string) bool {
	if id == "" || id == "." || id == ".." {
		return false
	}
	for _, c := range []byte(id) {
		ok := c == '-' || c == '_' || c == '.' ||
			(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		if !ok {
			return false
		}
	}
	return true
}

// splitBody reads a verified body: a refusal (a JSON object carrying "code")
// or a success (any other JSON object). A body that is not a JSON object is
// errBadResponse. No success type of the contract has a "code" field.
func splitBody(body []byte) (*pc.ErrorResponse, error) {
	if t := bytes.TrimSpace(body); len(t) == 0 || t[0] != '{' {
		return nil, errBadResponse
	}
	var probe struct {
		Code json.RawMessage `json:"code"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, errBadResponse
	}
	if len(probe.Code) == 0 {
		return nil, nil
	}
	var r pc.ErrorResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, errBadResponse
	}
	return &r, nil
}

// RouteCheckProbe is the route-check request the reconciler sends for
// tenantID.
func RouteCheckProbe(tenantID string) (Request, error) {
	r := pc.RouteCheckRequest{TenantID: tenantID}
	if !validPathID(tenantID) || r.Validate() != nil {
		return Request{}, fmt.Errorf("hostapi.RouteCheckProbe: %w", ErrBadIntent)
	}
	body, err := json.Marshal(r)
	if err != nil {
		return Request{}, fmt.Errorf("hostapi.RouteCheckProbe: %w", err)
	}
	return Request{Method: methodPost, Path: pc.PathRouteCheck, Body: body}, nil
}

// HealthProbe is the health request the reconciler sends for tenantID.
func HealthProbe(tenantID string) (Request, error) {
	if !validPathID(tenantID) {
		return Request{}, fmt.Errorf("hostapi.HealthProbe: %w", ErrBadIntent)
	}
	return Request{Method: methodGet, Path: pc.PathTenantHealth(tenantID)}, nil
}

// ReadRouteCheck returns the route-check answer when a is a verified success
// whose body is a well-formed answer; ok is false otherwise (never trusted).
func ReadRouteCheck(a Answer) (pc.RouteCheckResponse, bool) {
	if a.Kind != AnswerVerified {
		return pc.RouteCheckResponse{}, false
	}
	if ref, err := splitBody(a.Body); err != nil || ref != nil {
		return pc.RouteCheckResponse{}, false
	}
	var r pc.RouteCheckResponse
	if err := json.Unmarshal(a.Body, &r); err != nil || r.LifecycleGen < 0 {
		return pc.RouteCheckResponse{}, false
	}
	if r.Served && !r.State.Valid() {
		return pc.RouteCheckResponse{}, false
	}
	return r, true
}

// ReadHealth returns the health answer for tenantID when a is a verified
// success whose body validates and names tenantID; ok is false otherwise.
func ReadHealth(a Answer, tenantID string) (pc.HealthResponse, bool) {
	if a.Kind != AnswerVerified {
		return pc.HealthResponse{}, false
	}
	if ref, err := splitBody(a.Body); err != nil || ref != nil {
		return pc.HealthResponse{}, false
	}
	var r pc.HealthResponse
	if err := json.Unmarshal(a.Body, &r); err != nil || r.TenantID != tenantID || r.Validate() != nil {
		return pc.HealthResponse{}, false
	}
	return r, true
}
