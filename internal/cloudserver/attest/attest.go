// Package attest implements the ContentLogging route-policy canary (plan §2.2):
// the attested, bound, re-checked capability read that authorizes a Foundry
// route for real-evidence inference. The mechanism is the Azure Resource
// Manager REST API (the Microsoft.CognitiveServices/accounts resource read) —
// the service NEVER shells out to `az`; the CLI is grounding evidence only. A
// managed-identity token source is the sole credential, holding only the reader
// action for that resource.
//
// The healthy verdict is narrow: the capability value must be present, a JSON
// boolean, and exactly `false` (ContentLogging disabled). Absent, duplicate-
// collapsed, malformed, non-boolean, or `true` values are ALL unhealthy, and so
// is any control-plane outage — the canary fails closed in every ambiguous
// state (plan §2.2).
package attest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Binding is the resolved resource an attestation is keyed to (plan §2.2). An
// attestation authorizes ONLY the route whose resolved resource matches ALL of
// these identifiers AND the route generation; any change invalidates it.
type Binding struct {
	TenantID         string
	SubscriptionID   string
	ARMResourceID    string
	EndpointAudience string
	RouteGeneration  int64
}

// Complete reports whether every binding identifier needed for an ARM read is
// present. An incomplete binding (the fail-closed default before an operator
// provisions the resource post-approval) is never healthy.
func (b Binding) Complete() bool {
	return strings.TrimSpace(b.TenantID) != "" &&
		strings.TrimSpace(b.SubscriptionID) != "" &&
		strings.TrimSpace(b.ARMResourceID) != "" &&
		strings.TrimSpace(b.EndpointAudience) != ""
}

// Attestation is the result of one canary read (plan §2.2). It records the
// binding it was taken against, the raw capability value, the verdict, and the
// fetched-at freshness stamp.
type Attestation struct {
	Binding
	ContentLoggingValue string
	Healthy             bool
	Reason              string
	FetchedAt           time.Time
}

// Attestor performs one ContentLogging capability read for a binding. b is the
// resolved resource; now stamps FetchedAt. Implementations FAIL CLOSED: a
// transport error, outage, or ambiguous value yields an unhealthy Attestation
// with a Reason, never a nil error that would let a caller proceed.
type Attestor interface {
	Attest(ctx context.Context, b Binding, now time.Time) (Attestation, error)
}

// TokenSource mints a bearer token for an audience — the managed-identity seam
// (no `az`, no secret in code). The Azure driver plugs an IMDS/Workload-Identity
// token; tests plug a static token.
type TokenSource interface {
	Token(ctx context.Context, audience string) (string, error)
}

// StaticTokenSource returns a fixed token (dev/test).
type StaticTokenSource struct{ Value string }

// Token returns the fixed token.
func (s StaticTokenSource) Token(context.Context, string) (string, error) { return s.Value, nil }

// ARMAttestor reads the capability via the ARM REST API.
type ARMAttestor struct {
	// HTTPClient is used for the ARM GET; nil ⇒ a 10s-timeout default.
	HTTPClient *http.Client
	// Tokens mints the ARM bearer token. Required.
	Tokens TokenSource
	// BaseURL is the ARM endpoint; "" ⇒ https://management.azure.com.
	BaseURL string
	// APIVersion is the resource read api-version; "" ⇒ a sane default.
	APIVersion string
	// CapabilityPath is the dot-path into the JSON response at which the
	// ContentLogging capability value lives; "" ⇒ "properties.contentLogging".
	CapabilityPath string
}

var _ Attestor = (*ARMAttestor)(nil)

const (
	defaultARMBase        = "https://management.azure.com"
	defaultARMAPIVersion  = "2023-05-01"
	defaultCapabilityPath = "properties.contentLogging"
)

// Attest reads the resource and evaluates the ContentLogging capability. It
// fails closed: an incomplete binding, a missing token, a transport error, a
// non-2xx status, unparseable JSON, an absent/non-boolean value, or a `true`
// value all return an UNHEALTHY attestation (nil error). A nil error with
// Healthy=false is the normal fail-closed path; a non-nil error is reserved for
// caller-programming faults (a nil TokenSource).
func (a *ARMAttestor) Attest(ctx context.Context, b Binding, now time.Time) (Attestation, error) {
	res := Attestation{Binding: b, FetchedAt: now, Healthy: false}
	if a.Tokens == nil {
		return res, fmt.Errorf("attest: nil TokenSource")
	}
	if !b.Complete() {
		res.Reason = "route not bound to a resource (fail closed)"
		return res, nil
	}
	base := a.BaseURL
	if base == "" {
		base = defaultARMBase
	}
	apiVersion := a.APIVersion
	if apiVersion == "" {
		apiVersion = defaultARMAPIVersion
	}
	tok, err := a.Tokens.Token(ctx, b.EndpointAudience)
	if err != nil {
		res.Reason = "managed-identity token unavailable (fail closed): " + err.Error()
		return res, nil
	}
	url := strings.TrimRight(base, "/") + b.ARMResourceID + "?api-version=" + apiVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Reason = "build request: " + err.Error()
		return res, nil
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	client := a.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		res.Reason = "ARM unreachable (fail closed): " + err.Error()
		return res, nil
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		res.Reason = fmt.Sprintf("ARM status %d (fail closed)", resp.StatusCode)
		return res, nil
	}
	value, kind, ok := extractCapability(body, a.capabilityPath())
	if !ok {
		res.Reason = "ContentLogging capability absent (fail closed)"
		return res, nil
	}
	res.ContentLoggingValue = value
	if kind != jsonBool {
		res.Reason = "ContentLogging capability is not a boolean (fail closed)"
		return res, nil
	}
	if value != "false" {
		res.Reason = "ContentLogging is enabled (abuse-monitoring content storage active)"
		return res, nil
	}
	res.Healthy = true
	res.Reason = "ContentLogging disabled"
	return res, nil
}

func (a *ARMAttestor) capabilityPath() string {
	if a.CapabilityPath == "" {
		return defaultCapabilityPath
	}
	return a.CapabilityPath
}

type jsonKind int

const (
	jsonOther jsonKind = iota
	jsonBool
)

// extractCapability walks a dot-path into the JSON body and returns the value's
// canonical string form + kind. A boolean returns ("true"|"false", jsonBool);
// anything else returns (raw, jsonOther); an absent path returns ("", _, false).
func extractCapability(body []byte, path string) (value string, kind jsonKind, ok bool) {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return "", jsonOther, false
	}
	var cur any = root
	for _, seg := range strings.Split(path, ".") {
		m, isMap := cur.(map[string]any)
		if !isMap {
			return "", jsonOther, false
		}
		v, present := m[seg]
		if !present {
			return "", jsonOther, false
		}
		cur = v
	}
	switch v := cur.(type) {
	case bool:
		if v {
			return "true", jsonBool, true
		}
		return "false", jsonBool, true
	case string:
		return v, jsonOther, true
	case float64:
		return fmt.Sprintf("%v", v), jsonOther, true
	case nil:
		return "null", jsonOther, true
	default:
		return fmt.Sprintf("%v", v), jsonOther, true
	}
}

// OperatorAttestor is the operator-asserted ContentLogging attestation
// (plan §2.2, operator-attested variant). Azure AIServices does NOT expose the
// ContentLogging capability as a readable ARM property, so a resource that has
// genuinely obtained Microsoft Modified Abuse Monitoring approval cannot be
// machine-verified through the ARM canary (ARMAttestor). This attestor lets the
// operator — who HAS obtained that approval and confirmed content logging is
// disabled on the resource — assert it explicitly, in place of the (non-
// functional against real Azure) live read.
//
// It is honest and narrowly scoped: it is HEALTHY only for a binding whose
// ARMResourceID exactly equals the single AttestedResourceID the operator
// configured (every other resource fails closed); an incomplete binding is never
// healthy; the verdict NAMES itself "operator-attested" and carries the
// attesting identity, so the audit trail never mistakes it for a live ARM read.
// It performs no network read and holds no credential.
type OperatorAttestor struct {
	// AttestedResourceID is the exact route.ARMResourceID the operator attests.
	// An empty value verifies nothing (fail closed).
	AttestedResourceID string
	// AttestedBy is the operator identity recorded in the verdict for audit.
	AttestedBy string
}

var _ Attestor = OperatorAttestor{}

// Attest returns a healthy verdict ONLY for the exact attested resource; every
// other binding (or an incomplete one) fails closed. No network, no `az`.
func (o OperatorAttestor) Attest(_ context.Context, b Binding, now time.Time) (Attestation, error) {
	res := Attestation{Binding: b, FetchedAt: now, Healthy: false}
	if !b.Complete() {
		res.Reason = "operator attestation: route not bound to a resource (fail closed)"
		return res, nil
	}
	want := strings.TrimSpace(o.AttestedResourceID)
	if want == "" || b.ARMResourceID != want {
		res.Reason = "operator attestation: resource not attested (fail closed)"
		return res, nil
	}
	by := strings.TrimSpace(o.AttestedBy)
	if by == "" {
		by = "operator"
	}
	res.Healthy = true
	res.ContentLoggingValue = "false (operator-attested)"
	res.Reason = "content_logging operator-attested for " + want + " by " + by
	return res, nil
}

// FakeAttestor is a scripted Attestor for tests. If Func is set it is used;
// otherwise a copy of Result (with Binding + FetchedAt filled from the call) is
// returned, or Err if non-nil.
type FakeAttestor struct {
	Result Attestation
	Err    error
	Func   func(ctx context.Context, b Binding, now time.Time) (Attestation, error)
	Calls  int
}

// Attest returns the scripted attestation.
func (f *FakeAttestor) Attest(ctx context.Context, b Binding, now time.Time) (Attestation, error) {
	f.Calls++
	if f.Func != nil {
		return f.Func(ctx, b, now)
	}
	if f.Err != nil {
		return Attestation{Binding: b, FetchedAt: now}, f.Err
	}
	r := f.Result
	r.Binding = b
	r.FetchedAt = now
	return r, nil
}
