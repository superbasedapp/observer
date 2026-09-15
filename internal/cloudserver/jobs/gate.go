package jobs

import (
	"context"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/attest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// AttestationGate implements ProviderAttestor by binding the route's resolved
// resource (plan §2.2): it reads the route's binding identifiers + generation
// from the store, reuses its own attestation only when it is FRESH (within
// MaxAge), HEALTHY, and matches the binding AND generation exactly, otherwise it
// performs a fresh ARM read via the injected Attestor, persists the record, and
// returns the verdict. It fails closed on a store error, an unbound route, a
// stale/mismatched cache, an unhealthy ARM read, or a control-plane outage.
type AttestationGate struct {
	store    *store.Store
	attestor attest.Attestor
	maxAge   time.Duration
	mu       sync.Mutex
	cache    map[string]store.AttestationRecord
}

// NewAttestationGate builds a gate. maxAge <= 0 defaults to 15 minutes
// (plan §2.2). A nil attestor makes every check fail closed.
func NewAttestationGate(s *store.Store, a attest.Attestor, maxAge time.Duration) *AttestationGate {
	if maxAge <= 0 {
		maxAge = 15 * time.Minute
	}
	return &AttestationGate{store: s, attestor: a, maxAge: maxAge, cache: make(map[string]store.AttestationRecord)}
}

var _ ProviderAttestor = (*AttestationGate)(nil)

// Attest re-checks the ContentLogging attestation for the RESOLVED route
// snapshot the worker will execute under (FA1). It is called inside the
// execution lease immediately before every provider attempt, including retries
// (plan §2.2 / §6 CI-P4). Crucially it does NOT re-resolve the route by id — it
// binds to the snapshot the worker already resolved, so the attestation cannot
// authorize a different resource/generation than the one about to be called.
func (g *AttestationGate) Attest(ctx context.Context, route store.RouteInfo, now time.Time) (Attestation, error) {
	if g.attestor == nil {
		return Attestation{Verified: false, Reason: "no attestor configured (fail closed)"}, nil
	}
	// Each gate owns one immutable attestor configuration, chosen at startup.
	// Persisted verdicts are an audit trail, not reusable authorization: another
	// process (including an old replica during a roll) may use a different mode,
	// resource or disclosure policy. Only this gate's own reads may be cached.
	g.mu.Lock()
	defer g.mu.Unlock()
	binding := attest.Binding{
		TenantID:         route.TenantID,
		SubscriptionID:   route.SubscriptionID,
		ARMResourceID:    route.ARMResourceID,
		EndpointAudience: route.EndpointAudience,
		RouteGeneration:  route.Generation,
	}

	// Reuse this gate's attestation only when fresh + healthy + exactly matching
	// (binding AND generation). TOCTOU-safe: a generation bump or a binding edge
	// invalidates the cache, forcing a fresh read.
	if cached, ok := g.cache[route.RouteID]; ok {
		if attestationUsable(cached, binding, now, g.maxAge) {
			// Repeat the persisted verdict's own words: under the disclosed
			// mode (attest.DisclosedAttestor) the cached record never claims
			// ContentLogging is disabled, and a reused verdict must not either.
			return Attestation{Verified: true, Reason: "attestation reused (cached): " + cached.Reason}, nil
		}
	}

	att, err := g.attestor.Attest(ctx, binding, now)
	if err != nil {
		return Attestation{Verified: false, Reason: "attestation read error (fail closed): " + err.Error()}, nil
	}
	// Persist the record (best-effort; a persistence failure does not flip a
	// healthy verdict, but is surfaced in the reason on the unhealthy path).
	rec := store.AttestationRecord{
		RouteID: route.RouteID, RouteGeneration: binding.RouteGeneration,
		TenantID: binding.TenantID, SubscriptionID: binding.SubscriptionID,
		ARMResourceID: binding.ARMResourceID, EndpointAudience: binding.EndpointAudience,
		ContentLoggingValue: att.ContentLoggingValue, Healthy: att.Healthy,
		Reason: att.Reason, FetchedAt: att.FetchedAt,
	}
	_ = g.store.RecordAttestation(ctx, rec)
	g.cache[route.RouteID] = rec

	if !att.Healthy {
		return Attestation{Verified: false, Reason: att.Reason}, nil
	}
	return Attestation{Verified: true, Reason: att.Reason}, nil
}

// attestationUsable reports whether a persisted attestation authorizes the
// current binding: healthy, unexpired, and every identifier + generation equal.
func attestationUsable(a store.AttestationRecord, b attest.Binding, now time.Time, maxAge time.Duration) bool {
	if !a.Healthy {
		return false
	}
	if now.Sub(a.FetchedAt) > maxAge || a.FetchedAt.After(now.Add(time.Minute)) {
		return false // stale, or a future stamp (clock skew) — fail closed
	}
	return a.RouteGeneration == b.RouteGeneration &&
		a.TenantID == b.TenantID &&
		a.SubscriptionID == b.SubscriptionID &&
		a.ARMResourceID == b.ARMResourceID &&
		a.EndpointAudience == b.EndpointAudience
}
