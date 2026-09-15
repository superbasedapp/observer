package aigateway

import (
	"context"
	"errors"
	"time"
)

// ErrKeyNotFound is returned by KeyStore.ResolveByHash when no key matches.
var ErrKeyNotFound = errors.New("aigateway: virtual key not found")

// KeyStore is the durable virtual-key registry seam. Keys are stored as
// hashes only (custody: the plaintext is never persisted). The revocation
// watermark is a monotonic counter the store bumps on every revoke; the auth
// cache stamps each entry with the watermark it observed, and a cache fill
// older than the current watermark is rejected (Sol S9).
type KeyStore interface {
	// Insert persists a newly minted key. The plaintext is NOT passed — only
	// its hash lives in the record.
	Insert(ctx context.Context, k VirtualKey) error
	// ResolveByHash returns the key whose Hash matches, or ErrKeyNotFound.
	ResolveByHash(ctx context.Context, orgID, hash string) (VirtualKey, error)
	// Revoke marks a key revoked at time now, records the per-revocation
	// strict flag (HG8), and bumps the revocation watermark. It returns the
	// new watermark so a caller can invalidate caches immediately.
	Revoke(ctx context.Context, orgID, keyID string, strict bool, now time.Time) (int64, error)
	// Watermark returns the store's current monotonic revocation watermark.
	Watermark(ctx context.Context, orgID string) (int64, error)
	// AckProvisioned marks a bulk-provisioned key as ACKed before gateway
	// activation (design §2.3). An un-ACKed key is not yet usable.
	AckProvisioned(ctx context.Context, orgID, keyID string, now time.Time) error
}

// UpstreamStore is the registered-upstream registry seam. It returns upstream
// records WITHOUT resolving the credential — the SecretRef is resolved
// separately, in-memory, only in the dialer.
type UpstreamStore interface {
	// GetUpstream returns one upstream by id.
	GetUpstream(ctx context.Context, orgID, upstreamID string) (Upstream, error)
	// ListUpstreams returns all enabled upstreams for an org.
	ListUpstreams(ctx context.Context, orgID string) ([]Upstream, error)
}

// SecretResolver resolves an upstream's sealed credential reference to the
// plaintext provider key, in-memory, at dial time. It is the seam onto the
// existing sealed org secret store (internal/orgserver/secretref) — the core
// never imports it; the gwhttp wiring injects a resolver whose Resolve calls
// secretref.Resolver.Resolve. The plaintext must live only in the dialer and
// never enter a request log or any persisted row (design §2.3).
type SecretResolver interface {
	Resolve(ctx context.Context, orgID, ref string) (string, error)
}

// AuditStore is the metadata-only audit sink seam. Write MUST be durable for
// the reservation half of the two-phase model (design §2.7): the request row
// is written before forwarding, not best-effort. It never receives content.
type AuditStore interface {
	// Write persists one metadata-only audit event.
	Write(ctx context.Context, e AuditEvent) error
}

// ModelConfigStore is the seam for the ADMIN-AUTHORED model policy + rate card
// documents (migration 120 gw_model_policy / gw_rate_card; gap register
// G1-RESIDUALS "gwstore-sourced model policy/rate card"). found=false means no
// document is stored for the org and the caller falls back to the built-in
// default — the pre-120 behavior, byte-identical.
type ModelConfigStore interface {
	// GetModelPolicy returns the org's stored policy and its document version.
	GetModelPolicy(ctx context.Context, orgID string) (p ModelPolicy, version int64, found bool, err error)
	// GetRateCard returns the org's stored rate card and its document version.
	GetRateCard(ctx context.Context, orgID string) (c RateCard, version int64, found bool, err error)
}

// MemberCredentialStore resolves the per-developer secret ref for an upstream
// in CredentialPerDeveloper mode (migration 120 gw_upstream_member_credential;
// design §2.3, ToS research finding 3). found=false is a hard miss — the
// gateway FAILS CLOSED rather than falling back to the shared org credential.
type MemberCredentialStore interface {
	MemberSecretRef(ctx context.Context, orgID, upstreamID, userID string) (ref string, found bool, err error)
}
