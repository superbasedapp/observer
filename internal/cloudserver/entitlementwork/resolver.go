package entitlementwork

import (
	"context"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// Typed create refusals: the reasons a create_tenant row carries in its
// error class ("not_sent:resolve:<reason>") while it waits in the outbox.
const (
	// ReasonEntitlementsNotIssued: no entitlements document is stored for
	// the org yet (the issuer's next pass stores one).
	ReasonEntitlementsNotIssued = "entitlements_not_issued"
	// ReasonOwnerIdentityUnavailable: no owner WorkOS subject is known for
	// the org (its owner has no identity link, or the org is no longer
	// being created, which is the only time the lookup answers).
	ReasonOwnerIdentityUnavailable = "owner_identity_unavailable"
	// ReasonOwnerEmailHintUnavailable: the owner has no recorded address,
	// which the contract still requires as a display hint.
	ReasonOwnerEmailHintUnavailable = "owner_email_hint_unavailable"
	// ReasonOrgUnavailable: the org's slug and kind could not be read (the
	// org row is gone).
	ReasonOrgUnavailable = "org_unavailable"
)

// DocumentReader reads an org's latest stored document (*store.Store).
type DocumentReader interface {
	LatestEntitlementDocument(ctx context.Context, orgID string) (pc.EntitlementDocument, error)
}

// Owner is an org owner's identity as a create_tenant request carries it.
type Owner struct {
	// Sub is the owner's WorkOS subject: the host binds the owner by it.
	Sub string
	// Email is the owner's address, a display hint only (W14-D2): the request
	// marks it unverified unless EmailVerified.
	Email string
	// EmailVerified is true only when the source vouches for Email:
	// StoreOwners sets it when WorkOS verified the address (C2.tenant-cloud-2,
	// cloud 0096).
	EmailVerified bool
}

// OwnerSource resolves an org's owner identity.
type OwnerSource interface {
	Owner(ctx context.Context, orgID string) (Owner, error)
}

// NoOwnerSource refuses every call with ReasonOwnerIdentityUnavailable: a
// source with no lookup (the wave 13 posture, kept for tests and for a worker
// deliberately run without owner lookups). The production source is
// StoreOwners.
type NoOwnerSource struct{}

// Owner implements OwnerSource.
func (NoOwnerSource) Owner(context.Context, string) (Owner, error) {
	return Owner{}, &hostclient.ResolveError{Reason: ReasonOwnerIdentityUnavailable}
}

// OwnerStore is StoreOwners' store seam (*store.Store bound to sbci_worker):
// the two cloud 0093 SECURITY DEFINER lookups, each answering for ONE org
// still being created and listing nothing (ENTLWORK-5, lead decision
// W14-D2). store.ErrNotFound means the lookup answered nothing.
type OwnerStore interface {
	// OrgCreateOwnerSub returns the owner's WorkOS subject.
	OrgCreateOwnerSub(ctx context.Context, orgID string) (string, error)
	// OrgCreateOwnerEmailHint returns the owner's provider-asserted address.
	OrgCreateOwnerEmailHint(ctx context.Context, orgID string) (string, error)
}

// OwnerAddressStore is the optional store read StoreOwners prefers over
// OrgCreateOwnerEmailHint (*store.Store: OrgCreateOwnerAddress, cloud 0096):
// the owner's address and WorkOS's verification of it, from one snapshot.
type OwnerAddressStore interface {
	OrgCreateOwnerAddress(ctx context.Context, orgID string) (store.OrgCreateOwnerAddress, error)
}

// StoreOwners is the production OwnerSource (W14-D2): the owner's subject,
// chosen by the platform OIDC issuer's own rule, so the subject the host
// binds is the one every later platform sign-in presents; and the owner's
// address, sent as a hint marked verified exactly when WorkOS verified it
// (C2.tenant-cloud-2: account_verified_emails.email_verified, which only the
// WorkOS sign-in leg writes), else unverified. The host still binds the
// owner by subject; the address is never the binding. A missing subject or
// address is a typed refusal: the create waits in the outbox with that reason
// and is retried, never sent with a blank or invented identity.
//
// When Store also implements OwnerAddressStore (the production store does)
// the address and its flag come from one statement; otherwise the 0093 hint
// is sent unverified.
type StoreOwners struct {
	Store OwnerStore
}

// Owner implements OwnerSource.
func (o StoreOwners) Owner(ctx context.Context, orgID string) (Owner, error) {
	if o.Store == nil {
		return Owner{}, errors.New("entitlementwork.StoreOwners: Store is required")
	}
	sub, err := o.Store.OrgCreateOwnerSub(ctx, orgID)
	if errors.Is(err, store.ErrNotFound) {
		return Owner{}, &hostclient.ResolveError{Reason: ReasonOwnerIdentityUnavailable}
	}
	if err != nil {
		return Owner{}, fmt.Errorf("entitlementwork.StoreOwners: subject: %w", err)
	}
	addr, err := o.ownerAddress(ctx, orgID)
	if errors.Is(err, store.ErrNotFound) {
		return Owner{}, &hostclient.ResolveError{Reason: ReasonOwnerEmailHintUnavailable}
	}
	if err != nil {
		return Owner{}, fmt.Errorf("entitlementwork.StoreOwners: address hint: %w", err)
	}
	return Owner{Sub: sub, Email: addr.Hint, EmailVerified: addr.Verified}, nil
}

// ownerAddress reads the owner's address and its flag: one statement when the
// store offers it, else the unverified hint.
func (o StoreOwners) ownerAddress(ctx context.Context, orgID string) (store.OrgCreateOwnerAddress, error) {
	if a, ok := o.Store.(OwnerAddressStore); ok {
		return a.OrgCreateOwnerAddress(ctx, orgID)
	}
	hint, err := o.Store.OrgCreateOwnerEmailHint(ctx, orgID)
	return store.OrgCreateOwnerAddress{Hint: hint}, err
}

// OrgFactsReader reads the org's slug and kind for its create request
// (*store.Store: OrgCreateFacts, cloud 0089 / 0092 column grants).
type OrgFactsReader interface {
	OrgCreateFacts(ctx context.Context, orgID string) (store.OrgCreateFacts, error)
}

// orgKindsOnWire maps an org registry kind to the contract's org kind.
var orgKindsOnWire = []struct {
	org  store.OrgKind
	wire pc.OrgKind
}{
	{store.OrgTeam, pc.OrgKindTeam},
	{store.OrgPersonal, pc.OrgKindPersonal},
}

func wireKind(k store.OrgKind) (pc.OrgKind, bool) {
	for _, r := range orgKindsOnWire {
		if r.org == k {
			return r.wire, true
		}
	}
	return "", false
}

// CreateResolver implements hostclient.CreateResolver: the org's latest
// stored entitlements document (the first one the issuer stored), the owner
// identity from Owners, and the org's current slug and kind from Facts (a
// pooled host routes by slug and refuses a create without one).
type CreateResolver struct {
	Docs   DocumentReader
	Owners OwnerSource
	// Facts reads the slug and kind (nil: neither is sent, the wave 13
	// shape; a pooled host then refuses the create, so the worker always
	// sets it).
	Facts OrgFactsReader
}

// ResolveCreate implements hostclient.CreateResolver.
func (r CreateResolver) ResolveCreate(ctx context.Context, orgID string) (hostapi.CreateExtras, error) {
	if r.Docs == nil || r.Owners == nil {
		return hostapi.CreateExtras{}, errors.New("entitlementwork.CreateResolver: Docs and Owners are required")
	}
	doc, err := r.Docs.LatestEntitlementDocument(ctx, orgID)
	if errors.Is(err, store.ErrNotFound) {
		return hostapi.CreateExtras{}, &hostclient.ResolveError{Reason: ReasonEntitlementsNotIssued}
	}
	if err != nil {
		return hostapi.CreateExtras{}, fmt.Errorf("entitlementwork.CreateResolver: %w", err)
	}
	x := hostapi.CreateExtras{Entitlements: doc}
	if r.Facts != nil {
		f, err := r.Facts.OrgCreateFacts(ctx, orgID)
		if errors.Is(err, store.ErrNotFound) {
			return hostapi.CreateExtras{}, &hostclient.ResolveError{Reason: ReasonOrgUnavailable}
		}
		if err != nil {
			return hostapi.CreateExtras{}, fmt.Errorf("entitlementwork.CreateResolver: org: %w", err)
		}
		kind, ok := wireKind(f.Kind)
		if !ok || f.Slug == "" {
			return hostapi.CreateExtras{}, &hostclient.ResolveError{Reason: ReasonOrgUnavailable}
		}
		x.Slug, x.Kind = f.Slug, kind
	}
	owner, err := r.Owners.Owner(ctx, orgID)
	if err != nil {
		return hostapi.CreateExtras{}, fmt.Errorf("entitlementwork.CreateResolver: %w", err)
	}
	x.OwnerSub, x.OwnerEmail, x.OwnerEmailVerified = owner.Sub, owner.Email, owner.EmailVerified
	return x, nil
}
