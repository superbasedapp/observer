package entitlementwork

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// Issuer defaults.
const (
	// DefaultPageSize is how many orgs one store read returns.
	DefaultPageSize = 200
	// DefaultMaxSignAttempts bounds how often one issuance asks the signer
	// again after a version_not_newer answer.
	DefaultMaxSignAttempts = 4
)

// Store is the issuer's store seam (*store.Store bound to sbci_worker).
type Store interface {
	// ListOrgsForEntitlements pages the orgs (purged ones left out).
	ListOrgsForEntitlements(ctx context.Context, afterOrgID string, limit int) ([]store.OrgEntitlementView, error)
	// LatestEntitlementDocument returns the org's highest-version document,
	// or store.ErrNotFound.
	LatestEntitlementDocument(ctx context.Context, orgID string) (pc.EntitlementDocument, error)
	// IssueEntitlementDocument stores the document and its intent in one
	// transaction.
	IssueEntitlementDocument(ctx context.Context, orgID string, doc pc.EntitlementDocument, issuedBy string, issuedAt time.Time, intent store.OrgIntent) (bool, error)
	// OrgForEntitlements reads one org as ListOrgsForEntitlements does, or
	// store.ErrNotFound (EnsureOrg, the post-create pass).
	OrgForEntitlements(ctx context.Context, orgID string) (store.OrgEntitlementView, error)
	// DocumentVersionFloor returns the stream's version floor (0: none):
	// the version the document signer's record says it already signed,
	// raised by the operator after a database restore behind that record
	// (cloud 0097, W16-D6).
	DocumentVersionFloor(ctx context.Context, kind pc.DocumentKind, scope string) (int64, error)
}

// Signer signs an org's entitlements body at a version (the document
// signer's sign_document operation for kind entitlements). An error wrapping
// platformcontract.ErrVersionNotNewer means the signer already signed that
// version or a later one for the org.
type Signer interface {
	SignEntitlements(ctx context.Context, orgID string, version int64, body []byte) (sig []byte, keyID string, err error)
}

// SignerFunc adapts a function to Signer.
type SignerFunc func(ctx context.Context, orgID string, version int64, body []byte) ([]byte, string, error)

// SignEntitlements implements Signer.
func (f SignerFunc) SignEntitlements(ctx context.Context, orgID string, version int64, body []byte) ([]byte, string, error) {
	return f(ctx, orgID, version, body)
}

// Plan names a catalog plan (entitlements.Plan) and the document's validity
// end. A stored document carries the plan only when its body names the same
// plan, version and end, so a change of any of them issues a new document.
type Plan struct {
	Name    string
	Version int
	// NotAfter is the document's not_after (Unix seconds; 0: no end). A
	// launch document ends with its launch window (W14-D1a), so a host falls
	// back to the floor by itself if the control plane is silent.
	NotAfter int64
}

// PlanSource says which catalog plan an org's document is composed from.
type PlanSource interface {
	PlanFor(ctx context.Context, org store.OrgEntitlementView, kind entitlements.Kind) (Plan, error)
}

// FloorPlans is a PlanSource that answers the floor of the org's kind and
// nothing else (the issuer's default when no PlanSource is configured; the
// worker configures SubscriptionPlans, plans.go).
type FloorPlans struct{}

// PlanFor implements PlanSource.
func (FloorPlans) PlanFor(_ context.Context, _ store.OrgEntitlementView, kind entitlements.Kind) (Plan, error) {
	return floorPlan(kind)
}

// floorPlan is the floor template of kind.
func floorPlan(kind entitlements.Kind) (Plan, error) {
	b, ok := entitlements.Floor(kind)
	if !ok {
		return Plan{}, fmt.Errorf("entitlementwork.FloorPlans: no floor for kind %s", kind)
	}
	return Plan{Name: b.Plan.Name, Version: b.Plan.Version}, nil
}

// orgKinds maps an org registry kind to the entitlements kind its documents
// bind, walked top-down. An org kind with no row is never issued a document.
var orgKinds = []struct {
	org  store.OrgKind
	kind entitlements.Kind
}{
	{store.OrgPersonal, entitlements.KindPersonal},
	{store.OrgTeam, entitlements.KindTeam},
}

// KindFor returns the entitlements kind of an org registry kind.
func KindFor(k store.OrgKind) (entitlements.Kind, bool) {
	for _, r := range orgKinds {
		if r.org == k {
			return r.kind, true
		}
	}
	return "", false
}

// issuableStatuses are the org lifecycle states a document is issued in: a
// tenant being created or in service. An org on its way out
// (pending_deletion, purging) gets nothing new.
var issuableStatuses = []pc.TenantState{pc.StateProvisioning, pc.StateActive, pc.StateSuspended}

// Config configures an Issuer. Store, Signer and Keys are required.
type Config struct {
	Store  Store
	Signer Signer
	// Keys verifies every signed document before it is stored: the signer's
	// published entitlements keys (the same keys a host must pin).
	Keys pc.KeySet
	// Plans chooses each org's plan (nil: FloorPlans).
	Plans PlanSource
	// Now is the clock (nil: time.Now).
	Now func() time.Time
	// PageSize is the org page size (0: DefaultPageSize).
	PageSize int
	// MaxSignAttempts bounds the signer retries (0: DefaultMaxSignAttempts).
	MaxSignAttempts int
}

// Issuer issues and enqueues entitlements documents.
type Issuer struct {
	cfg Config
}

// New builds an Issuer.
func New(cfg Config) (*Issuer, error) {
	if cfg.Store == nil || cfg.Signer == nil || len(cfg.Keys) == 0 {
		return nil, errors.New("entitlementwork.New: Store, Signer and Keys are required")
	}
	if cfg.Plans == nil {
		cfg.Plans = FloorPlans{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PageSize <= 0 {
		cfg.PageSize = DefaultPageSize
	}
	if cfg.MaxSignAttempts <= 0 {
		cfg.MaxSignAttempts = DefaultMaxSignAttempts
	}
	return &Issuer{cfg: cfg}, nil
}

// Outcome is what Ensure did for one org.
type Outcome string

// Outcomes.
const (
	// OutcomeIssued: a new document was signed, stored and enqueued.
	OutcomeIssued Outcome = "issued"
	// OutcomeCurrent: the stored document already carries the org's plan.
	OutcomeCurrent Outcome = "current"
	// OutcomeSkipped: the org is not in an issuable state or kind.
	OutcomeSkipped Outcome = "skipped"
	// OutcomeRaced: another issuer stored a newer version first; the next
	// pass compares again.
	OutcomeRaced Outcome = "raced"
)

// Stats counts one pass.
type Stats struct {
	Orgs, Issued, Current, Skipped, Raced, Failed int
}

func (s *Stats) count(o Outcome) {
	switch o {
	case OutcomeIssued:
		s.Issued++
	case OutcomeCurrent:
		s.Current++
	case OutcomeRaced:
		s.Raced++
	default:
		s.Skipped++
	}
}

// IssueOnce walks every org once and ensures its document. A failure for
// one org does not stop the others; the errors are joined.
func (i *Issuer) IssueOnce(ctx context.Context) (Stats, error) {
	var st Stats
	var errs []error
	after := ""
	for {
		orgs, err := i.cfg.Store.ListOrgsForEntitlements(ctx, after, i.cfg.PageSize)
		if err != nil {
			return st, fmt.Errorf("entitlementwork.IssueOnce: %w", err)
		}
		for _, org := range orgs {
			st.Orgs++
			o, err := i.Ensure(ctx, org)
			if err != nil {
				st.Failed++
				errs = append(errs, fmt.Errorf("org %s: %w", org.OrgID, err))
				continue
			}
			st.count(o)
		}
		if len(orgs) < i.cfg.PageSize || ctx.Err() != nil {
			break
		}
		after = orgs[len(orgs)-1].OrgID
	}
	if len(errs) > 0 {
		return st, fmt.Errorf("entitlementwork.IssueOnce: %w", errors.Join(errs...))
	}
	return st, nil
}

// Ensure issues a document for org when its stored document does not carry
// the plan its PlanSource names.
func (i *Issuer) Ensure(ctx context.Context, org store.OrgEntitlementView) (Outcome, error) {
	kind, ok := KindFor(org.Kind)
	if !ok || !slices.Contains(issuableStatuses, pc.TenantState(org.Status)) {
		return OutcomeSkipped, nil
	}
	plan, err := i.cfg.Plans.PlanFor(ctx, org, kind)
	if err != nil {
		return "", fmt.Errorf("entitlementwork.Ensure: plan: %w", err)
	}
	var last int64
	latest, err := i.cfg.Store.LatestEntitlementDocument(ctx, org.OrgID)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return "", fmt.Errorf("entitlementwork.Ensure: latest: %w", err)
	default:
		last = latest.Version
		if carries(latest, kind, plan) {
			return OutcomeCurrent, nil
		}
	}
	floor, err := i.cfg.Store.DocumentVersionFloor(ctx, pc.KindEntitlements, org.OrgID)
	if err != nil {
		return "", fmt.Errorf("entitlementwork.Ensure: version floor: %w", err)
	}
	return i.issue(ctx, org.OrgID, kind, plan, versionBase(last, floor))
}

// versionBase is the version a new document must exceed: the higher of the
// org's latest stored version and its version floor (W16-D6). After a
// database restore behind the document signer's record, the floor makes the
// issuer ask for a version the signer has not signed yet, instead of
// stalling on version_not_newer answers.
func versionBase(stored, floor int64) int64 { return max(stored, floor) }

// carries reports whether a stored document's body binds kind and names
// plan. A body that does not decode is not current (it is replaced).
func carries(doc pc.EntitlementDocument, kind entitlements.Kind, plan Plan) bool {
	b, err := entitlements.Decode(doc.Body)
	return err == nil && b.Kind == kind && b.Plan.Name == plan.Name && b.Plan.Version == plan.Version &&
		b.NotAfter == plan.NotAfter
}

// EnsureOrg is Ensure for one org read by id: the dispatcher's post-create
// pass (hostclient.DispatcherConfig.AfterCreate), which issues the new
// tenant's launch document as soon as its create is acked (W14-D1a) instead
// of at the issuer's next pass. An org that no longer exists (or is purged)
// is skipped.
func (i *Issuer) EnsureOrg(ctx context.Context, orgID string) (Outcome, error) {
	org, err := i.cfg.Store.OrgForEntitlements(ctx, orgID)
	if errors.Is(err, store.ErrNotFound) {
		return OutcomeSkipped, nil
	}
	if err != nil {
		return "", fmt.Errorf("entitlementwork.EnsureOrg: %w", err)
	}
	return i.Ensure(ctx, org)
}

// nextVersion is max(last + 1, now in Unix seconds): strictly above what
// the store holds, and above anything an earlier issuance signed in an
// earlier second even if it never reached the store.
func nextVersion(last int64, now time.Time) int64 {
	return max(last+1, now.Unix())
}

// issue composes, signs, verifies, stores and enqueues one document.
func (i *Issuer) issue(ctx context.Context, orgID string, kind entitlements.Kind, plan Plan, last int64) (Outcome, error) {
	now := i.cfg.Now()
	body, err := entitlements.Compose(plan.Name, plan.Version, orgID, now.Unix(), 0, plan.NotAfter)
	if err != nil {
		return "", fmt.Errorf("entitlementwork.issue: %w", err)
	}
	if body.Kind != kind {
		return "", fmt.Errorf("entitlementwork.issue: plan %s v%d is kind %s, the org is %s", plan.Name, plan.Version, body.Kind, kind)
	}
	raw, err := body.Encode()
	if err != nil {
		return "", fmt.Errorf("entitlementwork.issue: %w", err)
	}
	doc, err := i.sign(ctx, orgID, nextVersion(last, now), raw)
	if err != nil {
		return "", err
	}
	if _, err := entitlements.Verify(doc, entitlements.Binding{Org: orgID, Kind: kind}, i.cfg.Keys, last); err != nil {
		return "", fmt.Errorf("entitlementwork.issue: the signed document does not verify: %w", err)
	}
	in, err := hostapi.SetEntitlementsIntent(orgID, doc)
	if err != nil {
		return "", fmt.Errorf("entitlementwork.issue: %w", err)
	}
	intent := store.OrgIntent{
		OrgID: in.OrgID, Verb: store.OrgOutboxVerb(in.Verb), IdempotencyKey: in.IdempotencyKey,
		LifecycleGen: in.LifecycleGen, Payload: in.Payload,
	}
	if _, err := i.cfg.Store.IssueEntitlementDocument(ctx, orgID, doc, store.IssuedBySystem, now, intent); err != nil {
		if errors.Is(err, pc.ErrVersionNotNewer) {
			return OutcomeRaced, nil
		}
		return "", fmt.Errorf("entitlementwork.issue: %w", err)
	}
	return OutcomeIssued, nil
}

// sign asks the signer for version, bumping it after each version_not_newer
// answer, at most MaxSignAttempts times.
func (i *Issuer) sign(ctx context.Context, orgID string, version int64, body []byte) (pc.EntitlementDocument, error) {
	var err error
	for range i.cfg.MaxSignAttempts {
		var sig []byte
		var keyID string
		sig, keyID, err = i.cfg.Signer.SignEntitlements(ctx, orgID, version, body)
		if err == nil {
			return pc.EntitlementDocument{Version: version, Body: body, Signature: sig, KeyID: keyID}, nil
		}
		if !errors.Is(err, pc.ErrVersionNotNewer) {
			break
		}
		version++
	}
	return pc.EntitlementDocument{}, fmt.Errorf("entitlementwork.sign: %w", err)
}
