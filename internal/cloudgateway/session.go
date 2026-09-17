package cloudgateway

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudclient"
	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// session.go is the FEATURE lane: the three entry points that resolve consent
// before any network attempt, and the NARROW session handle each hands an
// authorized caller.
//
// A session handle exists so the network client is UNREACHABLE except from
// inside an authorized callback. A caller cannot hold one, cache one, or
// construct one — it only ever receives one as a parameter after the check has
// passed.
//
// CAPABILITY NARROWING (F1). There is deliberately no single Session type any
// more. Go cannot stop a callback from storing the value it was handed, so the
// enforcement is that the STORED value can do nothing outside its authorized
// operation class:
//
//	FeatureFetch   -> ReadSession       — Results only. No upload method exists.
//	FeatureSend    -> UploadSession     — the session-evidence write only.
//	StandingSend   -> StructuralSession — the snapshot write only.
//
// The narrowing is compile-level: a fetch callback that tried to upload names a
// method that is not on its type, so the mistake cannot be made at all rather
// than being caught at run time. Each write method additionally consults the
// gateway's own revocation re-check immediately before every physical attempt
// (see recheck below), so a grant revoked DURING a long callback stops the next
// dispatch too.

// ErrPreAttemptRequired is returned when an upload is submitted without a
// per-item authorization re-check. A nil PreAttempt would let a send whose
// authorization vanished between prepare and dispatch (or between retries)
// leave the machine, so the seam refuses rather than dispatching unchecked.
// Requiring it here is what stops a FUTURE call site from forgetting it.
var ErrPreAttemptRequired = fmt.Errorf(
	"cloudgateway: an upload requires a PreAttempt authorization re-check; without one a revoked send could still dispatch",
)

// DispatchLease is the cross-process DISPATCH LEASE hook a STANDING-rail upload
// must carry (Sol re-review N2). It is invoked immediately before EVERY
// physical attempt — after the gateway's grant re-resolve and the caller's
// PreAttempt, as the very last thing before the socket — and its release func
// immediately after the attempt returns.
//
// The lease is DB-backed and keyed to the EXACT receipt + consent generation
// the bytes were built under (internal/store.AcquireCloudDispatchLease is the
// production implementation; cmd/observer wires it). It returns the instant
// the lease expires, which the transport applies as the attempt's request
// deadline, so an attempt descheduled past its lease can never begin dispatch.
// A `consent revoke` / superseding `consent grant` cancels the leases under the
// receipts it retires and does not return until none is active — bounded, by
// construction, by DispatchLeaseTTL.
type DispatchLease func(ctx context.Context) (expiresAt time.Time, release func(), err error)

// DispatchLeaseTTL is how long a dispatch lease lives, and therefore the
// longest a revoke can wait on one in-flight attempt. It equals the network
// client's per-attempt HTTP timeout (30s): the lease's expiry is applied as
// the attempt's own request deadline, so the two bounds are one bound.
const DispatchLeaseTTL = 30 * time.Second

// UploadRequest is one session-evidence upload. Envelope MUST be the exact bytes
// the store handed back at prepare time.
type UploadRequest struct {
	CloudSessionID string
	Feature        string
	Envelope       []byte
	UploadDigest   string
	SchemaVersion  string
	// PreAttempt is invoked immediately before every physical HTTP attempt —
	// the caller's per-item authorization re-check (FD3). A non-nil error aborts
	// the send without dispatching. It is REQUIRED: nil is ErrPreAttemptRequired.
	PreAttempt func() error
	// DispatchLease fences revocation against a physical per-upload attempt.
	DispatchLease DispatchLease
}

// UploadResult is the service's acknowledgement of an accepted enrichment job.
type UploadResult struct {
	JobID  string
	Status string
}

// StructuralUploadRequest is one immutable snapshot window. Payload MUST be the
// exact stored canonical bytes.
type StructuralUploadRequest struct {
	Payload           []byte
	Period            string
	PeriodRuleVersion int
	SchemaVersion     string
	Revision          int
	Digest            string
	// The STANDING-GRANT binding the server validates the upload against (R1).
	// It comes from the receipt THIS item is bound to — read inside the same
	// transaction that authorized the send — so what is declared on the wire is
	// what the developer agreed to for these exact bytes, never a separately
	// resolved "newest" grant.
	ConsentGeneration    int
	DataDictionaryDigest string
	SourceWindowRule     string
	// PreAttempt is the caller's per-item authorization re-check, invoked before
	// every physical attempt. REQUIRED: nil is ErrPreAttemptRequired.
	PreAttempt func() error
	// DispatchLease is the cross-process dispatch lease taken after PreAttempt
	// and released after the attempt. REQUIRED: nil is ErrDispatchLeaseRequired.
	DispatchLease DispatchLease
}

// StructuralUploadResult is the service's acknowledgement of a stored (or
// replay-acked) snapshot window.
type StructuralUploadResult struct {
	SnapshotID string
	Status     string
	Replay     bool
}

// CommunityUploadRequest is one derived per-window cohort-benchmarking
// contribution. Payload MUST be the exact canonical bytes the node serialized.
// The standing-grant binding it declares — generation, dictionary digest,
// source-window rule, declared timezone — comes from the EXACT receipt the
// send is authorized under (Sol re-review N1/N5: the rule and timezone are
// wire terms the server registers, not local receipt text).
type CommunityUploadRequest struct {
	Payload              []byte
	Digest               string
	ConsentGeneration    int
	DataDictionaryDigest string
	// SourceWindowRule is the receipt's bound rule
	// (cloudcontract.CommunitySourceWindowRule at grant time). REQUIRED.
	SourceWindowRule string
	// DeclaredTimezone is the receipt's bound timezone — always UTC for this
	// purpose (cloudcontract.CommunityDeclaredTimezone). REQUIRED.
	DeclaredTimezone string
	// Endpoint is the absolute URL the AUTHORIZING RECEIPT bound (grant.Endpoint
	// — read from the exact receipt the send is authorized under, never a
	// separately resolved "current" value). REQUIRED: checked against the
	// session's own live CommunityEndpoint() before every physical attempt,
	// failing closed (ErrEndpointMismatch) if config/--base-url moved the
	// destination after the grant was made (Sol review F3).
	Endpoint string
	// PreAttempt is the caller's per-item authorization re-check, invoked before
	// every physical attempt. REQUIRED: nil is ErrPreAttemptRequired.
	PreAttempt func() error
	// DispatchLease is the cross-process dispatch lease taken after PreAttempt
	// and released after the attempt. REQUIRED: nil is ErrDispatchLeaseRequired.
	DispatchLease DispatchLease
}

// CommunityUploadResult is the service's acknowledgement of a stored (or
// idempotently re-stored) contribution.
type CommunityUploadResult struct {
	Status string
	Replay bool
}

// ResultsPage is one page of enrichment results plus the cursor for the next.
type ResultsPage struct {
	Results    []cloudcontract.ResultRecord
	NextCursor string
}

// UsageView is the account's resolved plan and allowances (value-upgrade
// plan §W5), mirroring cloudclient.UsageView. DigestWeekly /
// ResultsRetentionDays stay pointers all the way through this seam: nil
// means unknown (an older server), never a fabricated false/zero.
type UsageView struct {
	Plan                 string
	PlanLabel            string
	PlanVersion          int
	BudgetPool           string
	DailyCap             int
	MonthlyCap           int
	DigestWeekly         *bool
	ResultsRetentionDays *int
	DigestsThisWeek      int
}

// JobStatus is one hosted enrichment job's status, mirroring
// cloudclient.JobStatus.
type JobStatus struct {
	ID             string
	State          string
	TerminalReason string
	Feature        string
	Attempts       int
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// --- the three narrow session handles ----------------------------------------

// ReadSession is the handle a feature READ receives. It exposes the results
// pull and the account's own plan/usage read — and NOTHING else: an
// unrelated grant that authorizes the read can therefore not be laundered
// into a write, because no write method exists on this type.
type ReadSession struct {
	c *cloudclient.Client
}

// Results fetches enrichment results newer than the opaque cursor.
func (s ReadSession) Results(ctx context.Context, after string) (ResultsPage, error) {
	page, err := s.c.Results(ctx, after)
	if err != nil {
		return ResultsPage{}, err
	}
	return ResultsPage{Results: page.Results, NextCursor: page.NextCursor}, nil
}

// Usage fetches the authenticated account's current plan and allowances
// (GET /v1/usage) — the same consent-gated read lane as Results, no new
// egress path.
func (s ReadSession) Usage(ctx context.Context) (UsageView, error) {
	v, err := s.c.Usage(ctx)
	if err != nil {
		return UsageView{}, err
	}
	return UsageView{
		Plan:                 v.Plan,
		PlanLabel:            v.PlanLabel,
		PlanVersion:          v.PlanVersion,
		BudgetPool:           v.BudgetPool,
		DailyCap:             v.DailyCap,
		MonthlyCap:           v.MonthlyCap,
		DigestWeekly:         v.DigestWeekly,
		ResultsRetentionDays: v.ResultsRetentionDays,
		DigestsThisWeek:      v.DigestsThisWeek,
	}, nil
}

// Job fetches one hosted enrichment job's status (GET /v1/jobs/{id}) — the
// same consent-gated read lane as Results and Usage, no new egress path. id is
// the CLOUD job id (the value UploadResult.JobID carried at submit time), not
// the node's own local outbox id. A 404 surfaces as ErrJobNotFound (re-
// exported below), which a caller classifies with errors.Is.
func (s ReadSession) Job(ctx context.Context, id string) (JobStatus, error) {
	j, err := s.c.Job(ctx, id)
	if err != nil {
		return JobStatus{}, err
	}
	return JobStatus{
		ID:             j.ID,
		State:          j.State,
		TerminalReason: j.TerminalReason,
		Feature:        j.Feature,
		Attempts:       j.Attempts,
		CreatedAt:      j.CreatedAt,
		UpdatedAt:      j.UpdatedAt,
	}, nil
}

// UploadSession is the handle a SESSION-EVIDENCE send receives. It exposes the
// one write that purpose authorizes, plus the endpoint/identity getters the
// caller needs to bind it.
type UploadSession struct {
	c *cloudclient.Client
	// recheck re-resolves the grant that authorized this session. It is composed
	// in FRONT of the caller's own PreAttempt on every physical attempt.
	recheck func() error
}

// DeviceThumbprint returns the device identifier this session's uploads are
// bound to.
func (s UploadSession) DeviceThumbprint() string { return s.c.DeviceThumbprint() }

// UploadEndpoint returns the absolute URL session evidence is POSTed to.
func (s UploadSession) UploadEndpoint() string { return s.c.UploadEndpoint() }

// Upload submits one session-evidence envelope. req.PreAttempt is required.
func (s UploadSession) Upload(ctx context.Context, req UploadRequest) (UploadResult, error) {
	pre, err := composePreAttempt(s.recheck, req.PreAttempt)
	if err != nil {
		return UploadResult{}, err
	}
	resp, err := s.c.Upload(ctx, cloudclient.UploadRequest{
		CloudSessionID: req.CloudSessionID,
		Feature:        req.Feature,
		Envelope:       req.Envelope,
		Digests:        cloudcontract.Digests{Upload: req.UploadDigest},
		SchemaVersion:  req.SchemaVersion,
		PreAttempt:     pre,
		DispatchGuard:  cloudclient.DispatchGuard(req.DispatchLease),
	})
	if err != nil {
		return UploadResult{}, err
	}
	return UploadResult{JobID: resp.JobID, Status: resp.Status}, nil
}

// PreviewConfirmRequest binds the two digests of the EXACT bytes a following
// Upload will carry. Fields mirror the client's contract.
type PreviewConfirmRequest struct {
	Purposes        []string
	FieldClasses    []string
	EvidenceSchema  string
	ScrubberVersion string
	RetentionPolicy string
	Endpoint        string
	UploadDigest    string
	ContentDigest   string
}

// PreviewConfirm registers the confirmed upload/content digests with the server
// immediately before Upload, satisfying the two-digest preview-truth invariant
// (the server admits an upload only for bytes it has seen confirmed). It runs the
// SAME grant re-check as Upload first, so a grant revoked mid-drain can neither
// confirm nor send.
func (s UploadSession) PreviewConfirm(ctx context.Context, req PreviewConfirmRequest) error {
	if s.recheck != nil {
		if err := s.recheck(); err != nil {
			return err
		}
	}
	_, err := s.c.PreviewConfirm(ctx, cloudclient.PreviewConfirmRequest{
		Purposes:        req.Purposes,
		FieldClasses:    req.FieldClasses,
		EvidenceSchema:  req.EvidenceSchema,
		ScrubberVersion: req.ScrubberVersion,
		RetentionPolicy: req.RetentionPolicy,
		Endpoint:        req.Endpoint,
		UploadDigest:    req.UploadDigest,
		ContentDigest:   req.ContentDigest,
	})
	return err
}

// StructuralSession is the handle the STANDING (structural-insights) rail
// receives. It exposes the snapshot write only — not the session-evidence
// write, and not the results read.
type StructuralSession struct {
	c       *cloudclient.Client
	recheck func() error
}

// StructuralEndpoint returns the absolute URL structural snapshots are POSTed to.
func (s StructuralSession) StructuralEndpoint() string { return s.c.StructuralEndpoint() }

// UploadStructural submits one immutable snapshot window. req.PreAttempt is
// required: the drain runs a per-item store re-check there, and a nil hook would
// let a `consent revoke` issued mid-drain be ignored by the POST and its retries.
func (s StructuralSession) UploadStructural(ctx context.Context, req StructuralUploadRequest) (StructuralUploadResult, error) {
	pre, err := composePreAttempt(s.recheck, req.PreAttempt)
	if err != nil {
		return StructuralUploadResult{}, err
	}
	if req.DispatchLease == nil {
		return StructuralUploadResult{}, ErrDispatchLeaseRequired
	}
	resp, err := s.c.UploadStructural(ctx, cloudclient.StructuralUploadRequest{
		Payload:              req.Payload,
		Period:               req.Period,
		PeriodRuleVersion:    req.PeriodRuleVersion,
		SchemaVersion:        req.SchemaVersion,
		Revision:             req.Revision,
		Digest:               req.Digest,
		ConsentGeneration:    req.ConsentGeneration,
		DataDictionaryDigest: req.DataDictionaryDigest,
		SourceWindowRule:     req.SourceWindowRule,
		PreAttempt:           pre,
		DispatchGuard:        cloudclient.DispatchGuard(req.DispatchLease),
	})
	if err != nil {
		return StructuralUploadResult{}, err
	}
	return StructuralUploadResult{SnapshotID: resp.SnapshotID, Status: resp.Status, Replay: resp.Replay}, nil
}

// CommunitySession is the handle the STANDING (cohort-benchmarking) rail
// receives. It exposes the contribution write only — not the snapshot write, the
// session-evidence write, or the results read.
type CommunitySession struct {
	c       *cloudclient.Client
	recheck func() error
}

// CommunityEndpoint returns the absolute URL community contributions are POSTed to.
func (s CommunitySession) CommunityEndpoint() string { return s.c.CommunityEndpoint() }

// UploadCommunity submits one derived per-window contribution. req.PreAttempt is
// required: the caller runs a per-item consent re-check there, and a nil hook
// would let a `consent revoke` issued mid-sync be ignored by the POST + retries.
//
// req.Endpoint (the receipt-bound destination) is compared against this
// session's own live CommunityEndpoint() before every physical attempt,
// including retries: community egress must never dispatch to a destination the
// authorizing receipt did not bind, even if config/--base-url changed after the
// grant was made (Sol review F3).
func (s CommunitySession) UploadCommunity(ctx context.Context, req CommunityUploadRequest) (CommunityUploadResult, error) {
	if req.PreAttempt == nil {
		return CommunityUploadResult{}, ErrPreAttemptRequired
	}
	if req.DispatchLease == nil {
		return CommunityUploadResult{}, ErrDispatchLeaseRequired
	}
	caller := req.PreAttempt
	withEndpointCheck := func() error {
		live := s.CommunityEndpoint()
		if req.Endpoint == "" || req.Endpoint != live {
			return fmt.Errorf("%w: receipt bound to %q, current endpoint is %q",
				ErrEndpointMismatch, req.Endpoint, live)
		}
		return caller()
	}
	pre, err := composePreAttempt(s.recheck, withEndpointCheck)
	if err != nil {
		return CommunityUploadResult{}, err
	}
	resp, err := s.c.UploadCommunity(ctx, cloudclient.CommunityUploadRequest{
		Payload:              req.Payload,
		Digest:               req.Digest,
		ConsentGeneration:    req.ConsentGeneration,
		DataDictionaryDigest: req.DataDictionaryDigest,
		SourceWindowRule:     req.SourceWindowRule,
		DeclaredTimezone:     req.DeclaredTimezone,
		PreAttempt:           pre,
		DispatchGuard:        cloudclient.DispatchGuard(req.DispatchLease),
	})
	if err != nil {
		return CommunityUploadResult{}, err
	}
	return CommunityUploadResult{Status: resp.Status, Replay: resp.Replay}, nil
}

// composePreAttempt refuses a missing caller hook and otherwise runs the
// GATEWAY's grant re-resolve FIRST, then the caller's per-item check. Ordering
// is deliberate: the cheaper, broader "is anything still granted at all?"
// question is asked before the item-specific one, and a revoked grant aborts
// without the item check needing to have been remembered.
func composePreAttempt(recheck, caller func() error) (func() error, error) {
	if caller == nil {
		return nil, ErrPreAttemptRequired
	}
	if recheck == nil {
		return caller, nil
	}
	return func() error {
		if err := recheck(); err != nil {
			return err
		}
		return caller()
	}, nil
}

// --- the three feature entry points -----------------------------------------

// FeatureSend authorizes SESSION-EVIDENCE egress for one consent purpose and,
// only then, hands the write handle to do. Any live grant for the purpose
// authorizes it — per-upload or standing — because both are the developer having
// said yes to this purpose; which SHAPE of grant a particular item needs is the
// store's per-item rule, not this seam's.
//
// The purpose must additionally be one whose rule row permits an evidence
// upload: a purpose whose surface does not exist in this release cannot
// authorize a body leaving the machine (ErrPurposeNotUploadable).
//
// No grant ⇒ ErrNoLiveGrant, returned before the network is touched.
func (g *Gateway) FeatureSend(ctx context.Context, purpose cloudcontract.Purpose, do func(UploadSession) error) error {
	if do == nil {
		return fmt.Errorf("cloudgateway: FeatureSend requires a callback")
	}
	// Lane classification runs FIRST so a bootstrap or unknown purpose keeps its
	// own named refusal; "does this purpose permit an evidence body to leave" is
	// only a meaningful question about a feature purpose.
	switch lane, known := LaneFor(purpose); {
	case !known:
		return fmt.Errorf("%w: %q is not a known consent purpose", ErrNoLiveGrant, string(purpose))
	case lane == LaneBootstrap:
		return fmt.Errorf("%w: %q", ErrBootstrapPurpose, string(purpose))
	}
	if ok, reason := EvidenceUploadable(purpose); !ok {
		return fmt.Errorf("%w: %q — %s", ErrPurposeNotUploadable, string(purpose), reason)
	}
	auth, err := g.authorize(ctx, grantFilter{purpose: purpose})
	if err != nil {
		return err
	}
	return do(UploadSession{c: auth.client, recheck: auth.recheck})
}

// StandingSend is the STRUCTURAL rail's entry point: FeatureSend's authorization
// narrowed to a STANDING grant, handing a handle that can ONLY write snapshots.
// A per-upload receipt for the same purpose does NOT authorize it — a receipt
// that bound one byte-string cannot authorize a rail of future snapshots.
func (g *Gateway) StandingSend(ctx context.Context, purpose cloudcontract.Purpose, do func(StructuralSession) error) error {
	if do == nil {
		return fmt.Errorf("cloudgateway: StandingSend requires a callback")
	}
	// This rail hands out a StructuralSession — a handle that can only write
	// snapshots. Accepting any standing purpose here (rather than exactly the
	// one this rail exists for) would let a grant minted for a DIFFERENT
	// purpose (e.g. cohort_benchmarking) authorize a structural snapshot write
	// (Sol review F4).
	if purpose != cloudcontract.PurposeStructuralInsights {
		return fmt.Errorf("%w: StandingSend only authorizes %q, got %q",
			ErrPurposeMismatch, cloudcontract.PurposeStructuralInsights, purpose)
	}
	auth, err := g.authorize(ctx, grantFilter{purpose: purpose, requireStanding: true})
	if err != nil {
		return err
	}
	return do(StructuralSession{c: auth.client, recheck: auth.recheck})
}

// StandingSendCommunity is the COHORT-BENCHMARKING rail's entry point: like
// StandingSend, it narrows authorization to a STANDING grant for the purpose and
// hands a handle that can ONLY write contributions. A per-upload receipt does
// not authorize it. No live standing grant ⇒ ErrNoLiveGrant, before the network.
func (g *Gateway) StandingSendCommunity(ctx context.Context, purpose cloudcontract.Purpose, do func(CommunitySession) error) error {
	if do == nil {
		return fmt.Errorf("cloudgateway: StandingSendCommunity requires a callback")
	}
	// This rail hands out a CommunitySession — a handle that can only write
	// contributions. Accepting any standing purpose here would let a grant
	// minted for a DIFFERENT purpose (e.g. structural_insights) authorize a
	// community contribution write — a structural<->community
	// cross-authorization (Sol review F4).
	if purpose != cloudcontract.PurposeCohortBenchmarking {
		return fmt.Errorf("%w: StandingSendCommunity only authorizes %q, got %q",
			ErrPurposeMismatch, cloudcontract.PurposeCohortBenchmarking, purpose)
	}
	auth, err := g.authorize(ctx, grantFilter{purpose: purpose, requireStanding: true})
	if err != nil {
		return err
	}
	return do(CommunitySession{c: auth.client, recheck: auth.recheck})
}

// FeatureFetch authorizes a feature READ — the enrichment-results pull — under
// ANY live feature grant, and hands a handle that can only read.
//
// Why any: the pull returns the PRODUCTS of uploads the developer already
// consented to and discloses nothing new outbound (the request carries a
// cursor). Requiring one specific purpose would either refuse a developer their
// own results because they consented under a different purpose, or force a
// purpose to be named that the read does not actually exercise. Requiring
// SOMETHING is still the point: with no live grant at all there is nothing on
// the service that belongs to this device, so the fetch is refused and no
// request is made.
//
// The handle is a ReadSession precisely BECAUSE the check here is broad: an
// unrelated grant must not be able to authorize a write, and the type is what
// guarantees it.
func (g *Gateway) FeatureFetch(ctx context.Context, do func(ReadSession) error) error {
	if do == nil {
		return fmt.Errorf("cloudgateway: FeatureFetch requires a callback")
	}
	auth, err := g.authorize(ctx, grantFilter{})
	if err != nil {
		return err
	}
	return do(ReadSession{c: auth.client})
}

// authorization is what a passed consent check yields: the network client, and
// the RECHECK hook a write method consults before every physical attempt.
type authorization struct {
	client  *cloudclient.Client
	recheck func() error
}

// authorize is the ONE authorization path all three entry points funnel through:
//
//  1. resolve the live grant state, fail-closed;
//  2. confirm the base URL is configured (after the consent check, so a
//     misconfigured node still reports the consent truth first);
//  3. RE-RESOLVE immediately before handing over — the pre-send revocation
//     re-check — and abort if nothing that authorized step 1 is still live;
//  4. only then yield the client, together with a recheck closure that re-runs
//     step 3 before EVERY later physical attempt.
//
// Steps 1 and 3 are deliberately two separate reads. They are cheap (a
// node-local indexed select) and they close the window in which a `revoke` run
// between the decision to send and the send itself would otherwise be ignored.
// Step 4 closes the longer window a multi-item, multi-retry callback opens.
func (g *Gateway) authorize(ctx context.Context, f grantFilter) (authorization, error) {
	authorized, err := g.resolve(ctx, f)
	if err != nil {
		return authorization{}, err
	}
	client, err := g.network()
	if err != nil {
		return authorization{}, err
	}

	// Pre-send revocation re-check: at least one of the receipts that authorized
	// this send must STILL be live at dispatch time.
	recheck := func() error {
		stillLive, rerr := g.resolve(ctx, f)
		if rerr != nil {
			return fmt.Errorf("%w: %w", ErrGrantRevoked, rerr)
		}
		live := make(map[string]bool, len(stillLive))
		for _, gr := range stillLive {
			live[gr.ReceiptID] = true
		}
		for _, gr := range authorized {
			if live[gr.ReceiptID] {
				return nil
			}
		}
		return fmt.Errorf("%w: every grant that authorized this send was revoked or expired mid-flight", ErrGrantRevoked)
	}
	if err := recheck(); err != nil {
		return authorization{}, err
	}
	return authorization{client: client, recheck: recheck}, nil
}
