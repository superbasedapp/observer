package cloudgateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Sentinel errors callers branch on with errors.Is.
var (
	// ErrNoLiveGrant is THE refusal of this package: no live consent grant
	// authorizes the requested feature egress. It is returned before any network
	// attempt is made, so a caller that sees it knows nothing left the machine.
	ErrNoLiveGrant = errors.New("cloudgateway: no live consent grant authorizes this cloud feature")
	// ErrGrantRevoked is returned when a grant that was live at resolution time
	// was invalidated (or expired) before the send was dispatched — the pre-send
	// revocation re-check. The send is abandoned, not retried.
	ErrGrantRevoked = errors.New("cloudgateway: the consent grant was revoked before the send was dispatched")
	// ErrBootstrapPurpose is returned when the account/device bootstrap purpose
	// is passed to the FEATURE lane. Bootstrap egress has its own named methods;
	// routing it through the feature lane would ask for a grant that, by design,
	// no one ever mints.
	ErrBootstrapPurpose = errors.New("cloudgateway: account_device_operations is bootstrap egress, not a feature purpose — use the Bootstrap* methods")
	// ErrNoConsentSource is returned when the gateway was constructed without a
	// GrantStore and a feature send is attempted. Fail closed: an unconfigured
	// consent source is not an authorized one.
	ErrNoConsentSource = errors.New("cloudgateway: no consent source is configured, so no feature egress can be authorized")
	// ErrNoBaseURL is returned when a network method is called on a gateway that
	// has no cloud base URL configured.
	ErrNoBaseURL = errors.New("cloudgateway: no cloud base URL is configured")
	// ErrPurposeNotUploadable is returned when a SESSION-EVIDENCE send names a
	// purpose whose rule row does not permit an evidence upload. A live grant is
	// necessary but not sufficient: consenting to a purpose whose surface does
	// not exist in this release cannot authorize a body leaving the machine.
	ErrPurposeNotUploadable = errors.New("cloudgateway: this consent purpose does not authorize a session-evidence upload")
	// ErrPurposeMismatch is returned when a STANDING rail entry point
	// (StandingSend / StandingSendCommunity) is called with a purpose other than
	// the exact one that rail exists for. Each standing rail hands out a session
	// handle that can only perform ITS write; accepting any standing purpose
	// would let a grant minted for one rail (e.g. structural_insights) authorize
	// a write on a different rail (e.g. cohort_benchmarking) — a
	// structural<->community cross-authorization (Sol review F4).
	ErrPurposeMismatch = errors.New("cloudgateway: this purpose does not authorize this standing rail")
	// ErrEndpointMismatch is returned when the endpoint a receipt bound at grant
	// time no longer matches the endpoint the current configuration would send
	// to. A live grant is necessary but not sufficient: the developer agreed to
	// send bytes to a specific origin, and a config/--base-url change after
	// granting must not silently redirect an already-authorized send to a
	// different one (Sol review F3). Fails closed before any network attempt.
	ErrEndpointMismatch = errors.New("cloudgateway: the receipt-bound endpoint no longer matches the configured endpoint")
	// ErrDispatchLeaseRequired is returned when a STANDING-rail upload is
	// submitted without a dispatch lease (Sol re-review N2). The lease is the
	// cross-process, DB-backed guard taken immediately before every physical
	// attempt and released after it; without one, a `consent revoke` issued
	// between the per-attempt re-check and the socket write could return —
	// having promised nothing further will be sent — while the paused sender
	// still dispatches. Requiring it here is what stops a future call site
	// from forgetting it, exactly as ErrPreAttemptRequired does for the
	// re-check.
	ErrDispatchLeaseRequired = errors.New(
		"cloudgateway: a standing-rail upload requires a DispatchLease; without one a revoked send could still dispatch",
	)
)

// GrantStore is the narrow store surface the gateway reads consent state from.
// *store.Store satisfies it; a test fake is three lines. Keeping it narrow is
// what lets the gateway be tested with zero database and zero filesystem.
type GrantStore interface {
	// ListLiveCloudConsentReceipts returns the not-invalidated receipts for a
	// purpose ("" = every purpose), newest first.
	ListLiveCloudConsentReceipts(ctx context.Context, purpose string) ([]store.CloudConsentReceipt, error)
}

// Grant is the live consent state the gateway resolved for a purpose. It is a
// read-only projection of a receipt: everything a caller needs to know what the
// developer agreed to, and nothing it could use to bypass the store's own
// per-item checks.
type Grant struct {
	// ReceiptID is the receipt this grant came from — the id a queued snapshot
	// binds itself to.
	ReceiptID string
	// Purpose is the consent purpose granted.
	Purpose cloudcontract.Purpose
	// Standing reports whether the grant authorizes a SCHEMA (standing) rather
	// than one exact upload (per-upload).
	Standing bool
	// Endpoint is the origin+path the receipt bound. The store enforces it
	// per item; it is surfaced here for honest output.
	Endpoint string
	// DataDictionaryDigest is the schema-level digest a standing grant binds.
	DataDictionaryDigest string
	// DeclaredTimezone is the IANA zone the account declared — what gives a
	// window period its meaning.
	DeclaredTimezone string
	// SourceWindowRule is the versioned rule identifying which activity a
	// standing grant covers.
	SourceWindowRule string
	// SchemaVersion is the envelope/snapshot schema version bound.
	SchemaVersion string
	// ConsentGeneration is the monotonic terms-changed counter.
	ConsentGeneration int
	// CreatedAt is when the grant was recorded. Capture never reaches back
	// before it: a standing grant authorizes future windows, not history the
	// developer had not agreed to when they granted it.
	CreatedAt time.Time
	// ReviewAt is the expiry / review date; nil means none was set.
	ReviewAt *time.Time
}

// Lane names which egress lane a purpose belongs to.
type Lane int

const (
	// LaneFeature is session- or window-derived egress: requires a live grant.
	LaneFeature Lane = iota
	// LaneBootstrap is authentication / account-device egress: authorized by the
	// user's own sign-in action, never by a stored grant.
	LaneBootstrap
)

// purposeRule is one row of the purpose table. Consent policy is DATA here
// (CLAUDE.md §5: an ordered rule set is a table, not an if-ladder), so adding a
// purpose to the standing-grant surface is a one-line data change with a test
// row, not a new branch in the CLI.
type purposeRule struct {
	// lane is the egress lane the purpose belongs to.
	lane Lane
	// standingGrantable reports whether a STANDING grant may be minted for this
	// purpose in this arc.
	standingGrantable bool
	// notYetReason is the honest copy shown when standingGrantable is false. It
	// says what the purpose actually needs, never "coming soon".
	notYetReason string
	// evidenceUploadable reports whether a live grant for this purpose may
	// authorize a SESSION-EVIDENCE upload — a body derived from one session
	// leaving the machine. It is a SEPARATE question from standingGrantable: a
	// purpose can be consentable per session (context enrichment) without being
	// grantable schema-wide, and a purpose whose consuming surface does not exist
	// yet must authorize neither.
	evidenceUploadable bool
	// noUploadReason is the honest copy shown when evidenceUploadable is false.
	noUploadReason string
}

// purposeRules is the closed table over cloudcontract's seven-purpose
// vocabulary. TestPurposeRulesCoverEveryPurpose pins that it stays exhaustive.
var purposeRules = map[cloudcontract.Purpose]purposeRule{
	cloudcontract.PurposeAccountDeviceOps: {
		lane: LaneBootstrap,
		notYetReason: "account and device operations are authorized by your own sign-in action, " +
			"not by a stored grant — there is nothing to grant here",
		noUploadReason: "account and device operations send no session-derived data at all; they are the " +
			"Bootstrap* methods, not a feature upload",
	},
	cloudcontract.PurposeStructuralInsights: {
		lane:               LaneFeature,
		standingGrantable:  true,
		evidenceUploadable: true,
	},
	cloudcontract.PurposeContextEnrichment: {
		lane: LaneFeature,
		notYetReason: "bounded context excerpts are consented per session, against the literal bytes " +
			"you preview (`observer cloud preview` then `observer cloud consent --session <id>`); " +
			"there is no schema-level standing grant for excerpt content in this release",
		evidenceUploadable: true,
	},
	cloudcontract.PurposeExtendedEvidence: {
		lane: LaneFeature,
		notYetReason: "extended evidence is just-in-time consent for one previewed job; no paid job kind " +
			"ships yet, so there is nothing a standing grant could authorize",
		evidenceUploadable: true,
	},
	cloudcontract.PurposeCohortBenchmarking: {
		lane:              LaneFeature,
		standingGrantable: true,
		// evidenceUploadable is deliberately false: cohort benchmarking authorizes
		// ONLY the derived per-window scalar contribution rail
		// (StandingSendCommunity / cloudSyncCommunity), never a SESSION-EVIDENCE
		// upload (a full envelope of actions + metrics for one session). Before this
		// fix, evidenceUploadable=true let `observer cloud consent --session S
		// --purpose community_cohort_benchmarking` build/enqueue/transmit a full
		// session envelope under a grant a developer gave for a single number
		// (Sol review F4).
		evidenceUploadable: false,
		noUploadReason: "cohort benchmarking authorizes only the derived per-window contribution upload " +
			"(the community leg of `observer cloud sync`), not a session-evidence upload — there is no " +
			"session body this purpose can send",
	},
	cloudcontract.PurposePublicProfile: {
		lane: LaneFeature,
		notYetReason: "public profiles are not implemented in this release; granting one now would " +
			"authorize a surface that does not exist",
		noUploadReason: "public profiles are not implemented in this release; uploading under this purpose " +
			"would send a body to a surface that does not exist",
	},
	cloudcontract.PurposeResearch: {
		lane: LaneFeature,
		notYetReason: "the research corpus is separately described and separately consented; it is not " +
			"part of this release",
		noUploadReason: "the research corpus is separately described and separately consented; no upload " +
			"path for it exists in this release",
	},
}

// LaneFor reports which egress lane a purpose belongs to. ok=false means the
// purpose is not in the closed vocabulary.
func LaneFor(p cloudcontract.Purpose) (Lane, bool) {
	rule, ok := purposeRules[p]
	if !ok {
		return LaneFeature, false
	}
	return rule.lane, true
}

// StandingGrantable reports whether a STANDING grant may be minted for a
// purpose. When it may not, reason is honest copy explaining what the purpose
// actually requires — for the CLI to print verbatim rather than inventing its
// own wording.
func StandingGrantable(p cloudcontract.Purpose) (bool, string) {
	rule, ok := purposeRules[p]
	if !ok {
		return false, fmt.Sprintf("%q is not a known consent purpose", string(p))
	}
	if rule.standingGrantable {
		return true, ""
	}
	return false, rule.notYetReason
}

// EvidenceUploadable reports whether a purpose may authorize a SESSION-EVIDENCE
// upload. When it may not, reason is honest copy naming what is missing — for
// the CLI to print verbatim at consent time rather than letting a developer mint
// a receipt that could only ever be refused at send time.
func EvidenceUploadable(p cloudcontract.Purpose) (bool, string) {
	rule, ok := purposeRules[p]
	if !ok {
		return false, fmt.Sprintf("%q is not a known consent purpose", string(p))
	}
	if rule.evidenceUploadable {
		return true, ""
	}
	return false, rule.noUploadReason
}

// StandingGrantablePurposes returns the purposes a standing grant may be minted
// for, in the contract's canonical order.
func StandingGrantablePurposes() []cloudcontract.Purpose {
	var out []cloudcontract.Purpose
	for _, p := range cloudcontract.AllPurposes() {
		if ok, _ := StandingGrantable(p); ok {
			out = append(out, p)
		}
	}
	return out
}

// grantFilter names what a resolution requires. It is a value rather than a pair
// of booleans threaded through call sites so the three feature entry points all
// funnel into ONE resolver.
type grantFilter struct {
	// purpose narrows to one purpose; the zero value means "any feature
	// purpose" (the enrichment-results fetch, which discloses nothing new).
	purpose cloudcontract.Purpose
	// requireStanding additionally requires grant_mode='standing'.
	requireStanding bool
}

// describe renders the filter for an honest refusal message.
func (f grantFilter) describe() string {
	switch {
	case f.purpose == "":
		return "any cloud feature"
	case f.requireStanding:
		return fmt.Sprintf("a standing grant for %q", string(f.purpose))
	default:
		return fmt.Sprintf("purpose %q", string(f.purpose))
	}
}

// remedy renders the command that would fix the refusal.
func (f grantFilter) remedy() string {
	if f.purpose == "" {
		return "run `observer cloud consent grant --purpose <purpose>` (or consent to a session with " +
			"`observer cloud consent --session <id> --purpose <purpose>`) first"
	}
	if f.requireStanding {
		return fmt.Sprintf("run `observer cloud consent grant --purpose %s` first", string(f.purpose))
	}
	return fmt.Sprintf("run `observer cloud consent --session <id> --purpose %s` first", string(f.purpose))
}

// resolve returns every live grant matching the filter, FAIL-CLOSED: a missing
// consent source, a bootstrap purpose, an unknown purpose, a store error, or an
// empty result are all refusals, never a permissive default.
//
// Expiry is applied HERE rather than in SQL, because it is clock policy: a
// receipt whose review_at has passed is no longer a live authorization, and one
// place decides that (with an injectable clock).
func (g *Gateway) resolve(ctx context.Context, f grantFilter) ([]Grant, error) {
	if g.grants == nil {
		return nil, fmt.Errorf("%w (%s)", ErrNoConsentSource, f.describe())
	}
	if f.purpose != "" {
		lane, known := LaneFor(f.purpose)
		if !known {
			return nil, fmt.Errorf("%w: %q is not a known consent purpose", ErrNoLiveGrant, string(f.purpose))
		}
		if lane == LaneBootstrap {
			return nil, fmt.Errorf("%w: %q", ErrBootstrapPurpose, string(f.purpose))
		}
	}

	rows, err := g.grants.ListLiveCloudConsentReceipts(ctx, string(f.purpose))
	if err != nil {
		return nil, fmt.Errorf("cloudgateway: read consent state: %w", err)
	}

	now := g.now()
	var out []Grant
	for _, r := range rows {
		// Defence in depth: the store filters invalidated rows in SQL, but this
		// seam must not depend on that to stay closed.
		if r.InvalidatedAt != nil {
			continue
		}
		if r.ReviewAt != nil && !r.ReviewAt.After(now) {
			continue
		}
		// A bootstrap-purpose receipt can only exist if something minted one; it
		// still authorizes no feature egress.
		if lane, known := LaneFor(cloudcontract.Purpose(r.Purpose)); !known || lane == LaneBootstrap {
			continue
		}
		standing := r.GrantMode == store.CloudGrantStanding
		if f.requireStanding && !standing {
			continue
		}
		out = append(out, Grant{
			ReceiptID:            r.ID,
			Purpose:              cloudcontract.Purpose(r.Purpose),
			Standing:             standing,
			Endpoint:             r.Endpoint,
			DataDictionaryDigest: r.DataDictionaryDigest,
			DeclaredTimezone:     r.DeclaredTimezone,
			SourceWindowRule:     r.SourceWindowRule,
			SchemaVersion:        r.EnvelopeSchemaVersion,
			ConsentGeneration:    r.ConsentGeneration,
			CreatedAt:            r.CreatedAt,
			ReviewAt:             r.ReviewAt,
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: nothing grants %s — %s", ErrNoLiveGrant, f.describe(), f.remedy())
	}
	return out, nil
}

// ResolveStandingGrant returns the newest live STANDING grant for a purpose. It
// makes NO network call — it is the read a capture pass needs (the declared
// timezone, the grant's creation day, the receipt to bind snapshots to) before
// deciding whether there is anything to capture at all.
func (g *Gateway) ResolveStandingGrant(ctx context.Context, purpose cloudcontract.Purpose) (Grant, error) {
	grants, err := g.resolve(ctx, grantFilter{purpose: purpose, requireStanding: true})
	if err != nil {
		return Grant{}, err
	}
	return grants[0], nil
}
