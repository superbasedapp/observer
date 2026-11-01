package orgclient

import (
	"context"
	"errors"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// accessgrant_target.go - the node's tool / feature grant consumers
// (request-grants G8) over the SAME re-verified grant read the guard uses
// (accessgrant_claim.go): a launcher asking "may this tool start" and the
// governance sidecar writer asking "which pinned settings are excepted" both
// decode what a grant covers from the signed body, and a use is counted by
// the same conditional UPDATE, so a hook, a launcher and the daemon racing on
// a grant's last use cannot all win. Every failure is "no grant": the org's
// block stands.

// TargetClaim is the answer to one tool / model / feature question.
type TargetClaim struct {
	// Hit is the grant; UsesLeft is what remains AFTER a claim's use (-1
	// unlimited).
	Hit accessgrant.Hit
	OK  bool
	// Unverified: the node holds a grant document that no longer verifies,
	// so every grant in it was ignored.
	Unverified bool
}

// ClaimTargetGrant answers q AND counts one use of the covering grant.
func ClaimTargetGrant(ctx context.Context, s *store.Store, q accessgrant.TargetQuery, now time.Time) TargetClaim {
	return claimOrPeekTarget(ctx, s, q, now, true)
}

// PeekTargetGrant answers q without counting a use (a read surface, or a
// caller that counts later).
func PeekTargetGrant(ctx context.Context, s *store.Store, q accessgrant.TargetQuery, now time.Time) TargetClaim {
	return claimOrPeekTarget(ctx, s, q, now, false)
}

func claimOrPeekTarget(ctx context.Context, s *store.Store, q accessgrant.TargetQuery, now time.Time, consume bool) TargetClaim {
	if s == nil || q.Target == "" {
		return TargetClaim{}
	}
	enr, err := s.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return TargetClaim{}
	}
	_ = s.NoteAccessGrantClock(ctx, now.UnixNano())
	for attempt := 0; attempt < maxClaimAttempts; attempt++ {
		v, err := LoadVerifiedAccessGrants(ctx, s)
		if err != nil {
			return TargetClaim{Unverified: errors.Is(err, ErrGrantCacheUnverified)}
		}
		if !v.Present {
			return TargetClaim{}
		}
		hit, ok := accessgrant.MatchTarget(q, v.Grants, v.Receipt, now)
		if !ok {
			return TargetClaim{}
		}
		if !consume {
			return TargetClaim{Hit: hit, OK: true}
		}
		maxUses := int64(0)
		for _, c := range v.Grants {
			if c.Grant.ID == hit.GrantID {
				maxUses = c.Grant.MaxUses
			}
		}
		counted, err := s.ConsumeAccessGrantUse(ctx, hit.GrantID, maxUses)
		if err != nil {
			return TargetClaim{}
		}
		if counted {
			if hit.UsesLeft > 0 {
				hit.UsesLeft--
			}
			return TargetClaim{Hit: hit, OK: true}
		}
	}
	return TargetClaim{}
}

// FeatureException is one pinned setting a verified feature-access grant
// lifts, until UntilNs (accessgrant.HonouredUntilNs: the earliest of the
// grant's expiry, its remaining TTL at receipt and the offline window).
type FeatureException struct {
	GrantID int64
	UntilNs int64
}

// FeatureGrantExceptions reports, for each of keys, the honoured feature
// grant that lifts its pin, if any. A cache that no longer verifies yields
// none (fail closed: every pin stands). Nothing is counted: a feature grant
// is time-bound only.
func FeatureGrantExceptions(ctx context.Context, s *store.Store, keys []string, now time.Time) (map[string]FeatureException, error) {
	out := map[string]FeatureException{}
	if s == nil || len(keys) == 0 {
		return out, nil
	}
	enr, err := s.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return out, err
	}
	v, err := LoadVerifiedAccessGrants(ctx, s)
	if err != nil {
		if errors.Is(err, ErrGrantCacheUnverified) {
			return out, nil
		}
		return out, err
	}
	if !v.Present {
		return out, nil
	}
	for _, k := range keys {
		hit, ok := accessgrant.MatchTarget(accessgrant.TargetQuery{Type: accessgrant.TypeFeatureEnable, Target: k}, v.Grants, v.Receipt, now)
		if !ok {
			continue
		}
		for _, c := range v.Grants {
			if c.Grant.ID == hit.GrantID {
				out[k] = FeatureException{GrantID: hit.GrantID, UntilNs: accessgrant.HonouredUntilNs(c.Grant, v.Receipt)}
			}
		}
	}
	return out, nil
}

// PageGrants lists the node dashboard pages and tabs the honoured page-access
// grants show on this machine (T-435). A cache that no longer verifies
// yields none (fail closed: the org's hiding stands). Nothing is counted: a
// page grant is time-bound only.
func PageGrants(ctx context.Context, s *store.Store, now time.Time) ([]string, error) {
	return honouredGrantTargets(ctx, s, accessgrant.TypePageAccess, now)
}

// ConfigEditGrants lists the AI tool settings (ids or "<tool>/*") the
// honoured edit grants open on this machine (T-436). Fail closed like
// PageGrants: an unverified cache opens nothing.
func ConfigEditGrants(ctx context.Context, s *store.Store, now time.Time) ([]string, error) {
	return honouredGrantTargets(ctx, s, accessgrant.TypeConfigEdit, now)
}

// ComponentGrants lists the node components the honoured component_enable
// grants activate on this machine (modular packaging P4, lane MP-GOV). Fail
// closed like PageGrants: an unverified cache activates nothing. The one
// resolver decides what a grant may override (a grantable deny and the
// unlisted rule, never the ceiling or a missing build).
func ComponentGrants(ctx context.Context, s *store.Store, now time.Time) ([]string, error) {
	return honouredGrantTargets(ctx, s, accessgrant.TypeComponentEnable, now)
}

// honouredGrantTargets is the one verified read behind PageGrants and
// ConfigEditGrants.
func honouredGrantTargets(ctx context.Context, s *store.Store, typ string, now time.Time) ([]string, error) {
	if s == nil {
		return nil, nil
	}
	enr, err := s.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return nil, err
	}
	v, err := LoadVerifiedAccessGrants(ctx, s)
	if err != nil {
		if errors.Is(err, ErrGrantCacheUnverified) {
			return nil, nil
		}
		return nil, err
	}
	if !v.Present {
		return nil, nil
	}
	return accessgrant.HonouredTargets(typ, v.Grants, v.Receipt, now), nil
}

// FindingExceptionGrant is one honoured finding_exception grant (lane
// SEC-E3): the finding's wire handle, its rule and when the grant stops
// being honoured on this node (zero: perpetual and online).
type FindingExceptionGrant struct {
	GrantID    int64
	FindingRef string
	RuleID     string
	UntilNs    int64
}

// FindingExceptionGrants lists the honoured finding_exception grants on this
// machine. Fail closed like PageGrants: an unverified cache, or no
// enrolment, yields none, so every org exception ends and its finding
// reopens.
func FindingExceptionGrants(ctx context.Context, s *store.Store, now time.Time) ([]FindingExceptionGrant, error) {
	if s == nil {
		return nil, nil
	}
	enr, err := s.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return nil, err
	}
	v, err := LoadVerifiedAccessGrants(ctx, s)
	if err != nil {
		if errors.Is(err, ErrGrantCacheUnverified) {
			return nil, nil
		}
		return nil, err
	}
	if !v.Present {
		return nil, nil
	}
	var out []FindingExceptionGrant
	for _, c := range v.Grants {
		g := c.Grant
		if g.Type != accessgrant.TypeFindingException || g.Target == "" {
			continue
		}
		if ok, _ := accessgrant.Honoured(g, c.UsesUsed, v.Receipt, now); !ok {
			continue
		}
		out = append(out, FindingExceptionGrant{GrantID: g.ID, FindingRef: g.Target, RuleID: g.RuleID, UntilNs: accessgrant.HonouredUntilNs(g, v.Receipt)})
	}
	return out, nil
}
