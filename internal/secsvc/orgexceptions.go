//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secexcept"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Org finding exceptions (security plan 5.12 and 7.5, lane SEC-E3): the
// node half of the org's finding_exception request type. The org server
// decides a grant (write:security, never its requester, a perpetual or
// critical-finding one by the super admin); the node's verified grant cache
// (internal/orgclient) holds it; this sync applies each honoured grant to the
// local exception register, the same register the developer's own
// exceptions use, so the commit gate and every surface read one place.
//
// An org exception is recorded with reason accepted_risk, granted_by
// "org:<grant id>" and a 30-day window capped at the grant's own expiry
// (the register's closed expiry picker has no "org" value, and node
// migration 183 pins it): while the grant stays honoured, a window that
// ends is applied again on the next pass. A grant that is no longer
// honoured (revoked, expired, superseded, or the cache no longer verifies)
// ends its exception at once and the finding reopens.

// OrgException is one honoured org finding_exception grant.
type OrgException struct {
	GrantID int64
	// FindingRef is the finding's wire handle (store.SecurityFindingRef).
	FindingRef string
	RuleID     string
	// ExpiresAt is the grant's expiry; zero is a perpetual grant.
	ExpiresAt time.Time
}

// OrgExceptionDeps are the sync's injected I/O.
type OrgExceptionDeps struct {
	Store ExceptionStore
	// OpenFindings lists the node's open findings.
	OpenFindings func(ctx context.Context) ([]secfinding.Finding, error)
	// Ref is the wire handle of a finding id.
	Ref func(id string) string
	Now func() time.Time
}

// OrgSyncResult counts what one sync did.
type OrgSyncResult struct {
	Applied int
	Ended   int
}

// orgGrantedByPrefix marks an exception applied from an org grant.
const orgGrantedByPrefix = string(secexcept.OriginOrg) + ":"

// orgWindow is the longest one applied window of an org exception.
const orgWindow = 30 * 24 * time.Hour

// OrgGrantedBy is the granted_by value of an exception applied from grant id.
func OrgGrantedBy(grantID int64) string {
	return orgGrantedByPrefix + strconv.FormatInt(grantID, 10)
}

// SyncOrgExceptions applies the honoured grants to the register and ends
// the org exceptions whose grant is no longer among them.
func SyncOrgExceptions(ctx context.Context, d OrgExceptionDeps, grants []OrgException) (OrgSyncResult, error) {
	var out OrgSyncResult
	if d.Store == nil || d.OpenFindings == nil || d.Ref == nil {
		return out, errors.New("secsvc.SyncOrgExceptions: incomplete deps")
	}
	now := time.Now()
	if d.Now != nil {
		now = d.Now()
	}
	open, err := d.Store.ListSecExceptions(ctx, store.SecExceptionFilter{OpenOnly: true, Limit: sweepPage})
	if err != nil {
		return out, fmt.Errorf("secsvc.SyncOrgExceptions: %w", err)
	}
	wanted := map[string]OrgException{}
	for _, g := range grants {
		wanted[OrgGrantedBy(g.GrantID)] = g
	}
	applied := map[string]bool{}
	for _, e := range open {
		if !strings.HasPrefix(e.GrantedBy, orgGrantedByPrefix) {
			continue
		}
		if _, ok := wanted[e.GrantedBy]; ok {
			applied[e.GrantedBy] = true
			continue
		}
		if err := d.Store.EndSecException(ctx, e.ID, store.SecExceptionRevoked, now); err != nil && !errors.Is(err, store.ErrSecExceptionNotFound) {
			return out, fmt.Errorf("secsvc.SyncOrgExceptions: %w", err)
		}
		out.Ended++
	}
	var pending []OrgException
	for by, g := range wanted {
		if !applied[by] && (g.ExpiresAt.IsZero() || now.Before(g.ExpiresAt)) {
			pending = append(pending, g)
		}
	}
	if len(pending) == 0 {
		return out, nil
	}
	findings, err := d.OpenFindings(ctx)
	if err != nil {
		return out, fmt.Errorf("secsvc.SyncOrgExceptions: %w", err)
	}
	byRef := map[string]secfinding.Finding{}
	for _, f := range findings {
		if f.Status == policy.FindingStatusOpen {
			byRef[d.Ref(f.ID)] = f
		}
	}
	reason, _ := secexcept.ReasonFor(string(secexcept.ReasonAcceptedRisk))
	for _, g := range pending {
		f, ok := byRef[g.FindingRef]
		if !ok || f.Rule.ID != g.RuleID {
			continue
		}
		until := now.Add(orgWindow)
		if !g.ExpiresAt.IsZero() && g.ExpiresAt.Before(until) {
			until = g.ExpiresAt
		}
		row := store.SecException{
			FindingID: f.ID, ProjectRootHash: f.Project.RootHash, RuleID: f.Rule.ID, Reason: string(reason.ID),
			Expiry: string(secexcept.Expiry30Days), ExpiresAt: until.UTC(), GrantedBy: OrgGrantedBy(g.GrantID),
			GrantedAt: now.UTC(), RelPath: f.Location.RelPath,
		}
		if _, err := d.Store.GrantSecException(ctx, row, reason.Status); err != nil {
			if errors.Is(err, store.ErrSecFindingNotOpen) {
				continue
			}
			return out, fmt.Errorf("secsvc.SyncOrgExceptions: %w", err)
		}
		out.Applied++
	}
	return out, nil
}
