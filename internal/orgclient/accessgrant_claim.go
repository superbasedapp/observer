package orgclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/machineid"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// accessgrant_claim.go - the ONE reader of the node's grant cache for every
// decision (request-grants design §3.2, phase G3). The hook process, the
// daemon's guard and the dashboard all come here, so they read the same
// verified state: the cached document is RE-VERIFIED on every read (its
// signature, its org, its key against the enrolment trust root, and its
// subject against THIS node's live member|machine subject, exactly), and
// what a grant covers, its window, its use limit and the offline window are
// decoded from the signed body.
//
// What a same-user writer of the node database CAN still move (review
// C156-37, stated honestly rather than claimed away): the local use counters
// (org_access_grants.uses_used) and the node's own clock observations
// (received_at_ns, last_verified_ns, high_water_ns) are unsigned by nature.
// Editing them can stretch the offline window or reset a use count; it can
// never widen what a grant covers, move it past its signed expiry, raise its
// signed use limit or its signed offline window, or carry it to another
// member or machine. The org sees every use as a shipped guard event
// (GRANT-4), so an over-spend is visible there.

// ErrGrantCacheUnverified is a grant cache that no longer verifies: every
// grant in it is treated as absent (fail closed, toward enforcement).
var ErrGrantCacheUnverified = errors.New("orgclient: the cached access-grant document does not verify")

// VerifiedAccessGrants is the node's grant picture after re-verification.
type VerifiedAccessGrants struct {
	// Present is false when the node holds no grant document for its current
	// enrolment (every solo install, and an enrolled node before its first
	// verified fetch).
	Present bool
	Grants  []accessgrant.Cached
	Receipt accessgrant.Receipt
	State   store.AccessGrantState
}

// LoadVerifiedAccessGrants re-verifies the cached grant document. Not
// enrolled, or nothing cached for this enrolment's org, is Present=false
// with no error. A cache that fails verification returns
// ErrGrantCacheUnverified (wrapped with the reason).
func LoadVerifiedAccessGrants(ctx context.Context, s *store.Store) (VerifiedAccessGrants, error) {
	if s == nil {
		return VerifiedAccessGrants{}, nil
	}
	enr, err := s.LoadEnrolment(ctx)
	if err != nil {
		return VerifiedAccessGrants{}, fmt.Errorf("orgclient.LoadVerifiedAccessGrants: enrolment: %w", err)
	}
	if enr == nil {
		return VerifiedAccessGrants{}, nil
	}
	st, ok, err := s.GetAccessGrantState(ctx)
	if err != nil {
		return VerifiedAccessGrants{}, fmt.Errorf("%w: %w", ErrGrantCacheUnverified, err)
	}
	if !ok || st.OrgID != enr.OrgID {
		return VerifiedAccessGrants{}, nil
	}
	unverified := func(why string) (VerifiedAccessGrants, error) {
		return VerifiedAccessGrants{Present: true, State: st}, fmt.Errorf("%w: %s", ErrGrantCacheUnverified, why)
	}
	// The subject is compared EXACTLY with this node's live member|machine
	// subject (C156-27 / M3-02): a machine-scoped document copied from
	// another machine of the same member does not verify here.
	managed, err := NodeManagedFor(ctx, s, enr)
	if err != nil {
		return unverified("the node's managed state cannot be read: " + err.Error())
	}
	if want, _ := grantSubjectFor(enr, managed); st.Subject != want {
		return unverified(fmt.Sprintf("the document is for subject %q, this node is %q", st.Subject, want))
	}
	states, err := s.LatestGuardPolicyStates(ctx)
	if err != nil {
		return unverified("the enrolment trust root cannot be read: " + err.Error())
	}
	if why := grantKeyAgainstTrustRoot(states, enr.OrgServerURL, st.ServerPubkey); why != "" {
		return unverified(why)
	}
	doc := orgcontract.AccessGrantDoc{
		OrgID: st.OrgID, Subject: st.Subject, Version: st.Version, Body: st.Body,
		BodyHash: st.BodyHash, Signature: st.Signature, PublicKey: st.ServerPubkey,
	}
	if err := orgcontract.VerifyAccessGrants(doc, enr.OrgID, st.Subject, st.ServerPubkey); err != nil {
		return unverified(err.Error())
	}
	body, err := orgcontract.DecodeAccessGrantBody(st.Body)
	if err != nil {
		return unverified(err.Error())
	}
	rows, err := s.CachedAccessGrants(ctx)
	if err != nil {
		return unverified("the local use counters cannot be read: " + err.Error())
	}
	uses := make(map[int64]int64, len(rows))
	for _, r := range rows {
		uses[r.Grant.ID] = r.UsesUsed
	}
	// The server clock and the offline window come from the SIGNED body, not
	// from their unsigned cache columns (C156-37): an edited max_offline_s
	// column can no longer stretch the offline window.
	rc := st.Receipt()
	rc.ServerNowNs, rc.MaxOfflineS = body.ServerNowNs, body.MaxOfflineS
	out := VerifiedAccessGrants{Present: true, Receipt: rc, State: st}
	for _, g := range body.Grants {
		used, ok := uses[g.ID]
		if !ok && g.MaxUses > 0 {
			// No counter row for a use-limited grant: its uses cannot be
			// counted, so it is read as spent (fail closed).
			used = g.MaxUses
		}
		out.Grants = append(out.Grants, accessgrant.Cached{Grant: g, UsesUsed: used})
	}
	return out, nil
}

// grantSubjectFor is the subject this node fetches and verifies grants under,
// right now: the member, plus the org-salted machine identity on a managed
// node (the same identity BindMachine and the fetch present). managed is
// NodeManagedFor: a managed enrolment, or one whose org switched it to
// enterprise (operator rulings P-204 and P-205), whose access requests
// declare managed and name this machine. It is the one owner of that subject
// for the fetch and for every read.
func grantSubjectFor(enr *store.Enrolment, managed bool) (subject, machine string) {
	if enr == nil {
		return orgcontract.AccessGrantSubject("", ""), ""
	}
	if managed {
		if mid, err := machineid.ForOrg(enr.OrgID); err == nil {
			machine = orgcontract.SanitizeMachineHeader(mid)
		}
	}
	return orgcontract.AccessGrantSubject(enr.UserID, machine), machine
}

// grantKeyAgainstTrustRoot checks the key the cached document was verified
// under against what the ENROLMENT established (orgpin.go's trust root): the
// enrolment key material when the node holds it, else the enrolment pin hash.
// With neither (an enrolment that predates both rows) the rail's own
// trust-on-first-fetch pin stands, exactly as the fetch accepted it. Returns
// "" when the key is acceptable.
func grantKeyAgainstTrustRoot(states []store.GuardPolicyStateRow, orgURL, key string) string {
	if material := materialFromStates(states, orgKeyMaterialPath(orgURL)); material != "" {
		if material != key {
			return fmt.Sprintf("the document was verified under key %s..., the enrolment pinned %s...", prefix8(key), prefix8(material))
		}
		return ""
	}
	if hash, _ := keyPinFromStates(states, PolicyKeyPinPath(orgURL)); hash != "" {
		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(raw) != ed25519.PublicKeySize || orgcontract.PublicKeyPinHash(raw) != hash {
			return fmt.Sprintf("the document's key %s... does not hash to the enrolment pin %s...", prefix8(key), prefix12(hash))
		}
	}
	return ""
}

// GrantClaim is the answer to one guard decision.
type GrantClaim struct {
	// Hit is the grant that covered the call; UsesLeft is what remains AFTER
	// this call's use (-1 unlimited).
	Hit accessgrant.Hit
	OK  bool
	// LockRefused: a grant would have covered the call, but the rule is
	// locked by the org and the grant was not issued under the locked-rule
	// approval rule.
	LockRefused bool
	// Unverified: the node holds a grant document that no longer verifies,
	// so every grant in it was ignored.
	Unverified bool
}

// maxClaimAttempts bounds the re-read after a lost race: each attempt that
// fails to count a use re-reads the counters, and a grant whose last use
// another process took no longer matches on the next read.
const maxClaimAttempts = 4

// ClaimAccessGrant answers the guard's grant question for one call AND
// counts the use (design §3.2 rows 2-3). The use is counted by one
// conditional UPDATE (store.ConsumeAccessGrantUse) bounded by the
// SIGNED max_uses, so two hook processes racing on the last use cannot both
// win: SQLite serialises the writes and the loser's UPDATE changes nothing,
// after which it re-reads and finds the grant spent. Every failure is "no
// grant" (enforcement stands); nothing here touches the network.
func ClaimAccessGrant(ctx context.Context, s *store.Store, q accessgrant.Query, now time.Time) GrantClaim {
	if s == nil || q.RuleID == "" {
		return GrantClaim{}
	}
	enr, err := s.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return GrantClaim{}
	}
	_ = s.NoteAccessGrantClock(ctx, now.UnixNano())
	for attempt := 0; attempt < maxClaimAttempts; attempt++ {
		v, err := LoadVerifiedAccessGrants(ctx, s)
		if err != nil {
			return GrantClaim{Unverified: errors.Is(err, ErrGrantCacheUnverified)}
		}
		if !v.Present {
			return GrantClaim{}
		}
		res := accessgrant.MatchDetail(q, v.Grants, v.Receipt, now)
		if !res.OK {
			return GrantClaim{LockRefused: res.LockRefused}
		}
		maxUses := int64(0)
		for _, c := range v.Grants {
			if c.Grant.ID == res.Hit.GrantID {
				maxUses = c.Grant.MaxUses
			}
		}
		counted, err := s.ConsumeAccessGrantUse(ctx, res.Hit.GrantID, maxUses)
		if err != nil {
			return GrantClaim{}
		}
		if counted {
			hit := res.Hit
			if hit.UsesLeft > 0 {
				hit.UsesLeft--
			}
			return GrantClaim{Hit: hit, OK: true}
		}
	}
	return GrantClaim{}
}

// PeekAccessGrant is ClaimAccessGrant without counting a use: the same
// re-verified read and the same match, for the guard's "is there a grant at
// all" question (a soften grant offered on a host that cannot ask counts
// nothing until the developer confirms). It never writes a counter.
func PeekAccessGrant(ctx context.Context, s *store.Store, q accessgrant.Query, now time.Time) GrantClaim {
	if s == nil || q.RuleID == "" {
		return GrantClaim{}
	}
	enr, err := s.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return GrantClaim{}
	}
	_ = s.NoteAccessGrantClock(ctx, now.UnixNano())
	v, err := LoadVerifiedAccessGrants(ctx, s)
	if err != nil {
		return GrantClaim{Unverified: errors.Is(err, ErrGrantCacheUnverified)}
	}
	if !v.Present {
		return GrantClaim{}
	}
	res := accessgrant.MatchDetail(q, v.Grants, v.Receipt, now)
	return GrantClaim{Hit: res.Hit, OK: res.OK, LockRefused: res.LockRefused}
}

// SoftenGrantForRule reports a verified, honoured soften grant naming ruleID
// on a rule the org locks (accessgrant.SoftenForRule). The local approval
// gates (`observer guard approve`, the dashboard approvals POST) consult it
// before refusing an approval on a locked rule: under such a grant the
// approval is the developer's per-call confirmation (request-grants G3).
func SoftenGrantForRule(ctx context.Context, s *store.Store, ruleID string, now time.Time) (int64, bool) {
	v, err := LoadVerifiedAccessGrants(ctx, s)
	if err != nil || !v.Present {
		return 0, false
	}
	return accessgrant.SoftenForRule(ruleID, true, v.Grants, v.Receipt, now)
}

// LookupAccessGrant reports the grant that WOULD cover q, without counting a
// use (for read surfaces; a decision goes through ClaimAccessGrant). It reads
// the same re-verified state.
func LookupAccessGrant(ctx context.Context, s *store.Store, q accessgrant.Query, now time.Time) (accessgrant.Hit, bool) {
	if s == nil {
		return accessgrant.Hit{}, false
	}
	enr, err := s.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return accessgrant.Hit{}, false
	}
	_ = s.NoteAccessGrantClock(ctx, now.UnixNano())
	v, err := LoadVerifiedAccessGrants(ctx, s)
	if err != nil || !v.Present {
		return accessgrant.Hit{}, false
	}
	return accessgrant.Match(q, v.Grants, v.Receipt, now)
}

// verifiedGrantsView is the node's grant picture for its surfaces, built from
// the re-verified document. An unverified cache lists its grants as not
// honoured, reason accessgrant.ReasonUnverified.
func verifiedGrantsView(ctx context.Context, s *store.Store, now time.Time) (store.AccessGrantsView, bool, error) {
	empty := store.AccessGrantsView{Grants: []store.AccessGrantView{}}
	v, err := LoadVerifiedAccessGrants(ctx, s)
	if err != nil && !errors.Is(err, ErrGrantCacheUnverified) {
		return empty, false, err
	}
	if !v.Present {
		return empty, false, nil
	}
	out := store.AccessGrantsView{
		Version: v.State.Version, LastVerifiedNs: v.State.LastVerifiedNs, MaxOfflineS: v.State.MaxOfflineS,
		Grants: []store.AccessGrantView{},
	}
	if err != nil {
		out.Unverified = true
		rows, rerr := s.CachedAccessGrants(ctx)
		if rerr != nil {
			return empty, false, rerr
		}
		for _, r := range rows {
			out.Grants = append(out.Grants, store.AccessGrantView{
				Grant: r.Grant, UsesUsed: r.UsesUsed, Honoured: false, Reason: accessgrant.ReasonUnverified,
			})
		}
		return out, true, nil
	}
	for _, c := range v.Grants {
		h, why := accessgrant.Honoured(c.Grant, c.UsesUsed, v.Receipt, now)
		out.Grants = append(out.Grants, store.AccessGrantView{Grant: c.Grant, UsesUsed: c.UsesUsed, Honoured: h, Reason: why})
	}
	return out, true, nil
}
