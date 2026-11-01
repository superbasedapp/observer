package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// accessgrants.go - the node half of the access-grant rail (request-grants
// design §3.1, phase G2): fetch, verify and cache the org's signed per-caller
// grants document, answer the guard's grant lookup from that cache, and post
// requests the developer raised while the org was unreachable.

// accessGrantRail names this rail in cross-rail key-identity refusals.
const accessGrantRail = "access-grants"

// Access-grant fetch outcomes (AccessGrantFetch.State).
const (
	GrantFetchApplied      = "applied"       // a newer verified document was cached
	GrantFetchCurrent      = "current"       // the same version verified again; offline window restarted
	GrantFetchNotSupported = "not_supported" // the server predates the rail: cache kept
	GrantFetchUnverified   = "unverified"    // refused document: cache kept
	GrantFetchAuth         = "auth"          // 401/403: cache kept
	GrantFetchConflict     = "conflict"      // 409: cache kept
	GrantFetchUnreachable  = "unreachable"   // transport error or 5xx: cache kept
)

// AccessGrantFetch is the honest result of one fetch.
type AccessGrantFetch struct {
	State   string
	Version int64
	Grants  int
}

// SetAccessGrantSink installs the callback run after a NEW grants version was
// verified and cached. Nil-safe; nil clears it.
func (c *Client) SetAccessGrantSink(sink func()) {
	if c == nil {
		return
	}
	c.accessGrantSink = sink
}

// accessGrantSubject is the subject this node fetches and verifies under:
// the member, plus the managed machine identity when there is one.
// It is grantSubjectFor (accessgrant_claim.go), so the fetch and every
// decision-time read agree on one subject.
func (c *Client) accessGrantSubject(ctx context.Context, enr *store.Enrolment) (string, string) {
	managed, _ := NodeManagedFor(ctx, c.store, enr) //nolint:errcheck // a read error fetches the member subject, the closed direction
	return grantSubjectFor(enr, managed)
}

// FetchAccessGrants pulls GET /api/agent/grants and applies the D-016 ladder:
//
//   - 404 (or an SPA page for the unknown route) is a server that predates
//     the rail: the cache is KEPT, never cleared;
//   - 401/403, 409, 5xx and transport errors keep the cache and report;
//   - a 200 is verified in order: one capped JSON value, this org, this
//     subject (member|machine), the offered key against the rail's own pin
//     and the org identity the other rails pinned, the Ed25519 signature
//     over the domain-tagged org/subject/version-bound message, then the
//     issued_at freshness window. Anything refused is "unverified" and keeps
//     the cache;
//   - the version is monotonic: an older document is refused; the same
//     version only restarts the offline window; a newer one replaces the
//     cache WHOLE. Only such a signed body with an empty list empties it.
func (c *Client) FetchAccessGrants(ctx context.Context) (AccessGrantFetch, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return AccessGrantFetch{}, fmt.Errorf("orgclient.FetchAccessGrants: enrolment: %w", err)
	}
	if enr == nil {
		return AccessGrantFetch{}, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return AccessGrantFetch{}, fmt.Errorf("orgclient.FetchAccessGrants: bearer: %w", err)
	}
	subject, machine := c.accessGrantSubject(ctx, enr)
	url := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.AccessGrantsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return AccessGrantFetch{State: GrantFetchUnreachable}, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if machine != "" {
		req.Header.Set(orgcontract.HeaderMachineIdentity, machine)
		// T-656: prove the claim with this machine's own key (registering
		// it first when needed). A released server ignores the headers.
		c.attachMachineProof(ctx, req, enr, machine, http.MethodGet, orgcontract.AccessGrantsPath)
	}
	// M4-01: report the version this node holds VERIFIED, so the org can
	// tell an issued grant from one a machine has. Only a document that
	// re-verifies right now counts; a released server ignores the header.
	if v, err := LoadVerifiedAccessGrants(ctx, c.store); err == nil && v.Present && v.State.Subject == subject && v.State.Version > 0 {
		req.Header.Set(orgcontract.HeaderGrantsVerified, strconv.FormatInt(v.State.Version, 10))
	}
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return AccessGrantFetch{State: GrantFetchUnreachable}, fmt.Errorf("orgclient.FetchAccessGrants: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if c.classifyRail(accessGrantRail, resp) == railReplyNotSupported {
		return AccessGrantFetch{State: GrantFetchNotSupported}, nil
	}
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound:
		// Unsigned: never clears (D-016). The server also answers 404 for a
		// bearer that is not an active member; that governs nothing here.
		return AccessGrantFetch{State: GrantFetchNotSupported}, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return AccessGrantFetch{State: GrantFetchAuth}, fmt.Errorf("orgclient.FetchAccessGrants: %w", ErrAuthFailed)
	case resp.StatusCode == http.StatusConflict:
		return AccessGrantFetch{State: GrantFetchConflict}, errors.New("orgclient.FetchAccessGrants: server returned 409; keeping the last verified grants")
	default:
		return AccessGrantFetch{State: GrantFetchUnreachable}, fmt.Errorf("orgclient.FetchAccessGrants: server returned %d", resp.StatusCode)
	}
	var doc orgcontract.AccessGrantDoc
	if err := orgcontract.DecodeCapped(resp.Body, maxOrgDocBytes, &doc); err != nil {
		return AccessGrantFetch{State: GrantFetchUnverified}, fmt.Errorf("orgclient.FetchAccessGrants: decode: %w", err)
	}
	return c.applyAccessGrantDoc(ctx, enr, subject, doc, time.Now())
}

// applyAccessGrantDoc is the verified-200 branch: the ONLY caller of the
// cache writer.
func (c *Client) applyAccessGrantDoc(ctx context.Context, enr *store.Enrolment, subject string, doc orgcontract.AccessGrantDoc, now time.Time) (AccessGrantFetch, error) {
	refuse := func(err error) (AccessGrantFetch, error) {
		return AccessGrantFetch{State: GrantFetchUnverified}, fmt.Errorf("orgclient.FetchAccessGrants: %w", err)
	}
	if doc.OrgID != enr.OrgID {
		return refuse(fmt.Errorf("document is for org %q, this node is enrolled with %q - refusing", doc.OrgID, enr.OrgID))
	}
	if doc.Subject != subject {
		return refuse(fmt.Errorf("document is for subject %q, this node is %q - refusing", doc.Subject, subject))
	}
	cached, hasCached, err := c.store.GetAccessGrantState(ctx)
	if err != nil {
		return AccessGrantFetch{State: GrantFetchUnverified}, err
	}
	// A cache for another org or another subject constrains nothing here.
	if hasCached && (cached.OrgID != enr.OrgID || cached.Subject != subject) {
		hasCached = false
	}
	pinned := doc.PublicKey
	repinned := false
	if hasCached && cached.ServerPubkey != doc.PublicKey {
		if err := c.acceptOfferedKeyChange(ctx, accessGrantRail, cached.ServerPubkey, doc.PublicKey); err != nil {
			return refuse(err)
		}
		repinned = true
	}
	if hasCached && !repinned {
		pinned = cached.ServerPubkey
	}
	if err := c.checkOrgKeyIdentity(ctx, accessGrantRail, doc.PublicKey); err != nil {
		return refuse(err)
	}
	if err := orgcontract.VerifyAccessGrants(doc, enr.OrgID, subject, pinned); err != nil {
		return refuse(err)
	}
	body, err := orgcontract.DecodeAccessGrantBody(doc.Body)
	if err != nil {
		return refuse(err)
	}
	if fresh, why := orgcontract.AccessGrantFresh(body.IssuedAt, now); !fresh {
		return refuse(errors.New(why))
	}
	nowNs := now.UnixNano()
	if hasCached && doc.Version < cached.Version {
		return refuse(fmt.Errorf("document version %d is older than the cached %d (replay)", doc.Version, cached.Version))
	}
	if hasCached && doc.Version == cached.Version && !repinned {
		if err := c.store.TouchAccessGrantsVerified(ctx, cached.Version, nowNs); err != nil {
			return AccessGrantFetch{State: GrantFetchUnverified}, err
		}
		return AccessGrantFetch{State: GrantFetchCurrent, Version: cached.Version}, nil
	}
	st := store.AccessGrantState{
		OrgID: doc.OrgID, Subject: doc.Subject, Version: doc.Version, Body: doc.Body, BodyHash: doc.BodyHash,
		Signature: doc.Signature, ServerPubkey: pinned, ServerNowNs: body.ServerNowNs, ReceivedAtNs: nowNs,
		LastVerifiedNs: nowNs, HighWaterNs: nowNs, MaxOfflineS: body.MaxOfflineS, IssuedAt: body.IssuedAt,
	}
	if err := c.store.SaveAccessGrants(ctx, st, body.Grants); err != nil {
		return AccessGrantFetch{State: GrantFetchUnverified}, err
	}
	if repinned || !hasCached {
		c.adoptEnrolmentKeyMaterial(ctx, pinned)
	}
	c.logger.Info("org access grants cached", "version", doc.Version, "grants", len(body.Grants))
	return AccessGrantFetch{State: GrantFetchApplied, Version: doc.Version, Grants: len(body.Grants)}, nil
}

// refreshAccessGrants fetches the rail under railsMu and runs the sink when a
// new version was cached. The push cycle and the freshness dispatch both call
// it, so the two paths cannot diverge.
func (c *Client) refreshAccessGrants(ctx context.Context) (AccessGrantFetch, error) {
	c.railsMu.Lock()
	out, err := c.FetchAccessGrants(ctx)
	c.railsMu.Unlock()
	if err == nil && out.State == GrantFetchApplied && c.accessGrantSink != nil {
		c.accessGrantSink()
	}
	return out, err
}

// AccessGrantLookup reports the grant that would cover q on this node, from
// the re-verified cache (accessgrant_claim.go), without counting a use. A
// guard decision goes through ClaimAccessGrant instead.
func (c *Client) AccessGrantLookup(ctx context.Context, q accessgrant.Query) (accessgrant.Hit, bool) {
	if c == nil {
		return accessgrant.Hit{}, false
	}
	return LookupAccessGrant(ctx, c.store, q, time.Now())
}

// QueueAccessRequest stores a request the org could not be reached for, as
// the exact bytes the developer previewed; FlushAccessRequestOutbox posts it
// on a later cycle.
func (c *Client) QueueAccessRequest(ctx context.Context, in orgcontract.AccessRequestCreate) (int64, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return 0, fmt.Errorf("orgclient.QueueAccessRequest: enrolment: %w", err)
	}
	if enr == nil {
		return 0, ErrNotEnrolled
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	return c.store.EnqueueAccessRequest(ctx, enr.OrgID, string(raw), time.Now())
}

// FlushAccessRequestOutbox posts queued requests for the current org. A
// request the server refused on its merits (400) or a full open cap (429)
// stays queued with the reason so the developer sees it; a request queued for
// a different org (re-enrolment) is dropped. Returns the number posted.
func (c *Client) FlushAccessRequestOutbox(ctx context.Context) (int, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return 0, err
	}
	queued, err := c.store.ListAccessRequestOutbox(ctx)
	if err != nil {
		return 0, err
	}
	sent := 0
	for _, q := range queued {
		if q.OrgID != enr.OrgID {
			_, _ = c.store.DeleteOutboxRequest(ctx, q.ID)
			continue
		}
		var in orgcontract.AccessRequestCreate
		if err := json.Unmarshal([]byte(q.RequestJSON), &in); err != nil {
			_ = c.store.NoteOutboxAttempt(ctx, q.ID, "unreadable queued request: "+err.Error(), time.Now())
			continue
		}
		if _, err := c.PostAccessRequest(ctx, in); err != nil {
			_ = c.store.NoteOutboxAttempt(ctx, q.ID, err.Error(), time.Now())
			var refused *RequestRefusedError
			if errors.As(err, &refused) || errors.Is(err, ErrOrgRequestCapReached) {
				continue
			}
			return sent, err // transport trouble: try the rest next cycle
		}
		if _, err := c.store.DeleteOutboxRequest(ctx, q.ID); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}
