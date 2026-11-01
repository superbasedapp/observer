package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// managedpull.go is the node half of the module managed-pull kit (roadmap
// F0-7, lane SHR-KIT; design JSP-1). One generic fetch serves every rail of
// orgcontract.ManagedPullRails (GET /api/agent/security, GET
// /api/agent/sandbox): it classifies the answer through classifyRail (so an
// older server's login page or SPA reads as not_supported, JSP-1 R11),
// verifies a 200 against the enrolment's pinned org key (orgSigningKey, no
// TOFU of its own) and this node's OWN org and subject, and runs one decision
// table, DecideManagedPull. Each module only decodes the body it receives.
//
// The rules the table holds (a prototype walked all 2,304 input combinations
// and held each one, JSP-1):
//   - only a SIGNED empty body at a newer version clears the stored values,
//     and the clear keeps that version as the floor (a tombstone row), so no
//     older document installs after it;
//   - no non-200 answer changes the cache, a 404 never clears;
//   - nothing unverified changes it;
//   - no rollback: an older version, or the same version with another body,
//     is refused;
//   - managed values are IN FORCE only on a managed node whose honoured
//     grant holds the rail's authority, with an unexpired cached document;
//     otherwise the document is verified but inert (not_preauthorized), and an
//     expired one stops applying (the node's local values return).

// Managed-pull fetch states, the closed set reported for a rail.
const (
	ManagedPullStateOK                       = "ok"
	ManagedPullStateCleared                  = "cleared"
	ManagedPullStateNotEnrolled              = "not_enrolled"
	ManagedPullStateNotSupported             = "not_supported"
	ManagedPullStateAuthFailed               = "auth_failed"
	ManagedPullStateChannelOff               = "channel_off"
	ManagedPullStateUnreachable              = "unreachable"
	ManagedPullStateUnverified               = "unverified"
	ManagedPullStateExpired                  = "expired"
	ManagedPullStateExpiredOnArrival         = "expired_on_arrival"
	ManagedPullStateRollbackRefused          = "rollback_refused"
	ManagedPullStateSameVersionDifferentBody = "same_version_different_body"
)

// ManagedPullReply is a poll's answer, classified at the boundary.
type ManagedPullReply int

// The replies a managed pull distinguishes.
const (
	ManagedPullReply200 ManagedPullReply = iota
	ManagedPullReply304
	ManagedPullReply404
	// ManagedPullReplyNotSupported is an older server's page (a 302 to
	// /login followed to HTML, an SPA catch-all, 405, 501).
	ManagedPullReplyNotSupported
	ManagedPullReplyAuthFailed
	ManagedPullReply409
	ManagedPullReply5xx
	ManagedPullReplyTransport
	// ManagedPullReplyOther is any other status: kept, reported unverified.
	ManagedPullReplyOther
)

// ManagedPullVerdict is the verification of a 200 body.
type ManagedPullVerdict int

// The verdicts of a 200 body (ignored for every other reply).
const (
	ManagedPullVerified ManagedPullVerdict = iota
	ManagedPullVerifiedEmpty
	ManagedPullUnverified
)

// ManagedPullAction is what the ladder does to the cache.
type ManagedPullAction string

// The ladder's actions.
const (
	ManagedPullInstall ManagedPullAction = "install"
	ManagedPullKeep    ManagedPullAction = "keep"
	ManagedPullClear   ManagedPullAction = "clear"
	ManagedPullRefuse  ManagedPullAction = "refuse"
)

// ManagedPullCacheFacts is what the ladder needs of the stored document.
type ManagedPullCacheFacts struct {
	Have      bool
	Version   int64
	BodyHash  string
	ExpiresAt int64
	// Floor is the highest version this enrolment has stored for the rail
	// and FloorBodyHash the body hash stored with it. They outlive the
	// document: a clear leaves them (a tombstone row), and so does a stored
	// document that no longer verifies, so a replayed older document is
	// refused even when nothing is in force (audit SHR-KIT finding 2). Zero:
	// nothing was ever stored.
	Floor         int64
	FloorBodyHash string
}

// floor is the version below which every 200 is a rollback.
func (c ManagedPullCacheFacts) floor() int64 {
	if c.Have && c.Version > c.Floor {
		return c.Version
	}
	return c.Floor
}

// ManagedPullInput is one poll's facts.
type ManagedPullInput struct {
	Reply     ManagedPullReply
	Verdict   ManagedPullVerdict
	Version   int64
	BodyHash  string
	ExpiresAt int64
	Now       int64
	// Managed is managed tenancy under a managed-class consent.
	Managed bool
	// HoldsAuthority is the rail's enforce token in the honoured grant.
	HoldsAuthority bool
}

// ManagedPullDecision is the ladder's answer.
type ManagedPullDecision struct {
	Action ManagedPullAction
	State  string
	// InForce says whether managed values apply after this poll.
	InForce bool
	Reason  string
}

// managedPullRow is one row of the apply ladder, walked top-down; the first
// matching row decides (CLAUDE.md #5).
type managedPullRow struct {
	match  func(in ManagedPullInput, c ManagedPullCacheFacts) bool
	action ManagedPullAction
	state  string
	reason string
}

func replyIs(r ManagedPullReply) func(ManagedPullInput, ManagedPullCacheFacts) bool {
	return func(in ManagedPullInput, _ ManagedPullCacheFacts) bool { return in.Reply == r }
}

var managedPullLadder = []managedPullRow{
	{match: func(in ManagedPullInput, _ ManagedPullCacheFacts) bool {
		return in.Reply == ManagedPullReply200 && in.Verdict == ManagedPullUnverified
	}, action: ManagedPullRefuse, state: ManagedPullStateUnverified},
	{match: func(in ManagedPullInput, _ ManagedPullCacheFacts) bool {
		return in.Reply == ManagedPullReply200 && in.ExpiresAt <= in.Now
	}, action: ManagedPullRefuse, state: ManagedPullStateExpiredOnArrival},
	{match: func(in ManagedPullInput, c ManagedPullCacheFacts) bool {
		return in.Reply == ManagedPullReply200 && in.Version < c.floor()
	}, action: ManagedPullRefuse, state: ManagedPullStateRollbackRefused},
	{match: func(in ManagedPullInput, c ManagedPullCacheFacts) bool {
		return in.Reply == ManagedPullReply200 && c.Have && in.Version == c.Version && in.BodyHash != c.BodyHash
	}, action: ManagedPullRefuse, state: ManagedPullStateSameVersionDifferentBody},
	{match: func(in ManagedPullInput, c ManagedPullCacheFacts) bool {
		return in.Reply == ManagedPullReply200 && c.Have && in.Version == c.Version
	}, action: ManagedPullKeep, state: ManagedPullStateOK},
	// Nothing in force, but this version was stored before (a tombstone, or
	// a document that no longer verifies): another body at that version is
	// refused like any same-version replacement.
	{match: func(in ManagedPullInput, c ManagedPullCacheFacts) bool {
		return in.Reply == ManagedPullReply200 && !c.Have && c.Floor > 0 && in.Version == c.Floor && in.BodyHash != c.FloorBodyHash
	}, action: ManagedPullRefuse, state: ManagedPullStateSameVersionDifferentBody},
	{match: func(in ManagedPullInput, _ ManagedPullCacheFacts) bool {
		return in.Reply == ManagedPullReply200 && in.Verdict == ManagedPullVerifiedEmpty
	}, action: ManagedPullClear, state: ManagedPullStateCleared},
	{match: replyIs(ManagedPullReply200), action: ManagedPullInstall, state: ManagedPullStateOK},
	{match: func(in ManagedPullInput, c ManagedPullCacheFacts) bool {
		return in.Reply == ManagedPullReply304 && c.Have
	}, action: ManagedPullKeep, state: ManagedPullStateOK},
	{match: replyIs(ManagedPullReply304), action: ManagedPullKeep, state: ManagedPullStateUnverified, reason: "304 without a stored document"},
	{match: replyIs(ManagedPullReply404), action: ManagedPullKeep, state: ManagedPullStateNotSupported, reason: "a 404 never clears"},
	{match: replyIs(ManagedPullReplyNotSupported), action: ManagedPullKeep, state: ManagedPullStateNotSupported},
	{match: replyIs(ManagedPullReplyAuthFailed), action: ManagedPullKeep, state: ManagedPullStateAuthFailed},
	{match: replyIs(ManagedPullReply409), action: ManagedPullKeep, state: ManagedPullStateChannelOff},
	{match: replyIs(ManagedPullReply5xx), action: ManagedPullKeep, state: ManagedPullStateUnreachable, reason: "retry with backoff"},
	{match: replyIs(ManagedPullReplyTransport), action: ManagedPullKeep, state: ManagedPullStateUnreachable, reason: "retry with backoff"},
	{match: func(ManagedPullInput, ManagedPullCacheFacts) bool { return true }, action: ManagedPullKeep, state: ManagedPullStateUnverified, reason: "unexpected reply"},
}

// DecideManagedPull is the whole apply ladder. There is no other path that
// can change a node's managed values.
func DecideManagedPull(in ManagedPullInput, c ManagedPullCacheFacts) ManagedPullDecision {
	var d ManagedPullDecision
	for _, row := range managedPullLadder {
		if row.match(in, c) {
			d = ManagedPullDecision{Action: row.action, State: row.state, Reason: row.reason}
			break
		}
	}
	after := ApplyManagedPull(d, in, c)
	d.InForce = after.Have && after.ExpiresAt > in.Now && in.Managed && in.HoldsAuthority
	switch {
	case after.Have && after.ExpiresAt <= in.Now:
		d.Reason = strings.TrimSpace(d.Reason + " the stored document expired: local values apply")
		if d.State == ManagedPullStateOK {
			d.State = ManagedPullStateExpired
		}
	case after.Have && !(in.Managed && in.HoldsAuthority):
		d.Reason = strings.TrimSpace(d.Reason + " not_preauthorized: verified but inert")
	}
	return d
}

// ApplyManagedPull returns the cache facts after a decision.
func ApplyManagedPull(d ManagedPullDecision, in ManagedPullInput, c ManagedPullCacheFacts) ManagedPullCacheFacts {
	switch d.Action {
	case ManagedPullInstall:
		return ManagedPullCacheFacts{Have: true, Version: in.Version, BodyHash: in.BodyHash, ExpiresAt: in.ExpiresAt, Floor: in.Version, FloorBodyHash: in.BodyHash}
	case ManagedPullClear:
		return ManagedPullCacheFacts{Floor: in.Version, FloorBodyHash: in.BodyHash}
	}
	return c
}

// ManagedPullOutcome is one fetch's result for a rail.
type ManagedPullOutcome struct {
	Rail    string
	State   string
	Action  ManagedPullAction
	InForce bool
	// Version / ExpiresAt / Body describe the stored document after the
	// poll (zero when none is stored). Body is the module's closed body: a
	// caller applies it only when InForce.
	Version   int64
	ExpiresAt int64
	Body      json.RawMessage
	Reason    string
}

// ManagedPullConsent is what the caller resolved from the honoured grant.
type ManagedPullConsent struct {
	// Managed is managed tenancy under a managed-class consent.
	Managed bool
	// HoldsAuthority is the rail's enforce token in the honoured grant.
	HoldsAuthority bool
}

// maxManagedPullBytes bounds a managed-pull document.
const maxManagedPullBytes = 1 << 20

// FetchManagedPull polls one rail once and applies the ladder to the node's
// stored document. It returns ErrNotEnrolled when the node has no live
// enrolment. A non-nil error never comes with a cache change.
func (c *Client) FetchManagedPull(ctx context.Context, railName string, consent ManagedPullConsent) (ManagedPullOutcome, error) {
	rail, ok := orgcontract.LookupManagedPullRail(railName)
	if !ok {
		return ManagedPullOutcome{Rail: railName}, fmt.Errorf("orgclient.FetchManagedPull: unknown rail %q", railName)
	}
	out := ManagedPullOutcome{Rail: rail.Name, State: ManagedPullStateNotEnrolled}
	ident, err := c.managedPullIdentity(ctx)
	if err != nil {
		return out, err
	}
	cached, facts := c.loadVerifiedManagedPull(ctx, rail, ident)
	now := c.nowUnix()
	in := ManagedPullInput{Now: now, Managed: consent.Managed, HoldsAuthority: consent.HoldsAuthority}
	doc, signer, reply, verdict := c.getManagedPull(ctx, rail, ident, facts)
	in.Reply, in.Verdict = reply, verdict
	if reply == ManagedPullReply200 && verdict != ManagedPullUnverified {
		in.Version, in.ExpiresAt = doc.Version, doc.ExpiresAt
		in.BodyHash = orgcontract.ManagedPullBodyHash(doc.Body)
	}
	d := DecideManagedPull(in, facts)
	switch d.Action {
	case ManagedPullInstall:
		atRest := doc
		if codec, ok := managedPullCacheCodecs[rail.Name]; ok {
			body, serr := codec.strip(doc.Body)
			if serr != nil {
				return out, fmt.Errorf("orgclient.FetchManagedPull: %w", serr)
			}
			atRest.Body = body
		}
		raw, merr := json.Marshal(atRest)
		if merr != nil {
			return out, fmt.Errorf("orgclient.FetchManagedPull: %w", merr)
		}
		row := store.ManagedPullCache{
			Rail: rail.Name, OrgKey: ident.orgKey, Generation: ident.generation,
			Version: doc.Version, ExpiresAt: doc.ExpiresAt, BodyHash: in.BodyHash,
			DocJSON: string(raw), SignerFingerprint: signer, FetchedAt: time.Unix(now, 0).UTC().Format(time.RFC3339),
		}
		if serr := c.store.SaveManagedPull(ctx, row); serr != nil {
			return out, fmt.Errorf("orgclient.FetchManagedPull: %w", serr)
		}
		cached = doc
	case ManagedPullClear:
		tomb := store.ManagedPullCache{
			Rail: rail.Name, OrgKey: ident.orgKey, Generation: ident.generation,
			Version: doc.Version, BodyHash: in.BodyHash,
			SignerFingerprint: signer, FetchedAt: time.Unix(now, 0).UTC().Format(time.RFC3339),
		}
		if cerr := c.store.ClearManagedPull(ctx, tomb); cerr != nil {
			return out, fmt.Errorf("orgclient.FetchManagedPull: %w", cerr)
		}
		cached = orgcontract.ManagedPullDoc{}
	}
	after := ApplyManagedPull(d, in, facts)
	out = ManagedPullOutcome{Rail: rail.Name, State: d.State, Action: d.Action, InForce: d.InForce, Reason: d.Reason}
	if after.Have {
		out.Version, out.ExpiresAt, out.Body = cached.Version, cached.ExpiresAt, cached.Body
	}
	return out, nil
}

// LoadPersistedManagedPull reports the stored document of one rail without
// a request (daemon start), re-verified against the pinned key. Its state is
// unreachable, never ok: nothing was fetched by this process.
func (c *Client) LoadPersistedManagedPull(ctx context.Context, railName string, consent ManagedPullConsent) (ManagedPullOutcome, error) {
	rail, ok := orgcontract.LookupManagedPullRail(railName)
	if !ok {
		return ManagedPullOutcome{Rail: railName}, fmt.Errorf("orgclient.LoadPersistedManagedPull: unknown rail %q", railName)
	}
	ident, err := c.managedPullIdentity(ctx)
	if err != nil {
		return ManagedPullOutcome{Rail: rail.Name, State: ManagedPullStateNotEnrolled}, err
	}
	cached, facts := c.loadVerifiedManagedPull(ctx, rail, ident)
	in := ManagedPullInput{Reply: ManagedPullReplyTransport, Now: c.nowUnix(), Managed: consent.Managed, HoldsAuthority: consent.HoldsAuthority}
	d := DecideManagedPull(in, facts)
	out := ManagedPullOutcome{Rail: rail.Name, State: d.State, Action: d.Action, InForce: d.InForce, Reason: d.Reason}
	if facts.Have {
		out.Version, out.ExpiresAt, out.Body = cached.Version, cached.ExpiresAt, cached.Body
	}
	return out, nil
}

type managedPullIdent struct {
	enr        *store.Enrolment
	orgKey     string
	generation int64
}

func (c *Client) managedPullIdentity(ctx context.Context) (managedPullIdent, error) {
	if c == nil {
		return managedPullIdent{}, errors.New("orgclient: client unavailable")
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return managedPullIdent{}, fmt.Errorf("orgclient.managedPullIdentity: %w", err)
	}
	if enr == nil || strings.TrimSpace(enr.OrgID) == "" || strings.TrimSpace(enr.UserID) == "" {
		return managedPullIdent{}, ErrNotEnrolled
	}
	orgKey := OrgKey(enr.OrgServerURL, enr.OrgID)
	gen, ok, err := c.store.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil {
		return managedPullIdent{}, fmt.Errorf("orgclient.managedPullIdentity: %w", err)
	}
	if !ok || gen.Tombstoned {
		return managedPullIdent{}, ErrNotEnrolled
	}
	return managedPullIdent{enr: enr, orgKey: orgKey, generation: gen.Generation}, nil
}

// loadVerifiedManagedPull returns the stored document when it still verifies
// against the pinned key for this node; a row that does not, and a
// tombstone, hold no document (it can never apply) but still carry the
// stored version as the anti-rollback floor. The floor is safe to trust
// without re-verification: only this node's own ladder writes the row, and
// only after verifying the document it came from, for this enrolment
// identity (another identity's row reads as absent, floor included).
func (c *Client) loadVerifiedManagedPull(ctx context.Context, rail orgcontract.ManagedPullRail, ident managedPullIdent) (orgcontract.ManagedPullDoc, ManagedPullCacheFacts) {
	row, ok, err := c.store.LoadManagedPull(ctx, rail.Name, ident.orgKey, ident.generation)
	if err != nil || !ok {
		return orgcontract.ManagedPullDoc{}, ManagedPullCacheFacts{}
	}
	floor := ManagedPullCacheFacts{Floor: row.Version, FloorBodyHash: row.BodyHash}
	if row.Tombstone {
		return orgcontract.ManagedPullDoc{}, floor
	}
	var doc orgcontract.ManagedPullDoc
	if json.Unmarshal([]byte(row.DocJSON), &doc) != nil {
		return orgcontract.ManagedPullDoc{}, floor
	}
	if codec, ok := managedPullCacheCodecs[rail.Name]; ok {
		body, rerr := codec.restore(doc.Body)
		if rerr != nil {
			// What the cache left out cannot be put back: the document
			// does not verify, so the next fetch asks unconditionally.
			return orgcontract.ManagedPullDoc{}, floor
		}
		doc.Body = body
	}
	pub, err := c.orgSigningKey(ctx)
	if err != nil || orgcontract.VerifyManagedPull(pub, rail, ident.enr.OrgID, ident.enr.UserID, doc) != nil {
		return orgcontract.ManagedPullDoc{}, floor
	}
	hash := orgcontract.ManagedPullBodyHash(doc.Body)
	return doc, ManagedPullCacheFacts{Have: true, Version: doc.Version, BodyHash: hash, ExpiresAt: doc.ExpiresAt, Floor: doc.Version, FloorBodyHash: hash}
}

// managedPullCapabilities names, per rail, the optional body fields this
// build applies (orgcontract.ManagedPullCapabilitiesHeader). The server
// serves such a field only to a node that named it, because every body is
// closed and an older node would refuse it. A rail is pulled only while its
// module's consumer is registered, so a build without that module sends
// nothing for it.
var managedPullCapabilities = map[string][]string{
	"sandbox": {orgcontract.SandboxCapabilitySkipRepoScan, orgcontract.SandboxCapabilityE2BEndpoint, orgcontract.SandboxCapabilityInstallScripts, orgcontract.SandboxCapabilitySignInSeedForbid},
}

// managedPullCacheCodec keeps part of a rail's signed body out of the
// managed pull cache: strip runs before the document is stored, restore on
// every load before the signature is re-verified (a restore error leaves the
// stored document unverifiable). Only the security rail has one (lane
// LEFT-SHARED merge audit finding 4, security_pullcaps.go).
type managedPullCacheCodec struct {
	strip   func(body []byte) ([]byte, error)
	restore func(body []byte) ([]byte, error)
}

// managedPullCacheCodecs is the per-rail cache codec table.
var managedPullCacheCodecs = map[string]managedPullCacheCodec{}

// managedPullETag is the conditional-request validator for a stored version.
func managedPullETag(version int64) string { return `"v` + strconv.FormatInt(version, 10) + `"` }

// getManagedPull performs the GET and classifies the answer. On a verified
// 200 it returns the document and the verifying key's pin hash.
func (c *Client) getManagedPull(ctx context.Context, rail orgcontract.ManagedPullRail, ident managedPullIdent, facts ManagedPullCacheFacts) (orgcontract.ManagedPullDoc, string, ManagedPullReply, ManagedPullVerdict) {
	var none orgcontract.ManagedPullDoc
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return none, "", ManagedPullReplyAuthFailed, ManagedPullUnverified
	}
	url := strings.TrimRight(ident.enr.OrgServerURL, "/") + rail.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return none, "", ManagedPullReplyTransport, ManagedPullUnverified
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if caps := managedPullCapabilities[rail.Name]; len(caps) > 0 {
		req.Header.Set(orgcontract.ManagedPullCapabilitiesHeader, strings.Join(caps, ","))
	}
	if facts.Have {
		req.Header.Set("If-None-Match", managedPullETag(facts.Version))
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return none, "", ManagedPullReplyTransport, ManagedPullUnverified
	}
	defer func() { _ = resp.Body.Close() }()
	if c.classifyRail("managed-pull-"+rail.Name, resp) == railReplyNotSupported {
		if resp.StatusCode == http.StatusNotFound {
			return none, "", ManagedPullReply404, ManagedPullUnverified
		}
		return none, "", ManagedPullReplyNotSupported, ManagedPullUnverified
	}
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotModified:
		return none, "", ManagedPullReply304, ManagedPullUnverified
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return none, "", ManagedPullReplyAuthFailed, ManagedPullUnverified
	case resp.StatusCode == http.StatusConflict:
		return none, "", ManagedPullReply409, ManagedPullUnverified
	case resp.StatusCode >= 500 && resp.StatusCode <= 599:
		return none, "", ManagedPullReply5xx, ManagedPullUnverified
	default:
		return none, "", ManagedPullReplyOther, ManagedPullUnverified
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxManagedPullBytes+1))
	if err != nil || len(raw) > maxManagedPullBytes {
		return none, "", ManagedPullReply200, ManagedPullUnverified
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var doc orgcontract.ManagedPullDoc
	if dec.Decode(&doc) != nil {
		return none, "", ManagedPullReply200, ManagedPullUnverified
	}
	pub, err := c.orgSigningKey(ctx)
	if err != nil {
		return none, "", ManagedPullReply200, ManagedPullUnverified
	}
	if orgcontract.VerifyManagedPull(pub, rail, ident.enr.OrgID, ident.enr.UserID, doc) != nil {
		return none, "", ManagedPullReply200, ManagedPullUnverified
	}
	signer := orgcontract.PublicKeyPinHash(pub)
	if orgcontract.ManagedPullBodyIsEmpty(doc.Body) {
		return doc, signer, ManagedPullReply200, ManagedPullVerifiedEmpty
	}
	return doc, signer, ManagedPullReply200, ManagedPullVerified
}

// SetManagedPullClock sets the clock the managed-pull ladder reads (tests).
func (c *Client) SetManagedPullClock(now func() time.Time) { c.managedPullNow = now }

// nowUnix is the managed-pull clock in unix seconds.
func (c *Client) nowUnix() int64 {
	if c.managedPullNow != nil {
		return c.managedPullNow().Unix()
	}
	return time.Now().Unix()
}
