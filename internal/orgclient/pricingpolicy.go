package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The node half of the org PRICING rail
// (docs/plans/enterprise-pricing-and-admin-assistant-plan-2026-09-08.md §3.3,
// wave W2).
//
// It rides the EXISTING push cycle beside FetchRoutingPolicy,
// FetchBudgetPolicy and FetchOrgAnnouncement — no new timer, no new host, no
// new connection (the announce.go discipline).
//
// WHY THE CACHE IS PERSISTED, where the sibling budget rail's is not. A budget
// is re-derived from whatever is in force when a request is scanned, so a
// daemon that restarts and has not polled yet runs its own looser numbers for
// one cycle and then tightens — recoverable in both directions. A PRICE is
// not: api_turns.cost_usd is stamped at CAPTURE, and this arc has no
// retroactive re-pricing (ruling R8 / gap PRICE-REPRICE-1). Every turn a
// restarted daemon prices before its first successful poll is permanently
// wrong, and the org cap those dollars are measured against is permanently
// wrong with it. So the accepted document lands in org_pricing_cache
// (agent migration 106) through store.SaveOrgPricing, and the engine composes
// from it on a cold start.
//
// WHY EVERY NON-200 WRITES NOTHING. The ladder below never calls
// SaveOrgPricing outside the 200 branch, which is what makes "only a SIGNED
// body may ever empty a node's table" (plan §3.3 / N1) true by construction:
// there is no code path that could clear it on a header, a status line or a
// timeout. The 404 rung is the one this rule was written for — a 404 here is
// indistinguishable from "this org server predates the rail", so treating it
// the way the budget rail treats its 404 ("an explicit none, drop the cache")
// would make any downgrade, any misroute and any stray reverse-proxy rule a
// one-shot lever that drops a whole fleet back to list prices.
//
// TRUST MODEL. A PricingPolicyDoc carries no public key of its own, so this
// rail establishes NO TOFU pin; it verifies against the key this node was
// ENROLLED with, falling back to the key another signed-distribution rail
// already pinned when the enrolment predates that record (orgSigningKey,
// ruling R1). With no key at all the body is REFUSED as unverified, never
// applied unsigned. The pricing cache is deliberately NOT a third pin source
// (F23): a rail that could bootstrap its own trust from a document it accepted
// would have no trust to bootstrap from.

// PricingFetchOutcome is the TOTAL, typed classification of one pricing poll
// cycle, in the shape BudgetFetchOutcome established.
type PricingFetchOutcome struct {
	// State is the closed orgcontract.PricingFetch* enum.
	State string
	// Body is the VERIFIED document in force after this cycle (the freshly
	// accepted one, the cached one on any non-200, or the persisted one on a
	// cold start). Zero when none is in force.
	Body orgcontract.PricingPolicyBody
	// HaveBody is true only when Body came from a signature that verified.
	HaveBody bool
	// Changed is true when this cycle replaced the document in force.
	Changed bool
	// Authoritative mirrors the node's resolved tenancy at fetch time. It
	// rides on the outcome rather than being re-derived by the sink because
	// the two must be applied together: composing yesterday's rows under
	// today's tenancy flag would flip the whole precedence ladder for one
	// cycle.
	Authoritative bool
	// Binding identifies the enrollment epoch that verified Body, or the
	// captured current epoch when this outcome intentionally has no body.
	// Publication consumers must reject a body whose binding is no longer
	// current, even when its org signature remains valid.
	Binding string
	// Witness identifies the exact durable pricing document that produced Body.
	// It is known only after a successful fenced save or a verified persisted
	// restore; an in-memory body whose save failed carries no witness.
	Witness store.OrgPricingWitness
}

// pricingCache is the in-memory mirror of org_pricing_cache: the last VERIFIED
// document, the ETag that produced it, and the key that verified it.
//
// It mirrors rather than replaces the table. The table is what survives a
// restart; this is what a hot path reads without touching SQLite on every
// poll, and it is what holds the ETag (which is a property of the last HTTP
// exchange, not of the document, and would be meaningless after a restart
// against a server that had re-signed in the meantime).
type pricingCache struct {
	// publishMu serializes the durable-write/in-memory-publication pair without
	// holding a lock across network I/O. Concurrent requests use their captured
	// witness as an optimistic generation: once one publishes, a later response
	// based on the older snapshot is discarded and the next poll refetches.
	publishMu sync.Mutex
	mu        sync.Mutex
	etag      string
	body      orgcontract.PricingPolicyBody
	have      bool
	// signerFP is orgcontract.PublicKeyPinHash of the key that verified the
	// cached body. It is a FINGERPRINT rather than the raw key so a cold start
	// can restore it from org_pricing_cache (which records the fingerprint,
	// never the key) and the version-monotonicity guard keeps working on the
	// first poll after a restart (W7 review F1). Empty means "unknown signer".
	signerFP string
	// identity is the exact enrollment epoch that verified the cached body.
	// Empty binding is legacy provenance and is never used for managed fetch or
	// cold restore.
	identity store.OrgBudgetIdentity
	witness  store.OrgPricingWitness
}

func (c *pricingCache) snapshot() (etag string, body orgcontract.PricingPolicyBody, have bool, identity store.OrgBudgetIdentity, witness store.OrgPricingWitness) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.etag, c.body, c.have, c.identity, c.witness
}

// signedBy reports the fingerprint of the key that verified the cached body
// ("" when unknown).
func (c *pricingCache) signedBy() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signerFP
}

func (c *pricingCache) store(etag string, body orgcontract.PricingPolicyBody, signerFP string, identities ...store.OrgBudgetIdentity) {
	c.storeWithWitness(etag, body, signerFP, store.OrgPricingWitness{}, identities...)
}

func (c *pricingCache) storeWithWitness(etag string, body orgcontract.PricingPolicyBody, signerFP string, witness store.OrgPricingWitness, identities ...store.OrgBudgetIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.etag, c.body, c.have, c.signerFP, c.witness = etag, body, true, signerFP, witness
	if len(identities) > 0 {
		c.identity = identities[0]
	}
}

func (c *pricingCache) clearFor(binding string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if binding != "" && c.identity.Binding != binding {
		return
	}
	c.etag, c.body, c.have, c.signerFP = "", orgcontract.PricingPolicyBody{}, false, ""
	c.identity = store.OrgBudgetIdentity{}
	c.witness = store.OrgPricingWitness{}
}

// clearIfIdentity drops the cache only when it still belongs to identity. It
// closes the small race between an identity snapshot and a cleanup: an
// in-flight fetch from an older enrollment must not clear a replacement
// enrollment's body after that replacement has already been published.
func (c *pricingCache) clearIfIdentity(identity store.OrgBudgetIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.identity != identity {
		return
	}
	c.etag, c.body, c.have, c.signerFP = "", orgcontract.PricingPolicyBody{}, false, ""
	c.identity = store.OrgBudgetIdentity{}
	c.witness = store.OrgPricingWitness{}
}

// clearIfDifferent drops a hot cache from another enrollment while preserving
// a valid body for the current one. It is used when a durable restore observes
// a replacement enrollment before the next HTTP fetch begins.
func (c *pricingCache) clearIfDifferent(identity store.OrgBudgetIdentity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.have || c.identity == identity {
		return
	}
	c.etag, c.body, c.have, c.signerFP = "", orgcontract.PricingPolicyBody{}, false, ""
	c.identity = store.OrgBudgetIdentity{}
	c.witness = store.OrgPricingWitness{}
}

// SetPricingRail turns the pricing rail on and installs the sink that receives
// every poll's typed outcome.
//
// enabled is the RULING-R2 gate: `[guard.budget].from_org`, resolved through
// internal/orgpricing.Mode at the composition site. It is a func rather than a
// bool so a config reload can turn the rail off without a restart, and it
// gates the REQUEST, not merely the apply — a node that has not opted into the
// org's prices has no business asking for the org's commercial terms.
//
// Nil-defaulted additive seam (the SetBudgetSink precedent): with nothing
// installed the rail is off and every poll is a no-op, so a build with no
// pricing wiring behaves exactly as before this arc.
func (c *Client) SetPricingRail(enabled func() bool, sink func(PricingFetchOutcome)) {
	if c == nil {
		return
	}
	c.pricingEnabled = enabled
	c.pricingSink = sink
}

// SetPricingAuthoritative installs the live tenancy resolver: true only on a
// MANAGED node whose grant carries enforce.budget.
//
// LIVE rather than captured at wiring, the routingHandle.SetManagedEnforce
// precedent: a revoked grant must stop being authoritative on the next cycle,
// not at the next restart — otherwise a developer removed from managed
// tenancy keeps having their own price overrides overridden.
func (c *Client) SetPricingAuthoritative(fn func() bool) {
	if c == nil {
		return
	}
	c.pricingAuthoritative = fn
}

// LoadPersistedPricing seeds the in-memory cache from the node-local table on
// a cold start and returns the document in force, if any.
//
// It is separate from FetchPricingPolicy so the composition site can apply the
// persisted rates BEFORE the first poll: the poll happens on the push cycle,
// which is minutes away, and every turn priced in between would otherwise be
// stamped at list rates forever.
//
// The ETag is deliberately NOT restored: it describes the last HTTP exchange,
// not the document, and presenting a stale one to a server that has re-signed
// would earn a 200 the node then treats as "changed" — harmless, but the
// honest shape is to poll unconditionally once after a restart.
func (c *Client) LoadPersistedPricing(ctx context.Context) (PricingFetchOutcome, error) {
	out := PricingFetchOutcome{State: orgcontract.PricingFetchDisabled, Authoritative: c.pricingIsAuthoritative()}
	if !c.pricingRailEnabled() {
		c.notifyPricing(ctx, out)
		return out, nil
	}
	identity, active, err := CurrentBudgetIdentity(ctx, c.store)
	if err != nil {
		out.State = orgcontract.PricingFetchUnverified
		c.notifyPricing(ctx, out)
		return out, fmt.Errorf("orgclient.LoadPersistedPricing: identity: %w", err)
	}
	if !active || identity.Binding == "" {
		out.State = orgcontract.PricingFetchNotEnrolled
		c.pricing.clearFor("")
		c.notifyPricing(ctx, out)
		return out, nil
	}
	out.Binding = identity.Binding
	c.pricing.clearIfDifferent(identity)
	cached, err := c.store.LoadOrgPricing(ctx)
	if err != nil {
		// A corrupt or unreadable row is an ABSENCE for pricing purposes: the
		// engine falls back to the seed table, which is the fail-open
		// direction (the fail-closed direction here is pricing at zero).
		out.State = orgcontract.PricingFetchUnverified
		c.notifyPricing(ctx, out)
		return out, fmt.Errorf("orgclient.LoadPersistedPricing: %w", err)
	}
	if !cached.Have {
		out.State = orgcontract.PricingFetchUnreachable
		out.Witness = cached.Witness
		c.notifyPricing(ctx, out)
		return out, nil
	}
	if cached.Binding == "" || cached.Binding != identity.Binding {
		return c.notifyPersistedPricingFailure(ctx, out,
			fmt.Errorf("orgclient.LoadPersistedPricing: %w", store.ErrOrgPricingIdentityChanged))
	}
	pub, err := c.orgSigningKey(ctx)
	if err != nil {
		return c.notifyPersistedPricingFailure(ctx, out,
			fmt.Errorf("orgclient.LoadPersistedPricing: signing key: %w", err))
	}
	fingerprint := orgcontract.PublicKeyPinHash(pub)
	if cached.KeyFingerprint == "" || cached.KeyFingerprint != fingerprint {
		return c.notifyPersistedPricingFailure(ctx, out,
			errors.New("orgclient.LoadPersistedPricing: stored signing-key fingerprint does not match the current enrollment key"))
	}
	if err := orgcontract.VerifyPricingPolicy(pub, identity.OrgID, cached.Document); err != nil {
		return c.notifyPersistedPricingFailure(ctx, out,
			fmt.Errorf("orgclient.LoadPersistedPricing: verify stored document: %w", err))
	}
	confirmed, active, err := CurrentBudgetIdentity(ctx, c.store)
	if err != nil || !active || confirmed != identity {
		return c.notifyPersistedPricingFailure(ctx, out,
			fmt.Errorf("orgclient.LoadPersistedPricing: recheck identity: %w", store.ErrOrgPricingIdentityChanged))
	}
	c.pricing.publishMu.Lock()
	c.pricing.storeWithWitness("", cached.Body, cached.KeyFingerprint, cached.Witness, identity)
	confirmed, active, err = CurrentBudgetIdentity(ctx, c.store)
	if err != nil || !active || confirmed != identity {
		c.pricing.clearFor(identity.Binding)
		c.pricing.publishMu.Unlock()
		return c.notifyPersistedPricingFailure(ctx, out,
			fmt.Errorf("orgclient.LoadPersistedPricing: published identity: %w", store.ErrOrgPricingIdentityChanged))
	}
	out.State = cached.State
	if out.State == "" {
		out.State = orgcontract.PricingFetchVerified
	}
	out.Body, out.HaveBody, out.Changed, out.Witness = cached.Body, true, true, cached.Witness
	c.notifyPricing(ctx, out)
	c.pricing.publishMu.Unlock()
	return out, nil
}

// VerifyPersistedPricing verifies a stored pricing document against the
// current enrollment identity and the node's current org signing key. It is
// used by composition sites that must seed a cost table before a Client has
// been wired with its live sink; a binding check alone would briefly admit a
// forged or stale signed envelope during cold startup.
func VerifyPersistedPricing(ctx context.Context, st *store.Store, cached store.OrgPricingCache) error {
	if st == nil {
		return errors.New("orgclient.VerifyPersistedPricing: store unavailable")
	}
	identity, active, err := CurrentBudgetIdentity(ctx, st)
	if err != nil {
		return fmt.Errorf("orgclient.VerifyPersistedPricing: identity: %w", err)
	}
	if !active || identity.Binding == "" || cached.Binding == "" || cached.Binding != identity.Binding {
		return fmt.Errorf("orgclient.VerifyPersistedPricing: %w", store.ErrOrgPricingIdentityChanged)
	}
	if !cached.Have {
		return errors.New("orgclient.VerifyPersistedPricing: no stored document")
	}
	c := &Client{store: st, logger: slog.Default()}
	pub, err := c.orgSigningKey(ctx)
	if err != nil {
		return fmt.Errorf("orgclient.VerifyPersistedPricing: signing key: %w", err)
	}
	fingerprint := orgcontract.PublicKeyPinHash(pub)
	if cached.KeyFingerprint == "" || cached.KeyFingerprint != fingerprint {
		return errors.New("orgclient.VerifyPersistedPricing: stored signing-key fingerprint does not match the current enrollment key")
	}
	if err := orgcontract.VerifyPricingPolicy(pub, identity.OrgID, cached.Document); err != nil {
		return fmt.Errorf("orgclient.VerifyPersistedPricing: verify document: %w", err)
	}
	confirmed, active, err := CurrentBudgetIdentity(ctx, st)
	if err != nil {
		return fmt.Errorf("orgclient.VerifyPersistedPricing: recheck identity: %w", err)
	}
	if !active || confirmed != identity {
		return fmt.Errorf("orgclient.VerifyPersistedPricing: recheck identity: %w", store.ErrOrgPricingIdentityChanged)
	}
	return nil
}

func (c *Client) notifyPersistedPricingFailure(ctx context.Context, out PricingFetchOutcome, err error) (PricingFetchOutcome, error) {
	out.State = orgcontract.PricingFetchUnverified
	out.HaveBody = false
	out.Body = orgcontract.PricingPolicyBody{}
	c.pricing.publishMu.Lock()
	c.notifyPricing(ctx, out)
	c.pricing.publishMu.Unlock()
	return out, err
}

// publishCurrentPricingOutcome serializes a body-carrying fetch result with
// the durable-save/publication pair. The HTTP exchange has already completed;
// this lock only covers the bounded identity/cache read and sink callback.
// When another response has published first, it returns that current coherent
// body and witness so a late 304 or transport failure cannot rewind the live
// table. A cache entry from another enrollment is cleared before any body is
// exposed under the requested binding.
func (c *Client) publishCurrentPricingOutcome(ctx context.Context, identity store.OrgBudgetIdentity, authoritative bool, state string, cause error) (PricingFetchOutcome, error) {
	c.pricing.publishMu.Lock()
	current, active, checkErr := CurrentBudgetIdentity(ctx, c.store)
	if checkErr != nil || !active || current != identity {
		c.pricing.clearFor(identity.Binding)
		out := PricingFetchOutcome{State: orgcontract.PricingFetchUnverified, Authoritative: authoritative}
		if active {
			out.Binding = current.Binding
		}
		c.notifyPricing(ctx, out)
		c.pricing.publishMu.Unlock()
		if checkErr != nil {
			return out, fmt.Errorf("orgclient.FetchPricingPolicy: current identity: %w", checkErr)
		}
		return out, fmt.Errorf("orgclient.FetchPricingPolicy: %w", store.ErrOrgPricingIdentityChanged)
	}
	_, body, have, cachedIdentity, witness := c.pricing.snapshot()
	if have && cachedIdentity != identity {
		c.pricing.clearIfIdentity(cachedIdentity)
		body, have, witness = orgcontract.PricingPolicyBody{}, false, store.OrgPricingWitness{}
	}
	if state == "" {
		state = pricingStateOf(body, have)
	}
	out := PricingFetchOutcome{
		State: state, Body: body, HaveBody: have,
		Authoritative: authoritative, Binding: identity.Binding, Witness: witness,
	}
	c.notifyPricing(ctx, out)
	c.pricing.publishMu.Unlock()
	return out, cause
}

type pricingCacheSnapshot struct {
	etag     string
	body     orgcontract.PricingPolicyBody
	have     bool
	identity store.OrgBudgetIdentity
	witness  store.OrgPricingWitness
}

type pricingResponseClass struct {
	state       string
	err         error
	notModified bool
	ok          bool
}

type verifiedPricingDocument struct {
	doc orgcontract.PricingPolicyDoc
	// raw is the VERBATIM response body the document was decoded and verified
	// from. It is threaded to store.SaveOrgPricingRaw so the persisted copy is
	// the bytes that verified, not a typed re-marshal that would drop a field
	// this build does not model and freeze the node on the next restart (N1 /
	// P2-0).
	raw json.RawMessage
	pub []byte
}

func (c *Client) pricingIdentityStillCurrent(ctx context.Context, identity store.OrgBudgetIdentity) error {
	current, active, err := CurrentBudgetIdentity(ctx, c.store)
	if err != nil {
		return err
	}
	if !active || current != identity {
		return store.ErrOrgPricingIdentityChanged
	}
	return nil
}

func (c *Client) rejectPricingIdentity(ctx context.Context, identity store.OrgBudgetIdentity, authoritative bool, cause error) (PricingFetchOutcome, error) {
	c.pricing.publishMu.Lock()
	current, currentActive, checkErr := CurrentBudgetIdentity(ctx, c.store)
	c.pricing.clearFor(identity.Binding)
	out := PricingFetchOutcome{State: orgcontract.PricingFetchUnverified, Authoritative: authoritative}
	if currentActive {
		out.Binding = current.Binding
	}
	if checkErr != nil {
		out.Binding = ""
		c.notifyPricing(ctx, out)
		c.pricing.publishMu.Unlock()
		return out, fmt.Errorf("orgclient.FetchPricingPolicy: current identity: %w", checkErr)
	}
	if cause == nil {
		cause = store.ErrOrgPricingIdentityChanged
	}
	c.notifyPricing(ctx, out)
	c.pricing.publishMu.Unlock()
	return out, fmt.Errorf("orgclient.FetchPricingPolicy: %w", cause)
}

func (c *Client) failPricingFetch(ctx context.Context, identity store.OrgBudgetIdentity, authoritative bool, state string, cause error) (PricingFetchOutcome, error) {
	if err := c.pricingIdentityStillCurrent(ctx, identity); err != nil {
		return c.rejectPricingIdentity(ctx, identity, authoritative, err)
	}
	return c.publishCurrentPricingOutcome(ctx, identity, authoritative, state, cause)
}

func (c *Client) pricingFetchRequest(ctx context.Context, enr *store.Enrolment, identity store.OrgBudgetIdentity) (*http.Response, pricingCacheSnapshot, string, error) {
	var empty pricingCacheSnapshot
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return nil, empty, orgcontract.PricingFetchNotEnrolled,
			fmt.Errorf("orgclient.FetchPricingPolicy: bearer: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + "/api/agent/pricing"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, empty, orgcontract.PricingFetchUnreachable, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	cachedETag, cachedBody, cachedHave, cachedIdentity, cachedWitness := c.pricing.snapshot()
	if cachedIdentity.Binding != identity.Binding {
		// A re-enrollment may happen in another process while this client is
		// alive. Drop the old ETag and body before the next request so a 304
		// from the replacement enrollment can never keep the prior member's
		// rates in memory.
		c.pricing.clearIfIdentity(cachedIdentity)
		cachedETag, cachedBody, cachedHave, cachedWitness = "", orgcontract.PricingPolicyBody{}, false, store.OrgPricingWitness{}
	}
	if cachedETag != "" {
		req.Header.Set("If-None-Match", cachedETag)
	}
	cached := pricingCacheSnapshot{
		etag: cachedETag, body: cachedBody, have: cachedHave,
		identity: cachedIdentity, witness: cachedWitness,
	}
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return nil, cached, orgcontract.PricingFetchUnreachable,
			fmt.Errorf("orgclient.FetchPricingPolicy: %w", err)
	}
	return resp, cached, "", nil
}

func classifyPricingResponse(status int) pricingResponseClass {
	switch {
	case status == http.StatusNotModified:
		return pricingResponseClass{notModified: true}
	case status == http.StatusNotFound:
		return pricingResponseClass{state: orgcontract.PricingFetchNotSupported}
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return pricingResponseClass{
			state: orgcontract.PricingFetchAuthFailed,
			err:   fmt.Errorf("orgclient.FetchPricingPolicy: server returned %d", status),
		}
	case status == http.StatusConflict:
		return pricingResponseClass{
			state: orgcontract.PricingFetchChannelOff,
			err:   fmt.Errorf("orgclient.FetchPricingPolicy: policy channel off (409)"),
		}
	case status != http.StatusOK:
		return pricingResponseClass{
			state: orgcontract.PricingFetchUnreachable,
			err:   fmt.Errorf("orgclient.FetchPricingPolicy: server returned %d", status),
		}
	default:
		return pricingResponseClass{ok: true}
	}
}

func (c *Client) decodeVerifyPricingDocument(ctx context.Context, resp *http.Response, enr *store.Enrolment) (verifiedPricingDocument, error) {
	// Read the body into memory (bounded) BEFORE decoding so the exact received
	// bytes can be persisted verbatim. Verification runs over doc.rawRows, which
	// UnmarshalJSON populates from these same bytes, so the bytes we keep are the
	// bytes we verified (N1 / P2-0).
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOrgDocBytes))
	if err != nil {
		return verifiedPricingDocument{}, fmt.Errorf("orgclient.FetchPricingPolicy: read body: %w", err)
	}
	var doc orgcontract.PricingPolicyDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return verifiedPricingDocument{}, fmt.Errorf("orgclient.FetchPricingPolicy: decode: %w", err)
	}
	pub, err := c.orgSigningKey(ctx)
	if err != nil {
		return verifiedPricingDocument{}, fmt.Errorf("orgclient.FetchPricingPolicy: %w", err)
	}
	if err := orgcontract.VerifyPricingPolicy(pub, enr.OrgID, doc); err != nil {
		return verifiedPricingDocument{}, fmt.Errorf("orgclient.FetchPricingPolicy: %w", err)
	}
	return verifiedPricingDocument{doc: doc, raw: json.RawMessage(raw), pub: pub}, nil
}

func (c *Client) pricingReplayError(cached pricingCacheSnapshot, doc orgcontract.PricingPolicyDoc, pub []byte) error {
	// VERSION MONOTONICITY. Equal is fine; LOWER is a replay unless the
	// signing key changed. An unknown cached signer is treated as the same key.
	cachedFP := c.pricing.signedBy()
	if cached.have && doc.Version < cached.body.Version &&
		(cachedFP == "" || cachedFP == orgcontract.PublicKeyPinHash(pub)) {
		return fmt.Errorf("orgclient.FetchPricingPolicy: refusing pricing document version %d, older than the cached %d (replay)",
			doc.Version, cached.body.Version)
	}
	return nil
}

func (c *Client) acceptPricingDocument(ctx context.Context, resp *http.Response, enr *store.Enrolment, identity store.OrgBudgetIdentity, authoritative bool, cached pricingCacheSnapshot) (PricingFetchOutcome, error) {
	verified, err := c.decodeVerifyPricingDocument(ctx, resp, enr)
	if err != nil {
		return c.failPricingFetch(ctx, identity, authoritative, orgcontract.PricingFetchUnverified, err)
	}
	if err := c.pricingReplayError(cached, verified.doc, verified.pub); err != nil {
		return c.failPricingFetch(ctx, identity, authoritative, orgcontract.PricingFetchUnverified, err)
	}
	if err := c.pricingIdentityStillCurrent(ctx, identity); err != nil {
		return c.rejectPricingIdentity(ctx, identity, authoritative, err)
	}
	return c.publishPricingDocument(ctx, identity, authoritative, cached, verified,
		strings.TrimSpace(resp.Header.Get("ETag")), pricingStateOf(verified.doc.PricingPolicyBody, true))
}

func (c *Client) publishPricingDocument(ctx context.Context, identity store.OrgBudgetIdentity, authoritative bool, cached pricingCacheSnapshot, verified verifiedPricingDocument, etag, state string) (PricingFetchOutcome, error) {
	c.pricing.publishMu.Lock()
	out, err, identityChanged := c.publishPricingDocumentLocked(ctx, identity, authoritative, cached, verified, etag, state)
	c.pricing.publishMu.Unlock()
	if identityChanged {
		return c.rejectPricingIdentity(ctx, identity, authoritative, err)
	}
	return out, err
}

func (c *Client) publishPricingDocumentLocked(ctx context.Context, identity store.OrgBudgetIdentity, authoritative bool, cached pricingCacheSnapshot, verified verifiedPricingDocument, etag, state string) (PricingFetchOutcome, error, bool) {
	_, currentBody, currentHave, currentIdentity, currentWitness := c.pricing.snapshot()
	if currentHave != cached.have || currentWitness != cached.witness ||
		(currentHave && currentIdentity.Binding != identity.Binding) {
		out := PricingFetchOutcome{
			State: orgcontract.PricingFetchUnverified, Body: currentBody,
			HaveBody: currentHave, Authoritative: authoritative,
			Binding: identity.Binding, Witness: currentWitness,
		}
		c.notifyPricing(ctx, out)
		return out, errors.New("orgclient.FetchPricingPolicy: pricing cache changed during request"), false
	}
	fp := orgcontract.PublicKeyPinHash(verified.pub)
	currentSigner := c.pricing.signedBy()
	if currentHave && verified.doc.Version < currentBody.Version &&
		(currentSigner == "" || currentSigner == fp) {
		out := PricingFetchOutcome{
			State: orgcontract.PricingFetchUnverified, Body: currentBody,
			HaveBody: true, Authoritative: authoritative,
			Binding: identity.Binding, Witness: currentWitness,
		}
		c.notifyPricing(ctx, out)
		return out, fmt.Errorf("orgclient.FetchPricingPolicy: refusing pricing document version %d, older than the cached %d (replay)", verified.doc.Version, currentBody.Version), false
	}
	witness, err := c.store.SaveOrgPricingRaw(ctx, verified.doc, verified.raw, fp, state, identity)
	if err != nil {
		if errors.Is(err, store.ErrOrgPricingIdentityChanged) {
			return PricingFetchOutcome{}, err, true
		}
		out := PricingFetchOutcome{
			State: orgcontract.PricingFetchUnverified, Body: currentBody,
			HaveBody: currentHave, Authoritative: authoritative,
			Binding: identity.Binding, Witness: currentWitness,
		}
		c.notifyPricing(ctx, out)
		return out, fmt.Errorf("orgclient.FetchPricingPolicy: persist verified document: %w", err), false
	}
	changed := !currentHave || currentWitness != witness
	c.pricing.storeWithWitness(etag, verified.doc.PricingPolicyBody, fp, witness, identity)
	c.logger.Info("org pricing document accepted",
		"version", verified.doc.Version, "models", len(verified.doc.Rows), "state", state)
	out := PricingFetchOutcome{
		State: state, Body: verified.doc.PricingPolicyBody, HaveBody: true,
		Changed: changed, Authoritative: authoritative, Binding: identity.Binding,
		Witness: witness,
	}
	// Do not notify a sink after a concurrent re-enrollment. The in-memory
	// cache is cleared for the old binding and the caller receives an empty,
	// unverified outcome, so a delayed response cannot repopulate the engine.
	if err := c.pricingIdentityStillCurrent(ctx, identity); err != nil {
		return PricingFetchOutcome{}, err, true
	}
	c.notifyPricing(ctx, out)
	return out, nil, false
}

// FetchPricingPolicy pulls the org's price list from GET /api/agent/pricing
// over the enrolment bearer, verifies it against the org signing key this node
// has already pinned, persists it, and reports a typed outcome.
//
// Every failure is FAIL-OPEN: the outcome names the state, the persisted
// document stays in force, and the error is for logging only.
func (c *Client) FetchPricingPolicy(ctx context.Context) (PricingFetchOutcome, error) {
	authoritative := c.pricingIsAuthoritative()
	if !c.pricingRailEnabled() {
		out := PricingFetchOutcome{State: orgcontract.PricingFetchDisabled, Authoritative: authoritative}
		c.notifyPricing(ctx, out)
		return out, nil
	}
	enr, identity, early, err := c.loadPricingIdentity(ctx, authoritative)
	if err != nil {
		c.notifyPricing(ctx, early)
		return early, err
	}
	resp, cached, state, err := c.pricingFetchRequest(ctx, enr, identity)
	if err != nil {
		return c.failPricingFetch(ctx, identity, authoritative, state, err)
	}
	defer func() { _ = resp.Body.Close() }()
	// The response may have spent minutes in flight while another process
	// replaced or tombstoned this enrollment. Classify only after the same
	// identity fence that protects the durable save.
	if err := c.pricingIdentityStillCurrent(ctx, identity); err != nil {
		return c.rejectPricingIdentity(ctx, identity, authoritative, err)
	}
	classification := classifyPricingResponse(resp.StatusCode)
	if classification.notModified {
		return c.publishCurrentPricingOutcome(ctx, identity, authoritative, "", nil)
	}
	if !classification.ok {
		return c.failPricingFetch(ctx, identity, authoritative, classification.state, classification.err)
	}
	return c.acceptPricingDocument(ctx, resp, enr, identity, authoritative, cached)
}

func (c *Client) loadPricingIdentity(ctx context.Context, authoritative bool) (*store.Enrolment, store.OrgBudgetIdentity, PricingFetchOutcome, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return nil, store.OrgBudgetIdentity{}, PricingFetchOutcome{State: orgcontract.PricingFetchNotEnrolled, Authoritative: authoritative},
			fmt.Errorf("orgclient.FetchPricingPolicy: enrolment: %w", err)
	}
	if enr == nil {
		return nil, store.OrgBudgetIdentity{}, PricingFetchOutcome{State: orgcontract.PricingFetchNotEnrolled, Authoritative: authoritative}, ErrNotEnrolled
	}
	identity, active, err := budgetIdentityForEnrolment(ctx, c.store, enr)
	if err != nil {
		return nil, store.OrgBudgetIdentity{}, PricingFetchOutcome{State: orgcontract.PricingFetchNotEnrolled, Authoritative: authoritative},
			fmt.Errorf("orgclient.FetchPricingPolicy: identity: %w", err)
	}
	if !active || identity.Binding == "" {
		return nil, store.OrgBudgetIdentity{}, PricingFetchOutcome{State: orgcontract.PricingFetchNotEnrolled, Authoritative: authoritative}, ErrNotEnrolled
	}
	return enr, identity, PricingFetchOutcome{}, nil
}

// notifyPricing hands one outcome to the installed sink.
//
// It lives on the client rather than at the push loop because BOTH entry
// points must notify: the cold-start LoadPersistedPricing (which puts the
// persisted rates into force minutes before the first poll) and every
// FetchPricingPolicy cycle. A notification owned by the loop would leave the
// cold start silently un-notified — the engine would hold the org's rates
// while the posture reported that nothing had been applied.
//
// A CANCELLED context is a shutdown, not a verdict: notifying "unreachable"
// there would publish a posture describing the moment the daemon stopped.
func (c *Client) notifyPricing(ctx context.Context, out PricingFetchOutcome) {
	if c == nil || c.pricingSink == nil {
		return
	}
	if ctx != nil && ctx.Err() != nil {
		return
	}
	c.pricingSink(out)
}

// pricingStateOf distinguishes a verified document that PRICES something from
// one the org deliberately emptied. Both are verified; only the second means
// "price at seed", and a surface that could not tell them apart would render
// an org's explicit withdrawal as though the rail had never run.
func pricingStateOf(body orgcontract.PricingPolicyBody, have bool) string {
	if !have {
		return orgcontract.PricingFetchUnreachable
	}
	if len(body.Rows) == 0 {
		return orgcontract.PricingFetchNoPricing
	}
	return orgcontract.PricingFetchVerified
}

// pricingRailEnabled resolves the R2 gate. A nil resolver is OFF: the rail is
// opt-in, and a build that never wired it must make no request.
func (c *Client) pricingRailEnabled() bool {
	return c != nil && c.pricingEnabled != nil && c.pricingEnabled()
}

// pricingIsAuthoritative resolves the live tenancy flag. A nil resolver is
// false, which is every individual/BYO node by construction.
func (c *Client) pricingIsAuthoritative() bool {
	return c != nil && c.pricingAuthoritative != nil && c.pricingAuthoritative()
}
