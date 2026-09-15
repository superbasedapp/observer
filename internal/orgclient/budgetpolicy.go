package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The node half of the org BUDGET rail
// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
// §3.3b/§3.3c, wave W3b).
//
// It rides the EXISTING push cycle beside FetchRoutingPolicy and
// FetchOrgAnnouncement — no new timer, no new host, no new connection (the
// announce.go discipline). Individual nodes retain their local or last
// verified budget on fetch failures. A managed node with no verified document
// for its current enrollment publishes B-625 until one arrives.
//
// WHY THE CACHE IS BOTH IN MEMORY AND PERSISTED (agent migration 119,
// org-observer fundamentals finding H3). It used to be memory-only, on the
// reasoning that "a budget is re-fetched on the very next push cycle" and the
// restart window therefore failed OPEN onto the node's own looser numbers.
// Ruling R2 ended that: a MANAGED node holding enforce.budget may not run
// without a verified body, so a memory-only cache made every restart either a
// BLOCK (nothing proxied until the first successful poll — during an org
// outage, indefinitely) or, before the node learned it was required, a full
// push interval UNCAPPED AND UNARMED, which a developer could re-open at will
// by restarting the daemon.
//
// So the verified document is written through to org_budget_cache and read
// back at cold start ([Client.LoadPersistedBudget]), and the first poll of a
// new process is still CONDITIONAL because the ETag is stored with it. The
// in-memory cache remains the hot path; the table is the restart bridge.
// Only a SIGNED body ever replaces it, and only an explicit not-found (or an
// unenrol) ever clears it.
//
// WHY THE ETAG AND NOT THE VERSION. org_budget_policy_version moves on budget
// CRUD only. A member added to a capped TEAM changes that member's effective
// body with no version bump at all, so a poll that short-circuited on version
// would answer "unchanged" to a node whose cap had genuinely moved. The server
// digests the whole signed document; the node echoes that digest in
// If-None-Match and treats 304 as "keep the cached doc".

// BudgetFetchOutcome is the TOTAL, typed classification of one budget poll
// cycle, in the shape RoutingFetchOutcome established. It is what the guard
// wiring turns into an orgcontract.BudgetFetch* posture value, so every return
// site of FetchBudgetPolicy maps to exactly one honest state.
type BudgetFetchOutcome struct {
	// State is the closed orgcontract.BudgetFetch* enum.
	State string
	// Body is the VERIFIED body in force after this cycle (the freshly
	// accepted one, or the cached one on a 304). Zero when none is in force.
	Body orgcontract.BudgetPolicyBody
	// HaveBody is true only when Body came from a signature that verified.
	//
	// It is true for a SIGNED EXPLICIT NONE as well (a verified body whose
	// Empty() reports true - the org says no budget applies to this caller).
	// That is the point of the none document: "verified, and the answer is
	// nothing" is a different state from "we could not get an answer", and
	// only the first one is safe for a fail-closed managed node to run on.
	HaveBody bool
	// Changed is true when this cycle replaced the cached document.
	Changed bool
	// Binding is the opaque enrollment-epoch identity that verified Body, or
	// the captured current epoch when this outcome intentionally has no body.
	// Native intervention compares it with a fresh authority read before using
	// any numeric cap.
	Binding string
	// Witness identifies the exact durable org_budget_cache document state that
	// produced this outcome. It is known for a persisted signed document, a
	// persisted clear, and a read that observed absence or malformed bytes.
	// Native intervention requires it before acting.
	Witness store.OrgBudgetWitness
}

// BudgetPolicyBinding derives the shared opaque identity for a budget
// publication from one enrollment row and its durable generation. Callers
// that already performed a fenced enrollment read use this helper so the
// guard and process-authority paths cannot drift in how they bind a cap.
func BudgetPolicyBinding(enr *store.Enrolment, generation int64) string {
	if enr == nil || strings.TrimSpace(enr.OrgID) == "" || strings.TrimSpace(enr.UserID) == "" {
		return ""
	}
	raw, err := json.Marshal(struct {
		Domain     string `json:"domain"`
		OrgKey     string `json:"org_key"`
		UserID     string `json:"user_id"`
		EnrolledAt string `json:"enrolled_at"`
		Generation int64  `json:"generation"`
	}{
		Domain: "sbo-budget-enrollment-v1", OrgKey: OrgKey(enr.OrgServerURL, enr.OrgID),
		UserID: enr.UserID, EnrolledAt: enr.EnrolledAt, Generation: generation,
	})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// CurrentBudgetIdentity returns the current non-tombstoned enrollment epoch
// in the exact shape used by the budget cache's atomic save/clear fence.
func CurrentBudgetIdentity(ctx context.Context, st *store.Store) (store.OrgBudgetIdentity, bool, error) {
	if st == nil {
		return store.OrgBudgetIdentity{}, false, errors.New("orgclient.CurrentBudgetIdentity: store unavailable")
	}
	enr, err := st.LoadEnrolment(ctx)
	if err != nil {
		return store.OrgBudgetIdentity{}, false, fmt.Errorf("orgclient.CurrentBudgetIdentity: %w", err)
	}
	if enr == nil {
		return store.OrgBudgetIdentity{}, false, nil
	}
	identity, active, err := budgetIdentityForEnrolment(ctx, st, enr)
	if err != nil {
		return store.OrgBudgetIdentity{}, false, fmt.Errorf("orgclient.CurrentBudgetIdentity: %w", err)
	}
	if !active {
		return store.OrgBudgetIdentity{}, false, nil
	}
	current, err := st.LoadEnrolment(ctx)
	if err != nil {
		return store.OrgBudgetIdentity{}, false, fmt.Errorf("orgclient.CurrentBudgetIdentity: recheck enrollment: %w", err)
	}
	if current == nil || *current != *enr {
		return store.OrgBudgetIdentity{}, false, nil
	}
	confirmed, active, err := budgetIdentityForEnrolment(ctx, st, current)
	if err != nil {
		return store.OrgBudgetIdentity{}, false, fmt.Errorf("orgclient.CurrentBudgetIdentity: recheck: %w", err)
	}
	if !active || confirmed != identity {
		return store.OrgBudgetIdentity{}, false, nil
	}
	return identity, true, nil
}

func budgetIdentityForEnrolment(ctx context.Context, st *store.Store, enr *store.Enrolment) (store.OrgBudgetIdentity, bool, error) {
	if st == nil || enr == nil {
		return store.OrgBudgetIdentity{}, false, nil
	}
	orgKey := OrgKey(enr.OrgServerURL, enr.OrgID)
	gen, ok, err := st.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil {
		return store.OrgBudgetIdentity{}, false, fmt.Errorf("load generation: %w", err)
	}
	if ok && gen.Tombstoned {
		return store.OrgBudgetIdentity{}, false, nil
	}
	generation := int64(0)
	if ok {
		generation = gen.Generation
	}
	return store.OrgBudgetIdentity{
		OrgKey: orgKey, OrgID: enr.OrgID, OrgServerURL: enr.OrgServerURL,
		UserID: enr.UserID, EnrolledAt: enr.EnrolledAt, Generation: generation,
		Binding: BudgetPolicyBinding(enr, generation),
	}, true, nil
}

// budgetCache is the node-local, in-memory record of the last VERIFIED budget
// document plus the ETag that produced it.
type budgetCache struct {
	// publishMu serializes the durable-write/in-memory-publication pair without
	// holding a lock across network I/O. Concurrent requests use their captured
	// witness as an optimistic generation: once one publishes, a later response
	// based on the older snapshot is discarded and the next poll refetches.
	publishMu sync.Mutex
	mu        sync.Mutex
	etag      string
	body      orgcontract.BudgetPolicyBody
	have      bool
	// signer is the FINGERPRINT (orgcontract.PublicKeyPinHash) of the org
	// signing key that verified the cached body. It exists for the
	// version-monotonicity refusal (review fix round 2, LOW-3): a version
	// LOWER than the cached one is a replay unless the org rotated its key, in
	// which case the version lineage restarts and there is nothing to compare
	// against.
	//
	// It is the FINGERPRINT rather than the raw key because the cache is now
	// restored from disk at cold start (finding H3) and the stored row records
	// a fingerprint. Keeping raw bytes here would make every restart's first
	// poll compare a fingerprint against a key, find them unequal, and SKIP
	// the replay guard exactly once per restart — a once-per-restart window in
	// which a signed older document is accepted.
	signer string
	// identity is the exact enrollment epoch that verified body. A cache entry
	// from any other epoch is invisible to the current request, including for
	// ETag/304 and outage fallback purposes.
	identity store.OrgBudgetIdentity
	witness  store.OrgBudgetWitness
}

// snapshot returns the cached body under the lock.
func (c *budgetCache) snapshot() (etag string, body orgcontract.BudgetPolicyBody, have bool, signer string, identity store.OrgBudgetIdentity, witness store.OrgBudgetWitness) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.etag, c.body, c.have, c.signer, c.identity, c.witness
}

// store replaces the cached body under the lock.
func (c *budgetCache) store(etag string, body orgcontract.BudgetPolicyBody, signer string, identity store.OrgBudgetIdentity, witness store.OrgBudgetWitness) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.etag, c.body, c.have, c.signer = etag, body, true, signer
	c.identity = identity
	c.witness = witness
}

// clearFor drops the cached body only if it belongs to binding. A late 404
// from a replaced member cannot erase the replacement member's accepted cap.
func (c *budgetCache) clearFor(binding string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.identity.Binding != binding {
		return
	}
	c.etag, c.body, c.have, c.signer = "", orgcontract.BudgetPolicyBody{}, false, ""
	c.identity = store.OrgBudgetIdentity{}
	c.witness = store.OrgBudgetWitness{}
}

func (c *budgetCache) clear() {
	c.publishMu.Lock()
	defer c.publishMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.etag, c.body, c.have, c.signer = "", orgcontract.BudgetPolicyBody{}, false, ""
	c.identity = store.OrgBudgetIdentity{}
	c.witness = store.OrgBudgetWitness{}
}

// SetBudgetSink installs the callback that receives every budget poll's typed
// outcome. Nil-defaulted additive seam (R6-1): with no sink installed, the
// fetch still runs and caches but nothing downstream changes, so a build with
// no guard wiring behaves exactly as before. `observer start` wires it to the
// guard's effective-budget applier.
func (c *Client) SetBudgetSink(sink func(BudgetFetchOutcome)) {
	if c == nil {
		return
	}
	c.budgetSink = sink
}

// SetBudgetMaxDocumentAge installs the freshness window a signed budget
// document's issued_at must fall inside ([guard.budget].max_document_age,
// finding M3). A zero or negative duration restores the default
// (orgcontract.BudgetPolicyDefaultMaxAge), so "unset" and "misconfigured"
// both land on the safe value rather than disabling the check.
//
// Nil-safe and idempotent, like every other seam on this client.
func (c *Client) SetBudgetMaxDocumentAge(d time.Duration) {
	if c == nil {
		return
	}
	c.budgetMaxAge = d
}

// SetBudgetClock overrides the clock the freshness check reads. Test seam;
// nil restores time.Now.
func (c *Client) SetBudgetClock(now func() time.Time) {
	if c == nil {
		return
	}
	c.budgetNow = now
}

// budgetClock is the freshness check's now, defaulted.
func (c *Client) budgetClock() time.Time {
	if c.budgetNow != nil {
		return c.budgetNow()
	}
	return time.Now()
}

// budgetDocumentMaxAge is the configured freshness window, defaulted.
func (c *Client) budgetDocumentMaxAge() time.Duration {
	if c.budgetMaxAge > 0 {
		return c.budgetMaxAge
	}
	return orgcontract.BudgetPolicyDefaultMaxAge
}

// SetBudgetPostureProvider forwards the node's budget-posture seam onto the
// store this client pushes from (§3.3d).
//
// It is a forwarder rather than a direct store call at the composition site
// because the push loop's Store handle is OWNED by buildOrgBundle and is not
// otherwise exposed to `observer start` — and reaching for a second handle
// over the same SQLite file just to set one func would be a second owner of
// the same seam. Nil-safe; idempotent.
func (c *Client) SetBudgetPostureProvider(p store.BudgetPostureProvider) {
	if c == nil || c.store == nil {
		return
	}
	c.store.SetBudgetPostureProvider(p)
}

// FetchBudgetPolicy pulls this caller's effective org budget from
// GET /api/agent/budget over the enrolment bearer, verifies it against the org
// signing key this node has already pinned, and caches it in memory.
//
// TRUST MODEL — the one place this rail differs from routing, and deliberately:
// a BudgetPolicyDoc carries no public key of its own, so this rail establishes
// no TOFU pin. It verifies against the key the node was ENROLLED with, and
// falls back to the key another signed-distribution rail already pinned when
// the enrolment predates that record (orgSigningKey). With no key at all the
// body is REFUSED as unverified, never applied unsigned — the node's only
// defence on this rail is the signature, and one org has one signing key.
//
// Every return classifies the fetch outcome. The publication boundary keeps a
// current cached document where safe and fails a managed node closed when no
// current enrollment-bound document is available.
type budgetCacheSnapshot struct {
	etag    string
	body    orgcontract.BudgetPolicyBody
	have    bool
	signer  string
	witness store.OrgBudgetWitness
}

func budgetFetchOutcome(identity store.OrgBudgetIdentity, state string, body orgcontract.BudgetPolicyBody, have bool, witness store.OrgBudgetWitness) BudgetFetchOutcome {
	return BudgetFetchOutcome{State: state, Body: body, HaveBody: have, Binding: identity.Binding, Witness: witness}
}

func (c *Client) budgetIdentityStillCurrent(ctx context.Context, identity store.OrgBudgetIdentity) error {
	current, ok, err := CurrentBudgetIdentity(ctx, c.store)
	if err != nil {
		return fmt.Errorf("%w: %w", store.ErrOrgBudgetIdentityChanged, err)
	}
	if !ok || current != identity {
		return store.ErrOrgBudgetIdentityChanged
	}
	return nil
}

// budgetFetchRequest owns the bearer, request, and response-identity setup so
// FetchBudgetPolicy can focus on response classification and document
// acceptance. state is the honest outcome to pair with err.
func (c *Client) budgetFetchRequest(ctx context.Context, enr *store.Enrolment, identity store.OrgBudgetIdentity) (*http.Response, budgetCacheSnapshot, string, error) {
	var empty budgetCacheSnapshot
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return nil, empty, orgcontract.BudgetFetchNotEnrolled,
			fmt.Errorf("orgclient.FetchBudgetPolicy: bearer: %w", err)
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + "/api/agent/budget"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, empty, orgcontract.BudgetFetchUnreachable,
			fmt.Errorf("orgclient.FetchBudgetPolicy: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	cachedETag, cachedBody, cachedHave, cachedSigner, cachedIdentity, cachedWitness := c.budget.snapshot()
	if cachedIdentity.Binding != identity.Binding {
		cachedETag, cachedBody, cachedHave, cachedSigner = "", orgcontract.BudgetPolicyBody{}, false, ""
		cachedWitness = store.OrgBudgetWitness{}
	}
	if cachedETag != "" {
		req.Header.Set("If-None-Match", cachedETag)
	}
	cached := budgetCacheSnapshot{
		etag: cachedETag, body: cachedBody, have: cachedHave, signer: cachedSigner, witness: cachedWitness,
	}
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return nil, cached, orgcontract.BudgetFetchUnreachable,
			fmt.Errorf("orgclient.FetchBudgetPolicy: %w", err)
	}
	if identityErr := c.budgetIdentityStillCurrent(ctx, identity); identityErr != nil {
		_ = resp.Body.Close()
		return nil, budgetCacheSnapshot{}, orgcontract.BudgetFetchUnverified,
			fmt.Errorf("orgclient.FetchBudgetPolicy: response identity: %w", identityErr)
	}
	return resp, cached, "", nil
}

// classifyBudgetResponse handles statuses that do not carry a new signed
// document. It returns handled=false only for a successful 200 body.
func (c *Client) classifyBudgetResponse(ctx context.Context, resp *http.Response, identity store.OrgBudgetIdentity, cached budgetCacheSnapshot) (BudgetFetchOutcome, bool, error) {
	switch {
	case resp.StatusCode == http.StatusNotModified:
		if !cached.have {
			return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified, orgcontract.BudgetPolicyBody{}, false, cached.witness), true,
				errors.New("orgclient.FetchBudgetPolicy: 304 without a current enrollment-bound cache")
		}
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchOK, cached.body, true, cached.witness), true, nil
	case resp.StatusCode == http.StatusNotFound:
		// A 404 is an unsigned "no budget" response. It clears the prior
		// body, but cannot make a managed node safe without a signed none.
		c.budget.publishMu.Lock()
		defer c.budget.publishMu.Unlock()
		_, currentBody, currentHave, _, currentIdentity, currentWitness := c.budget.snapshot()
		if currentHave != cached.have || currentWitness != cached.witness ||
			(currentHave && currentIdentity.Binding != identity.Binding) {
			return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified,
					currentBody, currentHave, currentWitness), true,
				errors.New("orgclient.FetchBudgetPolicy: budget cache changed during request")
		}
		witness, err := c.store.ClearOrgBudgetForIdentityWithWitness(ctx, identity)
		if err != nil {
			if errors.Is(err, store.ErrOrgBudgetIdentityChanged) {
				return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified}, true, err
			}
			// The old durable body is still the only document a signal-time
			// witness can prove. Keep the matching memory body too; publishing an
			// unsigned absence after its durable clear failed would split proxy
			// policy from the SQLite fence.
			return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified,
					cached.body, cached.have, cached.witness), true,
				fmt.Errorf("orgclient.FetchBudgetPolicy: clear persisted document: %w", err)
		}
		c.budget.clearFor(identity.Binding)
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchNoBudget, orgcontract.BudgetPolicyBody{}, false, witness), true, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchAuthFailed, cached.body, cached.have, cached.witness), true,
			fmt.Errorf("orgclient.FetchBudgetPolicy: server returned %d", resp.StatusCode)
	case resp.StatusCode == http.StatusConflict:
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchChannelOff, cached.body, cached.have, cached.witness), true,
			fmt.Errorf("orgclient.FetchBudgetPolicy: policy channel off (409)")
	case resp.StatusCode != http.StatusOK:
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnreachable, cached.body, cached.have, cached.witness), true,
			fmt.Errorf("orgclient.FetchBudgetPolicy: server returned %d", resp.StatusCode)
	default:
		return BudgetFetchOutcome{}, false, nil
	}
}

func (c *Client) acceptBudgetDocument(ctx context.Context, resp *http.Response, enr *store.Enrolment, identity store.OrgBudgetIdentity, cached budgetCacheSnapshot) (BudgetFetchOutcome, error) {
	var doc orgcontract.BudgetPolicyDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOrgDocBytes)).Decode(&doc); err != nil {
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified, cached.body, cached.have, cached.witness),
			fmt.Errorf("orgclient.FetchBudgetPolicy: decode: %w", err)
	}
	pub, err := c.orgSigningKey(ctx)
	if err != nil {
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified, cached.body, cached.have, cached.witness),
			fmt.Errorf("orgclient.FetchBudgetPolicy: %w", err)
	}
	if err := orgcontract.VerifyBudgetPolicy(pub, enr.OrgID, enr.UserID, doc); err != nil {
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified, cached.body, cached.have, cached.witness),
			fmt.Errorf("orgclient.FetchBudgetPolicy: %w", err)
	}
	if fresh, why := orgcontract.BudgetPolicyFresh(doc.IssuedAt, c.budgetDocumentMaxAge(), c.budgetClock()); !fresh {
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified, cached.body, cached.have, cached.witness),
			fmt.Errorf("orgclient.FetchBudgetPolicy: refusing budget policy: %s", why)
	}
	fingerprint := orgcontract.PublicKeyPinHash(pub)
	if err := c.budgetIdentityStillCurrent(ctx, identity); err != nil {
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified, orgcontract.BudgetPolicyBody{}, false, store.OrgBudgetWitness{}),
			fmt.Errorf("orgclient.FetchBudgetPolicy: verified identity: %w", err)
	}
	etag := strings.TrimSpace(resp.Header.Get("ETag"))
	c.budget.publishMu.Lock()
	defer c.budget.publishMu.Unlock()
	_, currentBody, currentHave, currentSigner, currentIdentity, currentWitness := c.budget.snapshot()
	if currentIdentity.Binding != identity.Binding {
		// The request also captured an old-binding cache as empty. Normalize only
		// this comparison view: the real old-binding entry remains a coherent
		// fallback until the replacement is durably saved and published.
		currentBody, currentHave, currentSigner = orgcontract.BudgetPolicyBody{}, false, ""
		currentWitness = store.OrgBudgetWitness{}
	}
	if currentHave != cached.have || currentWitness != cached.witness {
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified,
				currentBody, currentHave, currentWitness),
			errors.New("orgclient.FetchBudgetPolicy: budget cache changed during request")
	}
	if currentHave && doc.Version < currentBody.Version && currentSigner == fingerprint {
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified, currentBody, true, currentWitness),
			fmt.Errorf("orgclient.FetchBudgetPolicy: refusing budget policy version %d, older than the cached %d (replay)", doc.Version, currentBody.Version)
	}
	witness, persistErr := c.store.SaveOrgBudgetWithWitness(ctx, doc, etag, fingerprint, identity)
	if persistErr != nil {
		if errors.Is(persistErr, store.ErrOrgBudgetIdentityChanged) {
			return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified, orgcontract.BudgetPolicyBody{}, false, store.OrgBudgetWitness{}), persistErr
		}
		// Durable publication is part of accepting a body for native process
		// control. Keep the previous coherent cache when the write fails; a new
		// numeric decision with no matching durable witness could never be
		// proven at signal time.
		return budgetFetchOutcome(identity, orgcontract.BudgetFetchUnverified,
				currentBody, currentHave, currentWitness),
			fmt.Errorf("orgclient.FetchBudgetPolicy: persist verified document: %w", persistErr)
	}
	changed := !currentHave || currentWitness != witness
	c.budget.store(etag, doc.BudgetPolicyBody, fingerprint, identity, witness)
	if err := c.budgetIdentityStillCurrent(ctx, identity); err != nil {
		c.budget.clearFor(identity.Binding)
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified},
			fmt.Errorf("orgclient.FetchBudgetPolicy: published identity: %w", err)
	}
	if doc.Empty() {
		c.logger.Info("org budget policy accepted: signed explicit none (no budget applies to this member)", "version", doc.Version)
	} else {
		c.logger.Info("org budget policy accepted", "version", doc.Version, "periods", len(doc.Caps))
	}
	return BudgetFetchOutcome{
		State: orgcontract.BudgetFetchOK, Body: doc.BudgetPolicyBody, HaveBody: true,
		Changed: changed, Binding: identity.Binding, Witness: witness,
	}, nil
}

func (c *Client) FetchBudgetPolicy(ctx context.Context) (BudgetFetchOutcome, error) {
	if c == nil {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchNotEnrolled}, errors.New("orgclient.FetchBudgetPolicy: client unavailable")
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchNotEnrolled},
			fmt.Errorf("orgclient.FetchBudgetPolicy: enrolment: %w", err)
	}
	if enr == nil {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchNotEnrolled}, ErrNotEnrolled
	}
	identity, active, err := budgetIdentityForEnrolment(ctx, c.store, enr)
	if err != nil {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchNotEnrolled},
			fmt.Errorf("orgclient.FetchBudgetPolicy: identity: %w", err)
	}
	if !active || identity.Binding == "" {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchNotEnrolled}, ErrNotEnrolled
	}
	resp, cached, state, err := c.budgetFetchRequest(ctx, enr, identity)
	if err != nil {
		return budgetFetchOutcome(identity, state, cached.body, cached.have, cached.witness), err
	}
	defer func() { _ = resp.Body.Close() }()
	if outcome, handled, err := c.classifyBudgetResponse(ctx, resp, identity, cached); handled {
		return outcome, err
	}
	return c.acceptBudgetDocument(ctx, resp, enr, identity, cached)
}

// LoadPersistedBudget restores the last VERIFIED budget document from
// org_budget_cache and reports it as a fetch outcome, WITHOUT making a request
// (org-observer fundamentals finding H3, the LoadPersistedPricing shape).
//
// It is called once at daemon start, before the first poll, so a restart
// continues with exactly the caps the previous process was enforcing. The
// state it reports is deliberately NOT `ok`: nothing has been fetched by THIS
// process, and claiming otherwise would make `last_fetch_ok` mean "we have a
// body" instead of "we spoke to the org". `unreachable` + HaveBody is the
// honest pair, and it is the same pair a live outage produces — which is the
// point: a restart during an outage should look like the outage, not like a
// new and different failure.
//
// A node with NOTHING stored reports HaveBody=false, which on a node that
// REQUIRES an org budget arms the block immediately rather than a push
// interval later. That is the fail-closed direction and it is the other half
// of what this function exists for.
//
// The persisted enrollment binding must match the current member and durable
// generation exactly. Legacy unbound rows and rows from a replaced enrollment
// are treated as absent, which arms B-625 on a managed node until a live fetch
// produces a document for the current epoch.
func (c *Client) LoadPersistedBudget(ctx context.Context) (BudgetFetchOutcome, error) {
	if c == nil {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnreachable}, errors.New("orgclient.LoadPersistedBudget: client unavailable")
	}
	c.budget.publishMu.Lock()
	defer c.budget.publishMu.Unlock()
	identity, active, err := CurrentBudgetIdentity(ctx, c.store)
	if err != nil {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnreachable},
			fmt.Errorf("orgclient.LoadPersistedBudget: identity: %w", err)
	}
	if !active || identity.Binding == "" {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnreachable}, nil
	}
	cached, err := c.store.LoadOrgBudget(ctx)
	if err != nil {
		// Malformed durable bytes are known but unverified. An unavailable SQL
		// read has no witness and remains unreachable. Both arm B-625 on a
		// required node, while only the first can be fenced to an exact state.
		state := orgcontract.BudgetFetchUnreachable
		if cached.Witness.Valid() && cached.Witness.Present {
			state = orgcontract.BudgetFetchUnverified
		}
		return BudgetFetchOutcome{State: state, Binding: identity.Binding, Witness: cached.Witness},
			fmt.Errorf("orgclient.LoadPersistedBudget: %w", err)
	}
	if !cached.Have {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnreachable, Binding: identity.Binding, Witness: cached.Witness}, nil
	}
	if cached.Binding == "" || cached.Binding != identity.Binding {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified, Binding: identity.Binding, Witness: cached.Witness},
			fmt.Errorf("orgclient.LoadPersistedBudget: %w", store.ErrOrgBudgetIdentityChanged)
	}
	pub, err := c.orgSigningKey(ctx)
	if err != nil {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified, Binding: identity.Binding, Witness: cached.Witness},
			fmt.Errorf("orgclient.LoadPersistedBudget: signing key: %w", err)
	}
	fingerprint := orgcontract.PublicKeyPinHash(pub)
	if cached.KeyFingerprint == "" || cached.KeyFingerprint != fingerprint {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified, Binding: identity.Binding, Witness: cached.Witness},
			errors.New("orgclient.LoadPersistedBudget: stored signing-key fingerprint does not match the current enrollment key")
	}
	if err := orgcontract.VerifyBudgetPolicy(pub, identity.OrgID, identity.UserID, cached.Document); err != nil {
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified, Binding: identity.Binding, Witness: cached.Witness},
			fmt.Errorf("orgclient.LoadPersistedBudget: verify stored document: %w", err)
	}
	confirmed, active, err := CurrentBudgetIdentity(ctx, c.store)
	if err != nil || !active || confirmed != identity {
		if err != nil {
			return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified, Witness: cached.Witness},
				fmt.Errorf("orgclient.LoadPersistedBudget: recheck identity: %w: %w", store.ErrOrgBudgetIdentityChanged, err)
		}
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified, Witness: cached.Witness},
			fmt.Errorf("orgclient.LoadPersistedBudget: %w", store.ErrOrgBudgetIdentityChanged)
	}
	c.budget.store(cached.ETag, cached.Body, cached.KeyFingerprint, identity, cached.Witness)
	confirmed, active, err = CurrentBudgetIdentity(ctx, c.store)
	if err != nil || !active || confirmed != identity {
		c.budget.clearFor(identity.Binding)
		if err != nil {
			return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified, Witness: cached.Witness},
				fmt.Errorf("orgclient.LoadPersistedBudget: published identity: %w: %w", store.ErrOrgBudgetIdentityChanged, err)
		}
		return BudgetFetchOutcome{State: orgcontract.BudgetFetchUnverified, Witness: cached.Witness},
			fmt.Errorf("orgclient.LoadPersistedBudget: published identity: %w", store.ErrOrgBudgetIdentityChanged)
	}
	return BudgetFetchOutcome{
		State: orgcontract.BudgetFetchUnreachable, Body: cached.Body, HaveBody: true,
		Binding: identity.Binding, Witness: cached.Witness,
	}, nil
}

// errNoPinnedOrgKey reports that no signed-distribution rail has pinned the
// org's signing key yet, so a budget body cannot be verified. It is a typed
// sentinel because it is a CAPABILITY gap (nothing has run yet), not a trust
// failure — the caller logs it differently and the posture reports it as
// "unverified", the honest label for "arrived but not checkable".
var errNoPinnedOrgKey = errors.New("orgclient: no rail has pinned the org signing key yet")

// orgSigningKey resolves the org's Ed25519 signing key for the rails that
// carry no key of their own (budget, pricing).
//
// R1: the ENROLMENT pin is the trust root and wins outright — it is the key
// the org server delivered over the channel that created this node, and it is
// the key that server signs budget, pricing and policy-bundle documents with.
// A FETCH rail pin that disagrees with it is STALE, not authoritative: that is
// precisely the state a node lands in when it TOFU-pinned the server's
// database key on the routing rail before the server was taught to sign every
// rail with the configured file key. Such a pin is refused as a source of
// truth (never used to verify a document) and named once in the log, rather
// than being allowed to veto a rail the operator needs.
//
// With no enrolment pin — a pre-R1 enrolment, or a server that delivers no
// key — the old rule applies unchanged: take the rail pins, and refuse when
// they disagree, because a budget must never be verified against whichever of
// two keys happens to be listed first.
func (c *Client) orgSigningKey(ctx context.Context) (ed25519.PublicKey, error) {
	pins, err := c.loadRailPins(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errPinStoreRead, err)
	}
	key := ""
	if len(pins) > 0 && pins[0].rail == enrolmentRail {
		key = pins[0].key
		for _, p := range pins[1:] {
			if p.key != key {
				c.railPinDriftOnce.Do(func() {
					c.logger.Warn("org distribution key: a fetch rail holds an older pin than the enrolment key — using the ENROLMENT key; the rail re-pins on its next accepted document",
						"enrolment_key", prefix8(key), "rail", p.rail, "rail_key", prefix8(p.key))
				})
			}
		}
	}
	if key == "" {
		for _, p := range pins {
			switch {
			case key == "":
				key = p.key
			case key != p.key:
				return nil, fmt.Errorf("%w (the %s rail pinned %s…, another pinned %s…) — refusing; re-enrol to rotate trust",
					errPinMismatch, p.rail, prefix8(p.key), prefix8(key))
			}
		}
	}
	if key == "" {
		return nil, errNoPinnedOrgKey
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("orgclient.orgSigningKey: decode pinned key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("orgclient.orgSigningKey: pinned key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
