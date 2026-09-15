package orgclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient/gen"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sealbox"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Node-side break-glass lease redemption (Plane B dual-mode gateway design
// 2026-08-29 §4.2 rung 3; gap register 2026-09-02 G1-BREAKGLASS). The server
// half (request → super-admin approve → per-machine sealed lease on the push
// response) shipped in P6; this file is the node half that makes it end-to-end:
//
//   1. SEAL KEY PUBLICATION. Every push carries orgcontract.HeaderSealKey — the
//      node's X25519 public seal key, derived from its enrolment Ed25519 seed
//      (sealbox.DeriveKeyPair) and signed under that same enrolment key, bound
//      to (org, node). The server records it after verifying the signature
//      against the agent key it bound at enrolment.
//   2. REDEMPTION. A push response may carry break_glass_leases. Each lease
//      runs the accept gates (org/server/node identity, signature, key pin,
//      declared pin, expiry, rung, scheme) — every refusal logged with a NAMED
//      reason, mirroring AcceptGrantReplacement — then the seal is opened with
//      the derived private key. The plaintext credential lives in the bearer
//      store's break-glass slot (keychain / 0600 file) and in memory; it is
//      never written to the agent DB and never logged.
//   3. ACK + REVOKE. Redeemed lease ids ride back on the next push
//      (HeaderBreakGlassAck) so delivery stops; early revocations the server
//      announces (break_glass_revoked_lease_ids) drop the local lease; TTL is
//      enforced locally on every read.
//
// CONSUMPTION SEAM: internal/proxy's break_glass terminal rung consults
// Client.BreakGlassCredential through a cmd/observer bridge (the same shape as
// the virtual-key VirtualKeySource bridge). That proxy edit is specified in
// docs/plans/arc1-stream-d-enforcement-notes-2026-09-02.md; until it lands the
// rung still fails closed exactly as before — a redeemed lease never widens
// access on its own.

// recBreakGlassLeases is the bearer-store record (fourth slot) holding the
// JSON-encoded redeemed leases.
const recBreakGlassLeases = "break-glass-leases"

// BreakGlassLeaseStore is the OPTIONAL fourth BearerStore slot. It is a
// separate interface (type-asserted) rather than new BearerStore methods so
// every existing BearerStore implementation — including test fakes in other
// packages — keeps compiling untouched (CLAUDE.md "additive, not invasive"). A
// store that does not implement it keeps leases in memory only for the life
// of the process, which is logged once.
type BreakGlassLeaseStore interface {
	// SaveBreakGlassLeases persists the encoded lease set (an empty slice
	// clears the slot).
	SaveBreakGlassLeases(raw []byte) error
	// LoadBreakGlassLeases returns the encoded lease set, or ErrNoSecret when
	// nothing has been saved.
	LoadBreakGlassLeases() ([]byte, error)
}

// redeemedLease is the node's persisted record of one opened lease. Credential
// is the plaintext provider credential — the ONLY place it exists on the node.
type redeemedLease struct {
	LeaseID     string `json:"lease_id"`
	RequestID   string `json:"request_id"`
	UpstreamID  string `json:"upstream_id"`
	Credential  string `json:"credential"`
	ApprovedBy  string `json:"approved_by"`
	GrantedAt   string `json:"granted_at"`
	ExpiresAt   string `json:"expires_at"`
	ReceiptHash string `json:"receipt_hash"`
	// Acked is set once the server has been told (on a successful push) that
	// this lease was redeemed; until then the id rides HeaderBreakGlassAck.
	Acked bool `json:"acked"`
}

// BreakGlassLeaseInfo is the metadata view of a live lease (no credential),
// for status surfaces.
type BreakGlassLeaseInfo struct {
	LeaseID    string    `json:"lease_id"`
	RequestID  string    `json:"request_id"`
	UpstreamID string    `json:"upstream_id"`
	ApprovedBy string    `json:"approved_by"`
	GrantedAt  time.Time `json:"granted_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// BreakGlassCredential is the answer to a consumer's lookup: the plaintext
// credential for one upstream plus the lease it came from.
type BreakGlassCredential struct {
	LeaseID    string
	UpstreamID string
	Credential string
	ExpiresAt  time.Time
}

// breakGlassState is the client's owning struct for redeemed leases (one owner
// per piece of state).
type breakGlassState struct {
	mu     sync.Mutex
	loaded bool
	leases map[string]redeemedLease // by lease id
	// warnedNoStore suppresses the memory-only warning after the first time.
	warnedNoStore bool
}

// sealKeyPair derives the node's seal key pair from its enrolment signing key.
func sealKeyPair(signKey ed25519.PrivateKey) (sealbox.KeyPair, error) {
	if len(signKey) != ed25519.PrivateKeySize {
		return sealbox.KeyPair{}, errors.New("orgclient: no enrolment signing key to derive a seal key from")
	}
	return sealbox.DeriveKeyPair(signKey.Seed())
}

// sealKeyEditor sets HeaderSealKey on a push: the node's derived public seal
// key, signed under the enrolment key and bound to (org, node). A derivation
// failure sends no header (the push proceeds; break-glass simply stays
// unavailable for this node until it is fixed).
func sealKeyEditor(signKey ed25519.PrivateKey, orgID, userID string) gen.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		kp, err := sealKeyPair(signKey)
		if err != nil || orgID == "" || userID == "" {
			return nil
		}
		adv := orgcontract.SignSealKeyAdvertisement(signKey, orgID, userID, sealbox.SchemeV1, kp.PublicB64())
		req.Header.Set(orgcontract.HeaderSealKey, adv.HeaderValue())
		return nil
	}
}

// breakGlassAckEditor reports the redeemed-but-unacked lease ids on a push.
func breakGlassAckEditor(ids []string) gen.RequestEditorFn {
	return func(_ context.Context, req *http.Request) error {
		if len(ids) > 0 {
			req.Header.Set(orgcontract.HeaderBreakGlassAck, strings.Join(ids, ","))
		}
		return nil
	}
}

// loadBreakGlass hydrates the in-memory set from the bearer store once per
// process. Corrupt/absent slot ⇒ empty set (logged), never a failed push.
func (c *Client) loadBreakGlass() {
	c.bg.mu.Lock()
	defer c.bg.mu.Unlock()
	if c.bg.loaded {
		return
	}
	c.bg.loaded = true
	c.bg.leases = map[string]redeemedLease{}
	ls, ok := c.bearers.(BreakGlassLeaseStore)
	if !ok {
		return
	}
	raw, err := ls.LoadBreakGlassLeases()
	if errors.Is(err, ErrNoSecret) || (err == nil && len(raw) == 0) {
		return
	}
	if err != nil {
		c.logger.Warn("break-glass: could not load redeemed leases from the bearer store; starting empty", "err", err)
		return
	}
	var list []redeemedLease
	if err := json.Unmarshal(raw, &list); err != nil {
		c.logger.Warn("break-glass: redeemed-lease slot is corrupt; starting empty", "err", err)
		return
	}
	for _, l := range list {
		c.bg.leases[l.LeaseID] = l
	}
}

// persistBreakGlassLocked writes the current set to the bearer-store slot.
// Caller holds c.bg.mu.
func (c *Client) persistBreakGlassLocked() {
	ls, ok := c.bearers.(BreakGlassLeaseStore)
	if !ok {
		if !c.bg.warnedNoStore {
			c.bg.warnedNoStore = true
			c.logger.Warn("break-glass: bearer store has no lease slot; redeemed leases are held in memory only for this process")
		}
		return
	}
	list := make([]redeemedLease, 0, len(c.bg.leases))
	for _, l := range c.bg.leases {
		list = append(list, l)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].LeaseID < list[j].LeaseID })
	raw, err := json.Marshal(list)
	if err != nil {
		c.logger.Warn("break-glass: encode leases", "err", err)
		return
	}
	if err := ls.SaveBreakGlassLeases(raw); err != nil {
		c.logger.Warn("break-glass: persist leases to the bearer store failed", "err", err)
	}
}

// pruneExpiredLocked drops TTL-expired leases. Caller holds c.bg.mu.
func (c *Client) pruneExpiredLocked(now time.Time) (dropped int) {
	for id, l := range c.bg.leases {
		if exp := parseRFC3339OrZero(l.ExpiresAt); exp.IsZero() || !now.Before(exp) {
			delete(c.bg.leases, id)
			dropped++
			c.logger.Info("break-glass: lease expired at TTL — custody restored for this upstream", "lease_id", id, "upstream", l.UpstreamID)
		}
	}
	return dropped
}

// pendingBreakGlassAcks returns redeemed lease ids not yet acked to the server.
func (c *Client) pendingBreakGlassAcks() []string {
	c.loadBreakGlass()
	c.bg.mu.Lock()
	defer c.bg.mu.Unlock()
	var ids []string
	for id, l := range c.bg.leases {
		if !l.Acked {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// markBreakGlassAcked stamps the ids the server has now heard (a 200 push).
func (c *Client) markBreakGlassAcked(ids []string) {
	if len(ids) == 0 {
		return
	}
	c.bg.mu.Lock()
	defer c.bg.mu.Unlock()
	changed := false
	for _, id := range ids {
		if l, ok := c.bg.leases[id]; ok && !l.Acked {
			l.Acked = true
			c.bg.leases[id] = l
			changed = true
		}
	}
	if changed {
		c.persistBreakGlassLocked()
	}
}

// maybeRedeemBreakGlassLeases decodes the lease + revocation seams from a 200
// push response body and feeds them to the accept path. Best-effort: nothing
// here can fail an already-accepted push.
func (c *Client) maybeRedeemBreakGlassLeases(ctx context.Context, body []byte, signKey ed25519.PrivateKey, enr *store.Enrolment) {
	if len(body) == 0 || enr == nil {
		return
	}
	var extra struct {
		Leases  []orgcontract.BreakGlassLease `json:"break_glass_leases"`
		Revoked []string                      `json:"break_glass_revoked_lease_ids"`
	}
	if err := json.Unmarshal(body, &extra); err != nil {
		return
	}
	if len(extra.Revoked) > 0 {
		c.DropBreakGlassLeases(extra.Revoked, "revoked by the org server")
	}
	for _, l := range extra.Leases {
		if _, err := c.RedeemBreakGlassLease(ctx, l, signKey, enr); err != nil {
			c.logger.Warn("break-glass: redemption path failed", "lease_id", l.LeaseID, "err", err)
		}
	}
}

// RedeemBreakGlassLease runs the accept gates for one lease and, on success,
// opens the per-machine seal and stores the credential. Like
// AcceptGrantReplacement it NEVER returns an error for an honest refusal:
// accepted=false, err=nil means the lease was refused (logged with a named
// reason) and nothing changed; err is reserved for local failures. An already
// redeemed lease id is accepted idempotently (accepted=true, no re-open).
func (c *Client) RedeemBreakGlassLease(ctx context.Context, l orgcontract.BreakGlassLease, signKey ed25519.PrivateKey, enr *store.Enrolment) (accepted bool, err error) {
	_ = ctx
	refuse := func(reason string, kv ...any) (bool, error) {
		c.logger.Warn("break-glass lease REFUSED: "+reason+" — custody stays with the gateway", append([]any{"lease_id", l.LeaseID}, kv...)...)
		return false, nil
	}
	if enr == nil {
		return refuse("not enrolled")
	}
	if l.OrgID != enr.OrgID {
		return refuse("names a different org than the current enrolment", "lease_org", l.OrgID)
	}
	if l.OrgServerURL != enr.OrgServerURL {
		return refuse("names a different org server than the current enrolment", "lease_server", l.OrgServerURL)
	}
	if l.UserID != enr.UserID {
		return refuse("targets a different node than this enrolment", "lease_user", l.UserID)
	}
	if l.Rung != "break_glass" {
		return refuse("unknown fallback rung", "rung", l.Rung)
	}
	pub, verr := orgcontract.VerifyBreakGlassLease(l)
	if verr != nil {
		return refuse("signature did not verify", "err", verr)
	}
	// Key pin: a lease is never TOFU-pinned. Without a recorded pin it is
	// refused rather than trusted on the spot (same rule as grant replacement).
	pinned, perr := c.loadKeyPin(ctx, enr.OrgServerURL)
	if perr != nil {
		return false, fmt.Errorf("orgclient.RedeemBreakGlassLease: read key pin: %w", perr)
	}
	if pinned == "" {
		return refuse("no org policy signing key is pinned yet for this enrolment")
	}
	if got := orgcontract.PublicKeyPinHash(pub); got != pinned {
		return refuse("signed under a key that does not match the pin recorded at enrolment", "lease_key_sha256", got, "pinned_key_sha256", pinned)
	}
	if l.KeyPinSHA256 != pinned {
		return refuse("declared key pin does not match the recorded pin", "declared", l.KeyPinSHA256, "pinned", pinned)
	}
	exp := parseRFC3339OrZero(l.ExpiresAt)
	if exp.IsZero() {
		return refuse("expires_at is not RFC3339", "expires_at", l.ExpiresAt)
	}
	now := time.Now().UTC()
	if !now.Before(exp) {
		return refuse("already expired", "expires_at", l.ExpiresAt)
	}
	if !sealbox.KnownScheme(l.SealScheme) {
		return refuse("unknown seal scheme", "scheme", l.SealScheme)
	}
	kp, kerr := sealKeyPair(signKey)
	if kerr != nil {
		return false, fmt.Errorf("orgclient.RedeemBreakGlassLease: %w", kerr)
	}
	c.loadBreakGlass()
	c.bg.mu.Lock()
	defer c.bg.mu.Unlock()
	if _, dup := c.bg.leases[l.LeaseID]; dup {
		return true, nil
	}
	cred, oerr := sealbox.Open(kp, l.SealedCredential, sealbox.LeaseAAD(l.OrgID, l.UserID, l.UpstreamID))
	if oerr != nil {
		c.logger.Warn("break-glass lease REFUSED: sealed credential did not open for this machine — custody stays with the gateway", "lease_id", l.LeaseID, "err", oerr)
		return false, nil
	}
	c.bg.leases[l.LeaseID] = redeemedLease{
		LeaseID: l.LeaseID, RequestID: l.RequestID, UpstreamID: l.UpstreamID,
		Credential: string(cred), ApprovedBy: l.ApprovedBy, GrantedAt: l.GrantedAt,
		ExpiresAt: l.ExpiresAt, ReceiptHash: orgcontract.BreakGlassLeaseReceiptHash(l),
	}
	c.persistBreakGlassLocked()
	// Loud by design: custody is suspended, visibly.
	c.logger.Warn("break-glass lease REDEEMED — custody is SUSPENDED for this upstream until the lease expires or is revoked",
		"lease_id", l.LeaseID, "upstream", l.UpstreamID, "approved_by", l.ApprovedBy, "expires_at", l.ExpiresAt)
	return true, nil
}

// DropBreakGlassLeases removes the named leases locally (server revoke, or an
// operator's `observer org break-glass drop`). Unknown ids are ignored.
func (c *Client) DropBreakGlassLeases(ids []string, why string) int {
	c.loadBreakGlass()
	c.bg.mu.Lock()
	defer c.bg.mu.Unlock()
	n := 0
	for _, id := range ids {
		if l, ok := c.bg.leases[id]; ok {
			delete(c.bg.leases, id)
			n++
			c.logger.Warn("break-glass lease DROPPED — custody restored for this upstream", "lease_id", id, "upstream", l.UpstreamID, "why", why)
		}
	}
	if n > 0 {
		c.persistBreakGlassLocked()
	}
	return n
}

// BreakGlassCredential returns the live credential leased for upstreamID, if
// any. Expired leases are pruned on the way; when several live leases name the
// same upstream the latest-expiring one wins. This is the consumption seam for
// the proxy's break_glass terminal rung.
func (c *Client) BreakGlassCredential(upstreamID string) (BreakGlassCredential, bool) {
	c.loadBreakGlass()
	c.bg.mu.Lock()
	defer c.bg.mu.Unlock()
	if c.pruneExpiredLocked(time.Now().UTC()) > 0 {
		c.persistBreakGlassLocked()
	}
	var best redeemedLease
	found := false
	for _, l := range c.bg.leases {
		if l.UpstreamID != upstreamID {
			continue
		}
		if !found || parseRFC3339OrZero(l.ExpiresAt).After(parseRFC3339OrZero(best.ExpiresAt)) {
			best, found = l, true
		}
	}
	if !found {
		return BreakGlassCredential{}, false
	}
	return BreakGlassCredential{
		LeaseID: best.LeaseID, UpstreamID: best.UpstreamID,
		Credential: best.Credential, ExpiresAt: parseRFC3339OrZero(best.ExpiresAt),
	}, true
}

// LiveBreakGlassLeases lists the live leases (metadata only) for status
// surfaces, soonest-expiring first.
func (c *Client) LiveBreakGlassLeases() []BreakGlassLeaseInfo {
	c.loadBreakGlass()
	c.bg.mu.Lock()
	defer c.bg.mu.Unlock()
	if c.pruneExpiredLocked(time.Now().UTC()) > 0 {
		c.persistBreakGlassLocked()
	}
	out := make([]BreakGlassLeaseInfo, 0, len(c.bg.leases))
	for _, l := range c.bg.leases {
		out = append(out, BreakGlassLeaseInfo{
			LeaseID: l.LeaseID, RequestID: l.RequestID,
			UpstreamID: l.UpstreamID, ApprovedBy: l.ApprovedBy,
			GrantedAt: parseRFC3339OrZero(l.GrantedAt), ExpiresAt: parseRFC3339OrZero(l.ExpiresAt),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out
}

// clearBreakGlass forgets every lease (unenrol). The bearer store's own Clear
// removes the persisted slot.
func (c *Client) clearBreakGlass() {
	c.bg.mu.Lock()
	defer c.bg.mu.Unlock()
	c.bg.leases = map[string]redeemedLease{}
	c.bg.loaded = true
}
