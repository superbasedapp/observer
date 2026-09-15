package orgclient

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// currentReplacementGeneration returns the highest grant-replacement generation
// this node has adopted (its stored grant's ReplacementGeneration), or 0 when
// the node holds no grant or the read fails. It is the value the push ACK
// header carries so the server's fleet-ACK gate learns the node is converged.
func (c *Client) currentReplacementGeneration(ctx context.Context, enr *store.Enrolment) int64 {
	if enr == nil {
		return 0
	}
	orgURL := strings.TrimRight(strings.TrimSpace(enr.OrgServerURL), "/")
	g, ok, err := c.store.LoadEnrolmentGrant(ctx, OrgKey(orgURL, enr.OrgID))
	if err != nil || !ok {
		return 0
	}
	return g.ReplacementGeneration
}

// maybeApplyGrantReplacement decodes an optional grant-replacement carried on a
// push response's RAW body (the generated 200 struct does not model it, so no
// OpenAPI regeneration is needed) and feeds it to AcceptGrantReplacement. It is
// best-effort: a missing field, a decode error, or an honest refusal all leave
// the node's last-good grant untouched and never fail the push.
func (c *Client) maybeApplyGrantReplacement(ctx context.Context, body []byte) {
	if len(body) == 0 {
		return
	}
	var extra struct {
		GrantReplacement *orgcontract.GrantReplacement `json:"grant_replacement"`
	}
	if err := json.Unmarshal(body, &extra); err != nil || extra.GrantReplacement == nil {
		return
	}
	applied, err := c.AcceptGrantReplacement(ctx, *extra.GrantReplacement)
	if err != nil {
		c.logger.Warn("grant replacement: accept path failed", "err", err)
		return
	}
	if applied {
		c.logger.Info("grant replacement: applied from push response",
			"generation", extra.GrantReplacement.Generation)
	}
}

// Grant replacement (Plane B dual-mode gateway/RBAC/IA design,
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §5.3
// item 5, Sol S4). AcceptGrantReplacement is the node's ACCEPT PATH for an
// out-of-band authority change the org server pushes to an already-enrolled
// node, without the node going through re-enrolment.
//
// It runs unattended — a replacement narrows or widens authority WITHIN an
// enrolment a human already consented to at Enroll time (or under Enterprise
// Managed Tenancy's standing consent), so unlike confirmAndStoreGrant's CLI
// flow there is no interactive prompt here: verify, then apply or refuse.
//
// Delivery wiring (how an orgcontract.GrantReplacement message actually
// reaches this function from a poll/push cycle) is OUT OF SCOPE for this
// lane — it is a new wire field/endpoint owned by the org-server side of
// this feature. This function is the complete, independently testable
// accept path; wiring a real delivery mechanism to call it is follow-up
// work once that server-side shape exists.

// AcceptGrantReplacement runs the accept gates for r and, on success,
// atomically supersedes the stored EnrolmentGrant via
// store.ReplaceEnrolmentGrant. It NEVER returns an error for an honest
// refusal: accepted=false, err=nil means the replacement was refused and
// the last-good grant is left completely untouched — the same convention
// store.ReplaceEnrolmentGrant itself uses, and the same shape
// evaluateGrantOffer established for the enrolment-time grant. err is
// reserved for genuine local failures (store I/O).
//
// Every refusal is logged with a NAMED reason via c.logger.Warn, mirroring
// evaluateGrantOffer's idiom (adversarial review A3: a silently skipped
// replacement leaves the admin staring at a stale-authority node with no
// diagnosis) — this IS the "emit an event" the design calls for; there is
// no separate DB-backed event table, matching every other refusal path in
// this package.
func (c *Client) AcceptGrantReplacement(ctx context.Context, r orgcontract.GrantReplacement) (accepted bool, err error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return false, fmt.Errorf("orgclient.AcceptGrantReplacement: load enrolment: %w", err)
	}
	if enr == nil {
		c.logger.Warn("grant replacement REFUSED: this node is not enrolled — nothing to replace")
		return false, nil
	}
	if r.OrgID != enr.OrgID {
		c.logger.Warn("grant replacement REFUSED: names a different org than the current enrolment — keeping last-good grant",
			"replacement_org_id", r.OrgID, "enrolment_org_id", enr.OrgID)
		return false, nil
	}
	orgURL := strings.TrimRight(strings.TrimSpace(enr.OrgServerURL), "/")
	if strings.TrimRight(strings.TrimSpace(r.OrgServerURL), "/") != orgURL {
		c.logger.Warn("grant replacement REFUSED: names a different org server than the current enrolment — keeping last-good grant",
			"replacement_server", r.OrgServerURL, "enrolment_server", enr.OrgServerURL)
		return false, nil
	}

	// Self-contained signature check (mirrors applyBundleGates' Gate 1):
	// extract the key the message claims to be signed under and verify
	// against it before trusting anything else in the message.
	pub, verr := orgcontract.VerifyGrantReplacement(r)
	if verr != nil {
		c.logger.Warn("grant replacement REFUSED: signature did not verify — keeping last-good grant", "err", verr)
		return false, nil
	}

	// Key pin check (mirrors applyBundleGates' Gate 2) — EXCEPT a
	// replacement never TOFU-pins. Unlike a first policy-bundle fetch, this
	// is never the node's first contact with the org: an enrolled node has
	// always already pinned a key, either at Enroll (evaluateGrantOffer) or
	// on its first policy-bundle fetch. An absent pin here means something
	// is wrong (a pre-governance enrolment, or corrupted state) and is
	// refused rather than trusted on the spot.
	pinnedKeyHash, perr := c.loadKeyPin(ctx, orgURL)
	if perr != nil {
		return false, fmt.Errorf("orgclient.AcceptGrantReplacement: read key pin: %w", perr)
	}
	if pinnedKeyHash == "" {
		c.logger.Warn("grant replacement REFUSED: no org policy signing key is pinned yet for this enrolment — keeping last-good grant")
		return false, nil
	}
	keyHash := orgcontract.PublicKeyPinHash(pub)
	if keyHash != pinnedKeyHash {
		c.logger.Warn("grant replacement REFUSED: signed under a key that does not match the pin recorded at enrolment — keeping last-good grant",
			"replacement_key_sha256", keyHash, "pinned_key_sha256", pinnedKeyHash)
		return false, nil
	}
	if r.KeyPinSHA256 != "" && r.KeyPinSHA256 != pinnedKeyHash {
		c.logger.Warn("grant replacement REFUSED: declared key pin does not match the recorded pin — keeping last-good grant",
			"declared_key_sha256", r.KeyPinSHA256, "pinned_key_sha256", pinnedKeyHash)
		return false, nil
	}

	if r.ExpiresAt != "" {
		exp, terr := time.Parse(time.RFC3339, r.ExpiresAt)
		if terr != nil {
			c.logger.Warn("grant replacement REFUSED: expires_at is not RFC3339 — keeping last-good grant", "expires_at", r.ExpiresAt)
			return false, nil
		}
		if !time.Now().UTC().Before(exp) {
			c.logger.Warn("grant replacement REFUSED: it is already expired — keeping last-good grant", "expires_at", r.ExpiresAt)
			return false, nil
		}
	}

	orgKey := OrgKey(orgURL, r.OrgID)

	// The `generation` column names which enrolment EPOCH this grant row
	// belongs to (the P0-5 identity fence) and store.ReplaceEnrolmentGrant
	// deliberately never touches it on an UPDATE — it is bound ONLY on a
	// fresh INSERT (a node that enrolled ungoverned, now receiving its
	// first grant via replacement rather than at Enroll). Prefer the
	// existing stored grant's value when one exists; fall back to the live
	// enrolment-identity generation for the fresh-row case.
	generation := int64(0)
	if existing, ok, lerr := c.store.LoadEnrolmentGrant(ctx, orgKey); lerr != nil {
		return false, fmt.Errorf("orgclient.AcceptGrantReplacement: read existing grant: %w", lerr)
	} else if ok {
		generation = existing.Generation
	} else if eg, ok, gerr := c.store.LoadEnrolmentGeneration(ctx, orgKey); gerr != nil {
		return false, fmt.Errorf("orgclient.AcceptGrantReplacement: read enrolment generation: %w", gerr)
	} else if ok {
		generation = eg.Generation
	}

	grant := store.EnrolmentGrant{
		OrgKey:                orgKey,
		Generation:            generation,
		OrgID:                 r.OrgID,
		OrgName:               enr.OrgName,
		OrgServerURL:          r.OrgServerURL,
		KeyPinSHA256:          pinnedKeyHash,
		Authority:             r.Authority,
		ConsentMode:           r.ConsentMode,
		ConsentActor:          r.ConsentActor,
		GrantedAt:             parseRFC3339OrNow(r.GrantedAt),
		ExpiresAt:             parseRFC3339OrZero(r.ExpiresAt),
		SignedExpiresAt:       parseRFC3339OrZero(r.ExpiresAt),
		Signature:             r.Signature,
		ReceiptHash:           orgcontract.GrantReplacementReceiptHash(r),
		ReplacementGeneration: r.Generation,
	}

	applied, werr := c.store.ReplaceEnrolmentGrant(ctx, grant)
	if werr != nil {
		return false, fmt.Errorf("orgclient.AcceptGrantReplacement: write replacement: %w", werr)
	}
	if !applied {
		c.logger.Warn("grant replacement REFUSED: generation is not strictly greater than the last accepted replacement — keeping last-good grant (stale or replayed message)",
			"replacement_generation", r.Generation)
		return false, nil
	}
	c.logger.Info("grant replacement accepted", "org_id", r.OrgID, "replacement_generation", r.Generation)
	return true, nil
}

// parseRFC3339OrNow parses s as RFC3339, defaulting to the current instant
// when s is empty or unparseable — mirrors cmd/observer/orggrant.go's
// helper of the same name/behaviour for the enrolment-time grant write, kept
// as a small local copy so internal/orgclient does not import cmd/observer.
func parseRFC3339OrNow(s string) time.Time {
	if s == "" {
		return time.Now().UTC()
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now().UTC()
	}
	return t
}

// parseRFC3339OrZero parses s as RFC3339, defaulting to the zero time (no
// TTL) when s is empty or unparseable — mirrors cmd/observer/orggrant.go's
// helper of the same name/behaviour.
func parseRFC3339OrZero(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
