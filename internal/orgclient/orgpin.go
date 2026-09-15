package orgclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Typed sentinels distinguishing the two failure modes of checkOrgKeyIdentity
// (R5-B6). Without them the caller cannot tell a LOCAL pin-store DB-read failure
// (non-decisive → Indeterminate) from a GENUINE cross-rail key mismatch
// (decisive → RejectKeyPinMismatch), and would misreport a transient SQLite
// error as a security rejection. errors.Is against these is the discriminator
// the routing/announcement fetch classifiers use.
var (
	// errPinStoreRead wraps a failure to READ the node-local rail pins (a
	// SQLite error), not a trust decision.
	errPinStoreRead = errors.New("orgclient: rail pin-store read failed")
	// errPinMismatch is the genuine cross-rail key-change refusal. Its message
	// preserves the "key CHANGED" human-readable class the caller wraps.
	errPinMismatch = errors.New("org distribution key CHANGED")
)

// Rail names used in key-identity refusals. They exist only to make the
// message name the rail that holds the conflicting pin, which is the
// one thing an operator needs in order to act on it.
const (
	routingPolicyRail = "routing-policy"
	announcementRail  = "announcement"
	// policyBundleRail and policyResourceRail are the two rails that
	// TRUST-ON-FIRST-FETCH into the shared `#policy-key` row; they name
	// themselves when they cross-check an offered key (C1).
	policyBundleRail   = "policy-bundle"
	policyResourceRail = "policy-resource"
	// enrolmentRail names the pin delivered over the ENROLMENT channel.
	// It is not a fetch rail: it is the TRUST ROOT the other rails are
	// checked against (ruling R1, docs/plans/
	// org-observer-fundamentals-fix-plan-2026-09-13.md §2).
	enrolmentRail = "enrolment"
)

// OrgKeyMaterialSuffix tags the guard_policy_state row that carries the
// FULL org distribution public key delivered at enrolment, standard
// base64 (the spelling every rail document uses), in the row's version
// column. Path = <org-server-url> + OrgKeyMaterialSuffix.
//
// It is a SIBLING of the PolicyKeyPinSuffix row, not a replacement: that
// row holds the pin HASH and is what the policy-bundle gate compares
// against, and a hash cannot verify a signature. Without the key itself
// the node could not verify budget or pricing documents against the key
// it was enrolled with, which is exactly the defect ruling R1 closes.
//
// guard_policy_state is append-only and deduplicates on content_hash, so
// re-enrolling with the SAME key is a no-op and a CHANGED key appends a
// new row that wins (LatestGuardPolicyStates reads the newest per path).
const OrgKeyMaterialSuffix = "#policy-key-material"

// orgKeyMaterialPath returns the guard_policy_state path identity of the
// enrolment key-material row for an org server.
func orgKeyMaterialPath(orgURL string) string { return orgURL + OrgKeyMaterialSuffix }

// recordEnrolmentKeyMaterial persists the org distribution public key an
// enrolment response delivered (base64url, the server's wire spelling)
// and returns it in the standard-base64 spelling the rail documents use.
//
// Best-effort at the call site by design: enrolment's primary job is the
// push channel and must not fail over a pin write.
func (c *Client) recordEnrolmentKeyMaterial(ctx context.Context, orgURL, keyB64URL string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(keyB64URL)
	if err != nil {
		return "", fmt.Errorf("orgclient.recordEnrolmentKeyMaterial: decode org policy public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return "", fmt.Errorf("orgclient.recordEnrolmentKeyMaterial: org policy public key is %d bytes, want %d",
			len(raw), ed25519.PublicKeySize)
	}
	keyStd := base64.StdEncoding.EncodeToString(raw)
	if _, err := c.store.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
		Layer:       "org",
		Path:        orgKeyMaterialPath(orgURL),
		Version:     keyStd,
		ContentHash: orgcontract.PublicKeyPinHash(raw),
		LoadedAt:    time.Now().UTC(),
	}); err != nil {
		return "", fmt.Errorf("orgclient.recordEnrolmentKeyMaterial: %w", err)
	}
	return keyStd, nil
}

// enrolmentKeyPin returns the standard-base64 org distribution public
// key this node was ENROLLED with, or "" when the material row does not
// exist (not enrolled, a server that delivered no key, or an enrolment
// that predates the row). A store failure is an ERROR, never a silent ""
// (M5): "the pin store is unreadable" and "there is no pin" are different
// facts and the callers classify them differently.
func (c *Client) enrolmentKeyPin(ctx context.Context) (string, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return "", err
	}
	if enr == nil || enr.OrgServerURL == "" {
		return "", nil
	}
	states, err := c.store.LatestGuardPolicyStates(ctx)
	if err != nil {
		return "", err
	}
	return materialFromStates(states, orgKeyMaterialPath(enr.OrgServerURL)), nil
}

// materialFromStates extracts the key material row's key, validating that the
// row agrees with itself. An unreadable or self-contradicting row is treated
// as ABSENT rather than trusted — it is node-local state, and the cost of
// re-establishing it is one poll.
func materialFromStates(states []store.GuardPolicyStateRow, path string) string {
	for _, st := range states {
		if st.Layer != "org" || st.Path != path {
			continue
		}
		raw, derr := base64.StdEncoding.DecodeString(st.Version)
		if derr != nil || len(raw) != ed25519.PublicKeySize {
			return ""
		}
		if orgcontract.PublicKeyPinHash(raw) != st.ContentHash {
			return ""
		}
		return st.Version
	}
	return ""
}

// enrolmentTrust is what this node knows about the key its ENROLMENT
// established — the trust root every other rail is resolved against.
type enrolmentTrust struct {
	// key is the standard-base64 public key, when the node holds the KEY
	// itself (the material row, or a rail pin proven against the hash).
	key string
	// hash is the sha256 pin of that key, when a `#policy-key` row exists.
	// A hash cannot verify a signature, but it can REFUSE one.
	hash string
	// promotable reports whether hash/key may be used as the TRUST ROOT —
	// i.e. whether an offered key matching it may be adopted as the org's
	// identity. False for a `#policy-key` row that could have been written
	// by a fetch rail's trust-on-first-fetch rather than by enrolment
	// (finding C1): such a row still CONSTRAINS (see checkOrgKeyIdentity),
	// it just never promotes.
	promotable bool
}

// enrolmentPinProvenance is stamped in the `#policy-key` row's version
// column by Enroll, and ONLY by Enroll. It is what distinguishes a pin the
// ENROLMENT channel established from one a fetch rail established by
// trust-on-first-fetch (the policy-bundle and policy-resource rails write the
// same row with an empty version).
//
// C1: without this marker, an attacker who reaches a node that has no pin at
// all can TOFU his key into `#policy-key` through the bundle rail and then
// have another rail "heal" it into the enrolment material — becoming the trust
// root. Provenance is what makes that impossible.
const enrolmentPinProvenance = "enrolment"

// railPinProvenance is stamped in the `#policy-key` row's version column by
// the two fetch rails that may ESTABLISH the pin on a node that has none (the
// policy-bundle and policy-resource rails' trust-on-first-fetch). It exists so
// that a TOFU-written row can never be mistaken for a pre-2026-09-13 Enroll
// row, which carries NO stamp: the empty stamp is what identifies the
// one-release migration shape (see enrolmentTrustFor), and a fetch rail must
// not be able to manufacture it. A row with this stamp CONSTRAINS (H1) and
// never promotes (C1).
const railPinProvenance = "rail"

// pinPromotable is the closed provenance -> trust-root table. One row per
// writer of the `#policy-key` row; a stamp outside it is treated as the
// safe direction (constrain, never promote).
var pinPromotable = map[string]bool{
	enrolmentPinProvenance: true,  // written by Enroll: the enrolment channel is the trust root (R1)
	"":                     true,  // a pre-2026-09-13 Enroll (no stamp existed yet): the live devbox shape
	railPinProvenance:      false, // a fetch rail's trust-on-first-fetch: constrains, never promotes (C1)
}

// enrolmentTrustFor resolves the trust root from the node's own records,
// given the fetch rails' current pins.
//
// Three shapes, in descending order of certainty:
//
//  1. the MATERIAL row — the key itself, written by Enroll (or promoted from
//     a proven hash). Fully promotable.
//  2. a `#policy-key` row carrying enrolmentPinProvenance — the hash, from the
//     enrolment channel. Promotable; the key becomes known as soon as a rail
//     offers one that hashes to it.
//  3. a `#policy-key` row with NO provenance — a pre-2026-09-13 Enroll (the
//     live devbox shape: `#policy-key` = the enrolment key's hash, written
//     2026-08-24 before the stamp existed). Promotable on a hash match. This
//     is the ONE-RELEASE migration path; once such a node heals (or
//     re-enrols) it is on shape 1.
//  4. a `#policy-key` row stamped railPinProvenance — a fetch rail's
//     trust-on-first-fetch. It CONSTRAINS (checkOrgKeyIdentity, H1) and never
//     promotes (C1).
//
// WHY SHAPE 3 NO LONGER NEEDS A CORROBORATING RAIL (2026-09-13, W7 live
// verification). The first cut required "some rail's pinned key hashes to
// the row" before an unstamped row could promote. On every real pre-arc node
// that is unsatisfiable: the routing and announcement rails are the only
// rails that hold a key, both TOFU-pinned the server's DATABASE key, and the
// enrolment hash names the FILE key — so no rail ever corroborates, the node
// refuses the re-signed routing policy forever, and the budget/pricing rails
// stay `unverified`. The devbox proved it after the v57 roll. Corroboration
// also bought nothing against C1: an attacker who can TOFU a hash into an
// unpinned node can TOFU the routing rail on that node too. What actually
// separates a TOFU row from an Enroll row is the WRITER, so the writer is
// now stamped (railPinProvenance) and the unstamped shape is, by
// construction, a pre-stamp Enroll. Residual, documented: an unstamped row
// written by a pre-2026-09-13 binary's bundle-rail TOFU on a node whose
// Enroll never wrote the row is indistinguishable from shape 3; such a node
// had no enrolment pin at all, so this is the same first-fetch trust the
// routing rail already extended to it.
//
// A fetch rail that holds a key which is NOT the enrolment key is WARNed
// about (once) and treated as stale, which is what it is: a hash names
// exactly one key, so it re-pins on its next accepted document.
func (c *Client) enrolmentTrustFor(ctx context.Context, rails []railPin) (enrolmentTrust, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return enrolmentTrust{}, err
	}
	if enr == nil || enr.OrgServerURL == "" {
		return enrolmentTrust{}, nil
	}
	states, err := c.store.LatestGuardPolicyStates(ctx)
	if err != nil {
		return enrolmentTrust{}, err
	}
	if material := materialFromStates(states, orgKeyMaterialPath(enr.OrgServerURL)); material != "" {
		raw, derr := base64.StdEncoding.DecodeString(material)
		if derr == nil {
			return enrolmentTrust{key: material, hash: orgcontract.PublicKeyPinHash(raw), promotable: true}, nil
		}
	}
	hash, provenance := keyPinFromStates(states, PolicyKeyPinPath(enr.OrgServerURL))
	if hash == "" {
		return enrolmentTrust{}, nil
	}
	trust := enrolmentTrust{hash: hash, promotable: pinPromotable[provenance]}
	// Which rail (if any) holds a key that hashes to the pin? When one does,
	// the KEY is known (not just its hash) and the budget/pricing rails can
	// verify with it before any material row exists.
	for _, p := range rails {
		raw, derr := base64.StdEncoding.DecodeString(p.key)
		if derr != nil || len(raw) != ed25519.PublicKeySize {
			continue
		}
		if orgcontract.PublicKeyPinHash(raw) == hash {
			trust.key = p.key
			break
		}
	}
	if trust.promotable {
		for _, p := range rails {
			raw, derr := base64.StdEncoding.DecodeString(p.key)
			if derr != nil || len(raw) != ed25519.PublicKeySize || orgcontract.PublicKeyPinHash(raw) == hash {
				continue
			}
			c.railPinDriftOnce.Do(func() {
				c.logger.Warn("org distribution key: a fetch rail holds a key that is not the enrolment pin — treating it as stale; it re-pins on its next accepted document",
					"rail", p.rail, "rail_key", prefix8(p.key), "enrolment_pin", hash[:16])
			})
			break
		}
	}
	return trust, nil
}

// keyPinFromStates returns the `#policy-key` row's content hash and the
// provenance stamped in its version column ("" for a row written by a fetch
// rail's TOFU, or by an Enroll that predates the stamp).
func keyPinFromStates(states []store.GuardPolicyStateRow, pinPath string) (hash, provenance string) {
	for _, st := range states {
		if st.Layer == "org" && st.Path == pinPath {
			return st.ContentHash, st.Version
		}
	}
	return "", ""
}

// acceptOfferedKeyChange decides what a fetch rail does when the key a
// document offers differs from the key that rail has cached.
//
// The enrolment key is the trust root (R1): an offered key that EQUALS
// it is the org's real identity and the rail RE-PINS, logged once at
// INFO. That is the migration path for every node that TOFU-pinned the
// database key on this rail before the server was taught to sign with
// the configured file key. Anything else is refused exactly as before —
// a changed key with no enrolment backing is still "re-enrol to rotate
// trust".
//
// It DECIDES and does not WRITE (finding M3): the trust root is only ever
// mutated after the document's signature verified and its cache write
// succeeded, through adoptEnrolmentKeyMaterial.
func (c *Client) acceptOfferedKeyChange(ctx context.Context, rail, cached, offered string) error {
	ok, err := c.offeredIsEnrolmentKey(ctx, offered)
	if err != nil {
		return fmt.Errorf("%w: %w", errPinStoreRead, err)
	}
	if ok {
		c.logger.Info("org distribution key re-pinned to the enrolment key",
			"rail", rail, "was", prefix8(cached), "now", prefix8(offered))
		return nil
	}
	return fmt.Errorf("%w (pinned %s… by the %s rail, got %s…) — refusing; re-enrol to rotate trust",
		errPinMismatch, prefix8(cached), rail, prefix8(offered))
}

// offeredIsEnrolmentKey reports whether an offered key IS the key this node
// was enrolled with — by the material row (a direct comparison) or by a
// PROMOTABLE `#policy-key` hash (a hash cannot verify a signature, but it can
// recognise the key that hashes to it).
//
// It has NO side effects (M3) and it propagates store failures (M5): "the pin
// store is unreadable" is an indeterminate cycle, not a trust verdict.
func (c *Client) offeredIsEnrolmentKey(ctx context.Context, offered string) (bool, error) {
	if offered == "" {
		return false, nil
	}
	rails, err := c.railCachePins(ctx)
	if err != nil {
		return false, err
	}
	trust, err := c.enrolmentTrustFor(ctx, rails)
	if err != nil {
		return false, err
	}
	if !trust.promotable {
		return false, nil
	}
	if trust.key != "" {
		return trust.key == offered, nil
	}
	raw, derr := base64.StdEncoding.DecodeString(offered)
	if derr != nil || len(raw) != ed25519.PublicKeySize {
		return false, nil
	}
	return orgcontract.PublicKeyPinHash(raw) == trust.hash, nil
}

// adoptEnrolmentKeyMaterial writes the key material a pre-R1 enrolment never
// stored, AFTER the document that carried the key verified and its rail cache
// was written (M3). It re-checks the trust decision rather than trusting the
// caller: the write is a trust-root mutation, so the rule that authorises it
// lives in exactly one place.
//
// Best-effort: a write failure only means the node re-proves the same key from
// the hash on the next cycle, which is what it just did.
func (c *Client) adoptEnrolmentKeyMaterial(ctx context.Context, offered string) {
	ok, err := c.offeredIsEnrolmentKey(ctx, offered)
	if err != nil || !ok {
		return
	}
	if material, merr := c.enrolmentKeyPin(ctx); merr != nil || material != "" {
		return // already stored
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr == nil || enr.OrgServerURL == "" {
		return
	}
	raw, derr := base64.StdEncoding.DecodeString(offered)
	if derr != nil || len(raw) != ed25519.PublicKeySize {
		return
	}
	if _, err := c.recordEnrolmentKeyMaterial(ctx, enr.OrgServerURL, base64.RawURLEncoding.EncodeToString(raw)); err != nil {
		c.logger.Warn("org distribution key recognised from the enrolment pin but not stored", "err", err)
		return
	}
	c.logger.Info("org distribution key adopted from the enrolment pin (no re-enrol needed)",
		"key_sha256_prefix", prefix12(orgcontract.PublicKeyPinHash(raw)), "key_prefix", prefix8(offered))
}

// prefix12 shortens a sha256 hex digest for a log line. Twelve hex
// characters is what the operator compares against the org server's own
// "key_sha256" log line; the full digest is never the thing an operator
// reads off two screens.
func prefix12(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// railPin is one signed-distribution rail's node-local pin of the org's
// signing key.
type railPin struct {
	rail string
	key  string
}

// loadRailPins returns the org signing key as pinned by every
// signed-distribution rail's node-local cache.
//
// There is exactly ONE org distribution identity — since ruling R1 the
// org server signs EVERY rail (routing policy, announcements, budget,
// pricing, policy bundle) with the key it delivered at enrolment — so
// the pins are not independent trust decisions and must never be allowed
// to disagree. Reading them as a set is what lets a rail's FIRST fetch be
// checked against trust the node already established elsewhere, instead
// of being a fresh TOFU that a network attacker can win.
//
// The ENROLMENT pin comes FIRST and is the trust root: it arrived over
// the channel that established the node's identity in the first place,
// whereas a rail pin is trust-on-first-fetch. Callers that resolve a key
// (orgSigningKey) take the first pin; callers that cross-check an offered
// key (checkOrgKeyIdentity) short-circuit on it.
func (c *Client) loadRailPins(ctx context.Context) ([]railPin, error) {
	rails, err := c.railCachePins(ctx)
	if err != nil {
		return nil, err
	}
	trust, err := c.enrolmentTrustFor(ctx, rails)
	if err != nil {
		return nil, err
	}
	if trust.promotable && trust.key != "" {
		return append([]railPin{{rail: enrolmentRail, key: trust.key}}, rails...), nil
	}
	return rails, nil
}

// railCachePins reads the FETCH rails' own node-local pins — trust-on-first-
// fetch records, not the trust root. Split out from loadRailPins so the
// enrolment resolution can consult them without recursing into itself.
func (c *Client) railCachePins(ctx context.Context) ([]railPin, error) {
	var rails []railPin
	rp, ok, err := c.store.GetOrgRoutingPolicy(ctx)
	if err != nil {
		return nil, err
	}
	if ok && rp.ServerPubkey != "" {
		rails = append(rails, railPin{rail: routingPolicyRail, key: rp.ServerPubkey})
	}
	ann, ok, err := c.store.GetOrgAnnouncement(ctx)
	if err != nil {
		return nil, err
	}
	if ok && ann.ServerPubkey != "" {
		rails = append(rails, railPin{rail: announcementRail, key: ann.ServerPubkey})
	}
	return rails, nil
}

// checkOrgKeyIdentity refuses an offered signing key that disagrees
// with a pin held by ANOTHER rail. The caller's own rail is skipped:
// it owns that comparison itself (it is fused with the monotonic-
// version short-circuit) and duplicating it here would only make two
// places able to disagree about the refusal wording.
//
// No pin anywhere ⇒ TOFU, exactly as before: the first key a freshly
// enrolled node ever sees is trusted, because the enrolment channel is
// the trust root. The change is that "first" now means first across the
// org, not first per rail.
//
// The refusal is loud and terminal for this cycle (no cache write, no
// silent downgrade), the same class as the per-rail key-change refusal,
// and the remedy is the same: re-enrol to rotate trust.
func (c *Client) checkOrgKeyIdentity(ctx context.Context, ownRail, offered string) error {
	rails, err := c.railCachePins(ctx)
	if err != nil {
		return fmt.Errorf("%w: %w", errPinStoreRead, err)
	}
	trust, err := c.enrolmentTrustFor(ctx, rails)
	if err != nil {
		return fmt.Errorf("%w: %w", errPinStoreRead, err)
	}
	// R1: the enrolment trust root decides on its own when it exists. A key
	// that EQUALS it is the org's identity even if another rail still holds an
	// older key (the cut-over window, where routing/announcements moved from
	// the database key to the configured file key); a key that differs is
	// refused even if some rail happens to agree with the offer, because a
	// rail pin is trust-on-first-FETCH and the enrolment pin is trust from the
	// channel that created the node.
	if trust.key != "" {
		if trust.key == offered {
			return nil
		}
		return fmt.Errorf("%w (pinned %s… at enrolment, the %s rail was offered %s…) — refusing; re-enrol to rotate trust",
			errPinMismatch, prefix8(trust.key), ownRail, prefix8(offered))
	}
	// H1: a `#policy-key` HASH with no key behind it still CONSTRAINS every
	// rail's first fetch. Without this, a node holding the real enrolment hash
	// but no rail pin yet would TOFU-accept any key at all — the exact window
	// a network attacker wants. Note this arm runs whatever the row's
	// provenance is: a hash may refuse a key even when it may not promote one
	// (C1), because refusing is the safe direction in both cases.
	if trust.hash != "" {
		raw, derr := base64.StdEncoding.DecodeString(offered)
		if derr != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("%w (the %s rail offered an unreadable key) — refusing", errPinMismatch, ownRail)
		}
		if orgcontract.PublicKeyPinHash(raw) != trust.hash {
			return fmt.Errorf("%w (pinned sha256 %s… at enrolment, the %s rail offered %s… which hashes to %s…) — refusing; re-enrol to rotate trust",
				errPinMismatch, prefix12(trust.hash), ownRail, prefix8(offered),
				prefix12(orgcontract.PublicKeyPinHash(raw)))
		}
		return nil
	}
	for _, p := range rails {
		if p.rail == ownRail || p.key == offered {
			continue
		}
		return fmt.Errorf("%w (pinned %s… by the %s rail, got %s…) — refusing; one org has one signing key, re-enrol to rotate trust",
			errPinMismatch, prefix8(p.key), p.rail, prefix8(offered))
	}
	return nil
}

// maxOrgDocBytes caps a signed distribution document read from the org
// server. Enforced as a DOCUMENT cap by orgcontract.DecodeCapped (a
// bare io.LimitReader caps the read, not the document, and says nothing
// about what follows the value).
const maxOrgDocBytes = 1 << 20
