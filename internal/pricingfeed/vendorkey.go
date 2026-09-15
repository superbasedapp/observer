package pricingfeed

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

// The pricing-feed VENDOR signing key material (§B.4 / §D1).
//
// This is a DISTINCT vendor key from the release-artifact key
// (internal/update/vendorkey.go) and from any org TOFU key: it signs the public
// pricing feed, which names no org and no subject, so offline verification
// against a key COMPILED INTO the binary is the whole trust story. Its private
// half lives only in the OBSERVER_PRICING_FEED_SIGNING_KEY secret on the
// private origin repo — never in this tree, and no test embeds one.
//
// The rotation-slot pattern mirrors internal/update/vendorkey.go: a CURRENT
// key plus one PREVIOUS slot retained for one release across a rotation so a
// fleet mid-flight accepts both. A consumer verifies against whichever key the
// envelope's key_id names (KeySet.Lookup), and an unknown key_id is refused
// (ErrUnknownKey) rather than tried against every key.
const (
	// PricingFeedKeyIDV1 is the key_id the publisher stamps into the envelope
	// for PricingFeedPublicKeyV1. It is a stable short label (not a hash) so an
	// operator can name it in a runbook.
	PricingFeedKeyIDV1 = "pricing-feed-v1"
	// PricingFeedPublicKeyV1 is the CURRENT verification key: hex of the 32 raw
	// Ed25519 public-key bytes. Generated 2026-09-11 (Wave 0); private half in
	// the OBSERVER_PRICING_FEED_SIGNING_KEY secret, never in this tree.
	PricingFeedPublicKeyV1 = "2188bf8e0e82411c7cc645c3215accf724d38c64279e17c4c5567d344e385f04"

	// PricingFeedKeyIDV0Previous / PricingFeedPublicKeyV0Previous are the
	// ROTATION SLOT: the key retained for ONE release after a rotation. Both
	// are EMPTY between rotations, and an empty slot contributes no key — the
	// zero value must never mean "accept anything". The rotation procedure
	// matches the update-key one: generate a new pair; move V1 HERE and put the
	// new key in V1; ship a release with both accepted and wait for the fleet;
	// swap the secret, then clear this slot one release later.
	PricingFeedKeyIDV0Previous     = ""
	PricingFeedPublicKeyV0Previous = ""
)

// keyEntry pairs a key_id with its hex-encoded public key. Unlike the update
// key set (a bare slice of keys), the feed set is keyed by id because the
// envelope NAMES the key that signed it, so verification is an O(1) lookup, not
// a try-every-key loop.
type keyEntry struct {
	keyID  string
	hexKey string
}

// compiledPricingFeedKeys is the ACCEPTED set, newest first. Adding a key is
// one entry here plus one release (the overlap window).
var compiledPricingFeedKeys = []keyEntry{
	{PricingFeedKeyIDV1, PricingFeedPublicKeyV1},
	{PricingFeedKeyIDV0Previous, PricingFeedPublicKeyV0Previous},
}

// KeySet is the set of pricing-feed vendor keys a build accepts, indexed by
// key_id. It is the argument to [Verify]; a build constructs the compiled one
// with [CompiledKeySet] and a test constructs a throwaway one with [NewKeySet].
type KeySet struct {
	keys map[string]ed25519.PublicKey
}

// Lookup returns the public key registered under keyID, and whether one exists.
// An empty keyID never matches (an envelope that names no key is as untrusted
// as one that names an unknown key).
func (ks KeySet) Lookup(keyID string) (ed25519.PublicKey, bool) {
	if keyID == "" || ks.keys == nil {
		return nil, false
	}
	pub, ok := ks.keys[keyID]
	return pub, ok
}

// Len reports how many keys the set accepts. A build whose key material is all
// empty or unparseable yields 0 — which a caller MUST treat as "this build can
// verify no feed" and fail closed on, never as "no key needed".
func (ks KeySet) Len() int { return len(ks.keys) }

// NewKeySet builds a KeySet from id -> hex-public-key pairs. Empty entries and
// all-zero keys are dropped (never accepted — an all-zero Ed25519 public key
// verifies an all-zero signature), and a malformed hex key is an error so a
// test or the release signer catches bad material explicitly.
func NewKeySet(pairs map[string]string) (KeySet, error) {
	out := KeySet{keys: make(map[string]ed25519.PublicKey, len(pairs))}
	for id, h := range pairs {
		if id == "" || h == "" {
			continue
		}
		pub, err := ParseFeedKey(h)
		if err != nil {
			return KeySet{}, fmt.Errorf("pricingfeed.NewKeySet: key %q: %w", id, err)
		}
		out.keys[id] = pub
	}
	return out, nil
}

// CompiledKeySet returns the keys this binary accepts (PricingFeedPublicKeyV1
// plus any populated rotation slot). Empty slots and unparseable or all-zero
// entries are dropped rather than panicked on (no panic in library code), so a
// build with blank key material returns an EMPTY set — fail-closed substrate,
// never "accept anything".
func CompiledKeySet() KeySet {
	out := KeySet{keys: make(map[string]ed25519.PublicKey, len(compiledPricingFeedKeys))}
	for _, e := range compiledPricingFeedKeys {
		if e.keyID == "" || e.hexKey == "" {
			continue
		}
		pub, err := ParseFeedKey(e.hexKey)
		if err != nil {
			continue
		}
		out.keys[e.keyID] = pub
	}
	return out
}

// ParseFeedKey decodes one hex-encoded Ed25519 public key. It is exported so
// the key material can be checked independently of whether this build accepts
// it (by a test and by the release signer). An all-zero key is refused: the
// identity point verifies an all-zero signature trivially, so accepting it
// would be a pass-with-zeros hole (the update.vendorkey placeholder lesson).
func ParseFeedKey(h string) (ed25519.PublicKey, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("pricingfeed.ParseFeedKey: not hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pricingfeed.ParseFeedKey: key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	if isAllZero(raw) {
		return nil, fmt.Errorf("pricingfeed.ParseFeedKey: refusing the all-zero key (it verifies an all-zero signature)")
	}
	return ed25519.PublicKey(raw), nil
}

func isAllZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
