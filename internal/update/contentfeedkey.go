package update

import "crypto/ed25519"

// The CONTENT-FEED signing key material (static feed mirroring plan,
// docs/plans/static-feed-mirroring-plan-2026-11-03.md section 6.4).
//
// This is a DISTINCT key from the release vendor key (vendorkey.go), the
// pricing-feed key (internal/pricingfeed/vendorkey.go) and any org TOFU
// key. The daily unattended publisher of the advisory feeds (the OSV
// exports first) runs on an online host, and the release vendor key, which
// also signs every agent binary, must never sit there. So the content
// channel (internal/update/content) accepts this key for ClassFeed kinds
// ONLY (malicious packages, popular names, OSV exports, the agent CVE
// table, rule packs), over its own domain (content.FeedSigningDomain,
// envelope signer "feed"); an engine pin or a sandbox artifact still needs
// the release key. A compromise of this key can therefore freeze or poison
// advisory data, bounded by rollback, epochs and expiry and visible as
// stale, but never swap an engine binary or the sandbox image.
//
// Its private half lives ONLY on the publisher host
// (/etc/sbo-feed/content-feed.key, written by
// `vendorsign keygen -feed -out /etc/sbo-feed`); it is never in this tree,
// never in a repository secret, and no test embeds one.
const (
	// ContentFeedPublicKeyV1 is the CURRENT content-feed verification key,
	// base64 of the 32 raw Ed25519 public-key bytes.
	//
	// Generated on the publisher host sbo-cloud-1 on 2026-11-03 (key id
	// ca02fc513f073cc73540d7203a06bed5). An empty slot would contribute no
	// key, so a build without one verifies no feed-signed manifest (fail
	// closed: content.ContentReasonNoKey).
	ContentFeedPublicKeyV1 = "vm07CiuTcWCPYlu/QUQRZU0dwQ4VcR0g2fn0nS+diVE="

	// ContentFeedPublicKeyV0Previous is the ROTATION SLOT: the key
	// retained for ONE release after a rotation, so an agent released
	// during the overlap accepts both the old and the new key.
	//
	// It is EMPTY between rotations, and an empty slot contributes no key:
	// the zero value must never mean "accept anything". The rotation
	// procedure is vendorkey.go's, and step 3 is again the one that cannot
	// be skipped:
	//
	//  1. generate a new keypair on the publisher host
	//     (`vendorsign keygen -feed -out DIR`);
	//  2. move ContentFeedPublicKeyV1's value HERE and put the new key in
	//     ContentFeedPublicKeyV1;
	//  3. SHIP A RELEASE with both accepted, and wait for the fleet to
	//     reach it: agents verify against a compiled-in key set, so a key
	//     they never received is a key they will never accept;
	//  4. switch the publisher to the new private key, then clear this slot
	//     one release later.
	ContentFeedPublicKeyV0Previous = ""
)

// contentFeedPublicKeysB64 is the ACCEPTED set, newest first. A variable
// only so a test can stand in slot shapes.
var contentFeedPublicKeysB64 = []string{ContentFeedPublicKeyV1, ContentFeedPublicKeyV0Previous}

// ContentFeedPublicKeys returns the content-feed verification keys this
// binary accepts, in preference order (the content channel's
// VerifyInput.FeedKeys).
//
// Empty slots, malformed entries and the all-zero placeholder are dropped,
// never panicked on. An EMPTY result means "this build verifies no
// feed-signed manifest" and the caller fails closed on it, never "no key
// needed".
func ContentFeedPublicKeys() []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, 0, len(contentFeedPublicKeysB64))
	for _, s := range contentFeedPublicKeysB64 {
		if s == "" || s == vendorPlaceholderKey {
			continue
		}
		raw, err := ParseVendorKey(s)
		if err != nil {
			continue
		}
		out = append(out, raw)
	}
	return out
}
