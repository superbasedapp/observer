package pricingfeed

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// SigningMessage returns the exact bytes signed over a feed (§A):
//
//	FeedSigningDomain || 0x00 || decimal(feedVersion) || 0x00 || canonicalRows
//
// UNLIKE the org policy rail, the bytes are NOT pre-hashed: Ed25519 signs this
// message directly (ed25519.Sign already SHA-512s internally). The domain tag
// is bound first so a signature can never be replayed on another rail; the
// feed_version is bound explicitly as well as being implied by the rows, so a
// replayed lower version over the same rows cannot be mistaken for a fresh one.
// There is NO org and NO subject bound — the public feed names neither (it is
// the same body for every consumer on earth), which is also why its body is
// cacheable at the edge where the org rail's is not.
func SigningMessage(feedVersion int64, canonicalRows []byte) []byte {
	var msg bytes.Buffer
	msg.Grow(len(FeedSigningDomain) + 2 + 20 + len(canonicalRows))
	msg.WriteString(FeedSigningDomain)
	msg.WriteByte(0)
	msg.WriteString(strconv.FormatInt(feedVersion, 10))
	msg.WriteByte(0)
	msg.Write(canonicalRows)
	return msg.Bytes()
}

// Sign returns the base64 (std) signature for env, derived from env.Rows and
// env.FeedVersion. It does NOT mutate env: the caller assigns the returned
// value to env.Signature (and is responsible for having set env.Digest, via
// [Digest], and env.KeyID to the key id of priv).
//
// It is the publisher-side helper (model-pricing/, Wave T / the air-gap bundle
// writer). The private half of PricingFeedPublicKeyV1 is operator-held and
// never in this tree; a caller passes it in.
func Sign(priv ed25519.PrivateKey, env Envelope) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("pricingfeed.Sign: bad private key size %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	canonical, err := CanonicalRows(env.Rows)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, SigningMessage(env.FeedVersion, canonical))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify checks env end to end against the accepted key set, ALL-OR-NOTHING and
// fail-closed (§E). On success the caller may apply the rows; on any returned
// error it keeps the previously applied prices and never applies env.
//
// The checks, in order (the first failure wins so a caller gets the most
// specific reason):
//
//  1. SchemaVersion == SupportedSchemaVersion, else ErrUnsupportedSchema.
//  2. FeedVersion > 0 and every row is well-formed, else ErrInvalidRows.
//  3. Digest recomputed from the rows equals env.Digest, else ErrDigestMismatch
//     (catches tampering and publisher bugs BEFORE the signature math).
//  4. A signature is present, else ErrUnsigned.
//  5. KeyID names a key this build accepts, else ErrUnknownKey.
//  6. The signature verifies over SigningMessage under that key, else
//     ErrBadSignature.
//
// Replay (a lower FeedVersion than one already applied) is the CALLER's
// concern: this function has no state. Verify establishes only that env is a
// genuine, well-formed, un-tampered feed body signed by a key we trust.
func Verify(env Envelope, keys KeySet) error {
	if env.SchemaVersion != SupportedSchemaVersion {
		return fmt.Errorf("%w: got %d, want %d", ErrUnsupportedSchema, env.SchemaVersion, SupportedSchemaVersion)
	}
	if err := validateRows(env.FeedVersion, env.Rows); err != nil {
		return err
	}
	canonical, err := CanonicalRows(env.Rows)
	if err != nil {
		return err
	}
	if got := digestOf(canonical); got != env.Digest {
		return fmt.Errorf("%w: envelope %q vs computed %q", ErrDigestMismatch, env.Digest, got)
	}
	if strings.TrimSpace(env.Signature) == "" {
		return ErrUnsigned
	}
	pub, ok := keys.Lookup(env.KeyID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownKey, env.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not base64: %w", ErrBadSignature, err)
	}
	if !ed25519.Verify(pub, SigningMessage(env.FeedVersion, canonical), sig) {
		return ErrBadSignature
	}
	return nil
}

// validateRows enforces the minimal well-formedness the feed depends on: a
// positive feed version and a non-empty, trimmed model id on every row.
// orgcontract.PricingPolicyRow carries no Validate of its own (the org-side
// rate validation lives in internal/orgserver/pricing.ValidateSet, which the
// importer runs on apply), so this is the contract-level floor — the rate
// pointers are deliberately unconstrained here (nil, 0 and positive are all
// meaningful).
func validateRows(feedVersion int64, rows []Row) error {
	if feedVersion <= 0 {
		return fmt.Errorf("%w: feed_version %d must be > 0", ErrInvalidRows, feedVersion)
	}
	for i, r := range rows {
		if strings.TrimSpace(r.Model) == "" {
			return fmt.Errorf("%w: row %d has an empty model id", ErrInvalidRows, i)
		}
		if err := validateEconomics(r.Economics); err != nil {
			return fmt.Errorf("%w: row %d (%s): %w", ErrInvalidRows, i, r.Model, err)
		}
	}
	return nil
}

// validateEconomics enforces the CLOSED enum vocabularies and the SafeText
// Notes constraint when Economics is present. Every field stays optional (a nil
// pointer or empty string is unknown); only a NON-empty enum value that is not
// in its vocabulary, or a Notes carrying a control/bidi/ANSI code point, fails
// — and then the whole envelope fails (all-or-nothing), never a silent drop of
// the bad field.
func validateEconomics(e *Economics) error {
	if e == nil {
		return nil
	}
	if !validEnum(e.CacheMode, CacheModeExplicit, CacheModeImplicit, CacheModeNone) {
		return fmt.Errorf("cache_mode %q not in {explicit, implicit, none}", e.CacheMode)
	}
	if !validEnum(e.CacheWriteBilling, CacheWriteBillingPerWrite, CacheWriteBillingIncluded, CacheWriteBillingNone) {
		return fmt.Errorf("cache_write_billing %q not in {per_write, included, none}", e.CacheWriteBilling)
	}
	if !validEnum(e.ReasoningBilling, ReasoningBillingOutputRate, ReasoningBillingSeparateRate, ReasoningBillingIncluded, ReasoningBillingNone) {
		return fmt.Errorf("reasoning_billing %q not in {output_rate, separate_rate, included, none}", e.ReasoningBilling)
	}
	if !isSafeText(e.Notes) {
		return fmt.Errorf("notes contains a control, bidi or ANSI code point")
	}
	return nil
}

// validEnum reports whether value is the empty string (unknown, always allowed)
// or one of the allowed members.
func validEnum(value string, allowed ...string) bool {
	if value == "" {
		return true
	}
	for _, a := range allowed {
		if value == a {
			return true
		}
	}
	return false
}

// isSafeText reports whether s is free of control characters, ANSI escapes and
// bidirectional-formatting code points — the SafeText constraint the cloud
// evidence path applies, reproduced here so a feed note can never smuggle a
// terminal-control sequence onto an operator's dashboard or CLI.
func isSafeText(s string) bool {
	for _, r := range s {
		if r == 0x1B { // ESC — the ANSI escape introducer
			return false
		}
		if unicode.IsControl(r) {
			return false
		}
		// Bidi embeddings / overrides / isolates and the LRM/RLM marks.
		if (r >= 0x202A && r <= 0x202E) || // LRE RLE PDF LRO RLO
			(r >= 0x2066 && r <= 0x2069) || // LRI RLI FSI PDI
			r == 0x200E || r == 0x200F { // LRM RLM
			return false
		}
	}
	return true
}
