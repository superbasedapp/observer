package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// releasemanifest.go verifies the manifest a RELEASE publishes, as opposed
// to the manifest an ORG publishes to its own fleet (verify.go's nine rules).
//
// The two documents have the same shape and the same signing message; what
// differs is who signs and what the verifier already knows. On a node, the
// signer is the org's TOFU-pinned distribution key and the questions are
// about eligibility (replay, downgrade, required stops, this platform). Here
// the signer is the VENDOR key compiled into this tree, and the question is
// only "is this the release I asked for, is it intact, and did we build it".
//
// It exists because `observer-org update sync` used to answer that question
// by GUESSING FILE NAMES: it composed `observer-<version>-<target>.<ext>`
// from a hard-coded target list and downloaded whatever came back. Everything
// downstream then rested on SHA256SUMS, an unsigned file from the same host.
// A signed manifest already names every artifact, its size, its archive hash,
// the hash of the binary INSIDE it and its vendor signature — so consuming
// that document instead of scraping names moves the connected path onto the
// same footing as the air-gapped one.
//
// It is PURE, like the rest of this package: bytes in, a manifest out. The
// caller owns the fetch, the mirror and the clock.

var (
	// ErrNoVendorKey means the caller offered no key to verify against.
	//
	// It is a REFUSAL, not a skip. An empty accepted set is exactly what a
	// tree looks like before its vendor key is compiled in (or after a
	// rotation blanks it), and treating "I have no key" as "no key needed"
	// is how an unverified binary reaches a fleet. The one escape is
	// AllowUnpinnedKey, which the operator must type.
	ErrNoVendorKey = errors.New("update: no vendor public key is available to verify this release manifest")
	// ErrManifestMismatch means the document is authentic but describes a
	// different release than the one asked for — another version, or
	// another channel. Authentic is not the same as relevant, and a
	// manifest for v1.32.0 must not fill a mirror for v1.33.0.
	ErrManifestMismatch = errors.New("update: manifest does not describe the requested release")
)

// ReleaseManifestInput is one verification of a published release manifest.
type ReleaseManifestInput struct {
	// EnvelopeBytes is the `update-manifest-<channel>.json` document as
	// fetched or as read off the air-gap bundle.
	EnvelopeBytes []byte
	// Keys are the vendor public keys to accept, newest first — normally
	// VendorPublicKeys(). More than one is the rotation overlap window.
	Keys []ed25519.PublicKey
	// AllowUnpinnedKey skips the signature check when Keys is empty. It is
	// the deliberate, typed escape for a tree that compiles in no vendor
	// key; it must never be a default, and it is never set by the server.
	AllowUnpinnedKey bool
	// Channel is the channel the caller asked for. Empty accepts whatever
	// the document declares.
	Channel Channel
	// Version is the release the caller asked for ("v1.33.0"). Empty
	// accepts whatever the document declares.
	Version string
	// Now is the comparison clock for expiry. Required: a freshness rule
	// judged against a clock the caller did not supply is not a rule.
	Now time.Time
}

// VerifyReleaseManifest checks a published release manifest and returns it.
//
// The order is the security content and mirrors verify.go: nothing about the
// document's CONTENT is trusted before its signature is checked, and nothing
// about its relevance is judged before its structure is known to be valid.
func VerifyReleaseManifest(in ReleaseManifestInput) (Manifest, error) {
	if len(in.EnvelopeBytes) == 0 {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: empty document", ErrEnvelopeDecode)
	}
	if len(in.EnvelopeBytes) > MaxEnvelopeBytes {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: %d bytes exceeds the %d cap",
			ErrEnvelopeDecode, len(in.EnvelopeBytes), MaxEnvelopeBytes)
	}
	var env Envelope
	dec := json.NewDecoder(bytes.NewReader(in.EnvelopeBytes))
	if err := dec.Decode(&env); err != nil {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: %w", ErrEnvelopeDecode, err)
	}
	if dec.More() {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: trailing JSON value", ErrEnvelopeDecode)
	}

	body, err := base64.StdEncoding.DecodeString(env.ManifestB64)
	if err != nil {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: manifest is not valid base64", ErrEnvelopeDecode)
	}
	if len(body) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: manifest is %d bytes (max %d)",
			ErrEnvelopeDecode, len(body), MaxManifestBytes)
	}
	if got := HashBytes(body); got != env.ManifestHash {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w (declared %s, computed %s)",
			ErrManifestHashMismatch, env.ManifestHash, got)
	}

	if err := verifyReleaseSignature(env, body, in); err != nil {
		return Manifest{}, err
	}

	schema, err := ProbeSchema(body)
	if err != nil {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w", err)
	}
	if schema != SchemaV1 {
		// Fail-open in the same direction as verify rule 5: a future
		// manifest reaching an older tool is forward compatibility, not
		// corruption. The CALLER decides what to do about it; here it is
		// simply not a document this build can read.
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: %q", ErrUnknownSchema, schema)
	}
	m, err := DecodeManifest(body)
	if err != nil {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w", err)
	}
	if err := Validate(m); err != nil {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w", err)
	}

	if in.Version != "" && m.Version != in.Version {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: it is for %s, not %s",
			ErrManifestMismatch, m.Version, in.Version)
	}
	if in.Channel != "" && m.Channel != in.Channel {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: it is for the %s channel, not %s",
			ErrManifestMismatch, m.Channel, in.Channel)
	}
	if in.Now.IsZero() {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: Now is required to judge freshness", ErrInvalidManifest)
	}
	exp, err := parseRFC3339(m.ExpiresAt)
	if err != nil {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w: expires_at: %w", ErrInvalidManifest, err)
	}
	if !exp.After(in.Now.UTC()) {
		return Manifest{}, fmt.Errorf("update.VerifyReleaseManifest: %w (expired %s)", ErrManifestExpired, m.ExpiresAt)
	}
	return m, nil
}

// verifyReleaseSignature checks the envelope signature against every accepted
// key, or refuses when there is nothing to check against.
//
// Every key is tried rather than only the newest, for the same reason the
// node's artifact verifier does: a rotation ships an overlap release that
// accepts both keys, so trying one would strand a fleet mid-rotation.
func verifyReleaseSignature(env Envelope, body []byte, in ReleaseManifestInput) error {
	if len(in.Keys) == 0 {
		if !in.AllowUnpinnedKey {
			return fmt.Errorf("update.VerifyReleaseManifest: %w — pass the accepted key set, "+
				"or opt out explicitly if this tree compiles none in", ErrNoVendorKey)
		}
		return nil
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("update.VerifyReleaseManifest: %w: bad signature encoding", ErrSignatureInvalid)
	}
	// manifest_version comes from the SIGNED bytes, never from an envelope
	// field an attacker could edit independently (the ROUTING-SIG-1 lesson).
	mv, err := manifestVersionOf(body)
	if err != nil {
		return fmt.Errorf("update.VerifyReleaseManifest: %w: %w", ErrEnvelopeDecode, err)
	}
	msg := ManifestSigningMessage(mv, env.ManifestHash)
	for _, k := range in.Keys {
		if len(k) == ed25519.PublicKeySize && ed25519.Verify(k, msg, sig) {
			return nil
		}
	}
	return fmt.Errorf("update.VerifyReleaseManifest: %w: it does not verify against any accepted vendor key",
		ErrSignatureInvalid)
}

// ArtifactByFilename returns the artifact a manifest names under exactly this
// file name.
//
// The match is EXACT and case-sensitive on purpose. A mirror uses it to ask
// "does the signed document make a claim about this file", and a fuzzy match
// there would let a file the manifest never named inherit another file's
// claim.
func ArtifactByFilename(m Manifest, filename string) (Artifact, bool) {
	if filename == "" {
		return Artifact{}, false
	}
	for _, a := range m.Artifacts {
		if a.Filename == filename {
			return a, true
		}
	}
	return Artifact{}, false
}
