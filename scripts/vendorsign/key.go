package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// KeyIDLen is how many hex characters of sha256(public key) form the
// key_id stamped into a release manifest. 32 hex characters is 16 bytes
// of digest: enough that two keys cannot collide in practice, short
// enough that an operator can compare it to the README beside the
// private key by eye.
const KeyIDLen = 32

// loadPrivateKey reads a signing key from a file.
//
// Two encodings are accepted and both are Ed25519 raw material, never a
// container: 32 bytes is a SEED (the shape keygen writes and the shape
// the GitHub secret holds), 64 bytes is a full private key. Anything
// else is refused rather than coerced, because a key that is silently
// reinterpreted signs with bytes nobody chose.
//
// Whitespace is trimmed, so a secret pasted with a trailing newline
// works — that is the single most likely operator slip and it must not
// produce an "invalid key" at release time.
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // an operator-supplied key path; this tool's entire job
	if err != nil {
		return nil, fmt.Errorf("vendorsign: read key: %w", err)
	}
	return parsePrivateKey(string(raw))
}

// parsePrivateKey decodes the base64 key material. Split from
// loadPrivateKey so the decision table is testable without a file.
func parsePrivateKey(s string) (ed25519.PrivateKey, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, errors.New("vendorsign: signing key is empty")
	}
	dec, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		return nil, fmt.Errorf("vendorsign: signing key is not base64: %w", err)
	}
	switch len(dec) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(dec), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(dec), nil
	default:
		return nil, fmt.Errorf("vendorsign: signing key is %d bytes, want %d (seed) or %d (private key)",
			len(dec), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// acceptedVendorKeys is the set a node will verify against. It is a variable
// only so a test can stand in a key: this tree compiles in NONE today (the
// pre-rotation state vendorkey.go documents), and a guard that could only be
// exercised once real key material lands is a guard nobody has tested.
var acceptedVendorKeys = update.VendorPublicKeys

// checkKeyIsPinned refuses to sign with a key the FLEET does not accept.
//
// This is the release-time half of §2.2's rotation discipline. A node verifies
// an artifact against update.VendorPublicKeys() — a set compiled into the
// agent — so signing with a key that is not in that set produces a release
// that is green in CI, green in the org's import, and refused by every node at
// the customer's first ring. The failure surfaces at the worst possible place,
// and the cause (a rotation step performed out of order, or the wrong secret
// bound to the job) is invisible from the artifacts.
//
// The check compares the PUBLIC HALF of the signing key against the same
// function the agent calls, so producer and consumer cannot disagree.
//
// Two escapes, both deliberate:
//   - an EMPTY accepted set means this tree compiles in no vendor key at all
//     (the pre-rotation state vendorkey.go documents). There is nothing to
//     check against, so the check is a loud no-op rather than a refusal that
//     would make the tool unusable in exactly the state it exists to fix.
//   - allowUnpinned is `-allow-unpinned-key`, the deliberate step 4 of a
//     rotation: the new secret is bound BEFORE the release that compiles the
//     new key in. It must be typed, never defaulted.
//
// It returns a warning to print (possibly empty) and an error to refuse on.
func checkKeyIsPinned(priv ed25519.PrivateKey, allowUnpinned bool) (string, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return "", errors.New("vendorsign: signing key is not Ed25519")
	}
	accepted := acceptedVendorKeys()
	if len(accepted) == 0 {
		return "WARNING: this tree compiles in NO vendor public key, so the signing key could not be\n" +
			"         checked against what nodes accept. Every node will report blocked{unsigned_artifact}\n" +
			"         until internal/update/vendorkey.go carries the matching public key.", nil
	}
	for _, k := range accepted {
		if pub.Equal(k) {
			return "", nil
		}
	}
	if allowUnpinned {
		return fmt.Sprintf(
			"WARNING: signing with key id %s, which is NOT among the keys this tree's agents accept.\n"+
				"         -allow-unpinned-key was given, so this is a deliberate rotation step; ship the\n"+
				"         release that compiles this public key in BEFORE any node is asked to verify it.",
			keyID(pub)), nil
	}
	return "", fmt.Errorf(
		"vendorsign: refusing to sign with key id %s - it is not among the vendor public keys this tree's agents accept (%s).\n"+
			"A release signed with an unaccepted key is refused by every node at the customer's first ring.\n"+
			"Fix the OBSERVER_VENDOR_SIGNING_KEY secret, or pass -allow-unpinned-key if this is the deliberate rotation step.",
		keyID(pub), acceptedKeyIDs(accepted))
}

// acceptedKeyIDs renders the accepted set for the refusal message, because
// "not accepted" without "these are" is not an actionable error.
func acceptedKeyIDs(keys []ed25519.PublicKey) string {
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, keyID(k))
	}
	return strings.Join(ids, ", ")
}

// keyID is the manifest's key_id for a public key: the first KeyIDLen
// hex characters of its sha256. It is computed the same way here, in
// internal/update's test pin, and in the operator README beside the
// private key, so the three cannot disagree about which key a release
// was signed with.
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:KeyIDLen]
}

// generateKeypair writes a fresh keypair into dir and returns the
// public key, base64.
//
// It REFUSES to overwrite an existing key file. Regenerating over a
// live signing key is unrecoverable in the direction that matters: the
// fleet accepts only keys that were compiled into a shipped agent, so a
// key lost before its rotation release means no node can ever verify
// again until every one of them is re-enrolled.
func generateKeypair(dir string) (pubB64, keyPath string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("vendorsign keygen: %w", err)
	}
	keyPath = filepath.Join(dir, "vendor-signing-key.key")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("vendorsign keygen: %w", err)
	}
	// O_EXCL, not Stat-then-Write. The refusal to overwrite a live signing key
	// is the whole point of this function, and a check separated from the
	// write is a check something else can win: two concurrent keygens, or an
	// operator's own copy landing between the two calls, and the key the
	// fleet accepts is gone with no way back.
	seed := base64.StdEncoding.EncodeToString(priv.Seed())
	f, err := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return "", "", fmt.Errorf("vendorsign keygen: %s already exists; refusing to overwrite a signing key", keyPath)
		}
		return "", "", fmt.Errorf("vendorsign keygen: write key: %w", err)
	}
	if _, err := f.WriteString(seed + "\n"); err != nil {
		_ = f.Close()
		return "", "", fmt.Errorf("vendorsign keygen: write key: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", "", fmt.Errorf("vendorsign keygen: write key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(pub), keyPath, nil
}

// parsePublicKey decodes a base64 Ed25519 public key. It defers to
// internal/update.ParseVendorKey so the producer and the agent agree,
// byte for byte, on what counts as a key.
func parsePublicKey(b64 string) (ed25519.PublicKey, error) {
	return update.ParseVendorKey(b64)
}
