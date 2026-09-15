package sealbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// SchemeV1 is the seal-scheme tag carried on a lease's SealScheme and on the
// node's seal-key advertisement. A node refuses to open a blob whose scheme it
// does not recognise; the server refuses to seal to a key advertised under an
// unknown scheme.
const SchemeV1 = "x25519-hkdf-sha256-aes256gcm-v1"

// KnownScheme reports whether this package can seal/open under scheme.
func KnownScheme(scheme string) bool { return scheme == SchemeV1 }

const (
	pubSize   = 32
	nonceSize = 12
	keySize   = 32
	// deriveInfo domain-separates the seal-key derivation from every other use
	// of the enrolment signing seed.
	deriveInfo = "sbo-break-glass-seal-key-v1"
	// kdfInfoPrefix domain-separates the per-message AEAD key derivation.
	kdfInfoPrefix = SchemeV1 + "\x00"
)

// Sentinel errors. Open never distinguishes WHY authentication failed beyond
// these (a wrong key, a tampered blob, and mismatched AAD all surface as
// ErrOpenFailed) so a caller cannot use the error as an oracle.
var (
	ErrBadPublicKey  = errors.New("sealbox: recipient public key is not a 32-byte X25519 key")
	ErrBadBlob       = errors.New("sealbox: sealed blob is malformed")
	ErrOpenFailed    = errors.New("sealbox: open failed (wrong key, tampered blob, or mismatched additional data)")
	ErrBadSeed       = errors.New("sealbox: derivation seed must be at least 32 bytes")
	ErrUnknownScheme = errors.New("sealbox: unknown seal scheme")
)

// KeyPair is an X25519 seal key pair. PublicBytes is what the node publishes.
type KeyPair struct {
	Private *ecdh.PrivateKey
}

// PublicBytes returns the 32-byte X25519 public key.
func (k KeyPair) PublicBytes() []byte { return k.Private.PublicKey().Bytes() }

// PublicB64 returns the base64url (unpadded) public key as carried on the
// seal-key advertisement header.
func (k KeyPair) PublicB64() string { return base64.RawURLEncoding.EncodeToString(k.PublicBytes()) }

// DeriveKeyPair derives the node's seal key pair deterministically from a
// long-lived secret seed (the enrolment Ed25519 private key's 32-byte seed).
// The same seed always yields the same pair, so a node restarts with the same
// seal identity and never has to persist a second secret. The derivation is
// domain-separated by deriveInfo, so the seal key is unrelated to the signing
// key's public half — an observer of the Ed25519 public key learns nothing
// about the X25519 key.
func DeriveKeyPair(seed []byte) (KeyPair, error) {
	if len(seed) < 32 {
		return KeyPair{}, ErrBadSeed
	}
	raw, err := hkdf.Key(sha256.New, seed, nil, deriveInfo, keySize)
	if err != nil {
		return KeyPair{}, fmt.Errorf("sealbox.DeriveKeyPair: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return KeyPair{}, fmt.Errorf("sealbox.DeriveKeyPair: %w", err)
	}
	return KeyPair{Private: priv}, nil
}

// ParsePublicB64 decodes a base64url public key into the X25519 public key
// Seal takes. It is the server-side half of the advertisement contract.
func ParsePublicB64(s string) (*ecdh.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadPublicKey, err)
	}
	if len(raw) != pubSize {
		return nil, ErrBadPublicKey
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadPublicKey, err)
	}
	return pub, nil
}

// Seal encrypts plaintext to recipient under SchemeV1, binding aad as AEAD
// additional data (the caller passes the lease's identity fields so a sealed
// blob cannot be transplanted onto a lease for a different org/node/upstream).
// It returns the base64 (std) wire blob. rng is the randomness source; nil
// means crypto/rand.
func Seal(rng io.Reader, recipient *ecdh.PublicKey, plaintext, aad []byte) (string, error) {
	if recipient == nil || len(recipient.Bytes()) != pubSize {
		return "", ErrBadPublicKey
	}
	if rng == nil {
		rng = rand.Reader
	}
	eph, err := ecdh.X25519().GenerateKey(rng)
	if err != nil {
		return "", fmt.Errorf("sealbox.Seal: ephemeral key: %w", err)
	}
	shared, err := eph.ECDH(recipient)
	if err != nil {
		return "", fmt.Errorf("sealbox.Seal: ecdh: %w", err)
	}
	ephPub := eph.PublicKey().Bytes()
	aead, err := aeadFor(shared, ephPub, recipient.Bytes())
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rng, nonce); err != nil {
		return "", fmt.Errorf("sealbox.Seal: nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)
	blob := make([]byte, 0, pubSize+nonceSize+len(ct))
	blob = append(blob, ephPub...)
	blob = append(blob, nonce...)
	blob = append(blob, ct...)
	return base64.StdEncoding.EncodeToString(blob), nil
}

// Open decrypts a Seal blob with the recipient's private key under the same
// aad. Any failure to authenticate is ErrOpenFailed.
func Open(recipient KeyPair, blobB64 string, aad []byte) ([]byte, error) {
	if recipient.Private == nil {
		return nil, ErrBadPublicKey
	}
	blob, err := base64.StdEncoding.DecodeString(blobB64)
	if err != nil || len(blob) < pubSize+nonceSize+16 {
		return nil, ErrBadBlob
	}
	ephPub, err := ecdh.X25519().NewPublicKey(blob[:pubSize])
	if err != nil {
		return nil, ErrBadBlob
	}
	shared, err := recipient.Private.ECDH(ephPub)
	if err != nil {
		return nil, ErrOpenFailed
	}
	aead, err := aeadFor(shared, ephPub.Bytes(), recipient.PublicBytes())
	if err != nil {
		return nil, err
	}
	nonce := blob[pubSize : pubSize+nonceSize]
	pt, err := aead.Open(nil, nonce, blob[pubSize+nonceSize:], aad)
	if err != nil {
		return nil, ErrOpenFailed
	}
	return pt, nil
}

// aeadFor derives the per-message AES-256-GCM key from the ECDH shared secret,
// binding both public keys into the HKDF info so the key is unique per
// (ephemeral, recipient) pair.
func aeadFor(shared, ephPub, recipientPub []byte) (cipher.AEAD, error) {
	info := kdfInfoPrefix + string(ephPub) + "\x00" + string(recipientPub)
	key, err := hkdf.Key(sha256.New, shared, nil, info, keySize)
	if err != nil {
		return nil, fmt.Errorf("sealbox: kdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sealbox: cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("sealbox: gcm: %w", err)
	}
	return aead, nil
}

// LeaseAAD builds the canonical additional data a break-glass seal is bound
// to: org, target node, and upstream, NUL-separated under a fixed domain tag.
// Both the server (Seal) and the node (Open) MUST build it from the same lease
// fields, so a blob sealed for (org, node A, upstream X) cannot be opened as
// (org, node A, upstream Y) even by node A.
func LeaseAAD(orgID, userID, upstreamID string) []byte {
	return []byte("sbo-break-glass-lease-seal-v1\x00" + orgID + "\x00" + userID + "\x00" + upstreamID)
}
