package execevidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
)

// seal.go is the signed seal over a run's evidence digest (component
// isolation.seal, ledger SHR-6, lane GATES-SEC): the node signs the digest
// and its key id with an Ed25519 key, so a later edit of the stored facts
// by someone without the key no longer verifies. It is tamper evidence
// against a later database edit, never proof that the machine told the
// truth when it recorded the facts (TAMPER-3). A managed node's key is
// registered with its org, which verifies the seal at ingest and
// countersigns it with its own key and the receipt time; an individual
// node's seal is self-attested (it carries its own public key).

// The seal's domains: the seal itself, the org's countersign and the
// managed node's key registration proof.
const (
	SealDomain        = "sbo-exec-evidence-seal-v1"
	CountersignDomain = "sbo-exec-evidence-countersign-v1"
	RegisterDomain    = "sbo-exec-evidence-seal-key-v1"
)

// Seal is one run's seal: the key id, the public key (base64) and the
// signature (base64).
type Seal struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Sig       string `json:"sig"`
}

// SealState is how a run's seal reads; the closed vocabulary.
type SealState string

// The seal states. A missing seal is unsealed and a bad one seal_invalid:
// neither drops the row or changes any other field. key_revoked is the
// org's verdict on a seal that verifies under a key the member registered
// and an org admin later revoked (ledger SHR-6): the org no longer vouches
// for it, so it is never countersigned; a row countersigned before the
// revocation keeps org_verified.
const (
	SealUnsealed     SealState = "unsealed"
	SealInvalid      SealState = "seal_invalid"
	SealSelfAttested SealState = "self_attested"
	SealOrgVerified  SealState = "org_verified"
	SealKeyRevoked   SealState = "key_revoked"
)

// The seal refusals.
var (
	ErrSealDigest = errors.New("execevidence: the seal needs a 64-hex evidence digest")
	ErrSealKey    = errors.New("execevidence: the seal's key is not an Ed25519 key or does not match its id")
	ErrSealSig    = errors.New("execevidence: the seal's signature does not verify")
)

// lp writes fields length-prefixed after the domain, so no two inputs
// share an encoding.
func lp(domain string, fields ...string) []byte {
	b := []byte(domain)
	for _, f := range fields {
		b = strconv.AppendInt(b, int64(len(f)), 10)
		b = append(b, ':')
		b = append(b, f...)
	}
	return b
}

// SealKeyID is a key's id: the first 32 hex characters of SHA-256 of the
// public key.
func SealKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// SealMessage is what the seal signs: the domain, the digest and the key
// id, length-prefixed.
func SealMessage(digest, keyID string) []byte { return lp(SealDomain, digest, keyID) }

// SignSeal seals digest with priv.
func SignSeal(priv ed25519.PrivateKey, digest string) (Seal, error) {
	if !isHex64(digest) {
		return Seal{}, ErrSealDigest
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(priv) != ed25519.PrivateKeySize {
		return Seal{}, ErrSealKey
	}
	id := SealKeyID(pub)
	return Seal{
		KeyID: id, PublicKey: base64.StdEncoding.EncodeToString(pub),
		Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, SealMessage(digest, id))),
	}, nil
}

// VerifySeal checks s over digest under the public key s carries: the key
// is Ed25519, its id is the one named, and the signature covers this
// digest and that id.
func VerifySeal(s Seal, digest string) error {
	if !isHex64(digest) {
		return ErrSealDigest
	}
	pub, err := base64.StdEncoding.Strict().DecodeString(s.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize || SealKeyID(pub) != s.KeyID {
		return ErrSealKey
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(s.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, SealMessage(digest, s.KeyID), sig) {
		return ErrSealSig
	}
	return nil
}

// StateOf reads a seal as the org does before any key registration is
// consulted: unsealed with none (an older node, or the component off),
// seal_invalid when it does not verify, else self_attested.
func StateOf(s *Seal, digest string) SealState {
	if s == nil || (s.KeyID == "" && s.PublicKey == "" && s.Sig == "") {
		return SealUnsealed
	}
	if VerifySeal(*s, digest) != nil {
		return SealInvalid
	}
	return SealSelfAttested
}

// CountersignMessage is what the org signs over a verified seal: the org,
// the run, the digest, the node key, the node's signature and the receipt
// time.
func CountersignMessage(orgID, runKey, digest, keyID, sig, receivedAt string) []byte {
	return lp(CountersignDomain, orgID, runKey, digest, keyID, sig, receivedAt)
}

// RegisterMessage is a managed node's proof of possession when it
// registers its seal key: the org, the key id, the public key, the machine
// identity and the time.
func RegisterMessage(orgID, keyID, publicKey, machine, at string) []byte {
	return lp(RegisterDomain, orgID, keyID, publicKey, machine, at)
}
