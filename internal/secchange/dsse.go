package secchange

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Envelope is a DSSE envelope (github.com/secure-systems-lab/dsse).
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature.
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// MaxEnvelopeSize caps an encoded envelope a verifier will read.
const MaxEnvelopeSize = MaxPayloadSize*2 + 4096

// digestDomain separates a record digest from every other hash.
const digestDomain = "sbo-change-record-digest-v1"

// The verification errors. Verify wraps exactly one of them, so a caller
// can tell why a record was refused.
var (
	ErrMalformed    = errors.New("secchange: malformed envelope")
	ErrPayloadType  = errors.New("secchange: wrong payload type")
	ErrUnknownKey   = errors.New("secchange: signing key not trusted")
	ErrBadSignature = errors.New("secchange: signature does not verify")
	ErrRevoked      = errors.New("secchange: signing key revoked")
	ErrKeyExpired   = errors.New("secchange: record outside the key's validity")
	ErrKeyMismatch  = errors.New("secchange: record names another key")
)

// refusalCodes is the ordered table of closed codes for the verification
// errors; the first that matches names the refusal.
var refusalCodes = []struct {
	err  error
	code string
}{
	{ErrRevoked, "key_revoked"},
	{ErrKeyExpired, "key_expired"},
	{ErrUnknownKey, "key_unknown"},
	{ErrBadSignature, "bad_signature"},
	{ErrKeyMismatch, "key_mismatch"},
	{ErrPayloadType, "payload_type"},
	{ErrInvalid, "invalid_record"},
	{ErrMalformed, "malformed_envelope"},
}

// RefusalCode is the closed code for why Verify (or ParseEnvelope) refused
// a record, so nothing a repository controls is echoed into a report;
// "unreadable" for anything else.
func RefusalCode(err error) string {
	for _, e := range refusalCodes {
		if errors.Is(err, e.err) {
			return e.code
		}
	}
	return "unreadable"
}

// PAE is DSSE's pre-authentication encoding of a payload type and body.
func PAE(payloadType string, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("DSSEv1 ")
	b.WriteString(strconv.Itoa(len(payloadType)))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	b.WriteString(strconv.Itoa(len(body)))
	b.WriteByte(' ')
	b.Write(body)
	return b.Bytes()
}

// KeyID is the hex of the first 16 bytes of SHA-256 of an Ed25519 public
// key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// Digest is the record digest of a canonical payload: hex SHA-256 over a
// domain string and the payload. It is what the org wire, the replay store
// and a squash statement name a record by.
func Digest(payload []byte) string {
	h := sha256.New()
	h.Write([]byte(digestDomain))
	h.Write([]byte{0})
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// Sign builds the record's payload and signs it. The record's Key.ID must
// be the key id of priv's public key.
func Sign(r Record, priv ed25519.PrivateKey) (Envelope, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("secchange.Sign: not an Ed25519 private key")
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	if r.Key.ID != KeyID(pub) {
		return Envelope{}, fmt.Errorf("secchange.Sign: %w", ErrKeyMismatch)
	}
	payload, err := r.Payload()
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(priv, PAE(PayloadType, payload))
	return Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: r.Key.ID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// Marshal is the envelope's one encoding (canonical JSON), as stored and
// as written into a git note.
func (e Envelope) Marshal() ([]byte, error) { return Canonical(e) }

// ParseEnvelope decodes an envelope strictly.
func ParseEnvelope(b []byte) (Envelope, error) {
	var e Envelope
	if len(b) > MaxEnvelopeSize {
		return e, fmt.Errorf("%w: over %d bytes", ErrMalformed, MaxEnvelopeSize)
	}
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&e); err != nil {
		return Envelope{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	if dec.More() {
		return Envelope{}, fmt.Errorf("%w: trailing data", ErrMalformed)
	}
	return e, nil
}

// Verified is a record whose signature, payload and key checked out.
type Verified struct {
	Record Record
	Digest string
	KeyID  string
	// Attestation is how the TrustSet vouched for the key (self_attested
	// or org_certified); it can be lower than what the record claims, never
	// higher.
	Attestation string
}

// Verify checks an envelope against a TrustSet: the payload type, exactly
// one signature by a key the set trusts (certificate and revocation list
// applied), the signature over the PAE, the payload's strict canonical
// decode, and that the record names the key that signed it and was
// recorded inside the key's validity. The binding to a commit is a
// separate check (CheckBinding).
func Verify(e Envelope, trust TrustSet) (Verified, error) {
	if e.PayloadType != PayloadType {
		return Verified{}, ErrPayloadType
	}
	if len(e.Signatures) != 1 {
		return Verified{}, fmt.Errorf("%w: want exactly one signature, got %d", ErrMalformed, len(e.Signatures))
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: payload: %w", ErrMalformed, err)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(e.Signatures[0].Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Verified{}, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	key, err := trust.lookup(e.Signatures[0].KeyID)
	if err != nil {
		return Verified{}, err
	}
	if !ed25519.Verify(key.Public, PAE(e.PayloadType, payload), sig) {
		return Verified{}, ErrBadSignature
	}
	rec, err := ParsePayload(payload)
	if err != nil {
		return Verified{}, err
	}
	if rec.Key.ID != key.ID {
		return Verified{}, ErrKeyMismatch
	}
	// A certified key speaks only for its own org and machine.
	if (key.OrgID != "" && rec.Binding.OrgID != key.OrgID) || (key.Machine != "" && rec.Binding.MachineIdentity != key.Machine) {
		return Verified{}, ErrKeyMismatch
	}
	if err := key.covers(rec.RecordedAt); err != nil {
		return Verified{}, err
	}
	return Verified{Record: rec, Digest: Digest(payload), KeyID: key.ID, Attestation: key.Attestation}, nil
}
