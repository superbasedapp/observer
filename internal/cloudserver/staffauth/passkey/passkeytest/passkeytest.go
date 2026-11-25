package passkeytest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// Alg is a COSE algorithm the authenticator can sign with.
type Alg int

// The supported algorithms.
const (
	ES256 Alg = -7
	EdDSA Alg = -8
)

// Authenticator flag bits (WebAuthn level 3, 6.1).
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

// Authenticator is one passkey.
type Authenticator struct {
	// CredentialID is the credential id the authenticator mints.
	CredentialID []byte
	// Alg is the key's algorithm.
	Alg Alg
	// Counter is the signature counter; CounterStep is added before every
	// assertion. A synced platform passkey keeps no counter (step 0).
	Counter     uint32
	CounterStep uint32
	// UserHandle is the user.id stored at registration.
	UserHandle []byte
	// AAGUID is reported in the attested credential data.
	AAGUID [16]byte
	// BackupEligible sets the BE flag on every response.
	BackupEligible bool

	ec *ecdsa.PrivateKey
	ed ed25519.PrivateKey
}

// New returns an authenticator with a fresh key and a credential id derived
// from seed.
func New(seed byte, alg Alg) (*Authenticator, error) {
	a := &Authenticator{CredentialID: bytes.Repeat([]byte{seed}, 32), Alg: alg, CounterStep: 1}
	a.AAGUID[0] = seed
	switch alg {
	case ES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("passkeytest.New: %w", err)
		}
		a.ec = k
	case EdDSA:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("passkeytest.New: %w", err)
		}
		a.ed = k
	default:
		return nil, fmt.Errorf("passkeytest.New: unsupported algorithm %d", alg)
	}
	return a, nil
}

// Ceremony is the browser's half of one ceremony. Challenge, Origin and RPID
// are what the relying party's options named; the other fields default to
// the honest response and tamper with it when set.
type Ceremony struct {
	Challenge string // base64url, as in the options
	Origin    string
	RPID      string

	// Type overrides clientDataJSON.type.
	Type string
	// NoUserVerification clears the UV flag; NoUserPresence clears UP.
	NoUserVerification bool
	NoUserPresence     bool
	// CrossOrigin sets clientDataJSON.crossOrigin.
	CrossOrigin bool
	// BackupStateWithoutEligibility sets BS while clearing BE.
	BackupStateWithoutEligibility bool
	// RawID overrides the credential id the response names (rawId and id).
	RawID []byte
	// UserHandle overrides the assertion's user handle; OmitUserHandle
	// leaves it out.
	UserHandle     []byte
	OmitUserHandle bool
	// Counter, when non-nil, is the assertion's counter instead of the next
	// one.
	Counter *uint32
	// CorruptSignature flips a bit of the assertion signature.
	CorruptSignature bool
	// Transports is the registration's transports; nil means ["internal"].
	Transports []string
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (c Ceremony) clientDataJSON(defaultType string) ([]byte, error) {
	typ := c.Type
	if typ == "" {
		typ = defaultType
	}
	b, err := json.Marshal(clientData{Type: typ, Challenge: c.Challenge, Origin: c.Origin, CrossOrigin: c.CrossOrigin})
	if err != nil {
		return nil, fmt.Errorf("passkeytest: client data: %w", err)
	}
	return b, nil
}

func (a *Authenticator) flags(c Ceremony) byte {
	var f byte = flagUP | flagUV
	if c.NoUserPresence {
		f &^= flagUP
	}
	if c.NoUserVerification {
		f &^= flagUV
	}
	if a.BackupEligible {
		f |= flagBE
	}
	if c.BackupStateWithoutEligibility {
		f = (f | flagBS) &^ flagBE
	}
	return f
}

// cosePublicKey is the credential public key as a COSE_Key.
func (a *Authenticator) cosePublicKey() ([]byte, error) {
	switch a.Alg {
	case ES256:
		raw, err := a.ec.PublicKey.Bytes() // 0x04 || X || Y
		if err != nil {
			return nil, fmt.Errorf("passkeytest: public key: %w", err)
		}
		return webauthncbor.Marshal(map[int]any{1: 2, 3: int(ES256), -1: 1, -2: raw[1:33], -3: raw[33:65]})
	default:
		pub, _ := a.ed.Public().(ed25519.PublicKey)
		return webauthncbor.Marshal(map[int]any{1: 1, 3: int(EdDSA), -1: 6, -2: []byte(pub)})
	}
}

func authData(rpID string, flags byte, counter uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := make([]byte, 0, 37+len(attested))
	out = append(out, h[:]...)
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, counter)
	return append(out, attested...)
}

// Register answers a registration ceremony for the staff member userHandle
// with attestation "none", and remembers userHandle. It returns the
// PublicKeyCredential JSON a browser posts.
func (a *Authenticator) Register(c Ceremony, userHandle []byte) ([]byte, error) {
	a.UserHandle = bytes.Clone(userHandle)
	key, err := a.cosePublicKey()
	if err != nil {
		return nil, err
	}
	attested := make([]byte, 0, 18+len(a.CredentialID)+len(key))
	attested = append(attested, a.AAGUID[:]...)
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.CredentialID))) //nolint:gosec // G115: a test credential id is 32 bytes
	attested = append(attested, a.CredentialID...)
	attested = append(attested, key...)
	ad := authData(c.RPID, a.flags(c)|flagAT, a.Counter, attested)
	attObj, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": ad})
	if err != nil {
		return nil, fmt.Errorf("passkeytest: attestation object: %w", err)
	}
	transports := c.Transports
	if transports == nil {
		transports = []string{"internal"}
	}
	cdj, err := c.clientDataJSON("webauthn.create")
	if err != nil {
		return nil, err
	}
	id := a.CredentialID
	if c.RawID != nil {
		id = c.RawID
	}
	return json.Marshal(map[string]any{
		"id": b64(id), "rawId": b64(id), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64(cdj),
			"attestationObject": b64(attObj),
			"transports":        transports,
		},
		"clientExtensionResults": map[string]any{},
	})
}

// Assert answers an assertion ceremony, advancing the counter by
// CounterStep (unless c.Counter pins it). It returns the
// PublicKeyCredential JSON a browser posts.
func (a *Authenticator) Assert(c Ceremony) ([]byte, error) {
	counter := a.Counter + a.CounterStep
	if c.Counter != nil {
		counter = *c.Counter
	} else {
		a.Counter = counter
	}
	ad := authData(c.RPID, a.flags(c), counter, nil)
	cdj, err := c.clientDataJSON("webauthn.get")
	if err != nil {
		return nil, err
	}
	cdh := sha256.Sum256(cdj)
	signed := append(bytes.Clone(ad), cdh[:]...)
	var sig []byte
	switch a.Alg {
	case ES256:
		digest := sha256.Sum256(signed)
		s, err := ecdsa.SignASN1(rand.Reader, a.ec, digest[:])
		if err != nil {
			return nil, fmt.Errorf("passkeytest: sign: %w", err)
		}
		sig = s
	default:
		sig = ed25519.Sign(a.ed, signed)
	}
	if c.CorruptSignature {
		sig[len(sig)-1] ^= 0x01
	}
	resp := map[string]any{
		"clientDataJSON":    b64(cdj),
		"authenticatorData": b64(ad),
		"signature":         b64(sig),
	}
	switch {
	case c.OmitUserHandle:
	case c.UserHandle != nil:
		resp["userHandle"] = b64(c.UserHandle)
	default:
		resp["userHandle"] = b64(a.UserHandle)
	}
	id := a.CredentialID
	if c.RawID != nil {
		id = c.RawID
	}
	return json.Marshal(map[string]any{
		"id": b64(id), "rawId": b64(id), "type": "public-key",
		"response":               resp,
		"clientExtensionResults": map[string]any{},
	})
}
