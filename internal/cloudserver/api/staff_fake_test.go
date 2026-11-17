package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
)

// staff_fake_test.go is a minimal hand-built WebAuthn-shaped authenticator
// and the matching verifier, standing in for a WebAuthn library until the
// operator rules on the dependency (M6.0 Q7). It is exported so the external
// api_test package's Postgres tests use the same one.
//
// The protocol keeps WebAuthn's security-relevant structure and drops only
// CBOR and COSE: clientDataJSON carries type, challenge and origin;
// authenticatorData is rpIdHash (32) || flags (1) || signCount (4, big
// endian); the assertion signature is Ed25519 over
// authenticatorData || SHA-256(clientDataJSON); the "public key" is the raw
// 32-byte Ed25519 key. The verifier checks every field a real one does
// (staffauth.Verifier's contract), so the routes are exercised for passing
// the right challenge, origin, rp id, stored key and user handle.

// StaffTestAuthenticator is one passkey.
type StaffTestAuthenticator struct {
	CredentialID []byte
	Key          ed25519.PrivateKey
	Counter      uint32
}

// NewStaffTestAuthenticator makes a passkey with a deterministic key.
func NewStaffTestAuthenticator(seed byte) *StaffTestAuthenticator {
	return &StaffTestAuthenticator{
		CredentialID: bytes.Repeat([]byte{seed}, 20),
		Key:          ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)),
	}
}

type fakeClientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

type fakeResponse struct {
	ClientDataJSON    string `json:"clientDataJSON"`
	PublicKey         string `json:"publicKey,omitempty"`
	AuthenticatorData string `json:"authenticatorData,omitempty"`
	Signature         string `json:"signature,omitempty"`
	UserHandle        string `json:"userHandle,omitempty"`
}

type fakeCredential struct {
	ID       string       `json:"id"`
	RawID    string       `json:"rawId"`
	Type     string       `json:"type"`
	Response fakeResponse `json:"response"`
}

// Register answers a registration with the options' challenge (base64url)
// at origin.
func (a *StaffTestAuthenticator) Register(challenge, origin string) json.RawMessage {
	cd, _ := json.Marshal(fakeClientData{Type: "webauthn.create", Challenge: challenge, Origin: origin})
	return a.envelope(fakeResponse{
		ClientDataJSON: base64.RawURLEncoding.EncodeToString(cd),
		PublicKey:      base64.RawURLEncoding.EncodeToString(a.Key.Public().(ed25519.PublicKey)),
	})
}

// Assert answers an assertion for rpID with the next counter value.
func (a *StaffTestAuthenticator) Assert(challenge, origin, rpID string, userHandle []byte) json.RawMessage {
	a.Counter++
	return a.AssertWithCounter(challenge, origin, rpID, userHandle, a.Counter)
}

// AssertWithCounter answers an assertion with a chosen counter (to replay or
// regress it).
func (a *StaffTestAuthenticator) AssertWithCounter(challenge, origin, rpID string, userHandle []byte, counter uint32) json.RawMessage {
	cd, _ := json.Marshal(fakeClientData{Type: "webauthn.get", Challenge: challenge, Origin: origin})
	rp := sha256.Sum256([]byte(rpID))
	ad := make([]byte, 0, 37)
	ad = append(ad, rp[:]...)
	ad = append(ad, 0x05) // UP | UV
	ad = binary.BigEndian.AppendUint32(ad, counter)
	cdh := sha256.Sum256(cd)
	sig := ed25519.Sign(a.Key, append(append([]byte{}, ad...), cdh[:]...))
	return a.envelope(fakeResponse{
		ClientDataJSON:    base64.RawURLEncoding.EncodeToString(cd),
		AuthenticatorData: base64.RawURLEncoding.EncodeToString(ad),
		Signature:         base64.RawURLEncoding.EncodeToString(sig),
		UserHandle:        base64.RawURLEncoding.EncodeToString(userHandle),
	})
}

func (a *StaffTestAuthenticator) envelope(r fakeResponse) json.RawMessage {
	id := base64.RawURLEncoding.EncodeToString(a.CredentialID)
	raw, _ := json.Marshal(fakeCredential{ID: id, RawID: id, Type: "public-key", Response: r})
	return raw
}

// StaffTestVerifier verifies StaffTestAuthenticator responses.
type StaffTestVerifier struct{}

// Available reports true.
func (StaffTestVerifier) Available() bool { return true }

func decodeFake(response []byte) (fakeCredential, fakeClientData, []byte, error) {
	var c fakeCredential
	if err := json.Unmarshal(response, &c); err != nil {
		return c, fakeClientData{}, nil, err
	}
	cdRaw, err := base64.RawURLEncoding.DecodeString(c.Response.ClientDataJSON)
	if err != nil {
		return c, fakeClientData{}, nil, err
	}
	var cd fakeClientData
	if err := json.Unmarshal(cdRaw, &cd); err != nil {
		return c, cd, nil, err
	}
	return c, cd, cdRaw, nil
}

func checkClientData(cd fakeClientData, typ string, challenge []byte, origin string) error {
	if cd.Type != typ {
		return fmt.Errorf("type %q", cd.Type)
	}
	if cd.Challenge != base64.RawURLEncoding.EncodeToString(challenge) {
		return errors.New("challenge mismatch")
	}
	if cd.Origin != origin {
		return fmt.Errorf("origin %q", cd.Origin)
	}
	return nil
}

// VerifyRegistration checks type, challenge and origin and returns the key.
func (StaffTestVerifier) VerifyRegistration(c staffauth.RegistrationCeremony, response []byte) (staffauth.NewCredential, error) {
	cred, cd, _, err := decodeFake(response)
	if err != nil {
		return staffauth.NewCredential{}, err
	}
	if err := checkClientData(cd, "webauthn.create", c.Challenge, c.Origin); err != nil {
		return staffauth.NewCredential{}, err
	}
	id, err := staffauth.CredentialID(response)
	if err != nil {
		return staffauth.NewCredential{}, err
	}
	pub, err := base64.RawURLEncoding.DecodeString(cred.Response.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return staffauth.NewCredential{}, errors.New("bad public key")
	}
	if len(c.UserHandle) != 16 {
		return staffauth.NewCredential{}, errors.New("no user handle in the ceremony")
	}
	return staffauth.NewCredential{ID: id, PublicKey: pub, Transports: []string{"internal"}}, nil
}

// VerifyAssertion checks type, challenge, origin, rpIdHash, flags, the
// credential id, the user handle and the signature.
func (StaffTestVerifier) VerifyAssertion(c staffauth.AssertionCeremony, stored staffauth.StoredCredential, response []byte) (staffauth.VerifiedAssertion, error) {
	cred, cd, cdRaw, err := decodeFake(response)
	if err != nil {
		return staffauth.VerifiedAssertion{}, err
	}
	if err := checkClientData(cd, "webauthn.get", c.Challenge, c.Origin); err != nil {
		return staffauth.VerifiedAssertion{}, err
	}
	id, err := staffauth.CredentialID(response)
	if err != nil || !bytes.Equal(id, stored.ID) {
		return staffauth.VerifiedAssertion{}, errors.New("credential id mismatch")
	}
	ad, err := base64.RawURLEncoding.DecodeString(cred.Response.AuthenticatorData)
	if err != nil || len(ad) != 37 {
		return staffauth.VerifiedAssertion{}, errors.New("bad authenticator data")
	}
	rp := sha256.Sum256([]byte(c.RPID))
	if !bytes.Equal(ad[:32], rp[:]) {
		return staffauth.VerifiedAssertion{}, errors.New("rp id mismatch")
	}
	if ad[32]&0x05 != 0x05 {
		return staffauth.VerifiedAssertion{}, errors.New("user not present and verified")
	}
	if uh, _ := base64.RawURLEncoding.DecodeString(cred.Response.UserHandle); len(uh) > 0 && !bytes.Equal(uh, stored.UserHandle) {
		return staffauth.VerifiedAssertion{}, errors.New("user handle mismatch")
	}
	sig, err := base64.RawURLEncoding.DecodeString(cred.Response.Signature)
	if err != nil || len(stored.PublicKey) != ed25519.PublicKeySize {
		return staffauth.VerifiedAssertion{}, errors.New("bad signature or key")
	}
	cdh := sha256.Sum256(cdRaw)
	if !ed25519.Verify(ed25519.PublicKey(stored.PublicKey), append(append([]byte{}, ad...), cdh[:]...), sig) {
		return staffauth.VerifiedAssertion{}, errors.New("signature does not verify")
	}
	return staffauth.VerifiedAssertion{SignCount: binary.BigEndian.Uint32(ad[33:37])}, nil
}
