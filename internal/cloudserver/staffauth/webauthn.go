package staffauth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// ErrNotAvailable is what Unavailable returns: no WebAuthn verifier is wired
// into this build. The API answers it as 501 not_available.
var ErrNotAvailable = errors.New("staffauth: WebAuthn verification is not available in this build")

// ErrCounterRegression means an assertion's signature counter did not move
// forward: a cloned authenticator or a replayed assertion.
var ErrCounterRegression = errors.New("staffauth: WebAuthn signature counter did not increase")

// ErrMalformedCredential means a browser's credential response is not a
// well-formed PublicKeyCredential.
var ErrMalformedCredential = errors.New("staffauth: malformed WebAuthn credential")

// ChallengeBytes is the size of every ceremony challenge (WebAuthn asks for
// at least 16 random bytes; the staff_ceremonies CHECK pins 32).
const ChallengeBytes = 32

// MaxCredentialIDBytes is the WebAuthn bound on a credential id.
const MaxCredentialIDBytes = 1023

// MaxResponseBytes bounds a credential response a route will read.
const MaxResponseBytes = 64 << 10

// RegistrationCeremony is the server's half of a registration
// (navigator.credentials.create) ceremony.
type RegistrationCeremony struct {
	// RPID is the WebAuthn relying-party id: the staff console's host name.
	RPID string
	// Origin is the exact origin (scheme://host[:port]) the browser must
	// report in clientDataJSON.
	Origin string
	// Challenge is the ceremony's random challenge (ChallengeBytes).
	Challenge []byte
	// UserHandle is the WebAuthn user.id: the staff member's id.
	UserHandle []byte
}

// AssertionCeremony is the server's half of an assertion
// (navigator.credentials.get) ceremony.
type AssertionCeremony struct {
	RPID      string
	Origin    string
	Challenge []byte
}

// NewCredential is what a verified registration yields: the credential the
// store keeps.
type NewCredential struct {
	ID         []byte
	PublicKey  []byte
	SignCount  uint32
	AAGUID     []byte
	Transports []string
	// BackupEligible is the authenticator's BE flag: the credential may be
	// synced off the device (a synced passkey). The portal second factor
	// reports such a key as software-secured (RFC 8176 "swk"), any other as
	// hardware-secured ("hwk").
	BackupEligible bool
}

// StoredCredential is a registered credential as the store returns it for an
// assertion.
type StoredCredential struct {
	ID         []byte
	PublicKey  []byte
	SignCount  uint32
	UserHandle []byte
}

// VerifiedAssertion is what a verified assertion yields.
type VerifiedAssertion struct {
	// SignCount is the authenticator's counter in this assertion; the caller
	// applies CheckSignCount against the stored one.
	SignCount uint32
	// BackupEligible is the assertion's BE flag (see NewCredential).
	BackupEligible bool
}

// Verifier verifies WebAuthn ceremony responses. Its types are this
// package's own; an implementation over a WebAuthn library converts at its
// own boundary, and no library type crosses this interface.
//
// An implementation must check, for a registration: the clientDataJSON type
// ("webauthn.create"), challenge and origin; the rpIdHash; the user-present
// and user-verified flags; an attestation format it accepts ("none" at
// least); and that the returned credential id is the one in the response.
// For an assertion: the clientDataJSON type ("webauthn.get"), challenge and
// origin; the rpIdHash; the user-present and user-verified flags; the
// signature under cred.PublicKey; that the response names cred.ID; and, when
// the response carries a user handle, that it equals cred.UserHandle. It
// does NOT apply the counter rule (CheckSignCount) or touch any state.
//
// The production implementation is internal/cloudserver/staffauth/passkey
// (over github.com/go-webauthn/webauthn), which is stricter than this
// minimum: every staff ceremony is discoverable (NewRequestOptions lists no
// credentials), so it REQUIRES the user handle on an assertion, and it
// refuses an RPID that is not exactly the origin's host.
type Verifier interface {
	// Available reports whether this verifier can verify anything. The
	// routes answer not_available, and create no ceremony, when it is false.
	Available() bool
	// VerifyRegistration verifies a registration response for c.
	VerifyRegistration(c RegistrationCeremony, response []byte) (NewCredential, error)
	// VerifyAssertion verifies an assertion response for c against cred.
	VerifyAssertion(c AssertionCeremony, cred StoredCredential, response []byte) (VerifiedAssertion, error)
}

// Unavailable is the Verifier of a build without a WebAuthn implementation:
// it verifies nothing.
type Unavailable struct{}

// Available reports false.
func (Unavailable) Available() bool { return false }

// VerifyRegistration returns ErrNotAvailable.
func (Unavailable) VerifyRegistration(RegistrationCeremony, []byte) (NewCredential, error) {
	return NewCredential{}, ErrNotAvailable
}

// VerifyAssertion returns ErrNotAvailable.
func (Unavailable) VerifyAssertion(AssertionCeremony, StoredCredential, []byte) (VerifiedAssertion, error) {
	return VerifiedAssertion{}, ErrNotAvailable
}

// NewChallenge reads ChallengeBytes from r (crypto/rand.Reader in
// production; injected so tests are deterministic).
func NewChallenge(r io.Reader) ([]byte, error) {
	b := make([]byte, ChallengeBytes)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("staffauth.NewChallenge: %w", err)
	}
	return b, nil
}

// signCountRule is one row of the counter table.
type signCountRule struct {
	name  string
	match func(stored, presented uint32) bool
	ok    bool
}

// signCountRules is the WebAuthn signature-counter rule (WebAuthn level 2,
// 7.2 step 21) as a table walked top down: an authenticator that keeps no
// counter reports zero forever, which is allowed only while the stored value
// is zero too; otherwise the counter must strictly increase.
var signCountRules = []signCountRule{
	{name: "no counter kept", match: func(s, p uint32) bool { return s == 0 && p == 0 }, ok: true},
	{name: "counter increased", match: func(s, p uint32) bool { return p > s }, ok: true},
	{name: "counter regressed or repeated", match: func(uint32, uint32) bool { return true }, ok: false},
}

// CheckSignCount applies the counter rule to a stored and a presented
// counter: nil, or ErrCounterRegression.
func CheckSignCount(stored, presented uint32) error {
	for _, r := range signCountRules {
		if r.match(stored, presented) {
			if r.ok {
				return nil
			}
			return fmt.Errorf("%w (stored %d, presented %d)", ErrCounterRegression, stored, presented)
		}
	}
	return ErrCounterRegression
}

// credentialEnvelope is the outer shape of a PublicKeyCredential's JSON
// form (PublicKeyCredential.toJSON()).
type credentialEnvelope struct {
	ID    string `json:"id"`
	RawID string `json:"rawId"`
	Type  string `json:"type"`
}

// CredentialID returns the credential id a browser's credential response
// names. It reads only the envelope (id, rawId, type), which is all an
// assertion needs to find the stored credential before verification; it
// verifies nothing.
func CredentialID(response []byte) ([]byte, error) {
	if len(response) == 0 || len(response) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: size %d", ErrMalformedCredential, len(response))
	}
	var env credentialEnvelope
	if err := json.Unmarshal(response, &env); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedCredential, err)
	}
	if env.Type != "public-key" {
		return nil, fmt.Errorf("%w: type %q", ErrMalformedCredential, env.Type)
	}
	if env.ID == "" || env.ID != env.RawID {
		return nil, fmt.Errorf("%w: id and rawId differ or are empty", ErrMalformedCredential)
	}
	id, err := base64.RawURLEncoding.DecodeString(env.RawID)
	if err != nil {
		return nil, fmt.Errorf("%w: rawId: %w", ErrMalformedCredential, err)
	}
	if len(id) == 0 || len(id) > MaxCredentialIDBytes {
		return nil, fmt.Errorf("%w: credential id of %d bytes", ErrMalformedCredential, len(id))
	}
	return id, nil
}

// CredentialDescriptor names one credential in options.
type CredentialDescriptor struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// RelyingParty is the rp member of creation options.
type RelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserEntity is the user member of creation options.
type UserEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// CredentialParameter is one pubKeyCredParams entry.
type CredentialParameter struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// AuthenticatorSelection is the authenticatorSelection member.
type AuthenticatorSelection struct {
	ResidentKey        string `json:"residentKey"`
	RequireResidentKey bool   `json:"requireResidentKey"`
	UserVerification   string `json:"userVerification"`
}

// CreationOptions is PublicKeyCredentialCreationOptions in its JSON form
// (the shape PublicKeyCredential.parseCreationOptionsFromJSON reads).
type CreationOptions struct {
	RP                     RelyingParty           `json:"rp"`
	User                   UserEntity             `json:"user"`
	Challenge              string                 `json:"challenge"`
	PubKeyCredParams       []CredentialParameter  `json:"pubKeyCredParams"`
	Timeout                int64                  `json:"timeout"`
	ExcludeCredentials     []CredentialDescriptor `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	Attestation            string                 `json:"attestation"`
}

// RequestOptions is PublicKeyCredentialRequestOptions in its JSON form.
type RequestOptions struct {
	Challenge        string                 `json:"challenge"`
	RPID             string                 `json:"rpId"`
	Timeout          int64                  `json:"timeout"`
	UserVerification string                 `json:"userVerification"`
	AllowCredentials []CredentialDescriptor `json:"allowCredentials"`
}

// The COSE algorithms a staff passkey may use, in preference order: EdDSA,
// ES256, RS256.
var credentialAlgorithms = []int{-8, -7, -257}

// CredentialAlgorithms returns the COSE algorithms a staff passkey may use,
// the same list NewCreationOptions offers, so a verifier accepts exactly
// what the options asked for.
func CredentialAlgorithms() []int {
	return append([]int(nil), credentialAlgorithms...)
}

// RPName is the relying-party name a passkey prompt shows.
const RPName = "SuperBased staff console"

// NewCreationOptions builds the options for a registration ceremony: a
// discoverable credential, user verification required, no attestation, and
// the staff member's existing credentials excluded.
func NewCreationOptions(c RegistrationCeremony, displayName string, exclude [][]byte, timeout time.Duration) CreationOptions {
	return NewCreationOptionsNamed(RPName, c, displayName, exclude, timeout)
}

// NewCreationOptionsNamed is NewCreationOptions with the relying-party name
// a passkey prompt shows (the portal's second factor names "SuperBased", the
// staff console RPName).
func NewCreationOptionsNamed(rpName string, c RegistrationCeremony, displayName string, exclude [][]byte, timeout time.Duration) CreationOptions {
	params := make([]CredentialParameter, len(credentialAlgorithms))
	for i, alg := range credentialAlgorithms {
		params[i] = CredentialParameter{Type: "public-key", Alg: alg}
	}
	ex := make([]CredentialDescriptor, len(exclude))
	for i, id := range exclude {
		ex[i] = CredentialDescriptor{Type: "public-key", ID: base64.RawURLEncoding.EncodeToString(id)}
	}
	handle := base64.RawURLEncoding.EncodeToString(c.UserHandle)
	return CreationOptions{
		RP:                 RelyingParty{ID: c.RPID, Name: rpName},
		User:               UserEntity{ID: handle, Name: displayName, DisplayName: displayName},
		Challenge:          base64.RawURLEncoding.EncodeToString(c.Challenge),
		PubKeyCredParams:   params,
		Timeout:            timeout.Milliseconds(),
		ExcludeCredentials: ex,
		AuthenticatorSelection: AuthenticatorSelection{
			ResidentKey: "required", RequireResidentKey: true, UserVerification: "required",
		},
		Attestation: "none",
	}
}

// NewRequestOptions builds the options for an assertion ceremony: any
// discoverable staff credential, user verification required.
func NewRequestOptions(c AssertionCeremony, timeout time.Duration) RequestOptions {
	return NewRequestOptionsAllowing(c, nil, timeout)
}

// NewRequestOptionsAllowing is NewRequestOptions naming the credentials the
// browser may use (the portal's second factor: the signed-in account's own
// passkeys). The credentials are still discoverable, so the verifier's
// user-handle rule holds.
func NewRequestOptionsAllowing(c AssertionCeremony, allow [][]byte, timeout time.Duration) RequestOptions {
	al := make([]CredentialDescriptor, len(allow))
	for i, id := range allow {
		al[i] = CredentialDescriptor{Type: "public-key", ID: base64.RawURLEncoding.EncodeToString(id)}
	}
	return RequestOptions{
		Challenge:        base64.RawURLEncoding.EncodeToString(c.Challenge),
		RPID:             c.RPID,
		Timeout:          timeout.Milliseconds(),
		UserVerification: "required",
		AllowCredentials: al,
	}
}
