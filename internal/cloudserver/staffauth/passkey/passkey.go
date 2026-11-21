package passkey

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
)

// ErrVerification is the one error a ceremony that did not verify yields.
// The library's own error is flattened into its text: no library type
// reaches a caller through errors.As.
var ErrVerification = errors.New("passkey: WebAuthn ceremony did not verify")

// ErrConfiguration means the ceremony's relying-party id or origin is not
// one this verifier will sign anyone in for (see checkRelyingParty).
var ErrConfiguration = errors.New("passkey: relying party misconfigured")

// maxTransports bounds the transports kept with a credential.
const maxTransports = 8

// transportPattern is the shape of one kept transport hint ("usb",
// "internal", "hybrid", ...); anything else is dropped, not refused, since a
// hint never decides anything.
var transportPattern = regexp.MustCompile(`^[a-z][a-z-]{0,31}$`)

// verifier implements staffauth.Verifier. It holds no state: every input
// arrives with the ceremony.
type verifier struct{}

// New returns the production staff passkey verifier.
func New() staffauth.Verifier { return verifier{} }

// Available reports true: this build verifies WebAuthn.
func (verifier) Available() bool { return true }

// VerifyRegistration verifies a registration (navigator.credentials.create)
// response for c and returns the credential to store.
func (verifier) VerifyRegistration(c staffauth.RegistrationCeremony, response []byte) (staffauth.NewCredential, error) {
	if err := checkRelyingParty(c.RPID, c.Origin); err != nil {
		return staffauth.NewCredential{}, err
	}
	if err := checkCeremonyInputs(c.Challenge, response); err != nil {
		return staffauth.NewCredential{}, err
	}
	if len(c.UserHandle) == 0 {
		return staffauth.NewCredential{}, fmt.Errorf("%w: registration without a user handle", ErrConfiguration)
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return staffauth.NewCredential{}, flatten("parse registration", err)
	}
	if _, err := parsed.Verify(
		challengeString(c.Challenge), c.RPID,
		[]string{c.Origin}, nil, nil, protocol.TopOriginExplicitVerificationMode,
		false, // allowCrossOrigin
		true,  // verifyUser: user verification is required (ruling A2)
		true,  // verifyUserPresence
		nil,   // no metadata service: attestation is not judged against trust anchors
		credentialParameters(), protocol.AttestationPolicy{}, protocol.SignaturePolicy{},
	); err != nil {
		return staffauth.NewCredential{}, flatten("verify registration", err)
	}
	authData := parsed.Response.AttestationObject.AuthData
	if err := checkBackupFlags(authData.Flags); err != nil {
		return staffauth.NewCredential{}, err
	}
	att := authData.AttData
	if len(att.CredentialID) == 0 || len(att.CredentialID) > staffauth.MaxCredentialIDBytes {
		return staffauth.NewCredential{}, fmt.Errorf("%w: credential id of %d bytes", ErrVerification, len(att.CredentialID))
	}
	if len(att.CredentialPublicKey) == 0 {
		return staffauth.NewCredential{}, fmt.Errorf("%w: no credential public key", ErrVerification)
	}
	if _, err := webauthncose.ParsePublicKey(att.CredentialPublicKey); err != nil {
		return staffauth.NewCredential{}, flatten("parse credential public key", err)
	}
	out := staffauth.NewCredential{
		ID:             bytes.Clone(att.CredentialID),
		PublicKey:      bytes.Clone(att.CredentialPublicKey),
		SignCount:      authData.Counter,
		Transports:     keepTransports(parsed.Response.Transports),
		BackupEligible: authData.Flags.HasBackupEligible(),
	}
	if len(att.AAGUID) == 16 && !bytes.Equal(att.AAGUID, make([]byte, 16)) {
		out.AAGUID = bytes.Clone(att.AAGUID)
	}
	return out, nil
}

// VerifyAssertion verifies an assertion (navigator.credentials.get)
// response for c against the stored credential cred.
func (verifier) VerifyAssertion(c staffauth.AssertionCeremony, cred staffauth.StoredCredential, response []byte) (staffauth.VerifiedAssertion, error) {
	if err := checkRelyingParty(c.RPID, c.Origin); err != nil {
		return staffauth.VerifiedAssertion{}, err
	}
	if err := checkCeremonyInputs(c.Challenge, response); err != nil {
		return staffauth.VerifiedAssertion{}, err
	}
	if len(cred.ID) == 0 || len(cred.PublicKey) == 0 || len(cred.UserHandle) == 0 {
		return staffauth.VerifiedAssertion{}, fmt.Errorf("%w: stored credential incomplete", ErrVerification)
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(response)
	if err != nil {
		return staffauth.VerifiedAssertion{}, flatten("parse assertion", err)
	}
	if !bytes.Equal(parsed.RawID, cred.ID) {
		return staffauth.VerifiedAssertion{}, fmt.Errorf("%w: the assertion names another credential", ErrVerification)
	}
	// Every staff ceremony is discoverable (no allowCredentials), so the
	// authenticator always returns the user handle; one that does not, or
	// names another staff member, is refused.
	if len(parsed.Response.UserHandle) == 0 {
		return staffauth.VerifiedAssertion{}, fmt.Errorf("%w: no user handle in a discoverable assertion", ErrVerification)
	}
	if !bytes.Equal(parsed.Response.UserHandle, cred.UserHandle) {
		return staffauth.VerifiedAssertion{}, fmt.Errorf("%w: user handle does not own the credential", ErrVerification)
	}
	if err := parsed.Verify(
		challengeString(c.Challenge), c.RPID, "", // no FIDO AppID extension
		[]string{c.Origin}, nil, nil, protocol.TopOriginExplicitVerificationMode,
		false, // allowCrossOrigin
		true,  // verifyUser: user verification is required (ruling A2)
		true,  // verifyUserPresence
		cred.PublicKey, protocol.SignaturePolicy{},
	); err != nil {
		return staffauth.VerifiedAssertion{}, flatten("verify assertion", err)
	}
	if err := checkBackupFlags(parsed.Response.AuthenticatorData.Flags); err != nil {
		return staffauth.VerifiedAssertion{}, err
	}
	return staffauth.VerifiedAssertion{
		SignCount:      parsed.Response.AuthenticatorData.Counter,
		BackupEligible: parsed.Response.AuthenticatorData.Flags.HasBackupEligible(),
	}, nil
}

// checkCeremonyInputs bounds what a ceremony verifies before the library
// sees it.
func checkCeremonyInputs(challenge, response []byte) error {
	if len(challenge) != staffauth.ChallengeBytes {
		return fmt.Errorf("%w: challenge of %d bytes", ErrConfiguration, len(challenge))
	}
	if len(response) == 0 || len(response) > staffauth.MaxResponseBytes {
		return fmt.Errorf("%w: response of %d bytes", ErrVerification, len(response))
	}
	return nil
}

// loopbackHosts are the hosts an http (not https) staff origin may name: a
// developer's own machine.
var loopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}

// checkRelyingParty refuses a relying-party id that is not exactly the
// origin's host (ruling A3: the staff host itself, never the parent domain,
// so a passkey is never usable on a sibling subdomain) and an origin that is
// not a bare scheme://host[:port] over https (http only on loopback).
func checkRelyingParty(rpID, origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: origin %q is not scheme://host[:port]", ErrConfiguration, origin)
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && loopbackHosts[host]:
	default:
		return fmt.Errorf("%w: origin %q must be https (http only on loopback)", ErrConfiguration, origin)
	}
	if rpID == "" || !strings.EqualFold(rpID, host) {
		return fmt.Errorf("%w: relying-party id %q is not the origin's host %q", ErrConfiguration, rpID, host)
	}
	return nil
}

// checkBackupFlags refuses the invalid combination of the backup-state flag
// without backup eligibility (WebAuthn level 3, 6.1.3).
func checkBackupFlags(f protocol.AuthenticatorFlags) error {
	if f.HasBackupState() && !f.HasBackupEligible() {
		return fmt.Errorf("%w: backup state without backup eligibility", ErrVerification)
	}
	return nil
}

// credentialParameters converts staffauth's algorithm list (the one the
// creation options offered) into the library's form.
func credentialParameters() []protocol.CredentialParameter {
	algs := staffauth.CredentialAlgorithms()
	out := make([]protocol.CredentialParameter, len(algs))
	for i, alg := range algs {
		out[i] = protocol.CredentialParameter{
			Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.COSEAlgorithmIdentifier(alg),
		}
	}
	return out
}

// challengeString is the challenge as clientDataJSON carries it: base64url
// without padding, the encoding staffauth's options use.
func challengeString(challenge []byte) string {
	return base64.RawURLEncoding.EncodeToString(challenge)
}

// keepTransports keeps at most maxTransports well-formed transport hints.
func keepTransports(in []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		s := string(t)
		if len(out) == maxTransports || !transportPattern.MatchString(s) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// flatten turns a library error into ErrVerification carrying its text, so
// the library's error type never crosses this package's boundary.
func flatten(step string, err error) error {
	msg := err.Error()
	var pe *protocol.Error
	if errors.As(err, &pe) && pe.DevInfo != "" {
		msg += " (" + pe.DevInfo + ")"
	}
	return fmt.Errorf("%w: %s: %s", ErrVerification, step, msg)
}
