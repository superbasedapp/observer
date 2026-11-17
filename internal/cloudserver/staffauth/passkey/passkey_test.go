package passkey_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth/passkey"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth/passkey/passkeytest"
)

// passkey_test.go proves the production staff verifier against two
// independent sources, with no network:
//
//   - a software authenticator (passkeytest) that builds real CBOR, COSE,
//     authenticator data and ES256 / EdDSA signatures, driven through every
//     honest and tampered shape a client could send;
//   - the W3C WebAuthn level 3 section 16 registration test vectors (the
//     same bytes go-webauthn's own spec-vector tests use), which this
//     package did not produce.

const (
	testOrigin = "https://staff.superbased.app"
	testRPID   = "staff.superbased.app"
)

var testUserHandle = bytes.Repeat([]byte{0xAB}, 16)

func challenge(seed byte) []byte { return bytes.Repeat([]byte{seed}, staffauth.ChallengeBytes) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newAuth(t *testing.T, seed byte, alg passkeytest.Alg) *passkeytest.Authenticator {
	t.Helper()
	a, err := passkeytest.New(seed, alg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// register runs an honest registration and returns the stored credential.
func register(t *testing.T, v staffauth.Verifier, a *passkeytest.Authenticator) staffauth.StoredCredential {
	t.Helper()
	ch := challenge(1)
	resp, err := a.Register(passkeytest.Ceremony{Challenge: b64(ch), Origin: testOrigin, RPID: testRPID}, testUserHandle)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := v.VerifyRegistration(staffauth.RegistrationCeremony{RPID: testRPID, Origin: testOrigin, Challenge: ch, UserHandle: testUserHandle}, resp)
	if err != nil {
		t.Fatalf("VerifyRegistration: %v", err)
	}
	return staffauth.StoredCredential{ID: cred.ID, PublicKey: cred.PublicKey, SignCount: cred.SignCount, UserHandle: testUserHandle}
}

func TestAvailable(t *testing.T) {
	t.Parallel()
	if !passkey.New().Available() {
		t.Fatal("the production verifier reports unavailable")
	}
}

// TestRoundTrip registers and signs in with each algorithm the options
// offer that the software authenticator implements, checking what reaches
// the store and that the counter is reported, not judged.
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	for _, alg := range []passkeytest.Alg{passkeytest.ES256, passkeytest.EdDSA} {
		v := passkey.New()
		a := newAuth(t, 7, alg)
		ch := challenge(1)
		resp, err := a.Register(passkeytest.Ceremony{Challenge: b64(ch), Origin: testOrigin, RPID: testRPID, Transports: []string{"usb", "nfc", "Not A Transport"}}, testUserHandle)
		if err != nil {
			t.Fatal(err)
		}
		nc, err := v.VerifyRegistration(staffauth.RegistrationCeremony{RPID: testRPID, Origin: testOrigin, Challenge: ch, UserHandle: testUserHandle}, resp)
		if err != nil {
			t.Fatalf("alg %d: VerifyRegistration: %v", alg, err)
		}
		if !bytes.Equal(nc.ID, a.CredentialID) || len(nc.PublicKey) == 0 || nc.SignCount != 0 {
			t.Fatalf("alg %d: credential = %+v", alg, nc)
		}
		if len(nc.AAGUID) != 16 || nc.AAGUID[0] != 7 {
			t.Errorf("alg %d: aaguid = %x", alg, nc.AAGUID)
		}
		if strings.Join(nc.Transports, ",") != "usb,nfc" {
			t.Errorf("alg %d: transports = %q, want the two well-formed ones", alg, nc.Transports)
		}
		stored := staffauth.StoredCredential{ID: nc.ID, PublicKey: nc.PublicKey, SignCount: nc.SignCount, UserHandle: testUserHandle}
		for want := uint32(1); want <= 2; want++ {
			ch := challenge(byte(10 + want))
			resp, err := a.Assert(passkeytest.Ceremony{Challenge: b64(ch), Origin: testOrigin, RPID: testRPID})
			if err != nil {
				t.Fatal(err)
			}
			got, err := v.VerifyAssertion(staffauth.AssertionCeremony{RPID: testRPID, Origin: testOrigin, Challenge: ch}, stored, resp)
			if err != nil {
				t.Fatalf("alg %d: VerifyAssertion: %v", alg, err)
			}
			if got.SignCount != want {
				t.Fatalf("alg %d: sign count = %d, want %d", alg, got.SignCount, want)
			}
		}
		// A replayed counter verifies cryptographically; the counter rule is
		// the caller's (staffauth.CheckSignCount), and refuses it there.
		one := uint32(1)
		ch = challenge(30)
		resp, err = a.Assert(passkeytest.Ceremony{Challenge: b64(ch), Origin: testOrigin, RPID: testRPID, Counter: &one})
		if err != nil {
			t.Fatal(err)
		}
		got, err := v.VerifyAssertion(staffauth.AssertionCeremony{RPID: testRPID, Origin: testOrigin, Challenge: ch}, staffauth.StoredCredential{ID: nc.ID, PublicKey: nc.PublicKey, SignCount: 2, UserHandle: testUserHandle}, resp)
		if err != nil {
			t.Fatalf("alg %d: replayed counter: %v", alg, err)
		}
		if staffauth.CheckSignCount(2, got.SignCount) == nil {
			t.Errorf("alg %d: the counter rule accepted a regressed counter", alg)
		}
	}
}

// TestSyncedPasskeyKeepsNoCounter: a platform passkey that reports zero
// forever verifies, and the counter rule accepts zero after zero.
func TestSyncedPasskeyKeepsNoCounter(t *testing.T) {
	t.Parallel()
	v := passkey.New()
	a := newAuth(t, 8, passkeytest.ES256)
	a.CounterStep = 0
	a.BackupEligible = true
	stored := register(t, v, a)
	ch := challenge(2)
	resp, err := a.Assert(passkeytest.Ceremony{Challenge: b64(ch), Origin: testOrigin, RPID: testRPID})
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.VerifyAssertion(staffauth.AssertionCeremony{RPID: testRPID, Origin: testOrigin, Challenge: ch}, stored, resp)
	if err != nil {
		t.Fatalf("VerifyAssertion: %v", err)
	}
	if got.SignCount != 0 || staffauth.CheckSignCount(0, 0) != nil {
		t.Fatalf("sign count = %d", got.SignCount)
	}
}

func TestRegistrationRefusals(t *testing.T) {
	t.Parallel()
	other := newAuth(t, 9, passkeytest.ES256)
	cases := []struct {
		name      string
		ceremony  func(c *passkeytest.Ceremony)
		rpID      string
		origin    string
		wantError error
	}{
		{name: "another challenge", ceremony: func(c *passkeytest.Ceremony) { c.Challenge = b64(challenge(99)) }},
		{name: "another origin", ceremony: func(c *passkeytest.Ceremony) { c.Origin = "https://app.superbased.app" }},
		{name: "a parent-domain rp id hash", ceremony: func(c *passkeytest.Ceremony) { c.RPID = "superbased.app" }},
		{name: "no user verification", ceremony: func(c *passkeytest.Ceremony) { c.NoUserVerification = true }},
		{name: "no user presence", ceremony: func(c *passkeytest.Ceremony) { c.NoUserPresence = true }},
		{name: "an assertion's client data", ceremony: func(c *passkeytest.Ceremony) { c.Type = "webauthn.get" }},
		{name: "cross-origin", ceremony: func(c *passkeytest.Ceremony) { c.CrossOrigin = true }},
		{name: "rawId differs from the attested id", ceremony: func(c *passkeytest.Ceremony) { c.RawID = other.CredentialID }},
		{name: "backup state without eligibility", ceremony: func(c *passkeytest.Ceremony) { c.BackupStateWithoutEligibility = true }},
		{name: "configured rp id is the parent domain", rpID: "superbased.app", wantError: passkey.ErrConfiguration},
		{name: "configured origin is plain http", origin: "http://staff.superbased.app", wantError: passkey.ErrConfiguration},
		{name: "configured origin carries a path", origin: testOrigin + "/staff", wantError: passkey.ErrConfiguration},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := newAuth(t, 3, passkeytest.ES256)
			ch := challenge(1)
			c := passkeytest.Ceremony{Challenge: b64(ch), Origin: testOrigin, RPID: testRPID}
			if tc.ceremony != nil {
				tc.ceremony(&c)
			}
			resp, err := a.Register(c, testUserHandle)
			if err != nil {
				t.Fatal(err)
			}
			rpID, origin := testRPID, testOrigin
			if tc.rpID != "" {
				rpID = tc.rpID
			}
			if tc.origin != "" {
				origin = tc.origin
			}
			_, err = passkey.New().VerifyRegistration(staffauth.RegistrationCeremony{RPID: rpID, Origin: origin, Challenge: ch, UserHandle: testUserHandle}, resp)
			want := tc.wantError
			if want == nil {
				want = passkey.ErrVerification
			}
			if !errors.Is(err, want) {
				t.Fatalf("err = %v, want %v", err, want)
			}
		})
	}
}

func TestAssertionRefusals(t *testing.T) {
	t.Parallel()
	v := passkey.New()
	a := newAuth(t, 4, passkeytest.ES256)
	stored := register(t, v, a)
	impostor := newAuth(t, 4, passkeytest.ES256) // same credential id, another key
	impostor.UserHandle = testUserHandle
	cases := []struct {
		name     string
		signer   *passkeytest.Authenticator
		ceremony func(c *passkeytest.Ceremony)
		stored   func(s *staffauth.StoredCredential)
		rpID     string
	}{
		{name: "another challenge", ceremony: func(c *passkeytest.Ceremony) { c.Challenge = b64(challenge(99)) }},
		{name: "another origin", ceremony: func(c *passkeytest.Ceremony) { c.Origin = "https://acme.superbased.app" }},
		{name: "a parent-domain rp id hash", ceremony: func(c *passkeytest.Ceremony) { c.RPID = "superbased.app" }},
		{name: "no user verification", ceremony: func(c *passkeytest.Ceremony) { c.NoUserVerification = true }},
		{name: "no user presence", ceremony: func(c *passkeytest.Ceremony) { c.NoUserPresence = true }},
		{name: "a registration's client data", ceremony: func(c *passkeytest.Ceremony) { c.Type = "webauthn.create" }},
		{name: "cross-origin", ceremony: func(c *passkeytest.Ceremony) { c.CrossOrigin = true }},
		{name: "names another credential", ceremony: func(c *passkeytest.Ceremony) { c.RawID = bytes.Repeat([]byte{5}, 32) }},
		{name: "no user handle", ceremony: func(c *passkeytest.Ceremony) { c.OmitUserHandle = true }},
		{name: "another staff member's user handle", ceremony: func(c *passkeytest.Ceremony) { c.UserHandle = bytes.Repeat([]byte{0xCD}, 16) }},
		{name: "corrupt signature", ceremony: func(c *passkeytest.Ceremony) { c.CorruptSignature = true }},
		{name: "signed by another key", signer: impostor},
		{name: "backup state without eligibility", ceremony: func(c *passkeytest.Ceremony) { c.BackupStateWithoutEligibility = true }},
		{name: "stored credential without a user handle", stored: func(s *staffauth.StoredCredential) { s.UserHandle = nil }},
		{name: "configured rp id is not the origin host", rpID: "app.superbased.app"},
	}
	for _, tc := range cases {
		signer := a
		if tc.signer != nil {
			signer = tc.signer
		}
		ch := challenge(1)
		c := passkeytest.Ceremony{Challenge: b64(ch), Origin: testOrigin, RPID: testRPID}
		if tc.ceremony != nil {
			tc.ceremony(&c)
		}
		resp, err := signer.Assert(c)
		if err != nil {
			t.Fatal(err)
		}
		s := stored
		if tc.stored != nil {
			tc.stored(&s)
		}
		rpID := testRPID
		if tc.rpID != "" {
			rpID = tc.rpID
		}
		if _, err := v.VerifyAssertion(staffauth.AssertionCeremony{RPID: rpID, Origin: testOrigin, Challenge: ch}, s, resp); err == nil {
			t.Errorf("%s: verified", tc.name)
		} else if !errors.Is(err, passkey.ErrVerification) && !errors.Is(err, passkey.ErrConfiguration) {
			t.Errorf("%s: err = %v, not a passkey error", tc.name, err)
		}
	}
}

// TestLoopbackDevOrigin: a developer's http://localhost staff console
// works, with the rp id "localhost".
func TestLoopbackDevOrigin(t *testing.T) {
	t.Parallel()
	v := passkey.New()
	a := newAuth(t, 6, passkeytest.EdDSA)
	const origin, rpID = "http://localhost:8091", "localhost"
	ch := challenge(1)
	resp, err := a.Register(passkeytest.Ceremony{Challenge: b64(ch), Origin: origin, RPID: rpID}, testUserHandle)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.VerifyRegistration(staffauth.RegistrationCeremony{RPID: rpID, Origin: origin, Challenge: ch, UserHandle: testUserHandle}, resp); err != nil {
		t.Fatalf("loopback registration: %v", err)
	}
}

func TestMalformedResponses(t *testing.T) {
	t.Parallel()
	v := passkey.New()
	ch := challenge(1)
	for _, body := range [][]byte{nil, []byte("{}"), []byte(`{"id":"x","rawId":"x","type":"public-key"}`), bytes.Repeat([]byte("a"), staffauth.MaxResponseBytes+1)} {
		if _, err := v.VerifyRegistration(staffauth.RegistrationCeremony{RPID: testRPID, Origin: testOrigin, Challenge: ch, UserHandle: testUserHandle}, body); !errors.Is(err, passkey.ErrVerification) {
			t.Errorf("registration of %d bytes: err = %v", len(body), err)
		}
	}
	if _, err := v.VerifyRegistration(staffauth.RegistrationCeremony{RPID: testRPID, Origin: testOrigin, Challenge: []byte{1}, UserHandle: testUserHandle}, []byte("{}")); !errors.Is(err, passkey.ErrConfiguration) {
		t.Errorf("short challenge: err = %v", err)
	}
}

// The W3C WebAuthn level 3 section 16 registration vectors (rp id
// example.org, origin https://example.org). hexToCredential builds the
// PublicKeyCredential JSON a browser would post from the vector's fields.
type specVector struct {
	name, credentialID, attestationObject, clientDataJSON, challenge string
}

var (
	// 16.3 Self Attestation (Packed), ES256: flags 0x5d (UP, UV, BE, BS, AT).
	specPackedSelfES256 = specVector{
		name:              "16.3 packed self ES256",
		credentialID:      "455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c",
		attestationObject: "a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2",
		clientDataJSON:    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d",
		challenge:         "7869c2b772d4b58eba9378cf8f29e26cf935aa77df0da89fa99c0bdc0a76f7e5",
	}
	// 16.2 None Attestation, ES256: flags 0x59 (UP, BE, BS, AT; NO UV).
	specNoneES256 = specVector{
		name:              "16.2 none ES256 (no user verification)",
		credentialID:      "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4",
		attestationObject: "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220",
		clientDataJSON:    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d",
		challenge:         "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130",
	}
)

func (sv specVector) build(t *testing.T) (response, challenge []byte) {
	t.Helper()
	dec := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	id := b64(dec(sv.credentialID))
	body, err := json.Marshal(map[string]any{
		"id": id, "rawId": id, "type": "public-key",
		"response": map[string]any{
			"attestationObject": b64(dec(sv.attestationObject)),
			"clientDataJSON":    b64(dec(sv.clientDataJSON)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body, dec(sv.challenge)
}

func TestW3CSpecRegistrationVectors(t *testing.T) {
	t.Parallel()
	v := passkey.New()
	const rpID, origin = "example.org", "https://example.org"

	resp, ch := specPackedSelfES256.build(t)
	nc, err := v.VerifyRegistration(staffauth.RegistrationCeremony{RPID: rpID, Origin: origin, Challenge: ch, UserHandle: testUserHandle}, resp)
	if err != nil {
		t.Fatalf("%s: %v", specPackedSelfES256.name, err)
	}
	if hex.EncodeToString(nc.ID) != specPackedSelfES256.credentialID {
		t.Errorf("%s: credential id = %x", specPackedSelfES256.name, nc.ID)
	}
	if hex.EncodeToString(nc.AAGUID) != "df850e09db6afbdfab51697791506cfc" {
		t.Errorf("%s: aaguid = %x", specPackedSelfES256.name, nc.AAGUID)
	}
	// The same vector against another rp id or origin does not verify.
	if _, err := v.VerifyRegistration(staffauth.RegistrationCeremony{RPID: "staff.example.org", Origin: "https://staff.example.org", Challenge: ch, UserHandle: testUserHandle}, resp); !errors.Is(err, passkey.ErrVerification) {
		t.Errorf("%s under another rp: err = %v", specPackedSelfES256.name, err)
	}

	// The spec's none-attestation vector has no user verification: refused.
	resp, ch = specNoneES256.build(t)
	_, err = v.VerifyRegistration(staffauth.RegistrationCeremony{RPID: rpID, Origin: origin, Challenge: ch, UserHandle: testUserHandle}, resp)
	if !errors.Is(err, passkey.ErrVerification) || !strings.Contains(err.Error(), "User verification required") {
		t.Fatalf("%s: err = %v, want a user-verification refusal", specNoneES256.name, err)
	}
}
