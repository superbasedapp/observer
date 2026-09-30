package agentid

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

// TestSboCredClaim (CK-F1 / Option B): the optional sbo_cred claim carries
// the credential subject the minter read sbo_cred_gen under. It round-trips
// through Mint -> VerifyFull, is OMITTED (not "") when the minter has no
// credential subject, never fails verification when absent, and is accepted
// by the verifier (which has no unknown-claim refusal). The size delta is
// logged for the §4.7 budget record.
func TestSboCredClaim(t *testing.T) {
	const credID = "key_0123456789abcdef0123456789abcdef" // a regstore-shaped API key id (36 B)
	s := newSigner(t, jose.AlgEdDSA, "k")
	ring := ringOf(t, activeEntry(s, "k"))
	jwks, _ := ring.JWKS()
	mint := func(cred string) (string, Claims) {
		t.Helper()
		o := mintOpts()
		o.CredentialID = cred
		o.Rand = strings.NewReader(strings.Repeat("r", 16)) // equal jti: equal-size tokens but for the claim
		tok, c, err := Mint(ring, principal(), testAud, 0, nil, o)
		if err != nil {
			t.Fatal(err)
		}
		return tok, c
	}
	rows := []struct {
		name    string
		cred    string
		present bool
	}{
		{"credential subject stamped", credID, true},
		{"no credential subject -> claim omitted", "", false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			tok, c := mint(r.cred)
			if c.SboCred != r.cred {
				t.Fatalf("minted sbo_cred %q, want %q", c.SboCred, r.cred)
			}
			j, err := jose.Parse(tok, 0)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(j.Payload, &m); err != nil {
				t.Fatal(err)
			}
			v, ok := m["sbo_cred"]
			if ok != r.present || (ok && v != r.cred) {
				t.Fatalf("payload sbo_cred = %v (present %v), want present=%v %q", v, ok, r.present, r.cred)
			}
			got, err := VerifyFull(VerifyOptions{}, jwks, tok, testAud, testIss, t0.Add(time.Minute))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got.SboCred != r.cred || got.SboCredGen != 2 {
				t.Fatalf("verified sbo_cred %q gen %d", got.SboCred, got.SboCredGen)
			}
		})
	}

	// JSON round-trip of the claim set itself.
	_, c := mint(credID)
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back Claims
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.SboCred != credID {
		t.Fatalf("round-trip sbo_cred %q", back.SboCred)
	}

	// A token from a verifier-side view WITHOUT the claim (e.g. minted before
	// it existed) decodes with SboCred "" - absence is never a refusal.
	var old Claims
	if err := json.Unmarshal([]byte(strings.Replace(string(raw), `"sbo_cred":"`+credID+`",`, "", 1)), &old); err != nil || old.SboCred != "" {
		t.Fatalf("claim-less payload: %v sbo_cred=%q", err, old.SboCred)
	}
	if err := VerifyProfile(old, t0.Add(time.Minute)); err != nil {
		t.Fatalf("claim-less claims fail the profile: %v", err)
	}

	// §4.7 budget record: the byte cost of the claim.
	with, _ := mint(credID)
	without, _ := mint("")
	delta := len(with) - len(without)
	payloadDelta := len(`,"sbo_cred":"`) + len(credID) + len(`"`)
	t.Logf("sbo_cred size: token %d -> %d bytes (+%d); payload +%d JSON bytes for a %d-byte id", len(without), len(with), delta, payloadDelta, len(credID))
	if delta <= 0 || delta > (payloadDelta*4+2)/3+1 {
		t.Fatalf("token delta %d not the base64url of a %d-byte claim", delta, payloadDelta)
	}
}
