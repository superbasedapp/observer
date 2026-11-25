package sdkkeygrant

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// update rewrites testdata/vectors.json from the code:
//
//	go test ./internal/sdkkeygrant -run TestVectors -update
var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

// vectorSeedText derives the TEST-ONLY signing seed of the vectors. It is not
// a platform key and signs nothing outside this file.
const vectorSeedText = "sdkkeygrant test vector seed v1 (test only, never a platform key)"

// vectorFile is testdata/vectors.json: fixed grants another implementation
// (the cloud's signer, the tenant host's verifier, a port) checks itself
// against byte for byte.
type vectorFile struct {
	Doc        string         `json:"_doc"`
	Domain     string         `json:"signing_domain"`
	Prefix     string         `json:"token_prefix"`
	SeedSHA256 string         `json:"seed_is_sha256_of"`
	PublicKey  string         `json:"public_key"`
	KeyID      string         `json:"kid"`
	Redeem     []redeemVector `json:"redeem"`
	Valid      []validVector  `json:"valid"`
	Refused    []refuseVector `json:"refused"`
}

type redeemVector struct {
	Secret string `json:"redeem_secret"`
	Hash   string `json:"redeem_hash"`
}

type validVector struct {
	Name   string `json:"name"`
	Claims Claims `json:"claims"`
	Token  string `json:"token"`
	Now    int64  `json:"now"`
}

type refuseVector struct {
	Name     string `json:"name"`
	Token    string `json:"token"`
	Now      int64  `json:"now"`
	NoKeys   bool   `json:"no_keys_pinned,omitempty"`
	WantCode Reason `json:"want"`
}

func vectorKey() ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(vectorSeedText))
	return ed25519.NewKeyFromSeed(seed[:])
}

// edSign signs msg with the fixture's key.
func edSign(f fixture, msg []byte) []byte { return ed25519.Sign(f.priv, msg) }

// buildVectors computes the vector file from the code.
func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	priv := vectorKey()
	pub := priv.Public().(ed25519.PublicKey)
	f := fixture{pub: pub, priv: priv, now: time.Unix(1_800_000_000, 0)}
	secrets := []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"fake-redeem-secret-for-tests-only-000000000",
	}
	out := vectorFile{
		Doc: "Test vectors for internal/sdkkeygrant (docs/plans/onboarding-v2-connect-flow.md section 13). " +
			"The signing key is TEST ONLY: its seed is SHA-256 of seed_is_sha256_of. valid: Sign(key, claims) must equal token byte for byte, " +
			"and Verify(token, keys=[public_key], now) must return the claims. refused: Verify must refuse with the reason want. " +
			"redeem: redeem_hash = base64url-nopad(SHA-256(ASCII bytes of redeem_secret)). Regenerate: go test ./internal/sdkkeygrant -run TestVectors -update.",
		Domain: SigningDomain, Prefix: TokenPrefix, SeedSHA256: vectorSeedText,
		PublicKey: b64.EncodeToString(pub), KeyID: platformcontract.DocumentKeyID(pub),
	}
	for _, s := range secrets {
		out.Redeem = append(out.Redeem, redeemVector{Secret: s, Hash: RedeemHash(s)})
	}
	base := Claims{
		OrgID: "0b6f3d2a-6a51-4c1e-9d0f-6f1c2b7e8a90", Slug: "u-k7x2", Kind: KindPersonal,
		AccountID: "9a3e1c55-2f7b-4d8e-b1a0-3c4d5e6f7a8b", Subject: "user_01JD7FAKESUBJECT",
		RequestID: "6f1c8e2d-4b3a-4c5d-8e9f-0a1b2c3d4e5f", RedeemHash: RedeemHash(secrets[1]),
		IssuedAt: f.now.Unix(), ExpiresAt: f.now.Add(Lifetime).Unix(),
	}
	base.JTI = JTIFor(base.RequestID)
	team := base
	team.OrgID, team.Slug, team.Kind = "5d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a", "acme", KindTeam
	team.Subject, team.RequestID = "user_01JD7FAKETEAMMATE", "1e2d3c4b-5a69-4788-9a0b-1c2d3e4f5a6b"
	team.JTI = JTIFor(team.RequestID)
	for _, v := range []struct {
		name string
		c    Claims
	}{{"personal dashboard", base}, {"team dashboard", team}} {
		tok, err := Sign(priv, v.c)
		if err != nil {
			t.Fatal(err)
		}
		c := v.c
		c.V, c.KeyID = Version, out.KeyID
		out.Valid = append(out.Valid, validVector{Name: v.name, Claims: c, Token: tok, Now: f.now.Unix() + 60})
	}
	good := out.Valid[0].Token
	signed := base
	signed.V, signed.KeyID = Version, out.KeyID
	v2 := signed
	v2.V = 2
	now := f.now.Unix() + 60
	out.Refused = []refuseVector{
		{Name: "expired", Token: good, Now: f.now.Add(Lifetime).Unix(), WantCode: ReasonExpired},
		{Name: "issued in the future beyond the skew", Token: good, Now: f.now.Add(-ClockSkew - time.Second).Unix(), WantCode: ReasonSkew},
		{Name: "no key pinned", Token: good, Now: now, NoKeys: true, WantCode: ReasonNoKey},
		{Name: "signed under the attach grant's domain", Token: signRaw(t, priv, TokenPrefix, "sbo-attach-grant-v1", signed), Now: now, WantCode: ReasonDomain},
		{Name: "an attach grant's prefix", Token: "sbag1." + good[len(TokenPrefix):], Now: now, WantCode: ReasonDomain},
		{Name: "signed under an unrelated domain", Token: signRaw(t, priv, TokenPrefix, "sbo-entitlements-v1", signed), Now: now, WantCode: ReasonSignature},
		{Name: "claims version 2", Token: signRaw(t, priv, TokenPrefix, SigningDomain, v2), Now: now, WantCode: ReasonVersion},
		{Name: "not a grant", Token: "sbsk1.not-a-grant", Now: now, WantCode: ReasonShape},
	}
	return out
}

func TestVectors(t *testing.T) {
	path := filepath.Join("testdata", "vectors.json")
	want := buildVectors(t)
	if *update {
		raw, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	var got vectorFile
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	// The file on disk is what the code produces now.
	a, _ := json.Marshal(got)
	b, _ := json.Marshal(want)
	if string(a) != string(b) {
		t.Fatal("testdata/vectors.json is stale: go test ./internal/sdkkeygrant -run TestVectors -update")
	}
	// And every vector holds when read back from the file.
	pub, err := b64.DecodeString(got.PublicKey)
	if err != nil || platformcontract.DocumentKeyID(pub) != got.KeyID {
		t.Fatalf("public key / kid mismatch: %v", err)
	}
	keys := platformcontract.KeySet{platformcontract.NewDocumentKey(pub)}
	for _, r := range got.Redeem {
		if RedeemHash(r.Secret) != r.Hash || !RedeemSecretValid(r.Secret) {
			t.Errorf("redeem vector %q", r.Secret)
		}
	}
	for _, v := range got.Valid {
		tok, err := Sign(vectorKey(), v.Claims)
		if err != nil || tok != v.Token {
			t.Errorf("%s: Sign = %q, %v", v.Name, tok, err)
		}
		c, err := Verify(v.Token, Facts{Keys: keys, Now: time.Unix(v.Now, 0)})
		if err != nil || c != v.Claims {
			t.Errorf("%s: Verify = %+v, %v", v.Name, c, err)
		}
	}
	for _, v := range got.Refused {
		facts := Facts{Keys: keys, Now: time.Unix(v.Now, 0)}
		if v.NoKeys {
			facts.Keys = nil
		}
		if _, err := Verify(v.Token, facts); ReasonOf(err) != v.WantCode {
			t.Errorf("%s: Verify = %v, want %q", v.Name, err, v.WantCode)
		}
	}
}
