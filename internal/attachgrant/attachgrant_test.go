package attachgrant

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// fixture is one signer, one device and one valid claim set.
type fixture struct {
	signPub   ed25519.PublicKey
	signPriv  ed25519.PrivateKey
	devPub    ed25519.PublicKey
	devPriv   ed25519.PrivateKey
	claims    Claims
	now       time.Time
	agentPubB string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	sp, sk := testKey(t)
	dp, dk := testKey(t)
	ap, _ := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	return fixture{
		signPub: sp, signPriv: sk, devPub: dp, devPriv: dk, now: now,
		agentPubB: b64.EncodeToString(ap),
		claims: Claims{
			OrgID: "org-1", Slug: "acme", Kind: KindTeam, AccountID: "acct-1",
			Subject: "user_01ABC", Email: "dev@example.test",
			DeviceThumbprint: Thumbprint(dp), RequestID: "req-1", ShareLevel: ShareFull,
			IssuedAt: now.Unix(), ExpiresAt: now.Add(Lifetime).Unix(), JTI: JTIFor("req-1"),
		},
	}
}

func (f fixture) facts() Facts {
	return Facts{Keys: platformcontract.KeySet{platformcontract.NewDocumentKey(f.signPub)}, OrgID: "org-1", Now: f.now.Add(time.Minute)}
}

func (f fixture) mint(t *testing.T, c Claims) string {
	t.Helper()
	g, err := Mint(f.signPriv, c)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return g
}

// signRaw signs claims as-is (bypassing Mint's checks) under domain, so the
// table can build grants Mint would refuse.
func signRaw(t *testing.T, priv ed25519.PrivateKey, domain string, c Claims) string {
	t.Helper()
	payload, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	msg := append(append([]byte(domain), 0), payload...)
	return tokenPrefix + b64.EncodeToString(payload) + "." + b64.EncodeToString(ed25519.Sign(priv, msg))
}

func TestVerifyTable(t *testing.T) {
	f := newFixture(t)
	kid := platformcontract.DocumentKeyID(f.signPub)
	withKID := func(c Claims) Claims { c.V, c.KeyID = Version, kid; return c }
	_, otherPriv := testKey(t)

	cases := []struct {
		name  string
		token func() string
		facts func() Facts
		want  error
	}{
		{name: "valid", token: func() string { return f.mint(t, f.claims) }, want: nil},
		{name: "expired", token: func() string { return f.mint(t, f.claims) }, facts: func() Facts {
			x := f.facts()
			x.Now = f.now.Add(Lifetime)
			return x
		}, want: ErrExpired},
		{name: "wrong org", token: func() string { return f.mint(t, f.claims) }, facts: func() Facts {
			x := f.facts()
			x.OrgID = "org-2"
			return x
		}, want: ErrWrongOrg},
		{name: "no org on the request", token: func() string { return f.mint(t, f.claims) }, facts: func() Facts {
			x := f.facts()
			x.OrgID = ""
			return x
		}, want: ErrWrongOrg},
		{name: "wrong domain tag", token: func() string {
			return signRaw(t, f.signPriv, "sbo-entitlements-v1", withKID(f.claims))
		}, want: ErrBadSignature},
		{name: "signed by an unpinned key", token: func() string {
			c := withKID(f.claims)
			return signRaw(t, otherPriv, SigningDomain, c)
		}, want: ErrBadSignature},
		{name: "names an unpinned key", token: func() string {
			g, err := Mint(otherPriv, f.claims)
			if err != nil {
				t.Fatal(err)
			}
			return g
		}, want: ErrUnknownKey},
		{name: "tampered payload", token: func() string {
			g := f.mint(t, f.claims)
			c := withKID(f.claims)
			c.OrgID = "org-1"
			c.AccountID = "acct-evil"
			payload, _ := json.Marshal(c)
			parts := strings.Split(strings.TrimPrefix(g, tokenPrefix), ".")
			return tokenPrefix + b64.EncodeToString(payload) + "." + parts[1]
		}, want: ErrBadSignature},
		{name: "lifetime too long", token: func() string {
			c := withKID(f.claims)
			c.ExpiresAt = c.IssuedAt + int64(Lifetime/time.Second) + 1
			return signRaw(t, f.signPriv, SigningDomain, c)
		}, want: ErrLifetime},
		{name: "issued in the future", token: func() string {
			c := withKID(f.claims)
			c.IssuedAt = f.now.Add(5 * time.Minute).Unix()
			c.ExpiresAt = c.IssuedAt + 60
			return signRaw(t, f.signPriv, SigningDomain, c)
		}, want: ErrNotYetValid},
		{name: "unknown version", token: func() string {
			c := withKID(f.claims)
			c.V = 2
			return signRaw(t, f.signPriv, SigningDomain, c)
		}, want: ErrVersion},
		{name: "summary only for a team", token: func() string {
			c := withKID(f.claims)
			c.ShareLevel = ShareSummary
			return signRaw(t, f.signPriv, SigningDomain, c)
		}, want: ErrMalformed},
		{name: "jti not derived from the request", token: func() string {
			c := withKID(f.claims)
			c.JTI = "free-choice"
			return signRaw(t, f.signPriv, SigningDomain, c)
		}, want: ErrMalformed},
		{name: "no subject", token: func() string {
			c := withKID(f.claims)
			c.Subject = ""
			return signRaw(t, f.signPriv, SigningDomain, c)
		}, want: ErrMalformed},
		{name: "not a grant", token: func() string { return "eyJhbGciOiJFZERTQSJ9.e30.sig" }, want: ErrMalformed},
		{name: "unknown claim", token: func() string {
			payload := []byte(`{"v":1,"kid":"` + kid + `","extra":true}`)
			msg := append(append([]byte(SigningDomain), 0), payload...)
			return tokenPrefix + b64.EncodeToString(payload) + "." + b64.EncodeToString(ed25519.Sign(f.signPriv, msg))
		}, want: ErrMalformed},
		{name: "oversized", token: func() string { return tokenPrefix + strings.Repeat("A", MaxTokenBytes) }, want: ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := f.facts()
			if tc.facts != nil {
				facts = tc.facts()
			}
			c, err := Verify(tc.token(), facts)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if c.AccountID != "acct-1" || c.JTI != JTIFor("req-1") {
					t.Fatalf("claims = %+v", c)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestClaimRulesEachHaveACase(t *testing.T) {
	// Every claim rule row is exercised by TestVerifyTable: version, shape,
	// not-yet-valid, lifetime, expired, org.
	want := map[string]bool{"version": true, "shape": true, "not-yet-valid": true, "lifetime": true, "expired": true, "org": true}
	for _, r := range claimRules {
		if !want[r.name] {
			t.Errorf("claim rule %q has no case in TestVerifyTable", r.name)
		}
		delete(want, r.name)
	}
	for n := range want {
		t.Errorf("TestVerifyTable covers %q, which is no longer a rule", n)
	}
}

func TestMintIsDeterministic(t *testing.T) {
	f := newFixture(t)
	if a, b := f.mint(t, f.claims), f.mint(t, f.claims); a != b {
		t.Fatal("two mints of the same claims differ: a re-delivered approval must hand out the same grant")
	}
}

func TestMintRefusesWhatVerifyRefuses(t *testing.T) {
	f := newFixture(t)
	c := f.claims
	c.Kind = "org"
	if _, err := Mint(f.signPriv, c); !errors.Is(err, ErrMalformed) {
		t.Fatalf("Mint(kind org) err = %v, want ErrMalformed", err)
	}
	c = f.claims
	c.ExpiresAt = c.IssuedAt + int64(time.Hour/time.Second)
	if _, err := Mint(f.signPriv, c); !errors.Is(err, ErrLifetime) {
		t.Fatalf("Mint(1h) err = %v, want ErrLifetime", err)
	}
}

func TestProof(t *testing.T) {
	f := newFixture(t)
	grant := f.mint(t, f.claims)
	c, err := Verify(grant, f.facts())
	if err != nil {
		t.Fatal(err)
	}
	good, err := SignProof(f.devPriv, grant, f.agentPubB)
	if err != nil {
		t.Fatal(err)
	}
	_, otherDev := testKey(t)
	otherProof, err := SignProof(otherDev, grant, f.agentPubB)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		proof Proof
		agent string
		ok    bool
	}{
		{name: "the request's device key", proof: good, agent: f.agentPubB, ok: true},
		{name: "another device key", proof: otherProof, agent: f.agentPubB},
		{name: "another node key", proof: good, agent: b64.EncodeToString(make([]byte, 32))},
		{name: "a copied grant with no proof", proof: Proof{}, agent: f.agentPubB},
		{name: "the right key, a forged signature", proof: Proof{DevicePublicKey: good.DevicePublicKey, Signature: otherProof.Signature}, agent: f.agentPubB},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyProof(c, tc.proof, grant, tc.agent)
			if tc.ok && err != nil {
				t.Fatalf("VerifyProof: %v", err)
			}
			if !tc.ok && !errors.Is(err, ErrBadProof) {
				t.Fatalf("VerifyProof err = %v, want ErrBadProof", err)
			}
		})
	}
}

func TestJTIIsPerRequest(t *testing.T) {
	a1, a2 := JTIFor("a"), JTIFor(string([]byte{'a'}))
	if a1 == JTIFor("b") || a1 != a2 {
		t.Fatal("JTIFor must be a function of the request id")
	}
}
