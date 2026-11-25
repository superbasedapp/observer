package sdkkeygrant

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

// fakeRedeemSecret is a well-formed, obviously fake redeem secret.
const fakeRedeemSecret = "fake-redeem-secret-for-tests-only-000000000"

// fixture is one signer and one valid claim set.
type fixture struct {
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	claims Claims
	now    time.Time
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	pub, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	return fixture{
		pub: pub, priv: priv, now: now,
		claims: Claims{
			OrgID: "org-1", Slug: "u-k7x2", Kind: KindPersonal, AccountID: "acct-1",
			Subject: "user_01ABC", RequestID: "req-1", RedeemHash: RedeemHash(fakeRedeemSecret),
			IssuedAt: now.Unix(), ExpiresAt: now.Add(Lifetime).Unix(), JTI: JTIFor("req-1"),
		},
	}
}

func (f fixture) facts() Facts {
	return Facts{Keys: platformcontract.KeySet{platformcontract.NewDocumentKey(f.pub)}, Now: f.now.Add(time.Minute)}
}

func (f fixture) sign(t *testing.T, c Claims) string {
	t.Helper()
	g, err := Sign(f.priv, c)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return g
}

// signRaw signs any payload as-is (bypassing Sign's checks) under domain with
// prefix, so the table can build grants Sign would refuse.
func signRaw(t *testing.T, priv ed25519.PrivateKey, prefix, domain string, v any) string {
	t.Helper()
	payload, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return prefix + b64.EncodeToString(payload) + "." + b64.EncodeToString(ed25519.Sign(priv, signingMessage(domain, payload)))
}

func TestVerifyTable(t *testing.T) {
	f := newFixture(t)
	kid := platformcontract.DocumentKeyID(f.pub)
	withKID := func(c Claims) Claims { c.V, c.KeyID = Version, kid; return c }
	_, otherPriv := testKey(t)
	at := func(d time.Duration) func() Facts {
		return func() Facts { x := f.facts(); x.Now = f.now.Add(d); return x }
	}

	cases := []struct {
		name  string
		token func() string
		facts func() Facts
		want  Reason
	}{
		{name: "valid", token: func() string { return f.sign(t, f.claims) }, want: ReasonNone},
		{name: "valid with surrounding space", token: func() string { return " " + f.sign(t, f.claims) + "\n" }, want: ReasonNone},
		{name: "valid at the skew edge", token: func() string { return f.sign(t, f.claims) }, facts: at(-ClockSkew), want: ReasonNone},
		{name: "valid one second before expiry", token: func() string { return f.sign(t, f.claims) }, facts: at(Lifetime - time.Second), want: ReasonNone},
		{name: "valid under the rotation slot key", token: func() string { return f.sign(t, f.claims) }, facts: func() Facts {
			x := f.facts()
			op, _ := testKey(t)
			x.Keys = platformcontract.KeySet{platformcontract.NewDocumentKey(op), platformcontract.NewDocumentKey(f.pub)}
			return x
		}, want: ReasonNone},

		// Before the signature.
		{name: "empty", token: func() string { return "" }, want: ReasonShape},
		{name: "another prefix", token: func() string { return "sbxx1." + strings.TrimPrefix(f.sign(t, f.claims), TokenPrefix) }, want: ReasonShape},
		{name: "an attach grant's prefix", token: func() string { return "sbag1." + strings.TrimPrefix(f.sign(t, f.claims), TokenPrefix) }, want: ReasonDomain},
		{name: "too long", token: func() string { return TokenPrefix + strings.Repeat("A", MaxTokenBytes) + ".x" }, want: ReasonShape},
		{name: "no signature part", token: func() string { return TokenPrefix + "abc" }, want: ReasonShape},
		{name: "three parts", token: func() string { return f.sign(t, f.claims) + ".x" }, want: ReasonShape},
		{name: "payload not base64url", token: func() string {
			_, s, _ := strings.Cut(strings.TrimPrefix(f.sign(t, f.claims), TokenPrefix), ".")
			return TokenPrefix + "!!!." + s
		}, want: ReasonShape},
		{name: "short signature", token: func() string {
			p, _, _ := strings.Cut(strings.TrimPrefix(f.sign(t, f.claims), TokenPrefix), ".")
			return TokenPrefix + p + "." + b64.EncodeToString([]byte("short"))
		}, want: ReasonShape},
		{name: "payload not JSON", token: func() string {
			return TokenPrefix + b64.EncodeToString([]byte("nope")) + "." + b64.EncodeToString(make([]byte, ed25519.SignatureSize))
		}, want: ReasonShape},
		{name: "no key pinned", token: func() string { return f.sign(t, f.claims) }, facts: func() Facts {
			x := f.facts()
			x.Keys = nil
			return x
		}, want: ReasonNoKey},
		{name: "names an unpinned key", token: func() string {
			g, err := Sign(otherPriv, f.claims)
			if err != nil {
				t.Fatal(err)
			}
			return g
		}, want: ReasonUnknownKey},

		// The signature and the domain.
		{name: "signed by another key under the pinned kid", token: func() string {
			return signRaw(t, otherPriv, TokenPrefix, SigningDomain, withKID(f.claims))
		}, want: ReasonSignature},
		{name: "tampered payload", token: func() string {
			c := withKID(f.claims)
			good := signRaw(t, f.priv, TokenPrefix, SigningDomain, c)
			c.OrgID = "org-2"
			bad := signRaw(t, f.priv, TokenPrefix, SigningDomain, c)
			p, _, _ := strings.Cut(strings.TrimPrefix(bad, TokenPrefix), ".")
			_, s, _ := strings.Cut(strings.TrimPrefix(good, TokenPrefix), ".")
			return TokenPrefix + p + "." + s
		}, want: ReasonSignature},
		{name: "signed by the pinned key under the attach grant's domain", token: func() string {
			return signRaw(t, f.priv, TokenPrefix, "sbo-attach-grant-v1", withKID(f.claims))
		}, want: ReasonDomain},
		{name: "signed by the pinned key under an unrelated domain", token: func() string {
			return signRaw(t, f.priv, TokenPrefix, "sbo-entitlements-v1", withKID(f.claims))
		}, want: ReasonSignature},

		// The claim table (one row each; TestClaimRulesEachHaveACase).
		{name: "version", token: func() string {
			c := withKID(f.claims)
			c.V = 2
			return signRaw(t, f.priv, TokenPrefix, SigningDomain, c)
		}, want: ReasonVersion},
		{name: "shape", token: func() string {
			c := withKID(f.claims)
			c.Kind = "admin"
			return signRaw(t, f.priv, TokenPrefix, SigningDomain, c)
		}, want: ReasonShape},
		{name: "skew", token: func() string { return f.sign(t, f.claims) }, facts: at(-ClockSkew - time.Second), want: ReasonSkew},
		{name: "lifetime", token: func() string {
			c := withKID(f.claims)
			c.ExpiresAt = c.IssuedAt + int64(Lifetime/time.Second) + 1
			return signRaw(t, f.priv, TokenPrefix, SigningDomain, c)
		}, want: ReasonLifetime},
		{name: "expired", token: func() string { return f.sign(t, f.claims) }, facts: at(Lifetime), want: ReasonExpired},

		// Strict decode after the signature.
		{name: "an unknown claim", token: func() string {
			var m map[string]any
			raw, _ := json.Marshal(withKID(f.claims))
			_ = json.Unmarshal(raw, &m)
			m["scopes"] = []string{"admin"}
			return signRaw(t, f.priv, TokenPrefix, SigningDomain, m)
		}, want: ReasonShape},
		{name: "two objects", token: func() string {
			raw, _ := json.Marshal(withKID(f.claims))
			payload := append(append([]byte{}, raw...), raw...)
			return TokenPrefix + b64.EncodeToString(payload) + "." + b64.EncodeToString(ed25519.Sign(f.priv, signingMessage(SigningDomain, payload)))
		}, want: ReasonShape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := f.facts()
			if tc.facts != nil {
				facts = tc.facts()
			}
			c, err := Verify(tc.token(), facts)
			if got := ReasonOf(err); got != tc.want {
				t.Fatalf("Verify reason = %q (%v), want %q", got, err, tc.want)
			}
			if tc.want == ReasonNone {
				if c.OrgID != f.claims.OrgID || c.Subject != f.claims.Subject || c.RedeemHash != f.claims.RedeemHash || c.KeyID != kid || c.V != Version {
					t.Fatalf("claims = %+v", c)
				}
			} else if c != (Claims{}) {
				t.Fatalf("refused grant returned claims %+v", c)
			}
		})
	}
}

// TestClaimRulesEachHaveACase keeps the claim table and TestVerifyTable in
// step: every rule name is a case name there.
func TestClaimRulesEachHaveACase(t *testing.T) {
	names := map[string]bool{"version": true, "shape": true, "skew": true, "lifetime": true, "expired": true}
	if len(claimRules) != len(names) {
		t.Fatalf("claimRules has %d rows, the test knows %d", len(claimRules), len(names))
	}
	for _, r := range claimRules {
		if !names[r.name] {
			t.Errorf("claim rule %q has no TestVerifyTable case", r.name)
		}
	}
}

func TestShapeRulesEachRefuse(t *testing.T) {
	f := newFixture(t)
	breakers := map[string]func(c *Claims){
		"kid":         func(c *Claims) { c.KeyID = "" },
		"org_id":      func(c *Claims) { c.OrgID = "org 1" },
		"slug":        func(c *Claims) { c.Slug = "" },
		"kind":        func(c *Claims) { c.Kind = "Team" },
		"account_id":  func(c *Claims) { c.AccountID = strings.Repeat("a", 129) },
		"sub":         func(c *Claims) { c.Subject = "" },
		"request_id":  func(c *Claims) { c.RequestID = "" },
		"redeem_hash": func(c *Claims) { c.RedeemHash = fakeRedeemSecret[:42] + "=" },
		"jti":         func(c *Claims) { c.JTI = JTIFor("req-2") },
		"iat":         func(c *Claims) { c.IssuedAt = 0 },
	}
	if len(breakers) != len(shapeRules) {
		t.Fatalf("shapeRules has %d rows, the test breaks %d", len(shapeRules), len(breakers))
	}
	for _, r := range shapeRules {
		brk, ok := breakers[r.field]
		if !ok {
			t.Errorf("shape rule %q has no breaker", r.field)
			continue
		}
		c := f.claims
		c.V, c.KeyID = Version, platformcontract.DocumentKeyID(f.pub)
		if err := checkShape(c); err != nil {
			t.Fatalf("valid claims refused: %v", err)
		}
		brk(&c)
		if err := checkShape(c); !errors.Is(err, ErrShape) || !strings.Contains(err.Error(), r.field) {
			t.Errorf("%s: checkShape = %v", r.field, err)
		}
	}
}

func TestSignIsDeterministic(t *testing.T) {
	f := newFixture(t)
	if a, b := f.sign(t, f.claims), f.sign(t, f.claims); a != b {
		t.Fatal("two signatures of one approval differ")
	}
}

func TestSignRefusesWhatVerifyRefuses(t *testing.T) {
	f := newFixture(t)
	for name, mod := range map[string]func(c *Claims){
		"kind":            func(c *Claims) { c.Kind = "org" },
		"redeem hash":     func(c *Claims) { c.RedeemHash = "" },
		"jti":             func(c *Claims) { c.JTI = "x" },
		"too long":        func(c *Claims) { c.ExpiresAt = c.IssuedAt + int64(2*Lifetime/time.Second) },
		"expires at once": func(c *Claims) { c.ExpiresAt = c.IssuedAt },
	} {
		c := f.claims
		mod(&c)
		if _, err := Sign(f.priv, c); err == nil {
			t.Errorf("%s: Sign accepted claims Verify refuses", name)
		}
	}
	if _, err := Sign(ed25519.PrivateKey("short"), f.claims); ReasonOf(err) != ReasonShape {
		t.Errorf("a short private key: %v", err)
	}
}

func TestJTIIsPerRequest(t *testing.T) {
	a, again := JTIFor("a"), JTIFor("a")
	if a == JTIFor("b") || a != again {
		t.Fatal("JTIFor is not one per request")
	}
	if len(JTIFor("a")) != 22 {
		t.Fatalf("jti length %d", len(JTIFor("a")))
	}
}

func TestRedeemHelpers(t *testing.T) {
	// The redeem hash is over the secret's text exactly as sent (checked
	// against Python's hashlib: base64url(sha256(b"A"*43)) without padding).
	if got, want := RedeemHash(strings.Repeat("A", 43)), "DwBzhbb51LfusnSGBa_hqYSgo7-j8BTQnip4TOnlzRo"; got != want || len(got) != RedeemSecretLen {
		t.Fatalf("RedeemHash = %q, want %q", got, want)
	}
	if RedeemHash(fakeRedeemSecret) == RedeemHash(fakeRedeemSecret[:42]+"1") {
		t.Fatal("two secrets hash alike")
	}
	for s, want := range map[string]bool{
		fakeRedeemSecret:              true,
		fakeRedeemSecret[:42]:         false,
		fakeRedeemSecret + "0":        false,
		fakeRedeemSecret[:42] + "=":   false,
		fakeRedeemSecret[:42] + "+":   false,
		strings.Repeat("_", 43):       true,
		"":                            false,
		strings.Repeat("A", 41) + "é": false,
	} {
		if got := RedeemSecretValid(s); got != want {
			t.Errorf("RedeemSecretValid(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestReasonOf(t *testing.T) {
	if ReasonOf(nil) != ReasonNone {
		t.Fatal("nil is not ReasonNone")
	}
	if ReasonOf(errors.New("other")) != ReasonShape {
		t.Fatal("a foreign error is not ReasonShape")
	}
	seen := map[Reason]bool{}
	for _, r := range reasons {
		if got := ReasonOf(r.err); got != r.reason {
			t.Errorf("ReasonOf(%v) = %q, want %q", r.err, got, r.reason)
		}
		if seen[r.reason] || r.reason == ReasonNone {
			t.Errorf("reason %q repeated or empty", r.reason)
		}
		seen[r.reason] = true
	}
}
