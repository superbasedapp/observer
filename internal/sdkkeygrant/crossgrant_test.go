package sdkkeygrant

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/attachgrant"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// TestForeignTablesNameTheAttachGrant pins this package's copies of the
// attach grant's tag and prefix to the attach grant's own: if attachgrant
// changes either, the domain refusal must follow.
func TestForeignTablesNameTheAttachGrant(t *testing.T) {
	if foreignDomains[0] != attachgrant.SigningDomain {
		t.Fatalf("foreignDomains[0] = %q, attachgrant.SigningDomain = %q", foreignDomains[0], attachgrant.SigningDomain)
	}
	g := attachGrant(t, newFixture(t))
	if !strings.HasPrefix(g, prefixRules[1].prefix) {
		t.Fatalf("an attach grant %q does not start with %q", g[:8], prefixRules[1].prefix)
	}
	if SigningDomain == attachgrant.SigningDomain || TokenPrefix == prefixRules[1].prefix {
		t.Fatal("the key grant shares the attach grant's tag or prefix")
	}
	if JTIFor("req-1") == attachgrant.JTIFor("req-1") {
		t.Fatal("the key grant's jti equals the attach grant's for one request")
	}
}

// attachGrant mints a valid attach grant with the fixture's key (the same
// platform key signing both kinds: ruling R13's cheaper option, the worst
// case for confusion).
func attachGrant(t *testing.T, f fixture) string {
	t.Helper()
	dp, _ := testKey(t)
	g, err := attachgrant.Mint(f.priv, attachgrant.Claims{
		OrgID: f.claims.OrgID, Slug: f.claims.Slug, Kind: attachgrant.KindPersonal, AccountID: f.claims.AccountID,
		Subject: f.claims.Subject, DeviceThumbprint: attachgrant.Thumbprint(dp), RequestID: f.claims.RequestID,
		ShareLevel: attachgrant.ShareSummary, IssuedAt: f.claims.IssuedAt, ExpiresAt: f.claims.ExpiresAt,
		JTI: attachgrant.JTIFor(f.claims.RequestID),
	})
	if err != nil {
		t.Fatalf("attachgrant.Mint: %v", err)
	}
	return g
}

// TestAttachAndKeyGrantsNeverVerifyAsEachOther is SDKQS-2's pin: with one key
// pinned on both sides, an attach grant (as minted, or re-prefixed) never
// verifies as a key grant, and a key grant (as signed, or re-prefixed) never
// verifies as an attach grant. A grant signed over the other kind's claims
// under the wrong tag is refused too.
func TestAttachAndKeyGrantsNeverVerifyAsEachOther(t *testing.T) {
	f := newFixture(t)
	keys := platformcontract.KeySet{platformcontract.NewDocumentKey(f.pub)}
	now := f.now.Add(time.Minute)
	keyFacts := Facts{Keys: keys, Now: now}
	attachFacts := attachgrant.Facts{Keys: keys, OrgID: f.claims.OrgID, Now: now}

	ag := attachGrant(t, f)
	kg := f.sign(t, f.claims)
	if _, err := attachgrant.Verify(ag, attachFacts); err != nil {
		t.Fatalf("the attach grant itself does not verify: %v", err)
	}
	if _, err := Verify(kg, keyFacts); err != nil {
		t.Fatalf("the key grant itself does not verify: %v", err)
	}

	swap := func(token, from, to string) string { return to + strings.TrimPrefix(token, from) }
	kid := platformcontract.DocumentKeyID(f.pub)
	keyClaims := f.claims
	keyClaims.V, keyClaims.KeyID = Version, kid

	asKey := []struct {
		name  string
		token string
		want  Reason
	}{
		{"an attach grant as minted", ag, ReasonDomain},
		{"an attach grant re-prefixed sbsk1", swap(ag, "sbag1.", TokenPrefix), ReasonDomain},
		{"key-grant claims signed under the attach tag", signRaw(t, f.priv, TokenPrefix, attachgrant.SigningDomain, keyClaims), ReasonDomain},
	}
	for _, c := range asKey {
		if _, err := Verify(c.token, keyFacts); ReasonOf(err) != c.want {
			t.Errorf("Verify(%s) = %v, want %q", c.name, err, c.want)
		}
	}

	asAttach := []struct {
		name  string
		token string
	}{
		{"a key grant as signed", kg},
		{"a key grant re-prefixed sbag1", swap(kg, TokenPrefix, "sbag1.")},
		{"attach-shaped claims signed under the key grant tag", func() string {
			// The attach grant's own payload, re-signed under this package's tag.
			p, _, _ := strings.Cut(strings.TrimPrefix(ag, "sbag1."), ".")
			payload, err := b64.DecodeString(p)
			if err != nil {
				t.Fatal(err)
			}
			return "sbag1." + p + "." + b64.EncodeToString(edSign(f, signingMessage(SigningDomain, payload)))
		}()},
	}
	for _, c := range asAttach {
		_, err := attachgrant.Verify(c.token, attachFacts)
		if err == nil {
			t.Errorf("attachgrant.Verify(%s) accepted a key grant", c.name)
			continue
		}
		if !errors.Is(err, attachgrant.ErrMalformed) && !errors.Is(err, attachgrant.ErrBadSignature) {
			t.Errorf("attachgrant.Verify(%s) = %v, want malformed or bad signature", c.name, err)
		}
	}
}
