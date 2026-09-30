package agentid

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 Appendix B

func TestS256ChallengeMatchesRFC7636AppendixB(t *testing.T) {
	if got, want := S256Challenge(testVerifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; got != want {
		t.Fatalf("S256Challenge = %q, want %q", got, want)
	}
}

func TestCheckCodeChallenge(t *testing.T) {
	good := S256Challenge(testVerifier)
	for _, tc := range []struct {
		name, method, challenge string
		want                    error
	}{
		{"s256 ok", "S256", good, nil},
		{"plain is a downgrade", "plain", testVerifier, ErrPKCEDowngrade},
		{"absent method defaults to plain", "", good, ErrPKCEDowngrade},
		{"method is case-sensitive", "s256", good, ErrPKCEDowngrade},
		{"short challenge", "S256", good[:42], ErrPKCEChallenge},
		{"non-base64url challenge", "S256", strings.Repeat("+", 43), ErrPKCEChallenge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckCodeChallenge(tc.method, tc.challenge); !errors.Is(err, tc.want) && !(err == nil && tc.want == nil) {
				t.Fatalf("CheckCodeChallenge = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifyPKCE(t *testing.T) {
	ch := S256Challenge(testVerifier)
	for _, tc := range []struct {
		name, verifier string
		want           error
	}{
		{"match", testVerifier, nil},
		{"wrong verifier", strings.Repeat("a", 43), ErrPKCEMismatch},
		{"too short", strings.Repeat("a", 42), ErrPKCEVerifier},
		{"too long", strings.Repeat("a", 129), ErrPKCEVerifier},
		{"reserved char", strings.Repeat("a", 42) + "/", ErrPKCEVerifier},
		{"the challenge itself is not a verifier for it", ch, ErrPKCEMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyPKCE(tc.verifier, ch)
			if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("VerifyPKCE = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDecideCodeRedemptionTable(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	base := AuthzCode{
		ClientID: "dcr_a", RedirectURI: "https://app.example/cb", CodeChallenge: S256Challenge(testVerifier),
		CodeChallengeMethod: PKCEMethodS256, Resource: "https://gw.example/mcp/gh", ExpiresAt: now.Add(time.Minute),
	}
	req := CodeRedemption{ClientID: "dcr_a", RedirectURI: "https://app.example/cb", CodeVerifier: testVerifier, Resource: "https://gw.example/mcp/gh"}
	for _, tc := range []struct {
		name   string
		code   func(*AuthzCode)
		req    func(*CodeRedemption)
		reason string
		oauth  OAuthError
		revoke bool
	}{
		{"allowed", nil, nil, CodeReasonAllowed, "", false},
		{"allowed without a token-side resource", nil, func(r *CodeRedemption) { r.Resource = "" }, CodeReasonAllowed, "", false},
		{"replay revokes the family", func(c *AuthzCode) { c.Consumed = true }, nil, CodeReasonReplayed, OAuthInvalidGrant, true},
		{"expired", func(c *AuthzCode) { c.ExpiresAt = now }, nil, CodeReasonExpired, OAuthInvalidGrant, false},
		{"another client (code injection)", nil, func(r *CodeRedemption) { r.ClientID = "dcr_b" }, CodeReasonClientMismatch, OAuthInvalidGrant, false},
		{"no client", nil, func(r *CodeRedemption) { r.ClientID = "" }, CodeReasonClientMismatch, OAuthInvalidGrant, false},
		{"redirect differs", nil, func(r *CodeRedemption) { r.RedirectURI = "https://app.example/cb2" }, CodeReasonRedirectMismatch, OAuthInvalidGrant, false},
		{"redirect omitted", nil, func(r *CodeRedemption) { r.RedirectURI = "" }, CodeReasonRedirectMismatch, OAuthInvalidGrant, false},
		{"stored plain method is refused", func(c *AuthzCode) { c.CodeChallengeMethod = "plain" }, nil, CodeReasonPKCEDowngrade, OAuthInvalidGrant, false},
		{"wrong verifier", nil, func(r *CodeRedemption) { r.CodeVerifier = strings.Repeat("b", 43) }, CodeReasonPKCEMismatch, OAuthInvalidGrant, false},
		{"no verifier", nil, func(r *CodeRedemption) { r.CodeVerifier = "" }, CodeReasonPKCEMismatch, OAuthInvalidGrant, false},
		{"resource differs", nil, func(r *CodeRedemption) { r.Resource = "https://gw.example/mcp/other" }, CodeReasonResourceMismatch, OAuthInvalidTarget, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r := base, req
			if tc.code != nil {
				tc.code(&c)
			}
			if tc.req != nil {
				tc.req(&r)
			}
			d := DecideCodeRedemption(nil, c, r, now)
			if d.Reason != tc.reason || d.Error != tc.oauth || d.RevokeFamily != tc.revoke || d.Allow != (tc.reason == CodeReasonAllowed) {
				t.Fatalf("decision = %+v", d)
			}
		})
	}
}

func TestOpaqueSecretsAndHashes(t *testing.T) {
	a, err := NewOpaqueSecret(bytes.NewReader(bytes.Repeat([]byte{1}, 32)), "sbo_rt_")
	if err != nil || !strings.HasPrefix(a, "sbo_rt_") || len(a) != len("sbo_rt_")+43 {
		t.Fatalf("NewOpaqueSecret = %q %v", a, err)
	}
	if _, err := NewOpaqueSecret(bytes.NewReader(nil), ""); err == nil {
		t.Fatal("short entropy must fail")
	}
	if HashOpaque(HashDomainCode, "x") == HashOpaque(HashDomainRefresh, "x") {
		t.Fatal("hash domains must separate uses")
	}
	if HashOpaque(HashDomainCode, "") != "" {
		t.Fatal("an empty value hashes to empty")
	}
	if h := HashOpaque(HashDomainState, "my-state"); strings.Contains(h, "my-state") || len(h) != 64 {
		t.Fatalf("hash leaks or is not 256-bit hex: %q", h)
	}
	f1, f2 := RefreshFamilyID("h1"), RefreshFamilyID("h1")
	if f1 != f2 || !strings.HasPrefix(f1, "rf_") || RefreshFamilyID("h2") == f1 {
		t.Fatalf("family ids: %q %q", f1, f2)
	}
}

func TestValidateRedirectURI(t *testing.T) {
	for _, tc := range []struct {
		uri string
		ok  bool
	}{
		{"https://app.example/cb", true},
		{"https://app.example/cb?x=1", true},
		{"http://127.0.0.1:33418/callback", true},
		{"http://[::1]/cb", true},
		{"http://localhost:8080/cb", true},
		{"cursor://anysphere.cursor-retrieval/oauth/callback", true},
		{"com.example.app:/oauth2redirect", true},
		{"http://app.example/cb", false},
		{"https://app.example/cb#frag", false},
		{"https://user:pw@app.example/cb", false},
		{"javascript:alert(1)", false},
		{"data:text/html,x", false},
		{"file:///etc/passwd", false},
		{"/relative/cb", false},
		{"", false},
		{"https:///nohost", false},
		{"https://app.example/c b", false},
		{`https://app.example\@evil.example/`, false},
	} {
		t.Run(tc.uri, func(t *testing.T) {
			err := ValidateRedirectURI(tc.uri)
			if (err == nil) != tc.ok {
				t.Fatalf("ValidateRedirectURI(%q) = %v, want ok=%v", tc.uri, err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrRedirectURI) {
				t.Fatalf("error %v is not ErrRedirectURI", err)
			}
		})
	}
}

func TestRedirectURIMatches(t *testing.T) {
	reg := []string{"https://app.example/cb", "http://127.0.0.1/callback", "cursor://x/cb"}
	for _, tc := range []struct {
		presented string
		ok        bool
	}{
		{"https://app.example/cb", true},
		{"https://app.example/cb/", false},
		{"https://APP.example/cb", false},
		{"https://app.example/cb?extra=1", false},
		{"http://127.0.0.1:49152/callback", true}, // RFC 8252 §7.3: any port
		{"http://127.0.0.1:49152/other", false},
		{"http://localhost:49152/callback", false}, // a different loopback host is not the registered one
		{"cursor://x/cb", true},
		{"cursor://x/cb2", false},
		{"", false},
	} {
		t.Run(tc.presented, func(t *testing.T) {
			if got := RedirectURIMatches(reg, tc.presented); got != tc.ok {
				t.Fatalf("RedirectURIMatches(%q) = %v", tc.presented, got)
			}
		})
	}
}
