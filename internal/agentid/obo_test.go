package agentid

import (
	"crypto"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

const (
	idpIss   = "https://login.example-idp.test/tenant-1/v2.0"
	idpAud   = "app-client-123"
	oboNowTS = int64(1790000000)
)

var oboNow = time.Unix(oboNowTS, 0)

// idp is a test IdP signing id_tokens.
type idp struct {
	alg string
	kid string
	key crypto.Signer
	jwk JWK
}

func newIDP(t testing.TB, alg, kid string) idp {
	t.Helper()
	k, err := jose.GenerateKey(rand.Reader, alg)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jose.PublicJWK(k.Public(), alg, kid)
	if err != nil {
		t.Fatal(err)
	}
	return idp{alg: alg, kid: kid, key: k, jwk: pub}
}

func (p idp) sign(t testing.TB, typ string, claims map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jose.Sign(p.key, jose.Header{Typ: typ, Alg: p.alg, Kid: p.kid}, raw)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func baseClaims() map[string]any {
	return map[string]any{"iss": idpIss, "sub": "user-42", "aud": idpAud, "iat": oboNowTS - 10, "exp": oboNowTS + 600, "nonce": "n-1"}
}

func basePolicy() TrustPolicy {
	return TrustPolicy{
		IssuerID: "tis_1", IssuerURL: idpIss, ClientID: "agent:ha", AllowedAud: []string{idpAud},
		MaxTokenAge: 300 * time.Second, SubjectStability: StabilitySub, Active: true,
	}
}

func TestVerifyIDTokenAlgorithms(t *testing.T) {
	for _, alg := range []string{jose.AlgEdDSA, jose.AlgES256, jose.AlgRS256} {
		t.Run(alg, func(t *testing.T) {
			p := newIDP(t, alg, "k1")
			tok := p.sign(t, "JWT", baseClaims())
			c, err := VerifyIDToken(tok, IDTokenExpect{Policy: basePolicy(), Keys: []JWK{p.jwk}, Now: oboNow})
			if err != nil {
				t.Fatal(err)
			}
			if c.Sub != "user-42" || c.Iss != idpIss || len(c.Aud) != 1 || c.Nonce != "n-1" {
				t.Fatalf("claims = %+v", c)
			}
		})
	}
}

func TestVerifyIDTokenRefusals(t *testing.T) {
	p := newIDP(t, jose.AlgES256, "k1")
	other := newIDP(t, jose.AlgES256, "k1")
	cases := []struct {
		name string
		tok  func() string
		keys []JWK
		pol  func(*TrustPolicy)
		want OBOErrorCode
	}{
		{"wrong signing key", func() string { return other.sign(t, "JWT", baseClaims()) }, []JWK{p.jwk}, nil, OBOErrSignature},
		{"kid not registered", func() string { return newIDP(t, jose.AlgES256, "k9").sign(t, "", baseClaims()) }, []JWK{p.jwk}, nil, OBOErrNoKey},
		{"at+jwt typ", func() string { return p.sign(t, TypAccessToken, baseClaims()) }, []JWK{p.jwk}, nil, OBOErrType},
		{"sbo-actor+jwt typ", func() string { return p.sign(t, TypActorAssertion, baseClaims()) }, []JWK{p.jwk}, nil, OBOErrType},
		{"alg outside the allowlist", func() string { return p.sign(t, "JWT", baseClaims()) }, []JWK{p.jwk}, nil, ""},
		{"disabled registration", func() string { return p.sign(t, "JWT", baseClaims()) }, []JWK{p.jwk}, func(tp *TrustPolicy) { tp.Active = false }, OBOErrInactive},
		{"malformed", func() string { return "not.a.jws" }, []JWK{p.jwk}, nil, OBOErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pol := basePolicy()
			if tc.pol != nil {
				tc.pol(&pol)
			}
			e := IDTokenExpect{Policy: pol, Keys: tc.keys, Now: oboNow}
			want := tc.want
			if tc.name == "alg outside the allowlist" {
				e.Algs, _ = jose.NewAlgSet(jose.AlgRS256)
				want = OBOErrSignature
			}
			if _, err := VerifyIDToken(tc.tok(), e); OBOCodeOf(err) != want {
				t.Fatalf("err = %v, want code %s", err, want)
			}
		})
	}
	t.Run("embedded jwk refused", func(t *testing.T) {
		raw, _ := json.Marshal(baseClaims())
		jwk := p.jwk
		tok, err := jose.Sign(p.key, jose.Header{Typ: "JWT", Alg: p.alg, Kid: p.kid, JWK: &jwk}, raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyIDToken(tok, IDTokenExpect{Policy: basePolicy(), Keys: []JWK{p.jwk}, Now: oboNow}); OBOCodeOf(err) != OBOErrMalformed {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestIDTokenClaimRows is one case per idTokenClaimRows row (doc3 §11.10
// step 3), plus the passing baseline.
func TestIDTokenClaimRows(t *testing.T) {
	good := IDTokenClaims{Iss: idpIss, Sub: "user-42", Aud: []string{idpAud}, Exp: oboNowTS + 600, Iat: oboNowTS - 10}
	cases := []struct {
		name string
		c    func(*IDTokenClaims)
		p    func(*TrustPolicy)
		want OBOErrorCode
	}{
		{"baseline passes", nil, nil, ""},
		{"policy without audiences", nil, func(p *TrustPolicy) { p.AllowedAud = nil }, OBOErrPolicyInvalid},
		{"multi-client policy without azp pin", nil, func(p *TrustPolicy) { p.MultiClient = true }, OBOErrPolicyInvalid},
		{"wrong issuer", func(c *IDTokenClaims) { c.Iss = "https://evil.test" }, nil, OBOErrIssuer},
		{"issuer differs by a trailing slash", func(c *IDTokenClaims) { c.Iss = idpIss + "/" }, nil, OBOErrIssuer},
		{"wrong tenant", func(c *IDTokenClaims) { c.Tid = "other" }, func(p *TrustPolicy) { p.Tenant = "tenant-1" }, OBOErrTenant},
		{"right tenant", func(c *IDTokenClaims) { c.Tid = "tenant-1" }, func(p *TrustPolicy) { p.Tenant = "tenant-1" }, ""},
		{"empty sub", func(c *IDTokenClaims) { c.Sub = "" }, nil, OBOErrClaims},
		{"control char in sub", func(c *IDTokenClaims) { c.Sub = "a\nb" }, nil, OBOErrClaims},
		{"single-client with two audiences", func(c *IDTokenClaims) { c.Aud = []string{idpAud, "other"} }, nil, OBOErrAudience},
		{"audience not allowed", func(c *IDTokenClaims) { c.Aud = []string{"other"} }, nil, OBOErrAudience},
		{
			"multi-client needs azp", func(c *IDTokenClaims) { c.Aud = []string{idpAud, "other"} },
			func(p *TrustPolicy) { p.MultiClient, p.AllowedAzp = true, []string{"acting-app"} }, OBOErrAzp,
		},
		{
			"multi-client wrong azp", func(c *IDTokenClaims) { c.Aud, c.Azp = []string{idpAud, "other"}, "intruder" },
			func(p *TrustPolicy) { p.MultiClient, p.AllowedAzp = true, []string{"acting-app"} }, OBOErrAzp,
		},
		{
			"multi-client pinned azp passes", func(c *IDTokenClaims) { c.Aud, c.Azp = []string{idpAud, "other"}, "acting-app" },
			func(p *TrustPolicy) { p.MultiClient, p.AllowedAzp = true, []string{"acting-app"} }, "",
		},
		{
			"multi-client with no allowed audience", func(c *IDTokenClaims) { c.Aud, c.Azp = []string{"x", "y"}, "acting-app" },
			func(p *TrustPolicy) { p.MultiClient, p.AllowedAzp = true, []string{"acting-app"} }, OBOErrAudience,
		},
		{"single-client foreign azp", func(c *IDTokenClaims) { c.Azp = "someone-else" }, nil, OBOErrAzp},
		{"single-client azp = aud passes", func(c *IDTokenClaims) { c.Azp = idpAud }, nil, ""},
		{"no exp", func(c *IDTokenClaims) { c.Exp = 0 }, nil, OBOErrClaims},
		{"no iat", func(c *IDTokenClaims) { c.Iat = 0 }, nil, OBOErrClaims},
		{"expired beyond skew", func(c *IDTokenClaims) { c.Exp = oboNowTS - 61 }, nil, OBOErrExpired},
		{"expired within skew passes", func(c *IDTokenClaims) { c.Exp = oboNowTS - 30; c.Iat = oboNowTS - 100 }, nil, ""},
		{"iat in the future", func(c *IDTokenClaims) { c.Iat = oboNowTS + 120 }, nil, OBOErrNotYetValid},
		{"nbf in the future", func(c *IDTokenClaims) { c.Nbf = oboNowTS + 120 }, nil, OBOErrNotYetValid},
		{"exp before iat", func(c *IDTokenClaims) { c.Iat, c.Exp = oboNowTS, oboNowTS }, nil, OBOErrClaims},
		{"older than max age", func(c *IDTokenClaims) { c.Iat = oboNowTS - 400 }, nil, OBOErrTooOld},
		{"oid stability without oid", nil, func(p *TrustPolicy) { p.SubjectStability = StabilityOID }, OBOErrSubject},
		{"unknown stability", nil, func(p *TrustPolicy) { p.SubjectStability = "email" }, OBOErrPolicyInvalid},
		{"oversized jti", func(c *IDTokenClaims) { c.Jti = strings.Repeat("j", 257) }, nil, OBOErrClaims},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p := good, basePolicy()
			c.Aud = append([]string(nil), good.Aud...)
			if tc.c != nil {
				tc.c(&c)
			}
			if tc.p != nil {
				tc.p(&p)
			}
			if got := OBOCodeOf(CheckIDTokenClaims(c, p, oboNow, IDTokenSkew)); got != tc.want {
				t.Fatalf("code = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifySubjectToken(t *testing.T) {
	p := newIDP(t, jose.AlgEdDSA, "k1")
	own := OwnIdentity{Issuer: "https://sts.acme.test", TokenEndpoint: "https://sts.acme.test/oauth2/token"}
	cases := []struct {
		name string
		tok  string
		want SubjectTokenClass
	}{
		{"id_token (typ JWT)", p.sign(t, "JWT", baseClaims()), SubjectIsIDTokenCandidate},
		{"id_token (no typ)", p.sign(t, "", baseClaims()), SubjectIsIDTokenCandidate},
		{"empty", "  ", SubjectIsEmpty},
		{"api key", "sbo_mcp_abcdef_0123", SubjectIsAPIKey},
		{"opaque bearer", "opaque-token-value", SubjectIsNotJWS},
		{"SBO access token", p.sign(t, TypAccessToken, map[string]any{"iss": own.Issuer, "sub": "x"}), SubjectIsAccessToken},
		{"node actor assertion", p.sign(t, TypActorAssertion, map[string]any{"iss": "node_1", "sub": "cred_1"}), SubjectIsNodeActor},
		{"dpop proof", p.sign(t, "dpop+jwt", map[string]any{"jti": "j"}), SubjectIsDPoPProof},
		{"typed client assertion", p.sign(t, "client-authentication+jwt", map[string]any{"iss": "c", "sub": "c"}), SubjectIsClientAssertion},
		{"generic client assertion to our token endpoint", p.sign(t, "JWT", map[string]any{"iss": "cred_x", "sub": "cred_x", "aud": own.TokenEndpoint}), SubjectIsClientAssertion},
		{"generic client assertion to our issuer", p.sign(t, "", map[string]any{"iss": "cred_x", "sub": "cred_x", "aud": []string{own.Issuer}}), SubjectIsClientAssertion},
		{"our own issuer under a JWT typ", p.sign(t, "JWT", map[string]any{"iss": own.Issuer, "sub": "u"}), SubjectIsOwnToken},
		{"unknown typ", p.sign(t, "secevent+jwt", baseClaims()), SubjectIsUnknownType},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifySubjectToken(tc.tok, own); got != tc.want {
				t.Fatalf("class = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestEndUserSubject(t *testing.T) {
	c := IDTokenClaims{Iss: idpIss, Sub: "user-42", Oid: "00000000-0000-0000-0000-00000000abcd"}
	cases := []struct {
		stability, want string
		wantErr         OBOErrorCode
	}{
		// R-S3-6: `sub` (and the empty DDL default) is ALWAYS issuer-namespaced,
		// byte-identical to `sub_iss`; only `oid` stays bare.
		{StabilitySub, "enduser:" + idpIss + "#user-42", ""},
		{"", "enduser:" + idpIss + "#user-42", ""},
		{StabilityOID, "enduser:00000000-0000-0000-0000-00000000abcd", ""},
		{StabilitySubIss, "enduser:" + idpIss + "#user-42", ""},
		{"email", "", OBOErrPolicyInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.stability, func(t *testing.T) {
			got, err := EndUserSubject(c, TrustPolicy{SubjectStability: tc.stability})
			if OBOCodeOf(err) != tc.wantErr || got != tc.want {
				t.Fatalf("got %q err %v", got, err)
			}
		})
	}
	t.Run("oid mode without oid", func(t *testing.T) {
		if _, err := EndUserSubject(IDTokenClaims{Sub: "x"}, TrustPolicy{SubjectStability: StabilityOID}); OBOCodeOf(err) != OBOErrSubject {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("oversized subject", func(t *testing.T) {
		for _, st := range []string{StabilitySub, StabilitySubIss} {
			if _, err := EndUserSubject(IDTokenClaims{Iss: strings.Repeat("i", 400), Sub: strings.Repeat("s", 200)}, TrustPolicy{SubjectStability: st}); OBOCodeOf(err) != OBOErrSubject {
				t.Fatalf("%s: err = %v", st, err)
			}
		}
	})
	t.Run("an issuer-namespaced stability needs iss and sub", func(t *testing.T) {
		for _, st := range []string{"", StabilitySub, StabilitySubIss} {
			for _, c := range []IDTokenClaims{{Sub: "x"}, {Iss: idpIss}} {
				if got, err := EndUserSubject(c, TrustPolicy{SubjectStability: st}); OBOCodeOf(err) != OBOErrSubject || got != "" {
					t.Fatalf("%q %+v: got %q err %v", st, c, got, err)
				}
			}
		}
	})
	// R-S3-6: OIDC `sub` is unique only per issuer, so the SAME sub from two
	// registered IdPs must name two DIFFERENT end users under `sub` (the
	// default) and `sub_iss` alike - and `sub` never drifts from `sub_iss`.
	t.Run("two issuers with the same sub are two end users", func(t *testing.T) {
		const otherIss = "https://second-idp.example.test"
		for _, st := range []string{"", StabilitySub, StabilitySubIss} {
			a, errA := EndUserSubject(IDTokenClaims{Iss: idpIss, Sub: "user-42"}, TrustPolicy{SubjectStability: st})
			b, errB := EndUserSubject(IDTokenClaims{Iss: otherIss, Sub: "user-42"}, TrustPolicy{SubjectStability: st})
			if errA != nil || errB != nil || a == b || a != "enduser:"+idpIss+"#user-42" || b != "enduser:"+otherIss+"#user-42" {
				t.Fatalf("%q: %q (%v) vs %q (%v)", st, a, errA, b, errB)
			}
			iss, _ := EndUserSubject(IDTokenClaims{Iss: otherIss, Sub: "user-42"}, TrustPolicy{SubjectStability: StabilitySubIss})
			if b != iss {
				t.Fatalf("%q drifted from sub_iss: %q vs %q", st, b, iss)
			}
		}
	})
}

func TestSubjectReplayKey(t *testing.T) {
	c := IDTokenClaims{Iss: idpIss, Sub: "u", Aud: []string{"b", "a"}, Iat: 100, Nonce: "n"}
	digest := SubjectReplayKey(c)
	if len(digest) != 64 {
		t.Fatalf("digest %q", digest)
	}
	reordered := c
	reordered.Aud = []string{"a", "b"}
	if SubjectReplayKey(reordered) != digest {
		t.Fatal("the digest must not depend on aud order")
	}
	for name, mut := range map[string]func(*IDTokenClaims){
		"iss":   func(x *IDTokenClaims) { x.Iss = "https://other" },
		"sub":   func(x *IDTokenClaims) { x.Sub = "v" },
		"aud":   func(x *IDTokenClaims) { x.Aud = []string{"a"} },
		"iat":   func(x *IDTokenClaims) { x.Iat = 101 },
		"nonce": func(x *IDTokenClaims) { x.Nonce = "m" },
	} {
		d := c
		d.Aud = append([]string(nil), c.Aud...)
		mut(&d)
		if SubjectReplayKey(d) == digest {
			t.Fatalf("changing %s must change the digest", name)
		}
	}
	withJTI := c
	withJTI.Jti = "jti-1"
	jk := SubjectReplayKey(withJTI)
	if jk == digest {
		t.Fatal("a jti-bearing token must key on its jti")
	}
	sameJTIOtherClaims := IDTokenClaims{Jti: "jti-1", Sub: "zzz"}
	if SubjectReplayKey(sameJTIOtherClaims) != jk {
		t.Fatal("the jti alone must key a jti-bearing token")
	}
	if got := SubjectReplayExpiry(IDTokenClaims{Iat: 1000, Exp: 5000}, TrustPolicy{MaxTokenAge: 300 * time.Second}, time.Minute); got != 1360 {
		t.Fatalf("expiry by age = %d", got)
	}
	if got := SubjectReplayExpiry(IDTokenClaims{Iat: 1000, Exp: 1100}, TrustPolicy{MaxTokenAge: 300 * time.Second}, time.Minute); got != 1160 {
		t.Fatalf("expiry by exp = %d", got)
	}
}

func TestHasCapability(t *testing.T) {
	cases := []struct {
		caps string
		want bool
	}{
		{`["act_for_end_users","other"]`, true},
		{`["other"]`, false},
		{`{"act_for_end_users":true}`, true},
		{`{"act_for_end_users":false}`, false},
		{`{"act_for_end_users":"yes"}`, false},
		{``, false},
		{`not json`, false},
	}
	for _, tc := range cases {
		if got := HasCapability(tc.caps, CapActForEndUsers); got != tc.want {
			t.Errorf("HasCapability(%s) = %t", tc.caps, got)
		}
	}
}

// TestOBORules is one case per DefaultOBORules row.
func TestOBORules(t *testing.T) {
	req := ExchangeRequest{GrantType: GrantTypeTokenExchange, SubjectToken: "id", SubjectType: TokenTypeIDToken, Resource: "https://gw/mcp/x"}
	ok := OBOContext{
		ClientAuthenticated: true, CredActive: true, AgentAllowed: true, SharedSecretAllowed: true,
		CredAssurance: CredWorkloadBound, ClientAttestation: AttestConfigured, Agent: AgentRef{ID: "ha", ClientID: "agent:ha", Kind: "hosted_agent"},
		SubjectClass: SubjectIsIDTokenCandidate, IssuerRegistered: true, Delegable: true, SubjectVerified: true, ReplayFresh: true,
	}
	cases := []struct {
		name   string
		r      func(*ExchangeRequest)
		c      func(*OBOContext)
		reason string
		code   OAuthError
	}{
		{"allowed", nil, nil, ReasonAllowed, ""},
		{"wrong subject type", func(r *ExchangeRequest) { r.SubjectType = TokenTypeAccessToken }, nil, ReasonOBONotOBO, OAuthInvalidRequest},
		{"no resource", func(r *ExchangeRequest) { r.Resource = "" }, nil, ReasonMissingResource, OAuthInvalidTarget},
		{"requested type", func(r *ExchangeRequest) { r.RequestedType = "urn:x" }, nil, ReasonRequestedType, OAuthInvalidRequest},
		{"no subject", func(r *ExchangeRequest) { r.SubjectToken = "" }, nil, ReasonMissingSubject, OAuthInvalidRequest},
		{"actor token present", func(r *ExchangeRequest) { r.ActorToken, r.ActorType = "a", TokenTypeJWT }, nil, ReasonOBOActorToken, OAuthInvalidRequest},
		{"actor type alone", func(r *ExchangeRequest) { r.ActorType = TokenTypeJWT }, nil, ReasonOBOActorToken, OAuthInvalidRequest},
		{"client unauthenticated", nil, func(c *OBOContext) { c.ClientAuthenticated = false }, ReasonClientUnauthed, OAuthInvalidClient},
		{"credential inactive", nil, func(c *OBOContext) { c.CredActive = false }, ReasonCredInactive, OAuthInvalidGrant},
		{"assurance unresolved", nil, func(c *OBOContext) { c.CredAssurance = CredUnknown }, ReasonAssuranceUnknown, OAuthInvalidGrant},
		{"shared secret disabled", nil, func(c *OBOContext) { c.CredAssurance, c.SharedSecretAllowed = CredSharedSecret, false }, ReasonSharedSecretDisabled, OAuthUnauthorizedClient},
		{"agent not allowed", nil, func(c *OBOContext) { c.AgentAllowed = false }, ReasonAgentNotAllowed, OAuthUnauthorizedClient},
		{"substitution", nil, func(c *OBOContext) { c.SubjectClass = SubjectIsNodeActor }, ReasonOBOSubjectSubstitute, OAuthInvalidGrant},
		{"issuer unregistered", nil, func(c *OBOContext) { c.IssuerRegistered = false }, ReasonOBOIssuerUnknown, OAuthInvalidGrant},
		{"not delegable", nil, func(c *OBOContext) { c.Delegable = false }, ReasonOBONotDelegable, OAuthUnauthorizedClient},
		{"subject invalid", nil, func(c *OBOContext) { c.SubjectVerified = false }, ReasonOBOSubjectInvalid, OAuthInvalidGrant},
		{"replayed", nil, func(c *OBOContext) { c.ReplayFresh = false }, ReasonOBOReplay, OAuthInvalidGrant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, c := req, ok
			if tc.r != nil {
				tc.r(&r)
			}
			if tc.c != nil {
				tc.c(&c)
			}
			d := DecideOBO(DefaultOBORules(), r, c)
			if d.Reason != tc.reason || d.Error != tc.code || d.Allow != (tc.reason == ReasonAllowed) {
				t.Fatalf("decision = %+v", d)
			}
			if d.Allow && (d.ActChain == nil || d.ActChain.Sub != "agent:ha" || d.ActChain.Act != nil) {
				t.Fatalf("act = %+v (the agent, with no nested node actor)", d.ActChain)
			}
		})
	}
	t.Run("the table fails closed with no rows", func(t *testing.T) {
		if d := DecideOBO(nil, req, ok); d.Allow || d.Reason != ReasonNoRuleMatched {
			t.Fatalf("%+v", d)
		}
	})
	t.Run("stages are ordered like the table", func(t *testing.T) {
		last := -1
		for _, r := range DefaultOBORules() {
			if r.Allow {
				continue
			}
			s := OBOStageOf(r.Reason)
			if s == OBOStageFinal || s < last {
				t.Fatalf("row %q stage %d after %d", r.Name, s, last)
			}
			last = s
		}
		if !IsOBOWireReason(ReasonOBOActorToken) || IsOBOWireReason(ReasonOBOReplay) {
			t.Fatal("wire classification")
		}
	})
}

func TestBoundedAMR(t *testing.T) {
	in := []string{"pwd", "mfa", "", "bad\x00", strings.Repeat("x", 65)}
	for i := 0; i < 20; i++ {
		in = append(in, "otp")
	}
	got := BoundedAMR(in)
	if len(got) != MaxAMRValues || got[0] != "pwd" || got[1] != "mfa" {
		t.Fatalf("amr = %v", got)
	}
}
