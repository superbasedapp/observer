package oidcissuer

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

// rules_test.go: one case per row of every rule table, each tripping exactly
// that row with every earlier row passing, plus a coverage check that no row
// is left without a case.

const testOrg = "0b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f"

// testSupportStaff is a staff id for the support claim rows.
const testSupportStaff = "5f5e5d5c-5b5a-4958-8756-555453525150"

var testVerifier = strings.Repeat("v", 43)

func validAuthorize() AuthorizeRequest {
	return AuthorizeRequest{
		ClientID: ClientIDForOrg(testOrg), RedirectURI: "https://acme.superbased.app/auth/oidc/callback",
		ResponseType: "code", Scope: "openid email profile", State: "st", Nonce: "nn",
		CodeChallenge: S256Challenge(testVerifier), CodeChallengeMethod: "S256",
	}
}

func validClient() Client {
	return Client{ClientID: ClientIDForOrg(testOrg), OrgID: testOrg, RedirectURIs: []string{"https://acme.superbased.app/auth/oidc/callback"}}
}

func coverage(t *testing.T, table string, ids []string, cases map[string]bool) {
	t.Helper()
	for _, id := range ids {
		if !cases[id] {
			t.Errorf("%s row %q has no test case", table, id)
		}
	}
}

func TestClientRulesOneCasePerRow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rule   string
		mutate func(r *AuthorizeRequest, c *Client, found *bool)
	}{
		{"client-id-present", func(r *AuthorizeRequest, _ *Client, _ *bool) { r.ClientID = "" }},
		{"client-id-shape", func(r *AuthorizeRequest, _ *Client, _ *bool) { r.ClientID = "org:not-a-uuid" }},
		{"client-id-once", func(r *AuthorizeRequest, _ *Client, _ *bool) { r.Duplicated = []string{"redirect_uri"} }},
		{"client-known", func(_ *AuthorizeRequest, _ *Client, f *bool) { *f = false }},
		{"client-enabled", func(_ *AuthorizeRequest, c *Client, _ *bool) { c.Disabled = true }},
		{"redirect-exact", func(r *AuthorizeRequest, _ *Client, _ *bool) {
			r.RedirectURI = "https://acme.superbased.app/auth/oidc/callbacK" // one character
		}},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		r, c, found := validAuthorize(), validClient(), true
		tc.mutate(&r, &c, &found)
		e := checkClient(r, c, found)
		if e == nil || e.RuleID != tc.rule {
			t.Errorf("case %s: got %+v, want rule %s", tc.rule, e, tc.rule)
		}
		seen[tc.rule] = true
	}
	if e := checkClient(validAuthorize(), validClient(), true); e != nil {
		t.Errorf("valid client refused: %v", e)
	}
	var ids []string
	for _, r := range clientRules {
		ids = append(ids, r.id)
	}
	coverage(t, "clientRules", ids, seen)
}

func TestAuthorizeRequestRulesOneCasePerRow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rule   string
		mutate func(r *AuthorizeRequest)
	}{
		{"params-once", func(r *AuthorizeRequest) { r.Duplicated = []string{"scope"} }},
		{"no-request-object", func(r *AuthorizeRequest) { r.Request = "eyJ..." }},
		{"response-type-code", func(r *AuthorizeRequest) { r.ResponseType = "token" }},
		{"response-mode-query", func(r *AuthorizeRequest) { r.ResponseMode = "fragment" }},
		{"scope-openid", func(r *AuthorizeRequest) { r.Scope = "email profile" }},
		{"state-present", func(r *AuthorizeRequest) { r.State = "" }},
		{"nonce-present", func(r *AuthorizeRequest) { r.Nonce = "" }},
		{"pkce-s256", func(r *AuthorizeRequest) { r.CodeChallengeMethod = "plain" }},
		{"prompt-supported", func(r *AuthorizeRequest) { r.Prompt = "login consent" }},
		{"prompt-none-alone", func(r *AuthorizeRequest) { r.Prompt = "none login" }},
		{"max-age-shape", func(r *AuthorizeRequest) { r.MaxAge = "-1" }},
		{"pkce-challenge-shape", func(r *AuthorizeRequest) { r.CodeChallenge = "short" }},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		r := validAuthorize()
		tc.mutate(&r)
		e := checkAuthorizeRequest(r)
		if e == nil || e.RuleID != tc.rule {
			t.Errorf("case %s: got %+v, want rule %s", tc.rule, e, tc.rule)
		}
		seen[tc.rule] = true
	}
	// A missing method is not a downgrade to plain: it is refused too.
	r := validAuthorize()
	r.CodeChallengeMethod = ""
	if e := checkAuthorizeRequest(r); e == nil || e.RuleID != "pkce-s256" {
		t.Errorf("missing code_challenge_method: got %+v, want pkce-s256", e)
	}
	if e := checkAuthorizeRequest(validAuthorize()); e != nil {
		t.Errorf("valid request refused: %v", e)
	}
	var ids []string
	for _, r := range authorizeRequestRules {
		ids = append(ids, r.id)
	}
	coverage(t, "authorizeRequestRules", ids, seen)
}

func validMember() Member {
	return Member{IsMember: true, AccountStatus: "active", OrgStatus: "active", RailEnabled: true, Sub: "user_01", Email: "a@example.com", EmailVerified: true}
}

func TestAccountRulesOneCasePerRow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rule   string
		mutate func(m *Member)
	}{
		{"member", func(m *Member) { m.IsMember = false }},
		{"account-active", func(m *Member) { m.AccountStatus = "suspended" }},
		{"org-active", func(m *Member) { m.OrgStatus = "suspended" }},
		{"rail-enabled", func(m *Member) { m.RailEnabled = false }},
		{"subject-known", func(m *Member) { m.Sub = "" }},
		{"email-known", func(m *Member) { m.Email = "no-at-sign" }},
		{"email-verified", func(m *Member) { m.EmailVerified = false }},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		m := validMember()
		tc.mutate(&m)
		e := checkAccount(m, ErrCodeAccessDenied, 302)
		if e == nil || e.RuleID != tc.rule || e.Code != ErrCodeAccessDenied {
			t.Errorf("case %s: got %+v", tc.rule, e)
		}
		seen[tc.rule] = true
	}
	// Every non-active org state is refused, not only suspended.
	for _, st := range []string{"provisioning", "suspended", "pending_deletion", "purging", "purged"} {
		m := validMember()
		m.OrgStatus = st
		if e := checkAccount(m, ErrCodeAccessDenied, 302); e == nil || e.RuleID != "org-active" {
			t.Errorf("org status %s: got %+v, want org-active", st, e)
		}
	}
	if e := checkAccount(validMember(), ErrCodeAccessDenied, 302); e != nil {
		t.Errorf("valid member refused: %v", e)
	}
	var ids []string
	for _, r := range accountRules {
		ids = append(ids, r.id)
	}
	coverage(t, "accountRules", ids, seen)
}

func validTokenReq() TokenRequest {
	return TokenRequest{
		GrantType: "authorization_code", Code: strings.Repeat("c", 43),
		RedirectURI: "https://acme.superbased.app/auth/oidc/callback",
		ClientID:    ClientIDForOrg(testOrg), CodeVerifier: testVerifier,
	}
}

func TestTokenRequestRulesOneCasePerRow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		rule   string
		mutate func(r *TokenRequest)
	}{
		{"params-once", func(r *TokenRequest) { r.Duplicated = []string{"code"} }},
		{"grant-type", func(r *TokenRequest) { r.GrantType = "client_credentials" }},
		{"public-client", func(r *TokenRequest) { r.ClientSecretSent = true }},
		{"client-id", func(r *TokenRequest) { r.ClientID = "acme" }},
		{"code-present", func(r *TokenRequest) { r.Code = "" }},
		{"redirect-present", func(r *TokenRequest) { r.RedirectURI = "" }},
		{"verifier-present", func(r *TokenRequest) { r.CodeVerifier = "" }},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		r := validTokenReq()
		tc.mutate(&r)
		e := checkTokenRequest(r)
		if e == nil || e.RuleID != tc.rule {
			t.Errorf("case %s: got %+v", tc.rule, e)
		}
		seen[tc.rule] = true
	}
	if e := checkTokenRequest(validTokenReq()); e != nil {
		t.Errorf("valid token request refused: %v", e)
	}
	var ids []string
	for _, r := range tokenRequestRules {
		ids = append(ids, r.id)
	}
	coverage(t, "tokenRequestRules", ids, seen)
}

func TestCodeBindingRulesOneCasePerRow(t *testing.T) {
	t.Parallel()
	code := CodeRecord{
		ClientID: ClientIDForOrg(testOrg), RedirectURI: "https://acme.superbased.app/auth/oidc/callback",
		CodeChallenge: S256Challenge(testVerifier), AuthTime: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC),
	}
	cases := []struct {
		rule   string
		mutate func(r *TokenRequest)
		code   func(c *CodeRecord)
	}{
		{"code-client", func(r *TokenRequest) { r.ClientID = ClientIDForOrg("1b5c3f1e-2d4a-4c6b-9e8f-1a2b3c4d5e6f") }, nil},
		{"code-redirect", func(r *TokenRequest) { r.RedirectURI += "/" }, nil},
		{"pkce-verifier", func(r *TokenRequest) { r.CodeVerifier = strings.Repeat("w", 43) }, nil},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		r := validTokenReq()
		tc.mutate(&r)
		code := code
		if tc.code != nil {
			tc.code(&code)
		}
		e := checkBinding(r, code)
		if e == nil || e.RuleID != tc.rule || e.Code != ErrCodeInvalidGrant {
			t.Errorf("case %s: got %+v", tc.rule, e)
		}
		seen[tc.rule] = true
	}
	if e := checkBinding(validTokenReq(), code); e != nil {
		t.Errorf("valid binding refused: %v", e)
	}
	// A code whose session's authentication time is not known (or one
	// minted before cloud 0083) binds: the token simply carries no auth_time.
	unknown := code
	unknown.AuthTime = time.Time{}
	if e := checkBinding(validTokenReq(), unknown); e != nil {
		t.Errorf("a code without auth_time refused: %v", e)
	}
	var ids []string
	for _, r := range codeBindingRules {
		ids = append(ids, r.id)
	}
	coverage(t, "codeBindingRules", ids, seen)
}

func validClaims(now time.Time) Claims {
	return Claims{
		Iss: "https://app.example/oauth2", Sub: "user_01", Aud: ClientIDForOrg(testOrg),
		Iat: now.Unix(), Exp: now.Unix() + 300, AuthTime: now.Unix() - 600, Jti: strings.Repeat("j", 32), Nonce: "nn",
		Org: testOrg, Email: "a@example.com", EmailVerified: true, AMR: []string{"pwd"},
	}
}

func TestClaimRulesOneCasePerRow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	const iss = "https://app.example/oauth2"
	cases := []struct {
		rule   string
		mutate func(c *Claims)
	}{
		{"iss-fixed", func(c *Claims) { c.Iss = "https://evil.example/oauth2" }},
		{"org-uuid", func(c *Claims) { c.Org = "acme" }},
		{"aud-is-org-client", func(c *Claims) { c.Aud = "https://acme.superbased.app" }},
		{"sub-present", func(c *Claims) { c.Sub = "" }},
		{"jti-present", func(c *Claims) { c.Jti = "" }},
		{"iat-present", func(c *Claims) { c.Iat, c.Exp = 0, 300 }},
		{"exp-after-iat", func(c *Claims) { c.Exp = c.Iat }},
		{"lifetime-cap", func(c *Claims) { c.Exp = c.Iat + 301 }},
		{"iat-fresh", func(c *Claims) { c.Iat -= 120; c.Exp = c.Iat + 300 }},
		{"auth-time-past", func(c *Claims) { c.AuthTime = -1 }},
		{"support-sub-staff", func(c *Claims) { c.Support = true }},
		{"member-sub-not-staff", func(c *Claims) { c.Sub = SupportSubject(testSupportStaff) }},
		{"support-no-email", func(c *Claims) { c.Support, c.Sub = true, SupportSubject(testSupportStaff) }},
		{"support-no-amr", func(c *Claims) {
			c.Support, c.Sub, c.Email, c.EmailVerified, c.AMR = true, SupportSubject(testSupportStaff), "", false, []string{"hwk"}
		}},
		{"support-auth-time", func(c *Claims) {
			c.Support, c.Sub, c.Email, c.EmailVerified, c.AMR, c.AuthTime = true, SupportSubject(testSupportStaff), "", false, nil, 0
		}},
		{"email-present", func(c *Claims) { c.Email = "" }},
		{"email-verified", func(c *Claims) { c.EmailVerified = false }},
		{"nonce-bounded", func(c *Claims) { c.Nonce = strings.Repeat("n", 513) }},
		{"amr-bounded", func(c *Claims) { c.AMR = []string{"has space"} }},
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		c := validClaims(now)
		tc.mutate(&c)
		err := ValidateClaims(c, iss, now)
		if err == nil || !strings.Contains(err.Error(), tc.rule+":") {
			t.Errorf("case %s: got %v", tc.rule, err)
		}
		seen[tc.rule] = true
	}
	if err := ValidateClaims(validClaims(now), iss, now); err != nil {
		t.Errorf("valid claims refused: %v", err)
	}
	// auth_time is a past authentication: one from after iat (beyond the
	// skew) is refused; one at iat, or within the skew after it, is not.
	for _, tc := range []struct {
		after int64
		ok    bool
	}{{0, true}, {60, true}, {61, false}} {
		c := validClaims(now)
		c.AuthTime = c.Iat + tc.after
		if err := ValidateClaims(c, iss, now); (err == nil) != tc.ok {
			t.Errorf("auth_time iat+%ds: err %v, want ok=%v", tc.after, err, tc.ok)
		}
	}
	// An absent auth_time (not known) is signed, and serializes as absent.
	noAuthTime := validClaims(now)
	noAuthTime.AuthTime = 0
	if err := ValidateClaims(noAuthTime, iss, now); err != nil {
		t.Errorf("claims without auth_time refused: %v", err)
	}
	if raw, err := json.Marshal(noAuthTime); err != nil || strings.Contains(string(raw), "auth_time") {
		t.Errorf("claims without auth_time serialize as %s (%v); want the claim absent", raw, err)
	}
	// A support token: staff subject, no email, no amr, a known auth_time.
	// It is signed, and serializes with support and without any address.
	sup := validClaims(now)
	sup.Support, sup.Sub, sup.Email, sup.EmailVerified, sup.AMR, sup.AuthTime = true, SupportSubject(testSupportStaff), "", false, nil, sup.Iat-30
	if err := ValidateClaims(sup, iss, now); err != nil {
		t.Errorf("valid support claims refused: %v", err)
	}
	if raw, err := json.Marshal(sup); err != nil || strings.Contains(string(raw), "email") || !strings.Contains(string(raw), `"support":true`) {
		t.Errorf("support claims serialize as %s (%v)", raw, err)
	}
	// An empty configured issuer refuses everything.
	if err := ValidateClaims(validClaims(now), "", now); err == nil {
		t.Error("a signer with no issuer signed")
	}
	var ids []string
	for _, r := range claimRules {
		ids = append(ids, r.id)
	}
	coverage(t, "claimRules", ids, seen)
}

func TestParseRecordsDuplicatesAndSecret(t *testing.T) {
	t.Parallel()
	q := url.Values{"client_id": {"a", "b"}, "state": {"s"}}
	if got := ParseAuthorizeQuery(q).Duplicated; len(got) != 1 || got[0] != "client_id" {
		t.Errorf("authorize duplicates = %v", got)
	}
	f := url.Values{"client_secret": {""}, "code": {"x"}}
	tr := ParseTokenForm(f)
	if !tr.ClientSecretSent {
		t.Error("an empty client_secret was not noticed")
	}
}

func TestVerifyPKCES256Only(t *testing.T) {
	t.Parallel()
	ch := S256Challenge(testVerifier)
	cases := []struct {
		name, challenge, verifier string
		want                      bool
	}{
		{"s256 match", ch, testVerifier, true},
		{"wrong verifier", ch, strings.Repeat("w", 43), false},
		{"plain: verifier equals challenge", testVerifier, testVerifier, false},
		{"verifier too short", S256Challenge("short"), "short", false},
		{"verifier too long", S256Challenge(strings.Repeat("v", 129)), strings.Repeat("v", 129), false},
		{"verifier bad characters", S256Challenge(strings.Repeat("v", 42) + "+"), strings.Repeat("v", 42) + "+", false},
	}
	for _, tc := range cases {
		if got := VerifyPKCE(tc.challenge, tc.verifier); got != tc.want {
			t.Errorf("%s: VerifyPKCE = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRedirectMatchesExactly(t *testing.T) {
	t.Parallel()
	reg := []string{"https://acme.superbased.app/auth/oidc/callback"}
	for _, got := range []string{
		"https://acme.superbased.app/auth/oidc/callback/",
		"https://ACME.superbased.app/auth/oidc/callback",
		"https://acme.superbased.app:443/auth/oidc/callback",
		"https://acme.superbased.app/auth/oidc/callback?x=1",
		"https://acme.superbased.app.evil.example/auth/oidc/callback",
		"http://acme.superbased.app/auth/oidc/callback",
		"",
	} {
		if RedirectMatches(reg, got) {
			t.Errorf("RedirectMatches(%q) = true", got)
		}
	}
	if !RedirectMatches(reg, reg[0]) {
		t.Error("the registered URI did not match itself")
	}
}

func TestTenantRedirectURIAndClientID(t *testing.T) {
	t.Parallel()
	c, err := ClientForOrg(testOrg, "acme", "superbased.app")
	if err != nil {
		t.Fatal(err)
	}
	if c.ClientID != "org:"+testOrg || len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://acme.superbased.app/auth/oidc/callback" {
		t.Errorf("ClientForOrg = %+v", c)
	}
	if org, ok := OrgFromClientID(c.ClientID); !ok || org != testOrg {
		t.Errorf("OrgFromClientID = %q %v", org, ok)
	}
	for _, bad := range []struct{ org, slug, domain string }{
		{"ACME", "acme", "superbased.app"},
		{testOrg, "", "superbased.app"},
		{testOrg, "acme/evil", "superbased.app"},
		{testOrg, "acme", ""},
	} {
		if _, err := ClientForOrg(bad.org, bad.slug, bad.domain); err == nil {
			t.Errorf("ClientForOrg(%+v) accepted", bad)
		}
	}
}

func TestValidateIssuerURL(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"https://app.superbased.app/oauth2", "http://127.0.0.1:8090/oauth2", "http://localhost/oauth2"} {
		if _, err := ValidateIssuerURL(ok); err != nil {
			t.Errorf("ValidateIssuerURL(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "https://app.superbased.app", "https://app.superbased.app/oauth2/", "https://app.superbased.app/other",
		"http://app.superbased.app/oauth2", "https://app.superbased.app/oauth2?x=1", "https://u@app.superbased.app/oauth2",
	} {
		if _, err := ValidateIssuerURL(bad); err == nil {
			t.Errorf("ValidateIssuerURL(%q) accepted", bad)
		}
	}
}

func TestKeyPublicationAndSelectionTable(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	mk := func(kid, status string, nb, na time.Time) SigningKey {
		return SigningKey{KID: kid, Status: status, NotBefore: nb, NotAfter: na, JWK: JWK{Kid: kid}}
	}
	keys := []SigningKey{
		mk("a-staged", KeyStaged, time.Time{}, time.Time{}),
		mk("b-active-old", KeyActive, now.Add(-48*time.Hour), time.Time{}),
		mk("c-active-new", KeyActive, now.Add(-time.Hour), time.Time{}),
		mk("d-active-future", KeyActive, now.Add(23*time.Hour), time.Time{}),
		mk("e-retiring", KeyRetiring, now.Add(-72*time.Hour), time.Time{}),
		mk("f-expired", KeyActive, now.Add(-72*time.Hour), now.Add(-time.Minute)),
		mk("g-retired", KeyRetired, now.Add(-72*time.Hour), time.Time{}),
	}
	var pub []string
	for _, j := range PublishedKeys(keys, now) {
		pub = append(pub, j.Kid)
	}
	if got, want := strings.Join(pub, ","), "b-active-old,c-active-new,d-active-future,e-retiring"; got != want {
		t.Errorf("published = %s, want %s", got, want)
	}
	held := map[string]bool{}
	for _, k := range keys {
		held[k.KID] = true
	}
	if k, ok := SelectSigningKey(keys, held, now); !ok || k.KID != "c-active-new" {
		t.Errorf("selected %q %v, want the newest usable active key c-active-new", k.KID, ok)
	}
	// A key published but not yet usable is never chosen; nor one the signer
	// does not hold.
	delete(held, "c-active-new")
	if k, ok := SelectSigningKey(keys, held, now); !ok || k.KID != "b-active-old" {
		t.Errorf("selected %q %v, want b-active-old", k.KID, ok)
	}
	if _, ok := SelectSigningKey(keys, map[string]bool{"d-active-future": true, "a-staged": true, "e-retiring": true}, now); ok {
		t.Error("a staged, future or retiring key was selected for signing")
	}
}

func TestKeyTransitionsOneCasePerRow(t *testing.T) {
	t.Parallel()
	allowed := []struct {
		from, to string
		nb       bool
	}{
		{KeyStaged, KeyActive, true},
		{KeyActive, KeyRetiring, false},
		{KeyRetiring, KeyRetired, false},
		{KeyStaged, KeyRetired, false},
	}
	seen := map[string]bool{}
	for _, tc := range allowed {
		nb, err := CheckKeyTransition(tc.from, tc.to)
		if err != nil || nb != tc.nb {
			t.Errorf("%s -> %s: needsNotBefore %v, %v", tc.from, tc.to, nb, err)
		}
		seen[tc.from+">"+tc.to] = true
	}
	var ids []string
	for _, tr := range keyTransitions {
		ids = append(ids, tr.from+">"+tr.to)
	}
	coverage(t, "keyTransitions", ids, seen)
	for _, bad := range [][2]string{
		{KeyActive, KeyStaged}, {KeyRetired, KeyActive}, {KeyRetiring, KeyActive}, {KeyActive, KeyRetired}, {KeyStaged, "bogus"},
	} {
		if _, err := CheckKeyTransition(bad[0], bad[1]); err == nil {
			t.Errorf("%s -> %s allowed", bad[0], bad[1])
		}
	}
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	if err := CheckPromotion(now.Add(PublicationLead), now, PublicationLead); err != nil {
		t.Errorf("a promotion one lead ahead refused: %v", err)
	}
	if err := CheckPromotion(now.Add(time.Hour), now, PublicationLead); err == nil {
		t.Error("a promotion inside the lead accepted")
	}
	if err := CheckPromotion(now, now, 0); err == nil {
		t.Error("a zero lead accepted")
	}
}
