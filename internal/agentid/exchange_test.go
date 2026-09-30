package agentid

import "testing"

func goodTE() (ExchangeRequest, ExchangeContext) {
	return ExchangeRequest{
			GrantType: GrantTypeTokenExchange, SubjectToken: "bearer", SubjectType: TokenTypeAccessToken,
			ActorToken: "actor", ActorType: TokenTypeJWT, Resource: testAud, RequestedType: TokenTypeAccessToken,
		}, ExchangeContext{
			MemberActive: true, MemberGen: 7, CredGen: 2, ActorCredGen: 2, AgentAllowed: true, CredActive: true, MachineBound: true,
			SubjectVerified: true, ActorVerified: true, CredAssurance: CredNodeEnrolled, ClientAttestation: AttestProcessAttested,
			Agent: AgentRef{ID: "ad_1", ClientID: "agent:claude-code", Kind: "coding_agent", Product: "claude-code"}, Node: NodeRef{ID: "m_9b21"},
		}
}

func goodCC() (ExchangeRequest, ExchangeContext) {
	return ExchangeRequest{GrantType: GrantTypeClientCredentials, Resource: testAud},
		ExchangeContext{
			ClientAuthenticated: true, CredActive: true, AgentAllowed: true, SharedSecretAllowed: true,
			CredAssurance: CredWorkloadBound, ClientAttestation: AttestConfigured, Agent: AgentRef{ID: "svc", ClientID: "svc"},
		}
}

// TestDecideExchangeTable: one case per rule row, plus the adversarial
// shapes doc3 §11.3 names (wrong subject/actor type, substitution,
// member deprovisioned mid-exchange, machine mismatch).
func TestDecideExchangeTable(t *testing.T) {
	cases := []struct {
		name   string
		base   func() (ExchangeRequest, ExchangeContext)
		mut    func(*ExchangeRequest, *ExchangeContext)
		allow  bool
		reason string
		oerr   OAuthError
	}{
		{"F1 allowed", goodTE, nil, true, ReasonAllowed, ""},
		{"F1 private enrolment URN allowed", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.SubjectType = TokenTypeEnrolmentBearer }, true, ReasonAllowed, ""},
		{"requested_type omitted is fine", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.RequestedType = "" }, true, ReasonAllowed, ""},
		{"F5 allowed", goodCC, nil, true, ReasonAllowed, ""},
		{"unknown grant", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.GrantType = "password" }, false, ReasonUnsupportedGrant, OAuthUnsupportedGrantType},
		{"jwt-bearer is v2 (F4)", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) {
			r.GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
		}, false, ReasonUnsupportedGrant, OAuthUnsupportedGrantType},
		{"resource missing", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.Resource = "" }, false, ReasonMissingResource, OAuthInvalidTarget},
		{"requested at+jwt refused (R6)", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) {
			r.RequestedType = "urn:ietf:params:oauth:token-type:at+jwt"
		}, false, ReasonRequestedType, OAuthInvalidRequest},
		{"subject missing", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.SubjectToken = "" }, false, ReasonMissingSubject, OAuthInvalidRequest},
		{"subject_type absent (R8.28.l always present)", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.SubjectType = "" }, false, ReasonMissingSubject, OAuthInvalidRequest},
		{"wrong subject type :jwt (finding-5)", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.SubjectType = TokenTypeJWT }, false, ReasonSubjectType, OAuthInvalidRequest},
		{"actor token without type", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.ActorType = "" }, false, ReasonActorHalfPresent, OAuthInvalidRequest},
		{"actor type without token", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.ActorToken = "" }, false, ReasonActorHalfPresent, OAuthInvalidRequest},
		{"wrong actor type (substitution: access_token as actor)", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.ActorType = TokenTypeAccessToken }, false, ReasonActorType, OAuthInvalidRequest},
		{"no actor on F1 in P1", goodTE, func(r *ExchangeRequest, _ *ExchangeContext) { r.ActorToken, r.ActorType = "", "" }, false, ReasonActorRequired, OAuthInvalidRequest},
		{"subject bearer invalid (substitution: actor passed as subject)", goodTE, func(_ *ExchangeRequest, c *ExchangeContext) { c.SubjectVerified = false }, false, ReasonSubjectInvalid, OAuthInvalidGrant},
		{"actor assertion invalid", goodTE, func(_ *ExchangeRequest, c *ExchangeContext) { c.ActorVerified = false }, false, ReasonActorInvalid, OAuthInvalidGrant},
		{"member deprovisioned mid-exchange", goodTE, func(_ *ExchangeRequest, c *ExchangeContext) { c.MemberActive = false }, false, ReasonMemberInactive, OAuthInvalidGrant},
		{"actor cred gen stale", goodTE, func(_ *ExchangeRequest, c *ExchangeContext) { c.ActorCredGen = 1 }, false, ReasonCredGenStale, OAuthInvalidGrant},
		{"machine mismatch", goodTE, func(_ *ExchangeRequest, c *ExchangeContext) { c.MachineBound = false }, false, ReasonMachineMismatch, OAuthInvalidGrant},
		{"credential revoked", goodTE, func(_ *ExchangeRequest, c *ExchangeContext) { c.CredActive = false }, false, ReasonCredInactive, OAuthInvalidGrant},
		{"assurance unresolved", goodTE, func(_ *ExchangeRequest, c *ExchangeContext) { c.ClientAttestation = AttestUnknown }, false, ReasonAssuranceUnknown, OAuthInvalidGrant},
		{"agent not allowed", goodTE, func(_ *ExchangeRequest, c *ExchangeContext) { c.AgentAllowed = false }, false, ReasonAgentNotAllowed, OAuthUnauthorizedClient},
		{"F5 unauthenticated client", goodCC, func(_ *ExchangeRequest, c *ExchangeContext) { c.ClientAuthenticated = false }, false, ReasonClientUnauthed, OAuthInvalidClient},
		{"F5 subject token smuggled", goodCC, func(r *ExchangeRequest, _ *ExchangeContext) { r.SubjectToken = "x" }, false, ReasonUnexpectedTokens, OAuthInvalidRequest},
		{"F5 client_secret allowed by default posture", goodCC, func(_ *ExchangeRequest, c *ExchangeContext) { c.CredAssurance = CredSharedSecret }, true, ReasonAllowed, ""},
		{"F5 client_secret disabled by org", goodCC, func(_ *ExchangeRequest, c *ExchangeContext) {
			c.CredAssurance, c.SharedSecretAllowed = CredSharedSecret, false
		}, false, ReasonSharedSecretDisabled, OAuthUnauthorizedClient},
		{"F5 revoked credential", goodCC, func(_ *ExchangeRequest, c *ExchangeContext) { c.CredActive = false }, false, ReasonCredInactive, OAuthInvalidGrant},
		{"F5 agent not allowed", goodCC, func(_ *ExchangeRequest, c *ExchangeContext) { c.AgentAllowed = false }, false, ReasonAgentNotAllowed, OAuthUnauthorizedClient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, c := tc.base()
			if tc.mut != nil {
				tc.mut(&r, &c)
			}
			d := DecideExchange(DefaultExchangeRules(), r, c)
			if d.Allow != tc.allow || d.Reason != tc.reason || d.Error != tc.oerr {
				t.Fatalf("decision = %+v, want allow=%v reason=%s err=%s", d, tc.allow, tc.reason, tc.oerr)
			}
			if d.Allow && (d.ActChain == nil || d.ActChain.SboCredAssurance != c.CredAssurance || !d.Cred.Valid()) {
				t.Fatalf("allow without act chain: %+v", d)
			}
		})
	}
}

func TestDecideExchangeFailsClosed(t *testing.T) {
	r, c := goodTE()
	if d := DecideExchange(nil, r, c); d.Allow || d.Reason != ReasonNoRuleMatched {
		t.Fatalf("empty table decision = %+v", d)
	}
	// A table with only deny rows that don't match still denies.
	rules := []ExchangeRule{{Name: "never", When: func(ExchangeRequest, ExchangeContext) bool { return false }}}
	if d := DecideExchange(rules, r, c); d.Allow {
		t.Fatal("no-match must deny")
	}
}
