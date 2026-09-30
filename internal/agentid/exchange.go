package agentid

// OAuth 2.0 wire vocabulary for the STS token endpoint (RFC 6749 / 8693).
const (
	// GrantTypeTokenExchange is the RFC 8693 grant (F1).
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // G101 false positive: public RFC 8693 grant-type URN, not a credential
	// GrantTypeClientCredentials is the RFC 6749 §4.4 grant (F5).
	GrantTypeClientCredentials = "client_credentials"
	// TokenTypeAccessToken is the subject_token_type of the enrolment bearer
	// and the ONLY requested_token_type (R2/R6 - never at+jwt).
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // G101 false positive: public RFC 8693 token-type URN, not a credential
	// TokenTypeJWT is the actor_token_type of the sbo-actor+jwt assertion.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt" //nolint:gosec // G101 false positive: public RFC 8693 token-type URN, not a credential
	// TokenTypeEnrolmentBearer is the documented private alternative
	// subject_token_type for the headerless two-segment enrolment bearer (R2).
	TokenTypeEnrolmentBearer = "urn:superbased:token-type:enrolment-bearer" //nolint:gosec // G101 false positive: token-type URN identifier, not a credential
)

// OAuthError is the CLOSED external error vocabulary (RFC 6749 §5.2 / RFC
// 8693 §2.2.2). It is all a client ever sees - the internal Reason stays in
// the audit record, so the response is never an enumeration oracle.
type OAuthError string

// OAuth error codes.
const (
	OAuthInvalidRequest       OAuthError = "invalid_request"
	OAuthInvalidClient        OAuthError = "invalid_client"
	OAuthInvalidGrant         OAuthError = "invalid_grant"
	OAuthUnauthorizedClient   OAuthError = "unauthorized_client"
	OAuthUnsupportedGrantType OAuthError = "unsupported_grant_type"
	OAuthInvalidTarget        OAuthError = "invalid_target"
	OAuthInvalidDPoPProof     OAuthError = "invalid_dpop_proof"
	OAuthUseDPoPNonce         OAuthError = "use_dpop_nonce"
	OAuthServerError          OAuthError = "server_error"
	OAuthUnavailable          OAuthError = "temporarily_unavailable"
)

// Exchange reasons: the CLOSED internal vocabulary recorded with a decision.
const (
	ReasonAllowed              = "allowed"
	ReasonUnsupportedGrant     = "unsupported_grant_type"
	ReasonMissingSubject       = "missing_subject_token"
	ReasonSubjectType          = "unsupported_subject_token_type"
	ReasonRequestedType        = "unsupported_requested_token_type"
	ReasonMissingResource      = "missing_resource"
	ReasonActorHalfPresent     = "actor_token_and_type_mismatch"
	ReasonActorType            = "unsupported_actor_token_type"
	ReasonActorRequired        = "actor_token_required"
	ReasonUnexpectedTokens     = "unexpected_subject_or_actor_token"
	ReasonSubjectInvalid       = "subject_token_invalid"
	ReasonActorInvalid         = "actor_assertion_invalid"
	ReasonClientUnauthed       = "client_not_authenticated"
	ReasonMemberInactive       = "member_inactive"
	ReasonCredGenStale         = "credential_generation_stale" //nolint:gosec // G101 false positive: internal reason-code string, not a credential
	ReasonCredInactive         = "credential_inactive"         //nolint:gosec // G101 false positive: internal reason-code string, not a credential
	ReasonMachineMismatch      = "machine_binding_mismatch"
	ReasonAgentNotAllowed      = "agent_not_allowed"
	ReasonAssuranceUnknown     = "assurance_unresolved"
	ReasonSharedSecretDisabled = "shared_secret_disabled"
	ReasonNoRuleMatched        = "no_rule_matched"
)

// ExchangeRequest is the parsed token-endpoint request (doc3 §2.4, plus the
// grant type so one table covers F1 and F5).
type ExchangeRequest struct {
	GrantType                                                                 string
	SubjectToken, SubjectType, ActorToken, ActorType, Resource, RequestedType string
}

// ExchangeContext is everything the STS re-checked for THIS exchange (R2:
// every exchange re-checks member, generation, allowlist, credential and
// machine binding). The first seven fields are doc3's; the rest are the
// verification outcomes and resolved assurance the table also needs.
type ExchangeContext struct {
	MemberActive        bool
	MemberGen, CredGen  int64
	AgentAllowed        bool
	CredActive          bool
	MachineBound        bool
	SubjectVerified     bool // the enrolment bearer verified (token exchange)
	ActorVerified       bool // VerifyActorAssertion succeeded
	ActorCredGen        int64
	ClientAuthenticated bool // the OAuth client authenticated (client_credentials)
	SharedSecretAllowed bool // [agent_access].client_secret_governed_enabled
	CredAssurance       CredentialAssurance
	ClientAttestation   ClientAttestation
	Agent               AgentRef
	Node                NodeRef
}

// ExchangeDecision is the table's outcome.
type ExchangeDecision struct {
	Allow    bool
	Cred     CredentialAssurance
	Attest   ClientAttestation
	Reason   string
	ActChain *ActClaim
	Error    OAuthError
}

// ExchangeRule is one row: when GrantType matches ("" = any) and When holds,
// the row decides. Rows are walked top-down; the first match wins.
type ExchangeRule struct {
	Name      string
	GrantType string
	When      func(ExchangeRequest, ExchangeContext) bool
	Allow     bool
	Reason    string
	Error     OAuthError
}

const (
	gtTE = GrantTypeTokenExchange
	gtCC = GrantTypeClientCredentials
)

func deny(name, gt, reason string, e OAuthError, when func(ExchangeRequest, ExchangeContext) bool) ExchangeRule {
	return ExchangeRule{Name: name, GrantType: gt, When: when, Reason: reason, Error: e}
}

// DefaultExchangeRules is the canonical P1 table (F1 token exchange + F5
// client credentials). Deny rows come first; each grant type ends in ONE
// allow row whose predicate re-asserts every positive condition, and
// DecideExchange denies when nothing matched - so the table fails closed.
func DefaultExchangeRules() []ExchangeRule {
	return []ExchangeRule{
		deny("grant type unsupported", "", ReasonUnsupportedGrant, OAuthUnsupportedGrantType,
			func(r ExchangeRequest, _ ExchangeContext) bool { return r.GrantType != gtTE && r.GrantType != gtCC }),
		deny("resource missing", "", ReasonMissingResource, OAuthInvalidTarget,
			func(r ExchangeRequest, _ ExchangeContext) bool { return r.Resource == "" }),
		deny("requested type not access_token", "", ReasonRequestedType, OAuthInvalidRequest,
			func(r ExchangeRequest, _ ExchangeContext) bool {
				return r.RequestedType != "" && r.RequestedType != TokenTypeAccessToken
			}),
		// --- F1 token exchange: wire contract first (R2/R6/R8.28.l) ---
		deny("subject token missing", gtTE, ReasonMissingSubject, OAuthInvalidRequest,
			func(r ExchangeRequest, _ ExchangeContext) bool { return r.SubjectToken == "" || r.SubjectType == "" }),
		deny("subject type unsupported", gtTE, ReasonSubjectType, OAuthInvalidRequest,
			func(r ExchangeRequest, _ ExchangeContext) bool {
				return r.SubjectType != TokenTypeAccessToken && r.SubjectType != TokenTypeEnrolmentBearer
			}),
		deny("actor token/type half present", gtTE, ReasonActorHalfPresent, OAuthInvalidRequest,
			func(r ExchangeRequest, _ ExchangeContext) bool { return (r.ActorToken == "") != (r.ActorType == "") }),
		deny("actor type unsupported", gtTE, ReasonActorType, OAuthInvalidRequest,
			func(r ExchangeRequest, _ ExchangeContext) bool {
				return r.ActorType != "" && r.ActorType != TokenTypeJWT
			}),
		// P1 ships only the F1 NODE exchange, which always carries the
		// actor assertion; hosted OBO (P7b, actor omitted) adds its own rows
		// ABOVE this one when it lands.
		deny("actor token required (F1 node exchange)", gtTE, ReasonActorRequired, OAuthInvalidRequest,
			func(r ExchangeRequest, _ ExchangeContext) bool { return r.ActorToken == "" }),
		deny("subject bearer invalid", gtTE, ReasonSubjectInvalid, OAuthInvalidGrant,
			func(_ ExchangeRequest, c ExchangeContext) bool { return !c.SubjectVerified }),
		deny("actor assertion invalid", gtTE, ReasonActorInvalid, OAuthInvalidGrant,
			func(_ ExchangeRequest, c ExchangeContext) bool { return !c.ActorVerified }),
		deny("member deprovisioned/inactive", gtTE, ReasonMemberInactive, OAuthInvalidGrant,
			func(_ ExchangeRequest, c ExchangeContext) bool { return !c.MemberActive }),
		deny("actor cred generation stale", gtTE, ReasonCredGenStale, OAuthInvalidGrant,
			func(_ ExchangeRequest, c ExchangeContext) bool { return c.ActorCredGen != c.CredGen }),
		deny("machine binding mismatch", gtTE, ReasonMachineMismatch, OAuthInvalidGrant,
			func(_ ExchangeRequest, c ExchangeContext) bool { return !c.MachineBound }),
		// --- F5 client credentials ---
		deny("tokens on client_credentials", gtCC, ReasonUnexpectedTokens, OAuthInvalidRequest,
			func(r ExchangeRequest, _ ExchangeContext) bool {
				return r.SubjectToken != "" || r.ActorToken != "" || r.SubjectType != "" || r.ActorType != ""
			}),
		deny("client not authenticated", gtCC, ReasonClientUnauthed, OAuthInvalidClient,
			func(_ ExchangeRequest, c ExchangeContext) bool { return !c.ClientAuthenticated }),
		// --- common tail ---
		deny("credential inactive/revoked", "", ReasonCredInactive, OAuthInvalidGrant,
			func(_ ExchangeRequest, c ExchangeContext) bool { return !c.CredActive }),
		deny("assurance unresolved", "", ReasonAssuranceUnknown, OAuthInvalidGrant,
			func(_ ExchangeRequest, c ExchangeContext) bool {
				return !c.CredAssurance.Valid() || !c.ClientAttestation.Valid() || c.Agent.ClientID == ""
			}),
		deny("shared secret disabled", "", ReasonSharedSecretDisabled, OAuthUnauthorizedClient,
			func(_ ExchangeRequest, c ExchangeContext) bool {
				return c.CredAssurance == CredSharedSecret && !c.SharedSecretAllowed
			}),
		deny("agent not on the org allowlist", "", ReasonAgentNotAllowed, OAuthUnauthorizedClient,
			func(_ ExchangeRequest, c ExchangeContext) bool { return !c.AgentAllowed }),
		{
			Name: "F1 node exchange allowed", GrantType: gtTE, Allow: true, Reason: ReasonAllowed,
			When: func(r ExchangeRequest, c ExchangeContext) bool {
				return r.ActorToken != "" && c.SubjectVerified && c.ActorVerified && c.MemberActive &&
					c.ActorCredGen == c.CredGen && c.CredActive && c.MachineBound && c.AgentAllowed
			},
		},
		{
			Name: "F5 client credentials allowed", GrantType: gtCC, Allow: true, Reason: ReasonAllowed,
			When: func(_ ExchangeRequest, c ExchangeContext) bool {
				return c.ClientAuthenticated && c.CredActive && c.AgentAllowed
			},
		},
	}
}

// DecideExchange walks rules top-down and returns the first matching row's
// decision; no match denies (fail closed). An allow carries the resolved
// assurance enums and the RFC 8693 actor chain for the mint.
func DecideExchange(rules []ExchangeRule, req ExchangeRequest, ctx ExchangeContext) ExchangeDecision {
	for _, r := range rules {
		if r.GrantType != "" && r.GrantType != req.GrantType {
			continue
		}
		if r.When == nil || !r.When(req, ctx) {
			continue
		}
		if !r.Allow {
			e := r.Error
			if e == "" {
				e = OAuthInvalidGrant
			}
			return ExchangeDecision{Reason: r.Reason, Error: e}
		}
		return ExchangeDecision{
			Allow:    true,
			Cred:     ctx.CredAssurance,
			Attest:   ctx.ClientAttestation,
			Reason:   r.Reason,
			ActChain: actChain(ctx),
		}
	}
	return ExchangeDecision{Reason: ReasonNoRuleMatched, Error: OAuthInvalidGrant}
}

func actChain(ctx ExchangeContext) *ActClaim {
	a := &ActClaim{
		Sub:                  ctx.Agent.ClientID,
		SboKind:              ctx.Agent.Kind,
		SboProduct:           ctx.Agent.Product,
		SboCredAssurance:     ctx.CredAssurance,
		SboClientAttestation: ctx.ClientAttestation,
	}
	if ctx.Node.ID != "" {
		a.Act = &ActClaim{Sub: "node:" + ctx.Node.ID}
	}
	return a
}
