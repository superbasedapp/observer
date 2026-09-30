package agentid

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

// obo.go is the PURE core of hosted end-user OBO (doc3 §11.10 W7b, R9.10,
// R8.27.f/B12, R8.25.n, R8.24.n): an RFC 8693 token exchange whose
// subject_token is the end user's IdP id_token and which carries NO
// actor_token - the hosted app authenticates the token endpoint as the OAuth
// CLIENT and `act` is derived from that authenticated client. This file owns
// the subject-token classification (substitution refusals), the id_token
// claim checks against a registered trust issuer, the subject-stability rule
// that names the end user, the replay-key digest rule and the OBO exchange
// decision table. It performs no I/O: the trust registration, its keys, the
// agent's capabilities and the replay store are resolved by the caller
// (internal/mcpgw/gwhttp's oboExchange over the stswire trust seam).

// TokenTypeIDToken is the RFC 8693 subject_token_type of an OpenID Connect
// id_token (the hosted OBO subject).
const TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token" //nolint:gosec // G101 false positive: public RFC 8693 token-type URN, not a credential

// CapActForEndUsers is the agent_definition capability that lets a hosted
// agent act for end users (doc3 §3.2 agent_definition.capabilities).
const CapActForEndUsers = "act_for_end_users"

// id_token bounds.
const (
	// MaxIDTokenBytes caps an inbound id_token (IdP tokens carry group and
	// profile claims; 16 KiB is generous and still bounded).
	MaxIDTokenBytes = 16 << 10
	// IDTokenSkew tolerates clock drift between the IdP and the STS on
	// exp / nbf / iat / max age (the R9 low-friction posture: external IdP
	// clocks are not ours).
	IDTokenSkew = 60 * time.Second
	// DefaultMaxIDTokenAge is the trust registration's DDL default age bound.
	DefaultMaxIDTokenAge = 300 * time.Second
	// MaxIDTokenAudiences bounds an id_token aud array.
	MaxIDTokenAudiences = 16
	// MaxSubjectClaimBytes bounds sub / oid.
	MaxSubjectClaimBytes = 255
	// MaxEndUserSubjectBytes bounds the minted `enduser:` subject.
	MaxEndUserSubjectBytes = 512
	// MaxAMRValues bounds the amr values carried into the minted token.
	MaxAMRValues = 16
)

// Subject stability modes (agent_trust_issuer.subject_stability): which claim
// names the end user.
const (
	// StabilitySub: the IdP `sub` names the end user. The DDL default. OIDC
	// guarantees `sub` unique only WITHIN one issuer, so the minted subject
	// is ALWAYS issuer-namespaced (`enduser:<iss>#<sub>`, operator ruling
	// R-S3-6): two registered IdPs that happen to issue the same `sub` can
	// never collide onto one end user. It mints exactly what StabilitySubIss
	// mints (one function, issuerSubject, so the two cannot drift); the two
	// names remain distinct only as the admin's stated intent.
	StabilitySub = "sub"
	// StabilityOID: the Entra `oid` (object id, stable across the tenant's
	// apps, unlike Entra's per-app pairwise `sub`) names the end user; a token
	// without `oid` is refused.
	StabilityOID = "oid"
	// StabilitySubIss: the (iss, sub) pair names the end user - for estates
	// with several IdPs whose subjects may collide. Since R-S3-6 it mints the
	// same issuer-namespaced subject as StabilitySub.
	StabilitySubIss = "sub_iss"
)

// EndUserPrefix prefixes every OBO subject (UserRef "enduser:...").
const EndUserPrefix = "enduser:"

// TrustPolicy is the pure view of ONE registered agent_trust_issuer row the
// id_token is checked against (doc3 §11.10 DDL). The caller resolves it by
// (org, iss, acting client) and never hands a disabled row as Active.
type TrustPolicy struct {
	IssuerID  string
	IssuerURL string
	// Tenant, when set, must equal the id_token `tid` claim.
	Tenant string
	// ClientID is the OAuth client the registration trusts (R8.25.n: never a
	// wildcard) - matched by the caller against the authenticated client.
	ClientID string
	// MultiClient: the id_token may carry several audiences; azp is then
	// REQUIRED and must be one of AllowedAzp (it pins the acting client).
	MultiClient bool
	AllowedAud  []string
	AllowedAzp  []string
	// MaxTokenAge bounds now - iat (zero -> DefaultMaxIDTokenAge).
	MaxTokenAge      time.Duration
	SubjectStability string
	// MayAct is the issuer-side delegation grant: with it the registered
	// client may act for this issuer's end users even when its
	// agent_definition lacks act_for_end_users.
	MayAct bool
	Active bool
}

func (p TrustPolicy) maxAge() time.Duration {
	if p.MaxTokenAge <= 0 {
		return DefaultMaxIDTokenAge
	}
	return p.MaxTokenAge
}

// ---- subject-token classification (substitution refusals, R8.27.f) --------

// SubjectTokenClass is what a presented subject_token IS, decided before any
// trust lookup. Only SubjectIsIDTokenCandidate may proceed; every other
// class is a refused substitution.
type SubjectTokenClass string

// Subject token classes.
const (
	SubjectIsIDTokenCandidate SubjectTokenClass = "id_token_candidate"
	SubjectIsEmpty            SubjectTokenClass = "empty"
	SubjectIsAPIKey           SubjectTokenClass = "api_key"
	SubjectIsNotJWS           SubjectTokenClass = "not_a_jws"
	SubjectIsAccessToken      SubjectTokenClass = "access_token"
	SubjectIsNodeActor        SubjectTokenClass = "node_actor_assertion"
	SubjectIsDPoPProof        SubjectTokenClass = "dpop_proof"
	SubjectIsClientAssertion  SubjectTokenClass = "client_assertion"
	SubjectIsOwnToken         SubjectTokenClass = "own_issuer_token"
	SubjectIsUnknownType      SubjectTokenClass = "unknown_typ"
)

// OwnIdentity is this authorization server's own naming, used to recognise
// a token WE issued (or a client assertion addressed to us) presented as an
// OBO subject.
type OwnIdentity struct {
	Issuer        string
	TokenEndpoint string
}

// subjectProbe is the unverified view the classification rows read.
type subjectProbe struct {
	raw    string
	parsed bool
	typ    string
	iss    string
	sub    string
	aud    []string
	own    OwnIdentity
}

// idTokenTyps are the header typ values an id_token may carry: absent or the
// generic "JWT" (OIDC Core does not register an explicit type).
var idTokenTyps = map[string]bool{"": true, "jwt": true}

// subjectClassRows is the ordered classification table: the first matching
// row names the class; a token no row refuses is an id_token candidate.
var subjectClassRows = []struct {
	class SubjectTokenClass
	match func(p subjectProbe) bool
}{
	{SubjectIsEmpty, func(p subjectProbe) bool { return strings.TrimSpace(p.raw) == "" }},
	// An org-issued MCP API key is a CLIENT credential, never a subject.
	{SubjectIsAPIKey, func(p subjectProbe) bool { return strings.HasPrefix(p.raw, "sbo_mcp_") }},
	{SubjectIsNotJWS, func(p subjectProbe) bool { return !p.parsed }},
	{SubjectIsAccessToken, func(p subjectProbe) bool { return p.typ == TypAccessToken || p.typ == "application/at+jwt" }},
	// The node actor profile (§4.3) is F1-only; hosted OBO never accepts it.
	{SubjectIsNodeActor, func(p subjectProbe) bool { return p.typ == TypActorAssertion }},
	{SubjectIsDPoPProof, func(p subjectProbe) bool { return p.typ == "dpop+jwt" }},
	{SubjectIsClientAssertion, func(p subjectProbe) bool { return p.typ == "client-authentication+jwt" }},
	// A token this AS issued (or any token claiming our issuer).
	{SubjectIsOwnToken, func(p subjectProbe) bool { return p.own.Issuer != "" && p.iss == p.own.Issuer }},
	// An RFC 7523 client assertion (iss == sub, addressed to this AS) under a
	// generic typ.
	{SubjectIsClientAssertion, func(p subjectProbe) bool {
		if p.iss == "" || p.iss != p.sub {
			return false
		}
		for _, a := range p.aud {
			if a != "" && (a == p.own.TokenEndpoint || a == p.own.Issuer) {
				return true
			}
		}
		return false
	}},
	{SubjectIsUnknownType, func(p subjectProbe) bool { return !idTokenTyps[p.typ] }},
}

// ClassifySubjectToken decides what a presented OBO subject_token is WITHOUT
// verifying it. Anything but SubjectIsIDTokenCandidate is a substitution the
// exchange refuses (R8.27.f): a node sbo-actor+jwt, an access token (ours or
// anyone's), a DPoP proof, a client assertion or an sbo_mcp_ API key
// presented as the subject.
func ClassifySubjectToken(tok string, own OwnIdentity) SubjectTokenClass {
	p := subjectProbe{raw: tok, own: own}
	if j, err := jose.Parse(tok, MaxIDTokenBytes); err == nil {
		p.parsed = true
		p.typ = strings.ToLower(j.Header.Typ)
		var w struct {
			Iss string          `json:"iss"`
			Sub string          `json:"sub"`
			Aud json.RawMessage `json:"aud"`
		}
		if json.Unmarshal(j.Payload, &w) == nil {
			p.iss, p.sub = w.Iss, w.Sub
			p.aud, _ = decodeAudiences(w.Aud)
		}
	}
	for _, row := range subjectClassRows {
		if row.match(p) {
			return row.class
		}
	}
	return SubjectIsIDTokenCandidate
}

// IDTokenIssuer returns the (UNVERIFIED) iss of an id_token so the caller can
// look up the trust registration. Nothing else is trusted.
func IDTokenIssuer(tok string) (string, error) {
	j, err := jose.Parse(tok, MaxIDTokenBytes)
	if err != nil {
		return "", oboErr(OBOErrMalformed, "%v", err)
	}
	var w struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(j.Payload, &w); err != nil || w.Iss == "" {
		return "", oboErr(OBOErrMalformed, "id_token has no iss")
	}
	return w.Iss, nil
}

// ---- id_token verification ---------------------------------------------------

// IDTokenClaims is the verified id_token view the exchange reads.
type IDTokenClaims struct {
	Iss      string
	Sub      string
	Aud      []string
	Azp      string
	Exp      int64
	Iat      int64
	Nbf      int64
	Jti      string
	Nonce    string
	Oid      string
	Tid      string
	AuthTime int64
	Acr      string
	Amr      []string
}

// idTokenWire is the JSON shape (aud raw: a string or an array).
type idTokenWire struct {
	Iss      string          `json:"iss"`
	Sub      string          `json:"sub"`
	Aud      json.RawMessage `json:"aud"`
	Azp      string          `json:"azp"`
	Exp      int64           `json:"exp"`
	Iat      int64           `json:"iat"`
	Nbf      int64           `json:"nbf"`
	Jti      string          `json:"jti"`
	Nonce    string          `json:"nonce"`
	Oid      string          `json:"oid"`
	Tid      string          `json:"tid"`
	AuthTime int64           `json:"auth_time"`
	Acr      string          `json:"acr"`
	Amr      []string        `json:"amr"`
}

// OBOErrorCode is the CLOSED id_token rejection vocabulary. Every code maps
// to the same external invalid_grant (no enumeration oracle).
type OBOErrorCode string

// OBO error codes.
const (
	OBOErrMalformed     OBOErrorCode = "malformed"
	OBOErrType          OBOErrorCode = "bad_type"
	OBOErrNoKey         OBOErrorCode = "no_matching_key"
	OBOErrSignature     OBOErrorCode = "bad_signature"
	OBOErrIssuer        OBOErrorCode = "wrong_issuer"
	OBOErrTenant        OBOErrorCode = "wrong_tenant"
	OBOErrAudience      OBOErrorCode = "wrong_audience"
	OBOErrAzp           OBOErrorCode = "wrong_azp"
	OBOErrExpired       OBOErrorCode = "expired"
	OBOErrNotYetValid   OBOErrorCode = "not_yet_valid"
	OBOErrTooOld        OBOErrorCode = "exceeds_max_token_age"
	OBOErrClaims        OBOErrorCode = "bad_claims"
	OBOErrSubject       OBOErrorCode = "unstable_subject"
	OBOErrInactive      OBOErrorCode = "issuer_disabled"
	OBOErrPolicyInvalid OBOErrorCode = "trust_policy_invalid"
)

// ErrInvalidIDToken is matched (errors.Is) by every *OBOError.
var ErrInvalidIDToken = errors.New("agentid: invalid OBO id_token")

// OBOError is a typed id_token rejection.
type OBOError struct {
	Code   OBOErrorCode
	Detail string
}

// Error implements error.
func (e *OBOError) Error() string {
	return "agentid: invalid OBO id_token: " + string(e.Code) + ": " + e.Detail
}

// Is makes every OBOError match ErrInvalidIDToken.
func (e *OBOError) Is(target error) bool { return target == ErrInvalidIDToken }

func oboErr(code OBOErrorCode, format string, a ...any) error {
	return &OBOError{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// OBOCodeOf returns the OBOErrorCode of err ("" otherwise).
func OBOCodeOf(err error) OBOErrorCode {
	var oe *OBOError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return ""
}

// IDTokenExpect is what one OBO id_token is verified against.
type IDTokenExpect struct {
	// Policy is the registered trust issuer (resolved by the caller).
	Policy TrustPolicy
	// Keys are the registration's verification keys (jwks_inline, or the
	// jwks_uri set fetched by the caller).
	Keys []JWK
	// Algs is the asymmetric allowlist (empty -> jose.DefaultAlgs():
	// EdDSA / ES256 / RS256; none and HMAC are unrepresentable).
	Algs jose.AlgSet
	// Now is the verification instant (zero -> time.Now()).
	Now time.Time
	// Skew overrides IDTokenSkew (zero -> IDTokenSkew).
	Skew time.Duration
}

// VerifyIDToken verifies an OBO subject id_token: header typ (absent or
// "JWT"), no embedded jwk, alg in the allowlist and paired with the key,
// signature under a registered key (selected by kid, or every key when the
// header has none), then every claim rule of the trust registration
// (CheckIDTokenClaims). OBOErrNoKey means no registered key matched the kid -
// the caller may refresh a remote key set once and retry.
func VerifyIDToken(tok string, e IDTokenExpect) (IDTokenClaims, error) {
	if !e.Policy.Active {
		return IDTokenClaims{}, oboErr(OBOErrInactive, "trust issuer %s is not active", e.Policy.IssuerID)
	}
	j, err := jose.Parse(tok, MaxIDTokenBytes)
	if err != nil {
		return IDTokenClaims{}, oboErr(OBOErrMalformed, "%v", err)
	}
	if !idTokenTyps[strings.ToLower(j.Header.Typ)] {
		return IDTokenClaims{}, oboErr(OBOErrType, "typ %q is not an id_token", j.Header.Typ)
	}
	if j.Header.JWK != nil {
		return IDTokenClaims{}, oboErr(OBOErrMalformed, "an id_token never embeds its verification key")
	}
	algs := e.Algs
	if algs.Empty() {
		algs = jose.DefaultAlgs()
	}
	if !algs.Allows(j.Header.Alg) {
		return IDTokenClaims{}, oboErr(OBOErrSignature, "alg %q not in the allowlist", j.Header.Alg)
	}
	cands := keyCandidates(e.Keys, j.Header.Kid)
	if len(cands) == 0 {
		return IDTokenClaims{}, oboErr(OBOErrNoKey, "no registered key for kid %q", j.Header.Kid)
	}
	var sigErr error
	verified := false
	for _, k := range cands {
		if err := j.Verify(algs, k); err != nil {
			sigErr = err
			continue
		}
		verified = true
		break
	}
	if !verified {
		return IDTokenClaims{}, oboErr(OBOErrSignature, "%v", sigErr)
	}
	var w idTokenWire
	if err := jose.DecodeClaims(j.Payload, &w); err != nil {
		return IDTokenClaims{}, oboErr(OBOErrMalformed, "%v", err)
	}
	aud, err := decodeAudiences(w.Aud)
	if err != nil {
		return IDTokenClaims{}, oboErr(OBOErrAudience, "%v", err)
	}
	c := IDTokenClaims{
		Iss: w.Iss, Sub: w.Sub, Aud: aud, Azp: w.Azp, Exp: w.Exp, Iat: w.Iat, Nbf: w.Nbf,
		Jti: w.Jti, Nonce: w.Nonce, Oid: w.Oid, Tid: w.Tid, AuthTime: w.AuthTime, Acr: w.Acr, Amr: w.Amr,
	}
	now := e.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := e.Skew
	if skew <= 0 {
		skew = IDTokenSkew
	}
	if err := CheckIDTokenClaims(c, e.Policy, now, skew); err != nil {
		return IDTokenClaims{}, err
	}
	return c, nil
}

// keyCandidates orders the keys worth trying: those whose kid (or RFC 7638
// thumbprint) equals the header kid; with no header kid, every key.
func keyCandidates(keys []JWK, kid string) []JWK {
	if kid == "" {
		return keys
	}
	var out []JWK
	for _, k := range keys {
		if k.Kid == kid {
			out = append(out, k)
			continue
		}
		if tp, err := k.Thumbprint(); err == nil && tp == kid {
			out = append(out, k)
		}
	}
	return out
}

// claimCheck is one id_token rule row.
type claimCheck struct {
	name string
	code OBOErrorCode
	bad  func(c IDTokenClaims, p TrustPolicy, now, skew int64) bool
}

// idTokenClaimRows is the ordered id_token rule table (doc3 §11.10 step 3:
// iss / tenant / aud / azp per allowed_aud + allowed_azp + multi_client /
// exp / max age / subject stability). Every row is one test case.
var idTokenClaimRows = []claimCheck{
	{"trust policy names an issuer and at least one audience", OBOErrPolicyInvalid, func(_ IDTokenClaims, p TrustPolicy, _, _ int64) bool {
		return p.IssuerURL == "" || len(p.AllowedAud) == 0 || (p.MultiClient && len(p.AllowedAzp) == 0)
	}},
	{"iss equals the registered issuer exactly", OBOErrIssuer, func(c IDTokenClaims, p TrustPolicy, _, _ int64) bool {
		return c.Iss != p.IssuerURL
	}},
	{"tid equals the registered tenant", OBOErrTenant, func(c IDTokenClaims, p TrustPolicy, _, _ int64) bool {
		return p.Tenant != "" && c.Tid != p.Tenant
	}},
	{"sub present, bounded, printable", OBOErrClaims, func(c IDTokenClaims, _ TrustPolicy, _, _ int64) bool {
		return !boundedPrintable(c.Sub, MaxSubjectClaimBytes)
	}},
	{"single-client trust: exactly one audience", OBOErrAudience, func(c IDTokenClaims, p TrustPolicy, _, _ int64) bool {
		return !p.MultiClient && len(c.Aud) != 1
	}},
	{"every audience is an allowed audience", OBOErrAudience, func(c IDTokenClaims, p TrustPolicy, _, _ int64) bool {
		if p.MultiClient {
			return !anyIn(c.Aud, p.AllowedAud)
		}
		return !allIn(c.Aud, p.AllowedAud)
	}},
	{"multi-client trust: azp required and pinned", OBOErrAzp, func(c IDTokenClaims, p TrustPolicy, _, _ int64) bool {
		return p.MultiClient && (c.Azp == "" || !in(c.Azp, p.AllowedAzp))
	}},
	{"single-client trust: a present azp is the audience or allowed", OBOErrAzp, func(c IDTokenClaims, p TrustPolicy, _, _ int64) bool {
		return !p.MultiClient && c.Azp != "" && !in(c.Azp, c.Aud) && !in(c.Azp, p.AllowedAzp)
	}},
	{"exp present", OBOErrClaims, func(c IDTokenClaims, _ TrustPolicy, _, _ int64) bool { return c.Exp == 0 }},
	{"iat present", OBOErrClaims, func(c IDTokenClaims, _ TrustPolicy, _, _ int64) bool { return c.Iat == 0 }},
	{"not expired", OBOErrExpired, func(c IDTokenClaims, _ TrustPolicy, now, skew int64) bool { return now >= c.Exp+skew }},
	{"iat not in the future", OBOErrNotYetValid, func(c IDTokenClaims, _ TrustPolicy, now, skew int64) bool { return c.Iat > now+skew }},
	{"nbf reached", OBOErrNotYetValid, func(c IDTokenClaims, _ TrustPolicy, now, skew int64) bool { return c.Nbf != 0 && c.Nbf > now+skew }},
	{"exp after iat", OBOErrClaims, func(c IDTokenClaims, _ TrustPolicy, _, _ int64) bool { return c.Exp <= c.Iat }},
	{"within max_token_age", OBOErrTooOld, func(c IDTokenClaims, p TrustPolicy, now, skew int64) bool {
		return now-c.Iat > int64(p.maxAge()/time.Second)+skew
	}},
	{"oid stability needs a printable oid", OBOErrSubject, func(c IDTokenClaims, p TrustPolicy, _, _ int64) bool {
		return p.SubjectStability == StabilityOID && !boundedPrintable(c.Oid, MaxSubjectClaimBytes)
	}},
	{"known subject stability", OBOErrPolicyInvalid, func(_ IDTokenClaims, p TrustPolicy, _, _ int64) bool {
		return !validStability(p.SubjectStability)
	}},
	{"jti, when present, bounded", OBOErrClaims, func(c IDTokenClaims, _ TrustPolicy, _, _ int64) bool {
		return c.Jti != "" && len(c.Jti) > 256
	}},
}

// CheckIDTokenClaims walks the id_token rule table top-down; the first
// failing row is the error.
func CheckIDTokenClaims(c IDTokenClaims, p TrustPolicy, now time.Time, skew time.Duration) error {
	n, s := now.Unix(), int64(skew/time.Second)
	for _, row := range idTokenClaimRows {
		if row.bad(c, p, n, s) {
			return oboErr(row.code, "%s", row.name)
		}
	}
	return nil
}

func validStability(s string) bool {
	switch s {
	case "", StabilitySub, StabilityOID, StabilitySubIss:
		return true
	}
	return false
}

// boundedPrintable reports a non-empty value of at most max bytes with no
// control or whitespace-only content.
func boundedPrintable(s string, max int) bool {
	if strings.TrimSpace(s) == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func in(v string, set []string) bool {
	for _, s := range set {
		if s != "" && s == v {
			return true
		}
	}
	return false
}

func anyIn(vs, set []string) bool {
	for _, v := range vs {
		if in(v, set) {
			return true
		}
	}
	return false
}

func allIn(vs, set []string) bool {
	if len(vs) == 0 {
		return false
	}
	for _, v := range vs {
		if !in(v, set) {
			return false
		}
	}
	return true
}

// decodeAudiences reads aud as a string or a bounded array of strings.
func decodeAudiences(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, errors.New("aud missing")
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if one == "" {
			return nil, errors.New("aud is empty")
		}
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, errors.New("aud is neither a string nor an array of strings")
	}
	if len(many) == 0 || len(many) > MaxIDTokenAudiences {
		return nil, fmt.Errorf("aud array length %d outside 1..%d", len(many), MaxIDTokenAudiences)
	}
	return many, nil
}

// ---- end-user subject + replay key -------------------------------------------

// EndUserSubject names the end user of a VERIFIED id_token under the
// registration's subject_stability (the minted token's sub):
//
//	sub     -> "enduser:" + iss + "#" + sub   (R-S3-6: always issuer-namespaced)
//	sub_iss -> "enduser:" + iss + "#" + sub
//	oid     -> "enduser:" + oid               (Entra oid is tenant-stable)
//
// `sub` and `sub_iss` share issuerSubject so their minted format cannot
// drift. The empty stability is the DDL default, `sub`.
func EndUserSubject(c IDTokenClaims, p TrustPolicy) (string, error) {
	var v string
	switch p.SubjectStability {
	case "", StabilitySub, StabilitySubIss:
		var err error
		if v, err = issuerSubject(c); err != nil {
			return "", err
		}
	case StabilityOID:
		v = c.Oid
	default:
		return "", oboErr(OBOErrPolicyInvalid, "unknown subject_stability %q", p.SubjectStability)
	}
	if !boundedPrintable(v, MaxEndUserSubjectBytes-len(EndUserPrefix)) {
		return "", oboErr(OBOErrSubject, "the %s subject is empty, too long or unprintable", p.SubjectStability)
	}
	return EndUserPrefix + v, nil
}

// issuerSubject is the ONE issuer-namespaced end-user name, `<iss>#<sub>`
// (without the enduser: prefix), shared by the `sub` and `sub_iss`
// stabilities. Both claims are required: an id_token without an issuer or a
// subject names nobody.
func issuerSubject(c IDTokenClaims) (string, error) {
	if c.Iss == "" || c.Sub == "" {
		return "", oboErr(OBOErrSubject, "an issuer-namespaced subject needs iss and sub")
	}
	return c.Iss + "#" + c.Sub, nil
}

// Replay-key domain separators: a jti hash and a claims digest can never
// collide with each other.
const (
	replayJTIDomain    = "sbo-obo-subject-jti-v1\x00"
	replayDigestDomain = "sbo-obo-subject-digest-v1\x00"
)

// SubjectReplayKey is the subject_token_replay.jti_hash of a VERIFIED
// id_token (R8.27.f): hex SHA-256 of the token's jti when it has one, else
// hex SHA-256 of the canonical {aud (sorted), iat, iss, nonce, sub} object -
// a stable per-token digest for the jti-less id_tokens most IdPs issue. The
// two inputs are domain-separated.
func SubjectReplayKey(c IDTokenClaims) string {
	var sum [32]byte
	if c.Jti != "" {
		sum = sha256.Sum256([]byte(replayJTIDomain + c.Jti))
		return hex.EncodeToString(sum[:])
	}
	aud := append([]string(nil), c.Aud...)
	sort.Strings(aud)
	// Fields in lexicographic order: encoding/json emits struct fields in
	// declaration order, so this IS the canonical (sorted-key) form.
	canon, _ := json.Marshal(struct {
		Aud   []string `json:"aud"`
		Iat   int64    `json:"iat"`
		Iss   string   `json:"iss"`
		Nonce string   `json:"nonce"`
		Sub   string   `json:"sub"`
	}{aud, c.Iat, c.Iss, c.Nonce, c.Sub})
	sum = sha256.Sum256(append([]byte(replayDigestDomain), canon...))
	return hex.EncodeToString(sum[:])
}

// SubjectReplayExpiry is the replay row's exp: the last instant the id_token
// could still be accepted (the earlier of its exp and iat + max age) plus
// the skew, so a pruned row can never reopen a replay window.
func SubjectReplayExpiry(c IDTokenClaims, p TrustPolicy, skew time.Duration) int64 {
	if skew <= 0 {
		skew = IDTokenSkew
	}
	last := c.Exp
	if byAge := c.Iat + int64(p.maxAge()/time.Second); byAge < last {
		last = byAge
	}
	return last + int64(skew/time.Second)
}

// BoundedAMR returns the id_token amr values carried into the minted token
// (bounded count and length; the id_token is the fresh user assertion MFA
// claims may come from, R6).
func BoundedAMR(amr []string) []string {
	var out []string
	for _, v := range amr {
		if len(out) == MaxAMRValues {
			break
		}
		if boundedPrintable(v, 64) {
			out = append(out, v)
		}
	}
	return out
}

// HasCapability reports whether an agent_definition.capabilities JSON
// document grants name. Both shapes the registry has written are read: an
// array of names (["act_for_end_users"]) and an object of flags
// ({"act_for_end_users": true}). Anything else grants nothing.
func HasCapability(capabilitiesJSON, name string) bool {
	if strings.TrimSpace(capabilitiesJSON) == "" || name == "" {
		return false
	}
	var list []string
	if json.Unmarshal([]byte(capabilitiesJSON), &list) == nil {
		for _, c := range list {
			if c == name {
				return true
			}
		}
		return false
	}
	var flags map[string]json.RawMessage
	if json.Unmarshal([]byte(capabilitiesJSON), &flags) == nil {
		var on bool
		return json.Unmarshal(flags[name], &on) == nil && on
	}
	return false
}

// ---- the OBO exchange decision table ----------------------------------------

// OBO exchange reasons (the closed internal vocabulary, beside the F1/F5
// Reason* constants).
const (
	ReasonOBONotOBO            = "obo_not_an_id_token_exchange"
	ReasonOBOActorToken        = "obo_actor_token_present" //nolint:gosec // G101 false positive: internal reason-code string, not a credential
	ReasonOBOSubjectSubstitute = "obo_subject_token_substitution"
	ReasonOBOIssuerUnknown     = "obo_issuer_unregistered"
	ReasonOBONotDelegable      = "obo_agent_may_not_act_for_end_users"
	ReasonOBOSubjectInvalid    = "obo_subject_token_invalid"
	ReasonOBOReplay            = "obo_subject_token_replayed"
)

// OBOContext is everything the STS established for ONE hosted OBO exchange,
// gathered in table order (a stage that fails leaves every later flag
// false, so the first failing row is the stage that failed).
type OBOContext struct {
	ClientAuthenticated bool
	CredActive          bool
	AgentAllowed        bool
	SharedSecretAllowed bool
	CredAssurance       CredentialAssurance
	ClientAttestation   ClientAttestation
	Agent               AgentRef
	// SubjectClass is ClassifySubjectToken's verdict.
	SubjectClass SubjectTokenClass
	// IssuerRegistered: an ACTIVE agent_trust_issuer row trusts this (iss,
	// acting client).
	IssuerRegistered bool
	// Delegable: the agent holds act_for_end_users OR the issuer row has
	// may_act (doc3 §11.10 step 3).
	Delegable bool
	// SubjectVerified: VerifyIDToken + EndUserSubject succeeded.
	SubjectVerified bool
	// ReplayFresh: the subject_token_replay insert was fresh.
	ReplayFresh bool
}

// OBORule is one row of the OBO table: When holds -> the row decides.
type OBORule struct {
	Name   string
	When   func(ExchangeRequest, OBOContext) bool
	Allow  bool
	Reason string
	Error  OAuthError
}

func oboDeny(name, reason string, e OAuthError, when func(ExchangeRequest, OBOContext) bool) OBORule {
	return OBORule{Name: name, When: when, Reason: reason, Error: e}
}

// DefaultOBORules is the canonical hosted-OBO table (doc3 §11.10 W7b,
// R8.27.f). Wire rows first (decidable before any verification), then the
// client (same assurance tail as F5), then the subject, the trust issuer, the
// delegation gate, the id_token itself and the replay store; ONE allow row
// re-asserts every positive condition and DecideOBO denies when nothing
// matched, so the table fails closed.
func DefaultOBORules() []OBORule {
	return []OBORule{
		oboDeny("not a token exchange with an id_token subject", ReasonOBONotOBO, OAuthInvalidRequest,
			func(r ExchangeRequest, _ OBOContext) bool {
				return r.GrantType != GrantTypeTokenExchange || r.SubjectType != TokenTypeIDToken
			}),
		oboDeny("resource missing", ReasonMissingResource, OAuthInvalidTarget,
			func(r ExchangeRequest, _ OBOContext) bool { return r.Resource == "" }),
		oboDeny("requested type not access_token", ReasonRequestedType, OAuthInvalidRequest,
			func(r ExchangeRequest, _ OBOContext) bool {
				return r.RequestedType != "" && r.RequestedType != TokenTypeAccessToken
			}),
		oboDeny("subject token missing", ReasonMissingSubject, OAuthInvalidRequest,
			func(r ExchangeRequest, _ OBOContext) bool { return r.SubjectToken == "" }),
		// R8.27.f/B12: hosted OBO carries NO actor_token (act comes from the
		// authenticated OAuth client) - either half present is refused.
		oboDeny("actor token on hosted OBO", ReasonOBOActorToken, OAuthInvalidRequest,
			func(r ExchangeRequest, _ OBOContext) bool { return r.ActorToken != "" || r.ActorType != "" }),
		oboDeny("client not authenticated", ReasonClientUnauthed, OAuthInvalidClient,
			func(_ ExchangeRequest, c OBOContext) bool { return !c.ClientAuthenticated }),
		oboDeny("credential inactive/revoked", ReasonCredInactive, OAuthInvalidGrant,
			func(_ ExchangeRequest, c OBOContext) bool { return !c.CredActive }),
		oboDeny("assurance unresolved", ReasonAssuranceUnknown, OAuthInvalidGrant,
			func(_ ExchangeRequest, c OBOContext) bool {
				return !c.CredAssurance.Valid() || !c.ClientAttestation.Valid() || c.Agent.ClientID == ""
			}),
		oboDeny("shared secret disabled", ReasonSharedSecretDisabled, OAuthUnauthorizedClient,
			func(_ ExchangeRequest, c OBOContext) bool {
				return c.CredAssurance == CredSharedSecret && !c.SharedSecretAllowed
			}),
		oboDeny("agent not on the org allowlist", ReasonAgentNotAllowed, OAuthUnauthorizedClient,
			func(_ ExchangeRequest, c OBOContext) bool { return !c.AgentAllowed }),
		oboDeny("subject token is not an id_token (substitution)", ReasonOBOSubjectSubstitute, OAuthInvalidGrant,
			func(_ ExchangeRequest, c OBOContext) bool { return c.SubjectClass != SubjectIsIDTokenCandidate }),
		oboDeny("issuer not registered for this client", ReasonOBOIssuerUnknown, OAuthInvalidGrant,
			func(_ ExchangeRequest, c OBOContext) bool { return !c.IssuerRegistered }),
		oboDeny("agent may not act for end users", ReasonOBONotDelegable, OAuthUnauthorizedClient,
			func(_ ExchangeRequest, c OBOContext) bool { return !c.Delegable }),
		oboDeny("id_token invalid", ReasonOBOSubjectInvalid, OAuthInvalidGrant,
			func(_ ExchangeRequest, c OBOContext) bool { return !c.SubjectVerified }),
		oboDeny("id_token replayed", ReasonOBOReplay, OAuthInvalidGrant,
			func(_ ExchangeRequest, c OBOContext) bool { return !c.ReplayFresh }),
		{
			Name: "hosted OBO allowed", Allow: true, Reason: ReasonAllowed,
			When: func(r ExchangeRequest, c OBOContext) bool {
				return r.GrantType == GrantTypeTokenExchange && r.SubjectType == TokenTypeIDToken &&
					r.ActorToken == "" && r.ActorType == "" && c.ClientAuthenticated && c.CredActive &&
					c.AgentAllowed && c.SubjectClass == SubjectIsIDTokenCandidate && c.IssuerRegistered &&
					c.Delegable && c.SubjectVerified && c.ReplayFresh
			},
		},
	}
}

// DecideOBO walks rules top-down; the first matching row decides and no match
// denies (fail closed). An allow carries the client's assurance enums and the
// derived actor (the agent, with NO nested node actor).
func DecideOBO(rules []OBORule, req ExchangeRequest, c OBOContext) ExchangeDecision {
	for _, r := range rules {
		if r.When == nil || !r.When(req, c) {
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
			Allow: true, Cred: c.CredAssurance, Attest: c.ClientAttestation, Reason: r.Reason,
			ActChain: &ActClaim{
				Sub: c.Agent.ClientID, SboKind: c.Agent.Kind, SboProduct: c.Agent.Product,
				SboCredAssurance: c.CredAssurance, SboClientAttestation: c.ClientAttestation,
			},
		}
	}
	return ExchangeDecision{Reason: ReasonNoRuleMatched, Error: OAuthInvalidGrant}
}

// OBO gathering stages, in table order. The STS gathers OBOContext one stage
// at a time and asks the table after each: a denial whose reason belongs to
// an already-gathered stage is final; any later reason only means "not
// gathered yet". So the table - not the caller's control flow - decides, and
// no later stage (a key fetch, the replay insert) runs after an earlier
// refusal.
const (
	OBOStageWire = iota
	OBOStageClient
	OBOStageSubject
	OBOStageIssuer
	OBOStageDelegation
	OBOStageVerify
	OBOStageReplay
	OBOStageFinal
)

// oboStageOfReason maps each OBO table reason onto its gathering stage.
var oboStageOfReason = map[string]int{
	ReasonOBONotOBO:            OBOStageWire,
	ReasonMissingResource:      OBOStageWire,
	ReasonRequestedType:        OBOStageWire,
	ReasonMissingSubject:       OBOStageWire,
	ReasonOBOActorToken:        OBOStageWire,
	ReasonClientUnauthed:       OBOStageClient,
	ReasonCredInactive:         OBOStageClient,
	ReasonAssuranceUnknown:     OBOStageClient,
	ReasonSharedSecretDisabled: OBOStageClient,
	ReasonAgentNotAllowed:      OBOStageClient,
	ReasonOBOSubjectSubstitute: OBOStageSubject,
	ReasonOBOIssuerUnknown:     OBOStageIssuer,
	ReasonOBONotDelegable:      OBOStageDelegation,
	ReasonOBOSubjectInvalid:    OBOStageVerify,
	ReasonOBOReplay:            OBOStageReplay,
}

// OBOStageOf returns the gathering stage an OBO table reason belongs to;
// an unknown reason (incl. no_rule_matched) is OBOStageFinal.
func OBOStageOf(reason string) int {
	if s, ok := oboStageOfReason[reason]; ok {
		return s
	}
	return OBOStageFinal
}

// IsOBOWireReason reports whether an OBO table reason is a pure request-shape
// refusal (decidable before any client authentication or verification).
func IsOBOWireReason(reason string) bool {
	s, ok := oboStageOfReason[reason]
	return ok && s == OBOStageWire
}
