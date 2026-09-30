package agentid

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

// ClockSkew is the future-dated tolerance applied to iat/nbf. exp gets NO
// leeway: agentgateway tolerates ~60 s past exp (ADR-0007 §3.2), so our
// profile check is the strict one.
const ClockSkew = 5 * time.Second

// TokenErrorCode is the CLOSED access-token rejection vocabulary. Every code
// maps to the same external response (401 invalid_token), so the code is an
// audit/diagnostic value, never an oracle for the caller.
type TokenErrorCode string

// Token error codes.
const (
	TokErrMalformed       TokenErrorCode = "malformed"
	TokErrType            TokenErrorCode = "bad_type"
	TokErrAlg             TokenErrorCode = "bad_alg"
	TokErrUnknownKID      TokenErrorCode = "unknown_kid"
	TokErrSignature       TokenErrorCode = "bad_signature"
	TokErrIssuer          TokenErrorCode = "wrong_issuer"
	TokErrAudience        TokenErrorCode = "wrong_audience"
	TokErrExpired         TokenErrorCode = "expired"
	TokErrNotYetValid     TokenErrorCode = "not_yet_valid"
	TokErrClaims          TokenErrorCode = "bad_claims"
	TokErrGenerationStale TokenErrorCode = "below_generation_floor"
)

// ErrInvalidToken is matched (errors.Is) by every *TokenError.
var ErrInvalidToken = errors.New("agentid: invalid access token")

// TokenError is a typed access-token rejection.
type TokenError struct {
	Code   TokenErrorCode
	Detail string
}

// Error implements error. Detail is for logs only.
func (e *TokenError) Error() string {
	return "agentid: invalid access token: " + string(e.Code) + ": " + e.Detail
}

// Is makes every TokenError match ErrInvalidToken.
func (e *TokenError) Is(target error) bool { return target == ErrInvalidToken }

func tokErr(code TokenErrorCode, format string, a ...any) error {
	return &TokenError{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// CodeOf returns the TokenErrorCode of err ("" when err is not a TokenError).
func CodeOf(err error) TokenErrorCode {
	var te *TokenError
	if errors.As(err, &te) {
		return te.Code
	}
	return ""
}

// VerifyOptions tunes verification. The zero value means: the full default
// asymmetric allowlist.
type VerifyOptions struct {
	// Algs is the server-token allowlist (empty -> jose.DefaultAlgs()).
	Algs jose.AlgSet
}

func (o VerifyOptions) algs() jose.AlgSet {
	if o.Algs.Empty() {
		return jose.DefaultAlgs()
	}
	return o.Algs
}

// Verify checks an at+jwt's header, signature, issuer and exact single
// audience against jwks, with the default allowlist. It does NOT run the
// time/profile checks - call VerifyProfile (or use VerifyFull).
func Verify(jwks []JWK, token, expectedAud, expectedIss string) (Claims, error) {
	return VerifyWith(VerifyOptions{}, jwks, token, expectedAud, expectedIss)
}

// VerifyWith is Verify with explicit options.
func VerifyWith(o VerifyOptions, jwks []JWK, token, expectedAud, expectedIss string) (Claims, error) {
	j, err := parseAccessToken(token)
	if err != nil {
		return Claims{}, err
	}
	key, err := selectKey(jwks, j.Header.Kid)
	if err != nil {
		return Claims{}, err
	}
	return verifyParsed(o, j, key, expectedAud, expectedIss)
}

// VerifyFull runs Verify + VerifyProfile at now.
func VerifyFull(o VerifyOptions, jwks []JWK, token, expectedAud, expectedIss string, now time.Time) (Claims, error) {
	c, err := VerifyWith(o, jwks, token, expectedAud, expectedIss)
	if err != nil {
		return Claims{}, err
	}
	if err := VerifyProfile(c, now); err != nil {
		return Claims{}, err
	}
	return c, nil
}

// TokenKID returns the kid of an access token WITHOUT verifying it, so a
// caller can resolve the key (JWKSCache.KeyForKID). Only structure and typ
// are checked.
func TokenKID(token string) (string, error) {
	j, err := parseAccessToken(token)
	if err != nil {
		return "", err
	}
	return j.Header.Kid, nil
}

func parseAccessToken(token string) (*jose.JWS, error) {
	j, err := jose.Parse(token, MaxAccessTokenBytes)
	if err != nil {
		return nil, tokErr(TokErrMalformed, "%v", err)
	}
	// RFC 9068 §4: typ MUST be "at+jwt" (or the full media type).
	if typ := strings.ToLower(j.Header.Typ); typ != TypAccessToken && typ != "application/"+TypAccessToken {
		return nil, tokErr(TokErrType, "typ %q", j.Header.Typ)
	}
	if j.Header.Kid == "" {
		return nil, tokErr(TokErrUnknownKID, "token has no kid")
	}
	if j.Header.JWK != nil {
		return nil, tokErr(TokErrMalformed, "access tokens never embed a jwk")
	}
	return j, nil
}

func selectKey(jwks []JWK, kid string) (JWK, error) {
	var found []JWK
	for _, k := range jwks {
		if k.Kid == kid {
			found = append(found, k)
		}
	}
	switch len(found) {
	case 0:
		return JWK{}, tokErr(TokErrUnknownKID, "kid %q not in the key set", kid)
	case 1:
		return found[0], nil
	default:
		return JWK{}, tokErr(TokErrUnknownKID, "kid %q is ambiguous", kid)
	}
}

func verifyParsed(o VerifyOptions, j *jose.JWS, key JWK, expectedAud, expectedIss string) (Claims, error) {
	if !o.algs().Allows(j.Header.Alg) {
		return Claims{}, tokErr(TokErrAlg, "alg %q not in the allowlist", j.Header.Alg)
	}
	if err := j.Verify(o.algs(), key); err != nil {
		return Claims{}, tokErr(TokErrSignature, "%v", err)
	}
	members, err := jose.DecodeObject(j.Payload)
	if err != nil {
		return Claims{}, tokErr(TokErrMalformed, "claims: %v", err)
	}
	for _, m := range requiredClaims {
		if _, ok := members[m]; !ok {
			return Claims{}, tokErr(TokErrClaims, "missing required claim %q", m)
		}
	}
	var c Claims
	if err := jose.DecodeClaims(j.Payload, &c); err != nil {
		return Claims{}, tokErr(TokErrClaims, "%v", err)
	}
	if expectedIss == "" || c.Iss != expectedIss {
		return Claims{}, tokErr(TokErrIssuer, "iss %q", c.Iss)
	}
	if expectedAud == "" || c.Aud != expectedAud {
		return Claims{}, tokErr(TokErrAudience, "aud %q", c.Aud)
	}
	return c, nil
}

// VerifyProfile is the CONTEXT-FREE RFC 9068 profile + typed-claim check
// (R8.24.m): sub/client_id/jti/iat/exp/nbf, cnf shape, the act chain and its
// assurance enums, bounded groups/details, the informational sbo_sender's
// consistency with cnf, and non-negative generation claims. Bearer
// admission, the vserver sender_constraint and generation FLOORS are PDP
// decisions, not this function's (see CheckGenerations).
func VerifyProfile(c Claims, now time.Time) error {
	n := now.Unix()
	skew := int64(ClockSkew / time.Second)
	switch {
	case c.Sub == "":
		return tokErr(TokErrClaims, "empty sub")
	case c.ClientID == "":
		return tokErr(TokErrClaims, "empty client_id")
	case c.Jti == "" || len(c.Jti) > 128:
		return tokErr(TokErrClaims, "jti must be 1..128 bytes")
	case c.SboOrg == "":
		return tokErr(TokErrClaims, "empty sbo_org")
	case c.Iat <= 0 || c.Exp <= 0:
		return tokErr(TokErrClaims, "iat/exp required")
	case c.Exp <= c.Iat:
		return tokErr(TokErrClaims, "exp not after iat")
	case c.Exp-c.Iat > int64(MaxTokenTTL/time.Second):
		return tokErr(TokErrClaims, "lifetime %ds exceeds %ds", c.Exp-c.Iat, int64(MaxTokenTTL/time.Second))
	case c.Iat > n+skew:
		return tokErr(TokErrNotYetValid, "iat in the future")
	case c.Nbf != 0 && c.Nbf > n+skew:
		return tokErr(TokErrNotYetValid, "nbf in the future")
	case n >= c.Exp:
		return tokErr(TokErrExpired, "expired at %d", c.Exp)
	case c.SboMemberGen < 0 || c.SboCredGen < 0 || c.SboPolicyGen < 0 || c.SboIssuerEpoch < 0:
		return tokErr(TokErrClaims, "negative generation claim")
	case len(c.SboGroups) > MaxGroups:
		return tokErr(TokErrClaims, "too many sbo_groups")
	}
	for _, g := range c.SboGroups {
		if g == "" {
			return tokErr(TokErrClaims, "empty group")
		}
	}
	for _, d := range c.AuthorizationDetails {
		if d.Type == "" {
			return tokErr(TokErrClaims, "authorization_details entry without type")
		}
	}
	if err := checkAct(c.Act); err != nil {
		return err
	}
	if err := checkCnf(c); err != nil {
		return err
	}
	return checkABAC(c) // P11(e): bounded roster; project hash only on a relay-originated token
}

func checkAct(a *ActClaim) error {
	if a == nil {
		return tokErr(TokErrClaims, "act claim required")
	}
	if a.Sub == "" {
		return tokErr(TokErrClaims, "act.sub required")
	}
	if !a.SboCredAssurance.Valid() || !a.SboClientAttestation.Valid() {
		return tokErr(TokErrClaims, "act assurance enums required")
	}
	if a.Depth() > MaxActDepth {
		return tokErr(TokErrClaims, "actor chain deeper than %d", MaxActDepth)
	}
	for cur := a.Act; cur != nil; cur = cur.Act {
		if cur.Sub == "" {
			return tokErr(TokErrClaims, "nested act.sub required")
		}
	}
	return nil
}

func checkCnf(c Claims) error {
	if c.Cnf != nil {
		if (c.Cnf.JKT == "") == (c.Cnf.X5TS256 == "") {
			return tokErr(TokErrClaims, "cnf must carry exactly one confirmation method")
		}
		for _, v := range []string{c.Cnf.JKT, c.Cnf.X5TS256} {
			if v != "" && !isSHA256B64(v) {
				return tokErr(TokErrClaims, "cnf value is not a base64url SHA-256")
			}
		}
	}
	switch c.SboSender {
	case "":
	case SenderBearer:
		if c.Cnf != nil {
			return tokErr(TokErrClaims, "sbo_sender=bearer with cnf")
		}
	case SenderDPoP:
		if c.Cnf == nil || c.Cnf.JKT == "" {
			return tokErr(TokErrClaims, "sbo_sender=dpop without cnf.jkt")
		}
	case SenderMTLS:
		if c.Cnf == nil || c.Cnf.X5TS256 == "" {
			return tokErr(TokErrClaims, "sbo_sender=mtls without cnf.x5t#S256")
		}
	default:
		return tokErr(TokErrClaims, "unknown sbo_sender %q", c.SboSender)
	}
	return nil
}

// isSHA256B64 reports whether s is an unpadded base64url SHA-256 digest.
func isSHA256B64(s string) bool {
	if len(s) != 43 {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// GenerationFloor is the invalidation floor a PDP holds from
// agent_invalidation_state (§4.6). A token whose generation is BELOW any
// floor is rejected even while unexpired - the pre-CAEP revocation path.
type GenerationFloor struct {
	Member, Cred, Policy, IssuerEpoch int64
}

// CheckGenerations compares the token's generation claims to floor.
func CheckGenerations(c Claims, floor GenerationFloor) error {
	switch {
	case c.SboMemberGen < floor.Member:
		return tokErr(TokErrGenerationStale, "sbo_member_gen %d < %d", c.SboMemberGen, floor.Member)
	case c.SboCredGen < floor.Cred:
		return tokErr(TokErrGenerationStale, "sbo_cred_gen %d < %d", c.SboCredGen, floor.Cred)
	case c.SboPolicyGen < floor.Policy:
		return tokErr(TokErrGenerationStale, "sbo_policy_gen %d < %d", c.SboPolicyGen, floor.Policy)
	case c.SboIssuerEpoch < floor.IssuerEpoch:
		return tokErr(TokErrGenerationStale, "sbo_issuer_epoch %d < %d", c.SboIssuerEpoch, floor.IssuerEpoch)
	}
	return nil
}
