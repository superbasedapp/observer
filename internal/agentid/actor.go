package agentid

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

// Actor-assertion bounds (§4.3).
const (
	// MaxActorLifetime is the hard exp - iat ceiling of an sbo-actor+jwt.
	MaxActorLifetime = 60 * time.Second
	// ActorReplaySkew is added to exp for the replay-store TTL.
	ActorReplaySkew = 30 * time.Second
	// MaxActorBytes caps an inbound actor assertion.
	MaxActorBytes = 4 << 10
)

// ActorClaims is the sbo-actor+jwt payload. iss = node id, sub = agent
// credential id, aud = the STS token endpoint URL, single-use jti, exp <=
// iat + 60 s, and the binding claims sbo_member / sbo_machine_fp /
// sbo_cred_gen. SboAgent (the product client id the relay serves, e.g.
// "agent:claude-code") and SboClientAttestation (what the relay attests about
// the calling process) are additive optional claims the node relay sets;
// absent attestation means `configured` (node-wide principal, R2).
type ActorClaims struct {
	Iss                  string `json:"iss"`
	Sub                  string `json:"sub"`
	Aud                  string `json:"aud"`
	Jti                  string `json:"jti"`
	Iat                  int64  `json:"iat"`
	Exp                  int64  `json:"exp"`
	SboMember            string `json:"sbo_member"`
	SboMachineFP         string `json:"sbo_machine_fp"`
	SboCredGen           int64  `json:"sbo_cred_gen"`
	SboAgent             string `json:"sbo_agent,omitempty"`
	SboClientAttestation string `json:"sbo_client_attestation,omitempty"`
	// SboProjectHash is the RELAY-ATTESTED project hash of the coding
	// session the relay serves (P11(e), R10.9): the node resolves it from the
	// session's project root (internal/git + the resolver-v2 hash,
	// ProjectHashOfRoot) and signs it here; the STS copies it into the at+jwt
	// sbo_project_hash on the F1 exchange only. Optional; "" = no project
	// context (project-scoped grants then fail closed).
	SboProjectHash string `json:"sbo_project_hash,omitempty"`
	// KeyThumbprint is filled by VerifyActorAssertion (not a wire claim): the
	// RFC 7638 thumbprint of the verifying key, which must equal the token
	// endpoint DPoP proof's key (the same dedicated agent-access key).
	KeyThumbprint string `json:"-"`
}

// actorRequired are the members every actor assertion must carry.
var actorRequired = []string{"iss", "sub", "aud", "jti", "iat", "exp", "sbo_member", "sbo_machine_fp", "sbo_cred_gen"}

// ActorErrorCode is the CLOSED actor-assertion rejection vocabulary. Every
// code maps to the same external invalid_grant (no enumeration oracle).
type ActorErrorCode string

// Actor error codes.
const (
	ActErrMalformed         ActorErrorCode = "malformed"
	ActErrType              ActorErrorCode = "bad_type"
	ActErrAlg               ActorErrorCode = "bad_alg"
	ActErrKey               ActorErrorCode = "key_mismatch"
	ActErrSignature         ActorErrorCode = "bad_signature"
	ActErrAudience          ActorErrorCode = "wrong_audience"
	ActErrExpired           ActorErrorCode = "expired"
	ActErrNotYetValid       ActorErrorCode = "not_yet_valid"
	ActErrLifetime          ActorErrorCode = "lifetime_too_long"
	ActErrClaims            ActorErrorCode = "bad_claims"
	ActErrBinding           ActorErrorCode = "binding_mismatch"
	ActErrReplay            ActorErrorCode = "replayed"
	ActErrReplayUnavailable ActorErrorCode = "replay_store_unavailable"
	// ActErrSubject: sub does not name the credential the assertion was
	// verified against (cross-credential subject substitution, §4.3).
	ActErrSubject ActorErrorCode = "subject_mismatch"
)

// ErrInvalidActor is matched (errors.Is) by every *ActorError.
var ErrInvalidActor = errors.New("agentid: invalid actor assertion")

// ActorError is a typed actor-assertion rejection.
type ActorError struct {
	Code   ActorErrorCode
	Detail string
}

// Error implements error.
func (e *ActorError) Error() string {
	return "agentid: invalid actor assertion: " + string(e.Code) + ": " + e.Detail
}

// Is makes every ActorError match ErrInvalidActor.
func (e *ActorError) Is(target error) bool { return target == ErrInvalidActor }

func actErr(code ActorErrorCode, format string, a ...any) error {
	return &ActorError{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// ActorCodeOf returns the ActorErrorCode of err ("" otherwise).
func ActorCodeOf(err error) ActorErrorCode {
	var ae *ActorError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// ActorExpect is what the STS expects of one actor assertion.
type ActorExpect struct {
	// Key is the REGISTERED per-device agent-access public key (resolved by
	// the caller from ActorKeyID). The header kid must be its thumbprint.
	Key JWK
	// Audience is the STS token endpoint canonical URL.
	Audience string
	// Algs is the NODE PROOF allowlist - separate from the server-token one
	// (R8.23.m). Empty -> jose.DefaultAlgs().
	Algs jose.AlgSet
	// Now is the verification instant (zero -> time.Now()).
	Now time.Time
	// Skew tolerates clock drift on iat/exp (zero -> ClockSkew).
	Skew time.Duration
	// Member and MachineFP are the registered binding the assertion must
	// repeat (the credential row's member_id / machine_fp). Required.
	Member, MachineFP string
	// Issuer, when set, must equal iss (the node id).
	Issuer string
	// CredentialID, when set, is the id of the REGISTERED credential row Key
	// belongs to: sub must name exactly that credential (§4.3 "sub = agent
	// credential id"). A correctly signed assertion whose sub names another
	// credential (or arbitrary text) is refused with ActErrSubject. The STS
	// always sets it; it is optional only so a caller with no credential
	// table (pure key verification) keeps the pre-existing behaviour.
	CredentialID string
}

// ActorKeyID returns the kid (agent-access key thumbprint) of an actor
// assertion WITHOUT verifying it, so the STS can look up the registered
// credential. typ is checked; nothing else is trusted.
func ActorKeyID(a string) (string, error) {
	j, err := jose.Parse(a, MaxActorBytes)
	if err != nil {
		return "", actErr(ActErrMalformed, "%v", err)
	}
	if j.Header.Typ != TypActorAssertion {
		return "", actErr(ActErrType, "typ %q", j.Header.Typ)
	}
	if j.Header.Kid == "" {
		return "", actErr(ActErrKey, "no kid")
	}
	return j.Header.Kid, nil
}

// VerifyActorAssertion verifies an sbo-actor+jwt (§4.3). seen is the shared
// replay store's ATOMIC insert-if-absent over jti: it must record the jti and
// return alreadySeen=true for a replay; an error fails closed. seen runs LAST,
// after every other check, so a forged assertion can never burn a jti.
func VerifyActorAssertion(a string, expect ActorExpect, seen func(jti string, exp int64) (bool, error)) (ActorClaims, error) {
	j, err := jose.Parse(a, MaxActorBytes)
	if err != nil {
		return ActorClaims{}, actErr(ActErrMalformed, "%v", err)
	}
	if j.Header.Typ != TypActorAssertion {
		return ActorClaims{}, actErr(ActErrType, "typ %q", j.Header.Typ)
	}
	if j.Header.JWK != nil {
		return ActorClaims{}, actErr(ActErrMalformed, "actor assertions never embed a jwk")
	}
	algs := expect.Algs
	if algs.Empty() {
		algs = jose.DefaultAlgs()
	}
	if !algs.Allows(j.Header.Alg) {
		return ActorClaims{}, actErr(ActErrAlg, "alg %q not in the proof allowlist", j.Header.Alg)
	}
	tp, err := expect.Key.Thumbprint()
	if err != nil {
		return ActorClaims{}, actErr(ActErrKey, "registered key: %v", err)
	}
	if j.Header.Kid != tp {
		return ActorClaims{}, actErr(ActErrKey, "kid is not the registered key thumbprint")
	}
	if err := j.Verify(algs, expect.Key); err != nil {
		return ActorClaims{}, actErr(ActErrSignature, "%v", err)
	}
	members, err := jose.DecodeObject(j.Payload)
	if err != nil {
		return ActorClaims{}, actErr(ActErrMalformed, "claims: %v", err)
	}
	for _, m := range actorRequired {
		if _, ok := members[m]; !ok {
			return ActorClaims{}, actErr(ActErrClaims, "missing claim %q", m)
		}
	}
	var c ActorClaims
	if raw, ok := members["aud"]; ok {
		aud, aerr := singleAudience(raw)
		if aerr != nil {
			return ActorClaims{}, actErr(ActErrAudience, "%v", aerr)
		}
		members["aud"], _ = json.Marshal(aud)
		patched, _ := json.Marshal(members)
		j.Payload = patched
	}
	if err := json.Unmarshal(j.Payload, &c); err != nil {
		return ActorClaims{}, actErr(ActErrClaims, "%v", err)
	}
	if err := checkActorClaims(c, expect); err != nil {
		return ActorClaims{}, err
	}
	c.KeyThumbprint = tp
	if seen == nil {
		return ActorClaims{}, actErr(ActErrReplayUnavailable, "no replay store wired")
	}
	dup, err := seen(c.Jti, c.Exp+int64(ActorReplaySkew/time.Second))
	if err != nil {
		return ActorClaims{}, actErr(ActErrReplayUnavailable, "%v", err)
	}
	if dup {
		return ActorClaims{}, actErr(ActErrReplay, "jti already used")
	}
	return c, nil
}

func checkActorClaims(c ActorClaims, e ActorExpect) error {
	now := e.Now
	if now.IsZero() {
		now = time.Now()
	}
	skew := e.Skew
	if skew <= 0 {
		skew = ClockSkew
	}
	n, s := now.Unix(), int64(skew/time.Second)
	switch {
	case c.Iss == "" || c.Sub == "" || c.Jti == "" || len(c.Jti) > 128:
		return actErr(ActErrClaims, "iss/sub/jti required")
	case e.Audience == "" || c.Aud != e.Audience:
		return actErr(ActErrAudience, "aud %q", c.Aud)
	case c.Exp <= c.Iat:
		return actErr(ActErrClaims, "exp not after iat")
	case c.Exp-c.Iat > int64(MaxActorLifetime/time.Second):
		return actErr(ActErrLifetime, "lifetime %ds > %ds", c.Exp-c.Iat, int64(MaxActorLifetime/time.Second))
	case c.Iat > n+s:
		return actErr(ActErrNotYetValid, "iat in the future")
	case n >= c.Exp+s:
		return actErr(ActErrExpired, "expired")
	case c.SboCredGen < 0:
		return actErr(ActErrClaims, "negative sbo_cred_gen")
	case e.Member == "" || e.MachineFP == "":
		return actErr(ActErrBinding, "no registered binding to compare")
	case c.SboMember != e.Member:
		return actErr(ActErrBinding, "sbo_member does not match the credential")
	case c.SboMachineFP != e.MachineFP:
		return actErr(ActErrBinding, "sbo_machine_fp does not match the credential (foreign machine)")
	case e.Issuer != "" && c.Iss != e.Issuer:
		return actErr(ActErrBinding, "iss does not match the node")
	case e.CredentialID != "" && c.Sub != e.CredentialID:
		return actErr(ActErrSubject, "sub does not name the verified credential")
	}
	if c.SboClientAttestation != "" {
		if _, err := ParseClientAttestation(c.SboClientAttestation); err != nil {
			return actErr(ActErrClaims, "%v", err)
		}
	}
	if c.SboProjectHash != "" && !ValidProjectHash(c.SboProjectHash) {
		return actErr(ActErrClaims, "malformed sbo_project_hash")
	}
	return nil
}

// CreateActorAssertion signs an sbo-actor+jwt with the node's agent-access
// key (a NodeProofSigner's Signer). The header kid is the key's RFC 7638
// thumbprint. The caller sets every claim; iat/exp are validated here so the
// node can never emit an assertion the STS will refuse on lifetime.
func CreateActorAssertion(s Signer, c ActorClaims) (string, error) {
	if s == nil {
		return "", errors.New("agentid.CreateActorAssertion: nil signer")
	}
	if c.Exp <= c.Iat || c.Exp-c.Iat > int64(MaxActorLifetime/time.Second) {
		return "", fmt.Errorf("agentid.CreateActorAssertion: lifetime must be 1..%ds", int64(MaxActorLifetime/time.Second))
	}
	alg, jwk := s.PublicJWK()
	tp, err := jwk.Thumbprint()
	if err != nil {
		return "", fmt.Errorf("agentid.CreateActorAssertion: %w", err)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("agentid.CreateActorAssertion: %w", err)
	}
	tok, err := jose.Sign(s, jose.Header{Typ: TypActorAssertion, Alg: alg, Kid: tp}, payload)
	if err != nil {
		return "", fmt.Errorf("agentid.CreateActorAssertion: %w", err)
	}
	return tok, nil
}
