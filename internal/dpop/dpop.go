package dpop

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

// Typ is the RFC 9449 proof JOSE header typ.
const Typ = "dpop+jwt"

// Bounds.
const (
	// MaxProofBytes caps an inbound proof (embedded RSA-3072 JWK fits).
	MaxProofBytes = 4 << 10
	// DefaultMaxAge is how old a proof's iat may be.
	DefaultMaxAge = 60 * time.Second
	// DefaultSkew is how far in the future a proof's iat may be.
	DefaultSkew = 5 * time.Second
	// maxClaimLen bounds jti/nonce/sbo_corr members.
	maxClaimLen = 256
)

// Profile selects the verifier profile.
type Profile int

// Verifier profiles (R8.23.j).
const (
	// ProfileTokenEndpoint verifies htm/htu/iat/jti/nonce and REJECTS a
	// proof carrying ath: there is no access token yet, so an ath-bearing
	// proof is a resource-shaped (or otherwise malformed) proof presented to
	// the token endpoint - profile confusion, refused as ErrCodeATH.
	ProfileTokenEndpoint Profile = iota + 1
	// ProfileResource additionally REQUIRES ath (exact match against
	// Expect.ATH) and optionally the jkt.
	ProfileResource
)

// ReplayStore is the SHARED single-use jti store. InsertIfAbsent must be
// atomic across replicas and return fresh=false when the jti was already
// recorded for the org. exp is the unix time after which the row may be
// swept.
type ReplayStore interface {
	InsertIfAbsent(ctx context.Context, org, jti string, exp int64) (fresh bool, err error)
}

// Correlation is the relay-only `sbo_corr` proof claim (R11.8).
type Correlation struct {
	CodingSessionID string `json:"coding_session_id,omitempty"`
	TurnRef         string `json:"turn_ref,omitempty"`
	ActionRef       string `json:"action_ref,omitempty"`
	CallID          string `json:"call_id,omitempty"`
}

// Claims is the proof payload.
type Claims struct {
	JTI   string       `json:"jti"`
	HTM   string       `json:"htm"`
	HTU   string       `json:"htu"`
	IAT   int64        `json:"iat"`
	ATH   string       `json:"ath,omitempty"`
	Nonce string       `json:"nonce,omitempty"`
	Corr  *Correlation `json:"sbo_corr,omitempty"`
}

// ATH returns base64url(SHA-256(accessToken)) - the ath claim value.
func ATH(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Create signs a proof with the node's agent-access key (s + alg) - never a
// server-ring key. ath and nonce may be empty.
func Create(s crypto.Signer, alg, htm, htu, ath, nonce string, now time.Time) (string, error) {
	return CreateWith(s, alg, Claims{HTM: htm, HTU: htu, ATH: ath, Nonce: nonce}, now, nil)
}

// CreateWith signs a proof from a claim template: JTI (when empty) is drawn
// from r (nil -> crypto/rand) and IAT is set from now. HTU is canonicalised.
// Use it to add the relay's sbo_corr claim.
func CreateWith(s crypto.Signer, alg string, c Claims, now time.Time, r io.Reader) (string, error) {
	if s == nil {
		return "", errors.New("dpop.Create: nil signer")
	}
	if c.HTM == "" {
		return "", errors.New("dpop.Create: htm required")
	}
	htu, err := CanonicalHTU(c.HTU)
	if err != nil {
		return "", fmt.Errorf("dpop.Create: %w", err)
	}
	c.HTU = htu
	if c.JTI == "" {
		if r == nil {
			r = rand.Reader
		}
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("dpop.Create: jti: %w", err)
		}
		c.JTI = base64.RawURLEncoding.EncodeToString(buf)
	}
	c.IAT = now.Unix()
	jwk, err := jose.PublicJWK(s.Public(), alg, "")
	if err != nil {
		return "", fmt.Errorf("dpop.Create: %w", err)
	}
	jwk = jwk.PublicOnly()
	payload, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("dpop.Create: %w", err)
	}
	tok, err := jose.Sign(s, jose.Header{Typ: Typ, Alg: alg, JWK: &jwk}, payload)
	if err != nil {
		return "", fmt.Errorf("dpop.Create: %w", err)
	}
	return tok, nil
}

// Expect is what the verifier expects of one proof (doc3 §2.4 plus the
// profile, org, allowlist and binding fields the checks need).
type Expect struct {
	// HTM is the request method; HTU the expected canonical request URI.
	HTM, HTU string
	// ATH is the expected ath (ProfileResource). Use ATH(token) to compute.
	ATH string
	// RequireNonce demands a server nonce accepted by NonceCheck.
	RequireNonce bool
	// NonceCheck validates a presented nonce (e.g. NonceIssuer.Check).
	NonceCheck func(nonce string) bool
	// TrustedProxyCIDRs + Request: when Request is set, the expected htu is
	// reconstructed with CanonicalRequestHTU (X-Forwarded-* only from a
	// trusted proxy) and must agree with HTU when both are given.
	TrustedProxyCIDRs []string
	Request           *RequestInfo
	// Skew is the future-iat tolerance (zero -> DefaultSkew); MaxAge the
	// past-iat window (zero -> DefaultMaxAge).
	Skew, MaxAge time.Duration
	// Profile selects the verifier profile (zero -> ProfileResource, the
	// stricter one).
	Profile Profile
	// Org scopes the replay store.
	Org string
	// Algs is the NODE PROOF allowlist (empty -> jose.DefaultAlgs()); it is
	// separate from the server-token allowlist (R8.23.m).
	Algs jose.AlgSet
	// JKT, when set, must equal the proof key's thumbprint (the token's
	// cnf.jkt on the resource profile).
	JKT string
}

// Result is a verified proof.
type Result struct {
	JKT    string
	Claims Claims
}

// Verify checks proof per RFC 9449 §4.3 and returns the key thumbprint
// (jkt). It records the jti in rs LAST, only after every other check has
// passed, and fails closed if rs is nil or errors. doc3 §2.4 sketched
// Verify without a context; the context is required here because the
// replay store is I/O.
func Verify(ctx context.Context, proof string, e Expect, rs ReplayStore, now time.Time) (string, error) {
	r, err := VerifyDetailed(ctx, proof, e, rs, now)
	if err != nil {
		return "", err
	}
	return r.JKT, nil
}

// VerifyDetailed is Verify returning the verified claims (incl. sbo_corr).
func VerifyDetailed(ctx context.Context, proof string, e Expect, rs ReplayStore, now time.Time) (Result, error) {
	j, err := jose.Parse(proof, MaxProofBytes)
	if err != nil {
		return Result{}, perr(ErrCodeMalformed, "%v", err)
	}
	if j.Header.Typ != Typ {
		return Result{}, perr(ErrCodeType, "typ %q", j.Header.Typ)
	}
	if j.Header.JWK == nil {
		return Result{}, perr(ErrCodeMalformed, "no embedded jwk")
	}
	algs := e.Algs
	if algs.Empty() {
		algs = jose.DefaultAlgs()
	}
	if !algs.Allows(j.Header.Alg) {
		return Result{}, perr(ErrCodeAlg, "alg %q not in the proof allowlist", j.Header.Alg)
	}
	if err := j.Verify(algs, *j.Header.JWK); err != nil {
		return Result{}, perr(ErrCodeSignature, "%v", err)
	}
	jkt, err := j.Header.JWK.Thumbprint()
	if err != nil {
		return Result{}, perr(ErrCodeMalformed, "%v", err)
	}
	c, err := decodeClaims(j.Payload)
	if err != nil {
		return Result{}, err
	}
	if err := checkClaims(c, e, jkt, now); err != nil {
		return Result{}, err
	}
	if rs == nil {
		return Result{}, perr(ErrCodeReplayUnavailable, "no replay store wired")
	}
	maxAge, skew := e.window()
	fresh, err := rs.InsertIfAbsent(ctx, e.Org, c.JTI, c.IAT+int64((maxAge+skew)/time.Second))
	if err != nil {
		return Result{}, perr(ErrCodeReplayUnavailable, "%v", err)
	}
	if !fresh {
		return Result{}, perr(ErrCodeReplay, "jti already used")
	}
	return Result{JKT: jkt, Claims: c}, nil
}

func (e Expect) window() (maxAge, skew time.Duration) {
	maxAge, skew = e.MaxAge, e.Skew
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if skew <= 0 {
		skew = DefaultSkew
	}
	return maxAge, skew
}

var proofRequired = []string{"jti", "htm", "htu", "iat"}

func decodeClaims(payload []byte) (Claims, error) {
	members, err := jose.DecodeObject(payload)
	if err != nil {
		return Claims{}, perr(ErrCodeMalformed, "claims: %v", err)
	}
	for _, m := range proofRequired {
		if _, ok := members[m]; !ok {
			return Claims{}, perr(ErrCodeClaims, "missing claim %q", m)
		}
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return Claims{}, perr(ErrCodeClaims, "%v", err)
	}
	if c.JTI == "" || len(c.JTI) > maxClaimLen || len(c.Nonce) > maxClaimLen {
		return Claims{}, perr(ErrCodeClaims, "jti/nonce length")
	}
	if c.Corr != nil {
		for _, v := range []string{c.Corr.CodingSessionID, c.Corr.TurnRef, c.Corr.ActionRef, c.Corr.CallID} {
			if len(v) > maxClaimLen {
				return Claims{}, perr(ErrCodeClaims, "sbo_corr member too long")
			}
		}
	}
	return c, nil
}

func checkClaims(c Claims, e Expect, jkt string, now time.Time) error {
	if e.HTM == "" || c.HTM != e.HTM {
		return perr(ErrCodeHTM, "htm %q", c.HTM)
	}
	want, err := e.expectedHTU()
	if err != nil {
		return err
	}
	got, err := CanonicalHTU(c.HTU)
	if err != nil || got != want {
		return perr(ErrCodeHTU, "htu %q", c.HTU)
	}
	maxAge, skew := e.window()
	n := now.Unix()
	if c.IAT > n+int64(skew/time.Second) {
		return perr(ErrCodeIATFuture, "iat in the future")
	}
	if c.IAT < n-int64(maxAge/time.Second) {
		return perr(ErrCodeIATStale, "iat too old")
	}
	profile := e.Profile
	if profile == 0 {
		profile = ProfileResource
	}
	// ath is decided by the PROFILE alone (R8.23.j): required + exact on a
	// resource request, forbidden on the token endpoint. Expect.ATH never
	// widens the token-endpoint profile.
	switch profile {
	case ProfileResource:
		if e.ATH == "" || c.ATH != e.ATH {
			return perr(ErrCodeATH, "ath mismatch")
		}
	case ProfileTokenEndpoint:
		if c.ATH != "" {
			return perr(ErrCodeATH, "ath is not a token-endpoint proof claim")
		}
	default:
		return perr(ErrCodeClaims, "unknown verifier profile")
	}
	if e.JKT != "" && e.JKT != jkt {
		return perr(ErrCodeJKT, "proof key does not match cnf.jkt")
	}
	if e.RequireNonce {
		if c.Nonce == "" || e.NonceCheck == nil || !e.NonceCheck(c.Nonce) {
			return perr(ErrCodeUseNonce, "server nonce required")
		}
	}
	return nil
}

func (e Expect) expectedHTU() (string, error) {
	var fromReq string
	if e.Request != nil {
		var err error
		if fromReq, err = CanonicalRequestHTU(*e.Request, e.TrustedProxyCIDRs); err != nil {
			return "", perr(ErrCodeHTU, "%v", err)
		}
	}
	if e.HTU == "" {
		if fromReq == "" {
			return "", perr(ErrCodeHTU, "no expected htu configured")
		}
		return fromReq, nil
	}
	want, err := CanonicalHTU(e.HTU)
	if err != nil {
		return "", perr(ErrCodeHTU, "%v", err)
	}
	if fromReq != "" && fromReq != want {
		return "", perr(ErrCodeHTU, "reconstructed request URI disagrees with the configured one")
	}
	return want, nil
}
