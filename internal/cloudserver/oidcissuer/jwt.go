package oidcissuer

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

var b64 = base64.RawURLEncoding

// jwsHeader is the protected header of every id_token. The signer writes it;
// the caller cannot choose an algorithm or add a header field.
type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// SigningInput returns the JWS signing input (base64url header "."
// base64url payload) for c under kid.
func SigningInput(kid string, c Claims) (string, error) {
	if kid == "" {
		return "", errors.New("oidcissuer.SigningInput: empty kid")
	}
	h, err := json.Marshal(jwsHeader{Alg: AlgRS256, Kid: kid, Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("oidcissuer.SigningInput: header: %w", err)
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("oidcissuer.SigningInput: payload: %w", err)
	}
	return b64.EncodeToString(h) + "." + b64.EncodeToString(p), nil
}

// SignRS256 returns the compact JWS of c under key, named kid. It does not
// validate the claims; LocalSigner does that first.
func SignRS256(rnd io.Reader, key *rsa.PrivateKey, kid string, c Claims) (string, error) {
	input, err := SigningInput(kid, c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rnd, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("oidcissuer.SignRS256: %w", err)
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// VerifyRS256 checks token's RS256 signature against jwk (the header must
// name RS256 and jwk's kid) and returns its claims. It checks the signature
// and header only; claim checks are the relying party's (and, before
// signing, ValidateClaims).
func VerifyRS256(token string, jwk JWK) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("oidcissuer.VerifyRS256: not a compact JWS")
	}
	hb, err := b64.DecodeString(parts[0])
	if err != nil {
		return Claims{}, fmt.Errorf("oidcissuer.VerifyRS256: header: %w", err)
	}
	var h jwsHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return Claims{}, fmt.Errorf("oidcissuer.VerifyRS256: header: %w", err)
	}
	if h.Alg != AlgRS256 || h.Kid == "" || h.Kid != jwk.Kid {
		return Claims{}, fmt.Errorf("oidcissuer.VerifyRS256: header alg %q kid %q, want RS256 and %q", h.Alg, h.Kid, jwk.Kid)
	}
	pub, err := RSAPublicKey(jwk)
	if err != nil {
		return Claims{}, err
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("oidcissuer.VerifyRS256: signature: %w", err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
		return Claims{}, fmt.Errorf("oidcissuer.VerifyRS256: %w", err)
	}
	pb, err := b64.DecodeString(parts[1])
	if err != nil {
		return Claims{}, fmt.Errorf("oidcissuer.VerifyRS256: payload: %w", err)
	}
	var c Claims
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Claims{}, fmt.Errorf("oidcissuer.VerifyRS256: payload: %w", err)
	}
	return c, nil
}

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint of pub, base64url.
// It is the kid: a kid names exactly one key, and two VMs' keys never share
// one.
func Thumbprint(pub *rsa.PublicKey) string {
	e := b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	n := b64.EncodeToString(pub.N.Bytes())
	// RFC 7638 3.2: the required members in lexicographic order, no spaces.
	canon := `{"e":"` + e + `","kty":"RSA","n":"` + n + `"}`
	sum := sha256.Sum256([]byte(canon))
	return b64.EncodeToString(sum[:])
}

// PublicJWK returns pub as an RS256 signing JWK named by its thumbprint.
func PublicJWK(pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		Kid: Thumbprint(pub),
		Alg: AlgRS256,
		Use: "sig",
		N:   b64.EncodeToString(pub.N.Bytes()),
		E:   b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// RSAPublicKey decodes jwk. It refuses anything but an RS256 signing key of
// at least MinRSABits whose kid is its own thumbprint.
func RSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" || jwk.Alg != AlgRS256 || (jwk.Use != "" && jwk.Use != "sig") {
		return nil, fmt.Errorf("oidcissuer.RSAPublicKey: kty %q alg %q use %q, want an RS256 signing key", jwk.Kty, jwk.Alg, jwk.Use)
	}
	nb, err := b64.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("oidcissuer.RSAPublicKey: n: %w", err)
	}
	eb, err := b64.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("oidcissuer.RSAPublicKey: e: %w", err)
	}
	e := new(big.Int).SetBytes(eb)
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, errors.New("oidcissuer.RSAPublicKey: unusable exponent")
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}
	if pub.N.BitLen() < MinRSABits {
		return nil, fmt.Errorf("oidcissuer.RSAPublicKey: %d-bit modulus, want at least %d", pub.N.BitLen(), MinRSABits)
	}
	if Thumbprint(pub) != jwk.Kid {
		return nil, errors.New("oidcissuer.RSAPublicKey: kid is not the key's thumbprint")
	}
	return pub, nil
}

// JWKSDocument is the body of GET /oauth2/jwks.json.
type JWKSDocument struct {
	Keys []JWK `json:"keys"`
}

// Discovery is the OpenID Provider Metadata document.
type Discovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	// PromptValuesSupported is the OpenID Connect "prompt=create" draft's
	// metadata name for the prompt values the issuer honours; a request
	// carrying any other value is refused with invalid_request.
	PromptValuesSupported             []string `json:"prompt_values_supported"`
	AuthorizationResponseISSSupported bool     `json:"authorization_response_iss_parameter_supported"`
	// SupportAuthorizationEndpoint is the staff console's authorize endpoint
	// for support sign-ins (M7a.2), on the staff host; absent when the issuer
	// is not configured with one. A tenant's platform rail starts a support
	// sign-in there instead of at AuthorizationEndpoint; the token endpoint is
	// the same.
	SupportAuthorizationEndpoint string `json:"sb_support_authorization_endpoint,omitempty"`
}

// DiscoveryFor returns the discovery document for issuer (no trailing slash).
//
// claims_supported lists only what the issuer signs. It lists `amr` since C2
// (wave 17 portal-guardrails): a token carries one when, and only when, the
// portal session completed its passkey second factor ("hwk" or "swk" with
// "mfa", internal/cloudserver/portalmfa). AuthKit's own sign-in still reports
// no factor, so a session without a passkey carries none (decision log
// L-92's reasoning holds for it).
func DiscoveryFor(issuer string) Discovery {
	return Discovery{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/authorize",
		TokenEndpoint:                     issuer + "/token",
		JWKSURI:                           issuer + "/jwks.json",
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{AlgRS256},
		CodeChallengeMethodsSupported:     []string{ChallengeMethodS256},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		ScopesSupported:                   []string{"openid", "email", "profile"},
		ClaimsSupported:                   []string{"iss", "sub", "aud", "exp", "iat", "auth_time", "jti", "nonce", "org", "email", "email_verified", "support", "amr"},
		PromptValuesSupported:             SupportedPromptValues(),
		AuthorizationResponseISSSupported: true,
	}
}
