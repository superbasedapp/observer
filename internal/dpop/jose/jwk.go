package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// b64 is base64url without padding (RFC 7515 §2).
var b64 = base64.RawURLEncoding

// JWK is a PUBLIC JSON Web Key (RFC 7517) for one of the three supported key
// types, optionally tagged with its algorithm and key id. Private members
// (d, p, q, dp, dq, qi, k) are never representable: DecodeJWK refuses a key
// document that carries any of them.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

// privateMembers are JWK members that only a private (or symmetric) key
// carries. Their presence anywhere a PUBLIC key is expected is an error.
var privateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// PublicJWK builds the alg-tagged public JWK for pub. alg must be the
// algorithm paired with the key type (CheckKeyAlg); kid may be empty.
func PublicJWK(pub any, alg, kid string) (JWK, error) {
	if err := CheckKeyAlg(pub, alg); err != nil {
		return JWK{}, err
	}
	var k JWK
	switch p := pub.(type) {
	case ed25519.PublicKey:
		k = JWK{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(p)}
	case *ecdsa.PublicKey:
		k = JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(pad32(p.X)), Y: b64.EncodeToString(pad32(p.Y))}
	case *rsa.PublicKey:
		k = JWK{Kty: "RSA", N: b64.EncodeToString(p.N.Bytes()), E: b64.EncodeToString(big.NewInt(int64(p.E)).Bytes())}
	}
	k.Alg = alg
	k.Kid = kid
	return k, nil
}

// pad32 renders a P-256 coordinate as exactly 32 big-endian bytes (RFC 7518
// §6.2.1.2 requires the full field width).
func pad32(v *big.Int) []byte {
	out := make([]byte, 32)
	v.FillBytes(out)
	return out
}

// DecodeJWK strictly parses a PUBLIC JWK document. A document carrying any
// private/symmetric member is refused.
func DecodeJWK(raw []byte) (JWK, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return JWK{}, fmt.Errorf("jose.DecodeJWK: %w", err)
	}
	for _, m := range privateMembers {
		if _, ok := members[m]; ok {
			return JWK{}, fmt.Errorf("jose.DecodeJWK: key carries private member %q", m)
		}
	}
	var k JWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return JWK{}, fmt.Errorf("jose.DecodeJWK: %w", err)
	}
	if _, err := k.PublicKey(); err != nil {
		return JWK{}, err
	}
	return k, nil
}

// PublicKey decodes and validates the key material. The result is one of
// ed25519.PublicKey, *ecdsa.PublicKey (P-256, point on curve) or
// *rsa.PublicKey (>= MinRSABits, odd exponent > 1).
func (k JWK) PublicKey() (any, error) {
	switch k.Kty {
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("jose: OKP curve %q unsupported", k.Crv)
		}
		x, err := b64.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("jose: malformed Ed25519 x")
		}
		return ed25519.PublicKey(x), nil
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("jose: EC curve %q unsupported", k.Crv)
		}
		x, errX := b64.DecodeString(k.X)
		y, errY := b64.DecodeString(k.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("jose: malformed P-256 coordinates")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) { //nolint:staticcheck // explicit on-curve validation of untrusted input
			return nil, errors.New("jose: P-256 point is not on the curve")
		}
		return pub, nil
	case "RSA":
		n, errN := b64.DecodeString(k.N)
		e, errE := b64.DecodeString(k.E)
		if errN != nil || errE != nil || len(n) == 0 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("jose: malformed RSA modulus/exponent")
		}
		if n[0] == 0 {
			return nil, errors.New("jose: RSA modulus has a leading zero octet")
		}
		ev := new(big.Int).SetBytes(e)
		if ev.Cmp(big.NewInt(1)) <= 0 || ev.Bit(0) == 0 {
			return nil, errors.New("jose: RSA exponent must be odd and > 1")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ev.Int64())}
		if pub.N.BitLen() < MinRSABits {
			return nil, fmt.Errorf("jose: RSA modulus is %d bits, want >= %d", pub.N.BitLen(), MinRSABits)
		}
		return pub, nil
	default:
		return nil, fmt.Errorf("jose: kty %q unsupported", k.Kty)
	}
}

// ImpliedAlg returns the algorithm paired with the key type. When the JWK is
// alg-tagged the tag must agree with it.
func (k JWK) ImpliedAlg() (string, error) {
	pub, err := k.PublicKey()
	if err != nil {
		return "", err
	}
	alg, err := AlgForPublicKey(pub)
	if err != nil {
		return "", err
	}
	if k.Alg != "" && k.Alg != alg {
		return "", fmt.Errorf("jose: JWK alg tag %q does not match its key type (%q)", k.Alg, alg)
	}
	return alg, nil
}

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint, base64url without
// padding. The preimage is the lexicographically ordered REQUIRED members
// only, with no whitespace - so kid/alg/use never change the thumbprint.
func (k JWK) Thumbprint() (string, error) {
	if _, err := k.PublicKey(); err != nil {
		return "", err
	}
	var pre string
	switch k.Kty {
	case "OKP":
		pre = `{"crv":` + q(k.Crv) + `,"kty":"OKP","x":` + q(k.X) + `}`
	case "EC":
		pre = `{"crv":` + q(k.Crv) + `,"kty":"EC","x":` + q(k.X) + `,"y":` + q(k.Y) + `}`
	case "RSA":
		pre = `{"e":` + q(k.E) + `,"kty":"RSA","n":` + q(k.N) + `}`
	}
	sum := sha256.Sum256([]byte(pre))
	return b64.EncodeToString(sum[:]), nil
}

// q JSON-quotes a member value. Members are base64url / curve names, which
// never need escaping, but json.Marshal keeps this correct by construction.
func q(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// PublicOnly returns the key stripped of kid/alg/use - the form embedded in a
// DPoP proof header.
func (k JWK) PublicOnly() JWK {
	return JWK{Kty: k.Kty, Crv: k.Crv, X: k.X, Y: k.Y, N: k.N, E: k.E}
}
