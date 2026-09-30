package jose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
)

// strict64 rejects non-canonical base64url (non-zero trailing bits), so one
// token has exactly one encoding.
var strict64 = b64.Strict()

// Header is the protected JOSE header this package reads and writes. Field
// order is the serialisation order.
type Header struct {
	Typ string `json:"typ,omitempty"`
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	JWK *JWK   `json:"jwk,omitempty"`
}

// forbiddenHeaderMembers are header parameters this package refuses outright:
// remote key references (jku, x5u), certificate chains it does not validate
// (x5c), extensions it does not understand (crit, b64) and JWE members.
var forbiddenHeaderMembers = []string{"jku", "x5u", "x5c", "crit", "b64", "zip", "enc"}

// ErrMalformed is wrapped by every structural parse failure.
var ErrMalformed = errors.New("jose: malformed JWS")

// ErrSignature is wrapped by every signature/algorithm/key failure.
var ErrSignature = errors.New("jose: signature verification failed")

// JWS is a parsed (NOT yet verified) compact JWS.
type JWS struct {
	Header       Header
	RawHeader    []byte
	Payload      []byte
	Signature    []byte
	SigningInput []byte
}

// Parse splits and decodes a compact JWS without verifying it. maxBytes caps
// the input (<= 0 means 8 KiB). Every failure wraps ErrMalformed.
func Parse(compact string, maxBytes int) (*JWS, error) {
	if maxBytes <= 0 {
		maxBytes = 8 << 10
	}
	if len(compact) == 0 || len(compact) > maxBytes {
		return nil, fmt.Errorf("%w: size %d outside 1..%d", ErrMalformed, len(compact), maxBytes)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want 3 segments, got %d", ErrMalformed, len(parts))
	}
	rawHeader, err := strict64.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	payload, err := strict64.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	sig, err := strict64.DecodeString(parts[2])
	if err != nil || len(sig) == 0 {
		return nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	members, err := DecodeObject(rawHeader)
	if err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	for _, m := range forbiddenHeaderMembers {
		if _, ok := members[m]; ok {
			return nil, fmt.Errorf("%w: header parameter %q is not supported", ErrMalformed, m)
		}
	}
	var h Header
	if err := json.Unmarshal(rawHeader, &h); err != nil {
		return nil, fmt.Errorf("%w: header: %w", ErrMalformed, err)
	}
	if raw, ok := members["jwk"]; ok {
		k, err := DecodeJWK(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: header jwk: %w", ErrMalformed, err)
		}
		h.JWK = &k
	}
	if h.Alg == "" {
		return nil, fmt.Errorf("%w: header has no alg", ErrMalformed)
	}
	return &JWS{
		Header:       h,
		RawHeader:    rawHeader,
		Payload:      payload,
		Signature:    sig,
		SigningInput: []byte(parts[0] + "." + parts[1]),
	}, nil
}

// Verify checks the signature against key under the allowlist: the header alg
// must be allowed, must be the algorithm paired with key's type, and must
// agree with key's alg tag when it has one. Every failure wraps ErrSignature.
func (j *JWS) Verify(allow AlgSet, key JWK) error {
	if !allow.Allows(j.Header.Alg) {
		return fmt.Errorf("%w: alg %q not in the allowlist", ErrSignature, j.Header.Alg)
	}
	implied, err := key.ImpliedAlg()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	if implied != j.Header.Alg {
		return fmt.Errorf("%w: alg %q does not match the key (%q)", ErrSignature, j.Header.Alg, implied)
	}
	pub, err := key.PublicKey()
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	if err := VerifySignature(j.Header.Alg, pub, j.SigningInput, j.Signature); err != nil {
		return err
	}
	return nil
}

// Sign produces a compact JWS over payload with signer. h.Alg must be the
// algorithm paired with signer's public key; the result is self-verified
// before it is returned, so a signer whose Public() and Sign() disagree (a
// KMS key-version drift, a mis-wired provider) can never emit a token.
func Sign(signer crypto.Signer, h Header, payload []byte) (string, error) {
	return SignWithRand(rand.Reader, signer, h, payload)
}

// SignWithRand is Sign with an injected entropy source (tests).
func SignWithRand(r io.Reader, signer crypto.Signer, h Header, payload []byte) (string, error) {
	if signer == nil {
		return "", errors.New("jose.Sign: nil signer")
	}
	pub := signer.Public()
	if err := CheckKeyAlg(pub, h.Alg); err != nil {
		return "", fmt.Errorf("jose.Sign: %w", err)
	}
	rawHeader, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("jose.Sign: header: %w", err)
	}
	input := b64.EncodeToString(rawHeader) + "." + b64.EncodeToString(payload)
	sig, err := signInput(r, signer, h.Alg, []byte(input))
	if err != nil {
		return "", fmt.Errorf("jose.Sign: %w", err)
	}
	if err := VerifySignature(h.Alg, pub, []byte(input), sig); err != nil {
		return "", fmt.Errorf("jose.Sign: self-verification failed (signer public key and signature disagree): %w", err)
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// signInput runs the opaque signer and normalises its output to the JWS
// signature encoding for alg.
func signInput(r io.Reader, signer crypto.Signer, alg string, input []byte) ([]byte, error) {
	switch alg {
	case AlgEdDSA:
		return signer.Sign(r, input, crypto.Hash(0))
	case AlgES256:
		sum := sha256.Sum256(input)
		out, err := signer.Sign(r, sum[:], crypto.SHA256)
		if err != nil {
			return nil, err
		}
		return ecdsaToJWS(out)
	case AlgRS256:
		sum := sha256.Sum256(input)
		return signer.Sign(r, sum[:], crypto.SHA256)
	default:
		return nil, fmt.Errorf("algorithm %q unsupported", alg)
	}
}

// ecdsaSig is the ASN.1 form Go's ECDSA signers return.
type ecdsaSig struct{ R, S *big.Int }

// ecdsaToJWS converts a crypto.Signer ECDSA signature (ASN.1 DER by Go
// convention, or an already-fixed-width 64-byte R||S from a KMS that does not
// follow it) to the RFC 7518 §3.4 R||S form.
func ecdsaToJWS(sig []byte) ([]byte, error) {
	var es ecdsaSig
	if rest, err := asn1.Unmarshal(sig, &es); err == nil && len(rest) == 0 && es.R != nil && es.S != nil {
		if es.R.Sign() <= 0 || es.S.Sign() <= 0 || es.R.BitLen() > 256 || es.S.BitLen() > 256 {
			return nil, errors.New("ecdsa signature out of range")
		}
		out := make([]byte, 64)
		es.R.FillBytes(out[:32])
		es.S.FillBytes(out[32:])
		return out, nil
	}
	if len(sig) == 64 {
		return append([]byte(nil), sig...), nil
	}
	return nil, errors.New("ecdsa signer returned neither ASN.1 DER nor a 64-byte R||S signature")
}

// ECDSARawToDER converts a 64-byte R||S signature to ASN.1 DER - what a
// crypto.Signer over a KMS that returns raw signatures must hand back to
// honour the crypto.Signer ECDSA convention.
func ECDSARawToDER(raw []byte) ([]byte, error) {
	if len(raw) != 64 {
		return nil, fmt.Errorf("jose.ECDSARawToDER: want 64 bytes, got %d", len(raw))
	}
	return asn1.Marshal(ecdsaSig{R: new(big.Int).SetBytes(raw[:32]), S: new(big.Int).SetBytes(raw[32:])})
}

// VerifySignature verifies a JWS signature for alg over input with pub.
// Every failure wraps ErrSignature.
func VerifySignature(alg string, pub any, input, sig []byte) error {
	if err := CheckKeyAlg(pub, alg); err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	switch alg {
	case AlgEdDSA:
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub.(ed25519.PublicKey), input, sig) {
			return ErrSignature
		}
		return nil
	case AlgES256:
		if len(sig) != 64 {
			return ErrSignature
		}
		sum := sha256.Sum256(input)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub.(*ecdsa.PublicKey), sum[:], r, s) {
			return ErrSignature
		}
		return nil
	case AlgRS256:
		sum := sha256.Sum256(input)
		if err := rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, sum[:], sig); err != nil {
			return ErrSignature
		}
		return nil
	default:
		return fmt.Errorf("%w: alg %q unsupported", ErrSignature, alg)
	}
}

// DecodeObject decodes a JSON object into its top-level members, refusing
// duplicate member names (RFC 7515 §4 / RFC 7519 §4: a parser MUST reject or
// use the last; we reject, so two parsers can never disagree on a claim) and
// trailing data.
func DecodeObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("duplicate member %q", key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON object")
	}
	return out, nil
}

// DecodeClaims strictly decodes a JWS payload into v: it must be a single
// JSON object with no duplicate top-level members.
func DecodeClaims(payload []byte, v any) error {
	if _, err := DecodeObject(payload); err != nil {
		return fmt.Errorf("%w: claims: %w", ErrMalformed, err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("%w: claims: %w", ErrMalformed, err)
	}
	return nil
}
