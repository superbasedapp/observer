package cloudpop

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// typ is the fixed proof media type carried in the protected header's "typ".
const typ = "sbo-pop+jws"

// alg is the fixed JWS algorithm (EdDSA over Ed25519, RFC 8037).
const alg = "EdDSA"

// Sentinel errors so callers (and the attack tests) can branch on the precise
// verification failure. Every error returned by Verify wraps one of these.
var (
	// ErrMalformed is a structurally invalid proof (bad segments, bad base64,
	// bad JSON, wrong header typ/alg).
	ErrMalformed = errors.New("cloudpop: malformed proof")
	// ErrSignature is a signature that does not verify against the embedded key.
	ErrSignature = errors.New("cloudpop: signature verification failed")
	// ErrThumbprintMismatch means the embedded key does not match the expected
	// (registered) device thumbprint.
	ErrThumbprintMismatch = errors.New("cloudpop: device thumbprint mismatch")
	// ErrMethodMismatch means htm != the expected request method.
	ErrMethodMismatch = errors.New("cloudpop: htm method mismatch")
	// ErrHTUMismatch means htu != the canonical expected URL.
	ErrHTUMismatch = errors.New("cloudpop: htu URL mismatch")
	// ErrClockWindow means iat is outside the accepted window.
	ErrClockWindow = errors.New("cloudpop: iat outside clock window")
	// ErrAccessTokenMismatch means ath != the hash of the presented token.
	ErrAccessTokenMismatch = errors.New("cloudpop: access-token binding mismatch")
	// ErrBodyDigestMissing means a write-method proof carried no body digest.
	ErrBodyDigestMissing = errors.New("cloudpop: body digest required on write method")
	// ErrBodyDigestMismatch means the body digest did not match the request body.
	ErrBodyDigestMismatch = errors.New("cloudpop: body digest mismatch")
	// ErrJTIInvalid means the signed jti is empty, out of the bounded length
	// range, or contains a non-base64url character. A bounded fixed-format jti is
	// required (FC3): the replay cache primary-keys on this caller-controlled
	// text, so an empty or near-header-limit jti must be rejected at the verifier
	// rather than shifting validation onto a database key.
	ErrJTIInvalid = errors.New("cloudpop: jti malformed or out of bounds")
)

// jtiMinBytes / jtiMaxBytes bound the signed jti. A random 128-bit jti is 22
// base64url chars; the range accepts that and other conservative identifiers
// while rejecting empty and near-header-limit values (FC3).
const (
	jtiMinBytes = 16
	jtiMaxBytes = 64
)

// validJTI reports whether jti is a bounded base64url identifier: non-empty,
// 16–64 bytes, every character in [A-Za-z0-9_-] (the RFC 4648 base64url
// alphabet, no padding).
func validJTI(jti string) bool {
	if len(jti) < jtiMinBytes || len(jti) > jtiMaxBytes {
		return false
	}
	for i := 0; i < len(jti); i++ {
		c := jti[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// header is the JWS protected header.
type header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
	JWK jwk    `json:"jwk"`
}

// claims is the JWS payload. Field order is the serialization order; bdh is
// omitted (via omitempty) for non-write requests.
type claims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath"`
	BDH string `json:"bdh,omitempty"`
}

// CreateParams are the inputs to Create.
type CreateParams struct {
	// PrivateKey is the device Ed25519 private key. Required.
	PrivateKey ed25519.PrivateKey
	// Method is the HTTP method (case-insensitive; stored uppercased as htm).
	Method string
	// URL is the request target; canonicalized to htu internally.
	URL string
	// AccessToken is the SuperBased API token being bound (hashed into ath).
	AccessToken string
	// IssuedAt is the proof timestamp; zero means time.Now at call.
	IssuedAt time.Time
	// JTI is the unique proof id; empty means a fresh random 128-bit value.
	JTI string
	// Body is the request body for write methods (POST/PUT/PATCH/DELETE); its
	// "sha256:<hex>" digest becomes bdh. A nil body on a write method binds the
	// empty body (still a present, matchable digest).
	Body []byte
}

// Create signs and returns a compact proof string for a single request.
func Create(p CreateParams) (string, error) {
	if len(p.PrivateKey) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("cloudpop.Create: private key is %d bytes, want %d", len(p.PrivateKey), ed25519.PrivateKeySize)
	}
	method := strings.ToUpper(strings.TrimSpace(p.Method))
	if method == "" {
		return "", fmt.Errorf("cloudpop.Create: empty method")
	}
	if p.AccessToken == "" {
		return "", fmt.Errorf("cloudpop.Create: empty access token")
	}
	htu, err := CanonicalHTU(p.URL)
	if err != nil {
		return "", fmt.Errorf("cloudpop.Create: %w", err)
	}
	jti := p.JTI
	if jti == "" {
		jti, err = randomJTI()
		if err != nil {
			return "", fmt.Errorf("cloudpop.Create: %w", err)
		}
	}
	iat := p.IssuedAt
	if iat.IsZero() {
		iat = time.Now()
	}

	pub, ok := p.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("cloudpop.Create: private key has no ed25519 public half")
	}
	h := header{Typ: typ, Alg: alg, JWK: newJWK(pub)}
	c := claims{
		JTI: jti,
		HTM: method,
		HTU: htu,
		IAT: iat.Unix(),
		ATH: HashAccessToken(p.AccessToken),
	}
	if isWriteMethod(method) {
		c.BDH = BodyDigest(p.Body)
	}

	encHeader, err := encodeJSON(h)
	if err != nil {
		return "", fmt.Errorf("cloudpop.Create: encode header: %w", err)
	}
	encClaims, err := encodeJSON(c)
	if err != nil {
		return "", fmt.Errorf("cloudpop.Create: encode claims: %w", err)
	}
	signingInput := encHeader + "." + encClaims
	sig := ed25519.Sign(p.PrivateKey, []byte(signingInput))
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// VerifyParams are the inputs to Verify. All comparisons are exact.
type VerifyParams struct {
	// ExpectedMethod is the HTTP method the server observed (case-insensitive).
	// Its write-ness (POST/PUT/PATCH/DELETE) also decides whether a body digest
	// is required.
	ExpectedMethod string
	// ExpectedURL is the request target the server observed; canonicalized and
	// compared against htu.
	ExpectedURL string
	// ExpectedThumbprint, when non-empty, is the registered device key's
	// RFC 7638 thumbprint; the embedded key must match it.
	ExpectedThumbprint string
	// ExpectedAccessTokenHash, when non-empty, is HashAccessToken of the token
	// the caller presented (typically the Authorization bearer); ath must equal.
	ExpectedAccessTokenHash string
	// Now is the reference time for the iat window; zero means time.Now.
	Now time.Time
	// MaxAge bounds how far in the past iat may be. Zero disables the past bound
	// (not recommended outside tests).
	MaxAge time.Duration
	// MaxSkew bounds how far in the future iat may be (clock skew tolerance).
	MaxSkew time.Duration
	// Body is the request body the server received; on write methods its digest
	// must match bdh.
	Body []byte
}

// Verified is the trustworthy result of a successful Verify.
type Verified struct {
	// JTI is the proof's unique id — the CALLER must check it against a
	// single-use replay cache scoped to the clock window.
	JTI string
	// Thumbprint is the RFC 7638 thumbprint of the proving key (equals
	// ExpectedThumbprint when that was supplied).
	Thumbprint string
	// PublicKey is the device public key that signed the proof.
	PublicKey ed25519.PublicKey
	// IssuedAt is the proof timestamp.
	IssuedAt time.Time
	// Method is the verified htm.
	Method string
	// HTU is the verified canonical URL.
	HTU string
}

// Verify parses, authenticates, and validates a proof. Signature verification
// runs before any claim is trusted. Replay detection (jti) is the caller's job
// via the returned Verified.JTI.
func Verify(proof string, p VerifyParams) (*Verified, error) {
	h, c, signingInput, sig, err := parse(proof)
	if err != nil {
		return nil, err
	}
	pub, err := h.JWK.publicKey()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	// Authenticate first: never trust a claim from an unverified signature.
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, ErrSignature
	}

	tp := Thumbprint(pub)
	if p.ExpectedThumbprint != "" && subtle.ConstantTimeCompare([]byte(tp), []byte(p.ExpectedThumbprint)) != 1 {
		return nil, ErrThumbprintMismatch
	}

	if !strings.EqualFold(c.HTM, strings.TrimSpace(p.ExpectedMethod)) {
		return nil, fmt.Errorf("%w: proof htm=%q expected=%q", ErrMethodMismatch, c.HTM, p.ExpectedMethod)
	}
	expectedHTU, err := CanonicalHTU(p.ExpectedURL)
	if err != nil {
		return nil, fmt.Errorf("cloudpop.Verify: expected URL: %w", err)
	}
	if c.HTU != expectedHTU {
		return nil, fmt.Errorf("%w: proof htu=%q expected=%q", ErrHTUMismatch, c.HTU, expectedHTU)
	}

	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	iat := time.Unix(c.IAT, 0)
	if p.MaxAge > 0 && iat.Before(now.Add(-p.MaxAge)) {
		return nil, fmt.Errorf("%w: iat %s older than %s before %s", ErrClockWindow, iat.UTC(), p.MaxAge, now.UTC())
	}
	if iat.After(now.Add(p.MaxSkew)) {
		return nil, fmt.Errorf("%w: iat %s in the future beyond skew %s of %s", ErrClockWindow, iat.UTC(), p.MaxSkew, now.UTC())
	}

	if p.ExpectedAccessTokenHash != "" && subtle.ConstantTimeCompare([]byte(c.ATH), []byte(p.ExpectedAccessTokenHash)) != 1 {
		return nil, ErrAccessTokenMismatch
	}

	if isWriteMethod(c.HTM) {
		if c.BDH == "" {
			return nil, ErrBodyDigestMissing
		}
		if c.BDH != BodyDigest(p.Body) {
			return nil, fmt.Errorf("%w: proof bdh=%q", ErrBodyDigestMismatch, c.BDH)
		}
	}

	// The jti primary-keys the replay cache; reject an empty/oversize/malformed
	// value at the verifier rather than committing caller-controlled text to a
	// database key (FC3).
	if !validJTI(c.JTI) {
		return nil, fmt.Errorf("%w: len=%d", ErrJTIInvalid, len(c.JTI))
	}

	return &Verified{
		JTI:        c.JTI,
		Thumbprint: tp,
		PublicKey:  pub,
		IssuedAt:   iat,
		Method:     c.HTM,
		HTU:        c.HTU,
	}, nil
}

// parse splits and decodes a compact proof into its verified-once-signed parts.
func parse(proof string) (header, claims, string, []byte, error) {
	var h header
	var c claims
	parts := strings.Split(proof, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return h, c, "", nil, fmt.Errorf("%w: want 3 non-empty segments, got %d", ErrMalformed, len(parts))
	}
	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return h, c, "", nil, fmt.Errorf("%w: header base64: %w", ErrMalformed, err)
	}
	if err := strictUnmarshal(rawHeader, &h); err != nil {
		return h, c, "", nil, fmt.Errorf("%w: header json: %w", ErrMalformed, err)
	}
	if h.Typ != typ {
		return h, c, "", nil, fmt.Errorf("%w: typ %q, want %q", ErrMalformed, h.Typ, typ)
	}
	if h.Alg != alg {
		return h, c, "", nil, fmt.Errorf("%w: alg %q, want %q", ErrMalformed, h.Alg, alg)
	}
	rawClaims, err := b64.DecodeString(parts[1])
	if err != nil {
		return h, c, "", nil, fmt.Errorf("%w: claims base64: %w", ErrMalformed, err)
	}
	if err := strictUnmarshal(rawClaims, &c); err != nil {
		return h, c, "", nil, fmt.Errorf("%w: claims json: %w", ErrMalformed, err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return h, c, "", nil, fmt.Errorf("%w: signature base64: %w", ErrMalformed, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return h, c, "", nil, fmt.Errorf("%w: signature is %d bytes, want %d", ErrMalformed, len(sig), ed25519.SignatureSize)
	}
	return h, c, parts[0] + "." + parts[1], sig, nil
}

// strictUnmarshal rejects unknown fields so a proof cannot smuggle extra claims
// past a verifier.
func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

// HashAccessToken returns base64url(SHA-256(token)) — the value bound into the
// proof's ath claim. The server computes it from the presented bearer token.
func HashAccessToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return b64.EncodeToString(sum[:])
}

// BodyDigest returns the "sha256:<hex>" digest of a request body, matching the
// digest format used across the cloud contract (internal/cloudcontract). A nil
// body hashes as the empty byte slice.
func BodyDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// isWriteMethod reports whether an HTTP method mutates state and thus requires
// a body digest in its proof.
func isWriteMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

// randomJTI returns a fresh 128-bit base64url identifier.
func randomJTI() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}
	return b64.EncodeToString(raw[:]), nil
}
