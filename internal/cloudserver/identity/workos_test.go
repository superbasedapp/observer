package identity

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// jwksTestServer serves a JWKS built from the given RSA public keys (keyed by
// kid) and counts fetches so rotation behaviour can be asserted.
type jwksTestServer struct {
	srv    *httptest.Server
	fetch  atomic.Int32
	bodyFn func() []byte
}

func jwkJSON(t *testing.T, kid string, pub *rsa.PublicKey) map[string]string {
	t.Helper()
	var eb [8]byte
	binary.BigEndian.PutUint64(eb[:], uint64(pub.E))
	// trim leading zero bytes of the exponent
	i := 0
	for i < len(eb)-1 && eb[i] == 0 {
		i++
	}
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"alg": "RS256",
		"use": "sig",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(eb[i:]),
	}
}

func newJWKSServer(t *testing.T, keys map[string]*rsa.PublicKey) *jwksTestServer {
	t.Helper()
	j := &jwksTestServer{}
	j.bodyFn = func() []byte {
		out := map[string]any{}
		var arr []map[string]string
		for kid, pub := range keys {
			arr = append(arr, jwkJSON(t, kid, pub))
		}
		out["keys"] = arr
		b, _ := json.Marshal(out)
		return b
	}
	j.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		j.fetch.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(j.bodyFn())
	}))
	t.Cleanup(j.srv.Close)
	return j
}

func mintToken(t *testing.T, priv *rsa.PrivateKey, kid, alg string, claims jwt.MapClaims) string {
	t.Helper()
	method := jwt.GetSigningMethod(alg)
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = kid
	var key any = priv
	if alg == "none" {
		key = jwt.UnsafeAllowNoneSignatureType
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

const (
	testClientID = "client_01TESTWORKOSCLIENTID"
	testIssuer   = "https://api.workos.com/user_management/" + testClientID
)

func baseClaims(now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":       testIssuer,
		"sub":       "user_01HBEQKA6K4QJAS93VPE39W1JT",
		"client_id": testClientID,
		"sid":       "session_01HQSXZGF8FHF7A9ZZFCW4387R",
		"email":     "dev@example.com",
		"iat":       now.Add(-time.Minute).Unix(),
		"exp":       now.Add(time.Hour).Unix(),
	}
}

func newVerifier(t *testing.T, jwksURL string, now time.Time) *WorkOSVerifier {
	t.Helper()
	v, err := NewWorkOSVerifier(
		testClientID,
		WithJWKSURL(jwksURL),
		WithClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("NewWorkOSVerifier: %v", err)
	}
	return v
}

func TestWorkOSVerifierAcceptsValidToken(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	js := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &priv.PublicKey})
	now := time.Unix(1_800_000_000, 0)
	v := newVerifier(t, js.srv.URL, now)

	tok := mintToken(t, priv, "kid-1", "RS256", baseClaims(now))
	id, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify valid token: %v", err)
	}
	if id.Provider != "workos" || id.Subject != "user_01HBEQKA6K4QJAS93VPE39W1JT" {
		t.Fatalf("wrong identity: %+v", id)
	}
	if id.Email != "dev@example.com" {
		t.Fatalf("email not carried: %+v", id)
	}
}

func TestWorkOSVerifierRejects(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	js := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &priv.PublicKey})
	now := time.Unix(1_800_000_000, 0)
	v := newVerifier(t, js.srv.URL, now)
	ctx := context.Background()

	cases := []struct {
		name string
		tok  string
	}{
		{"expired", mintToken(t, priv, "kid-1", "RS256", func() jwt.MapClaims {
			c := baseClaims(now)
			c["exp"] = now.Add(-time.Minute).Unix()
			return c
		}())},
		{"wrong issuer", mintToken(t, priv, "kid-1", "RS256", func() jwt.MapClaims {
			c := baseClaims(now)
			c["iss"] = "https://evil.example.com"
			return c
		}())},
		{"wrong client_id", mintToken(t, priv, "kid-1", "RS256", func() jwt.MapClaims {
			c := baseClaims(now)
			c["client_id"] = "client_01SOMEONEELSE"
			return c
		}())},
		{"no exp", mintToken(t, priv, "kid-1", "RS256", func() jwt.MapClaims {
			c := baseClaims(now)
			delete(c, "exp")
			return c
		}())},
		{"empty sub", mintToken(t, priv, "kid-1", "RS256", func() jwt.MapClaims {
			c := baseClaims(now)
			c["sub"] = ""
			return c
		}())},
		{"unknown kid", mintToken(t, priv, "kid-UNKNOWN", "RS256", baseClaims(now))},
		{"wrong signing key", mintToken(t, other, "kid-1", "RS256", baseClaims(now))},
		{"alg none", mintToken(t, priv, "kid-1", "none", baseClaims(now))},
		{"empty token", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.Verify(ctx, tc.tok)
			if !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("%s: expected ErrInvalidToken, got %v", tc.name, err)
			}
		})
	}
}

// TestWorkOSVerifierHMACConfusionRejected proves an attacker cannot present an
// HS256 token signed with the (public) RSA modulus as the HMAC secret — the
// classic alg-confusion attack. WithValidMethods([]{"RS256"}) refuses it.
func TestWorkOSVerifierHMACConfusionRejected(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	js := newJWKSServer(t, map[string]*rsa.PublicKey{"kid-1": &priv.PublicKey})
	now := time.Unix(1_800_000_000, 0)
	v := newVerifier(t, js.srv.URL, now)

	// Forge an HS256 token using the RSA public modulus bytes as the HMAC key.
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, baseClaims(now))
	tok.Header["kid"] = "kid-1"
	forged, err := tok.SignedString(priv.PublicKey.N.Bytes())
	if err != nil {
		t.Fatalf("sign forged: %v", err)
	}
	if _, err := v.Verify(context.Background(), forged); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("HMAC-confusion token must be refused, got %v", err)
	}
}

// TestWorkOSVerifierRefetchesOnRotation proves an unknown kid triggers exactly
// one JWKS refetch, after which a token signed by the rotated key validates.
func TestWorkOSVerifierRefetchesOnRotation(t *testing.T) {
	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := map[string]*rsa.PublicKey{"kid-1": &priv1.PublicKey}
	js := newJWKSServer(t, keys)
	now := time.Unix(1_800_000_000, 0)
	v := newVerifier(t, js.srv.URL, now)
	ctx := context.Background()

	// First validation fetches the JWKS once.
	if _, err := v.Verify(ctx, mintToken(t, priv1, "kid-1", "RS256", baseClaims(now))); err != nil {
		t.Fatalf("initial verify: %v", err)
	}
	if got := js.fetch.Load(); got != 1 {
		t.Fatalf("expected 1 JWKS fetch, got %d", got)
	}

	// Rotate: the server now also serves kid-2. A token signed by kid-2 is an
	// unknown-kid cache miss ⇒ exactly one more fetch, then it validates.
	keys["kid-2"] = &priv2.PublicKey
	if _, err := v.Verify(ctx, mintToken(t, priv2, "kid-2", "RS256", baseClaims(now))); err != nil {
		t.Fatalf("post-rotation verify: %v", err)
	}
	if got := js.fetch.Load(); got != 2 {
		t.Fatalf("expected 2 JWKS fetches after rotation, got %d", got)
	}
}
