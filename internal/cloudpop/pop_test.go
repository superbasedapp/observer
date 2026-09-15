package cloudpop

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// mustKey generates a deterministic-enough test key pair.
func mustKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

const testToken = "sbo_api_token_abcdef"

func TestCreateVerifyRoundTrip(t *testing.T) {
	pub, priv := mustKey(t)
	now := time.Unix(1_800_000_000, 0)

	cases := []struct {
		name   string
		method string
		url    string
		body   []byte
	}{
		{"get no body", "GET", "https://cloud.superbased.app/v1/results?after=5", nil},
		{"post with body", "POST", "https://cloud.superbased.app/v1/jobs", []byte(`{"a":1}`)},
		{"delete empty body", "DELETE", "https://cloud.superbased.app/v1/devices/self", nil},
		{"port stripped", "GET", "https://cloud.superbased.app:443/v1/nonce", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof, err := Create(CreateParams{
				PrivateKey:  priv,
				Method:      tc.method,
				URL:         tc.url,
				AccessToken: testToken,
				IssuedAt:    now,
				Body:        tc.body,
			})
			if err != nil {
				t.Fatalf("Create: %v", err)
			}
			v, err := Verify(proof, VerifyParams{
				ExpectedMethod:          tc.method,
				ExpectedURL:             tc.url,
				ExpectedThumbprint:      Thumbprint(pub),
				ExpectedAccessTokenHash: HashAccessToken(testToken),
				Now:                     now,
				MaxAge:                  2 * time.Minute,
				MaxSkew:                 30 * time.Second,
				Body:                    tc.body,
			})
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if v.JTI == "" {
				t.Error("expected non-empty jti for replay tracking")
			}
			if v.Thumbprint != Thumbprint(pub) {
				t.Errorf("thumbprint = %q, want %q", v.Thumbprint, Thumbprint(pub))
			}
		})
	}
}

// forge builds a proof with fully controlled claims/header so attack cases can
// construct proofs Create would refuse to mint.
func forge(t *testing.T, priv ed25519.PrivateKey, h header, c claims) string {
	t.Helper()
	eh, err := encodeJSON(h)
	if err != nil {
		t.Fatalf("encode header: %v", err)
	}
	ec, err := encodeJSON(c)
	if err != nil {
		t.Fatalf("encode claims: %v", err)
	}
	si := eh + "." + ec
	sig := ed25519.Sign(priv, []byte(si))
	return si + "." + b64.EncodeToString(sig)
}

func baseClaims(now time.Time) claims {
	return claims{
		JTI: "jti-1",
		HTM: "POST",
		HTU: "https://cloud.superbased.app/v1/jobs",
		IAT: now.Unix(),
		ATH: HashAccessToken(testToken),
		BDH: BodyDigest([]byte("payload")),
	}
}

func TestVerifyAttackMatrix(t *testing.T) {
	pub, priv := mustKey(t)
	_, otherPriv := mustKey(t)
	now := time.Unix(1_800_000_000, 0)
	goodHeader := header{Typ: typ, Alg: alg, JWK: newJWK(pub)}

	baseVerify := VerifyParams{
		ExpectedMethod:          "POST",
		ExpectedURL:             "https://cloud.superbased.app/v1/jobs",
		ExpectedThumbprint:      Thumbprint(pub),
		ExpectedAccessTokenHash: HashAccessToken(testToken),
		Now:                     now,
		MaxAge:                  2 * time.Minute,
		MaxSkew:                 30 * time.Second,
		Body:                    []byte("payload"),
	}

	cases := []struct {
		name    string
		proof   func() string
		verify  VerifyParams
		wantErr error
	}{
		{
			name:    "wrong signing key",
			proof:   func() string { return forge(t, otherPriv, goodHeader, baseClaims(now)) },
			verify:  baseVerify,
			wantErr: ErrSignature,
		},
		{
			name: "thumbprint mismatch (key swapped, self-consistent)",
			proof: func() string {
				apub, apriv, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatalf("generate attacker key: %v", err)
				}
				h := header{Typ: typ, Alg: alg, JWK: newJWK(apub)}
				return forge(t, apriv, h, baseClaims(now))
			},
			verify:  baseVerify,
			wantErr: ErrThumbprintMismatch,
		},
		{
			name: "altered method",
			proof: func() string {
				c := baseClaims(now)
				c.HTM = "GET"
				return forge(t, priv, goodHeader, c)
			},
			verify:  baseVerify,
			wantErr: ErrMethodMismatch,
		},
		{
			name: "altered path",
			proof: func() string {
				c := baseClaims(now)
				c.HTU = "https://cloud.superbased.app/v1/admin"
				return forge(t, priv, goodHeader, c)
			},
			verify:  baseVerify,
			wantErr: ErrHTUMismatch,
		},
		{
			name:  "altered body",
			proof: func() string { return forge(t, priv, goodHeader, baseClaims(now)) },
			verify: func() VerifyParams {
				v := baseVerify
				v.Body = []byte("tampered")
				return v
			}(),
			wantErr: ErrBodyDigestMismatch,
		},
		{
			name: "missing body digest on write",
			proof: func() string {
				c := baseClaims(now)
				c.BDH = ""
				return forge(t, priv, goodHeader, c)
			},
			verify:  baseVerify,
			wantErr: ErrBodyDigestMissing,
		},
		{
			name: "expired iat",
			proof: func() string {
				c := baseClaims(now.Add(-10 * time.Minute))
				return forge(t, priv, goodHeader, c)
			},
			verify:  baseVerify,
			wantErr: ErrClockWindow,
		},
		{
			name: "future iat beyond skew",
			proof: func() string {
				c := baseClaims(now.Add(10 * time.Minute))
				return forge(t, priv, goodHeader, c)
			},
			verify:  baseVerify,
			wantErr: ErrClockWindow,
		},
		{
			name:  "access-token binding mismatch",
			proof: func() string { return forge(t, priv, goodHeader, baseClaims(now)) },
			verify: func() VerifyParams {
				v := baseVerify
				v.ExpectedAccessTokenHash = HashAccessToken("a-different-stolen-token")
				return v
			}(),
			wantErr: ErrAccessTokenMismatch,
		},
		{
			name: "wrong header typ",
			proof: func() string {
				h := header{Typ: "dpop+jwt", Alg: alg, JWK: newJWK(pub)}
				return forge(t, priv, h, baseClaims(now))
			},
			verify:  baseVerify,
			wantErr: ErrMalformed,
		},
		{
			name:    "not three segments",
			proof:   func() string { return "aaa.bbb" },
			verify:  baseVerify,
			wantErr: ErrMalformed,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(tc.proof(), tc.verify)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestEncodedPathAmbiguity is the load-bearing security property: an encoded
// slash must never canonicalize equal to a real path separator.
func TestEncodedPathAmbiguity(t *testing.T) {
	enc, err := CanonicalHTU("https://h.example/a%2Fb")
	if err != nil {
		t.Fatalf("CanonicalHTU encoded: %v", err)
	}
	plain, err := CanonicalHTU("https://h.example/a/b")
	if err != nil {
		t.Fatalf("CanonicalHTU plain: %v", err)
	}
	if enc == plain {
		t.Fatalf("/a%%2Fb and /a/b canonicalized equal (%q) — path-confusion hole", enc)
	}
	if !strings.Contains(enc, "%2F") {
		t.Errorf("encoded slash lost its encoding: %q", enc)
	}

	// A proof for the encoded path must not verify against the plain path.
	_, priv := mustKey(t)
	proof, err := Create(CreateParams{
		PrivateKey:  priv,
		Method:      "GET",
		URL:         "https://h.example/a%2Fb",
		AccessToken: testToken,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Verify(proof, VerifyParams{
		ExpectedMethod:          "GET",
		ExpectedURL:             "https://h.example/a/b",
		ExpectedAccessTokenHash: HashAccessToken(testToken),
		MaxSkew:                 time.Minute,
	}); !errors.Is(err, ErrHTUMismatch) {
		t.Fatalf("encoded-vs-plain path verified or wrong error: %v", err)
	}
}

// TestCanonicalHTU covers the normalization rules directly.
func TestCanonicalHTU(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"HTTPS://Cloud.SuperBased.App/v1/Jobs", "https://cloud.superbased.app/v1/Jobs"},
		{"https://h.example:443/x", "https://h.example/x"},
		{"http://h.example:80/x", "http://h.example/x"},
		{"https://h.example:8443/x", "https://h.example:8443/x"},
		{"https://h.example", "https://h.example/"},
		{"https://h.example/%41%42", "https://h.example/AB"}, // unreserved decoded
		{"https://h.example/a?q=1#frag", "https://h.example/a"},
		{"https://h.example/%2f", "https://h.example/%2F"}, // reserved kept, uppercased
	}
	for _, tc := range cases {
		got, err := CanonicalHTU(tc.in)
		if err != nil {
			t.Errorf("CanonicalHTU(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("CanonicalHTU(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	for _, bad := range []string{"ftp://h/x", "/relative/only", "https://"} {
		if _, err := CanonicalHTU(bad); err == nil {
			t.Errorf("CanonicalHTU(%q) accepted, want error", bad)
		}
	}
}

// TestVerifyRejectsMalformedJTI proves the FC3 bounded-jti grammar: a proof is
// rejected with ErrJTIInvalid when its signed jti is empty, out of the
// [16,64]-byte range, or carries a non-base64url character — while a valid
// bounded base64url jti verifies. The verifier must not shift jti validation
// onto the replay-cache database key.
func TestVerifyRejectsMalformedJTI(t *testing.T) {
	pub, priv := mustKey(t)
	now := time.Unix(1_800_000_000, 0)
	const url = "https://cloud.superbased.app/v1/usage"

	// Build a signed GET proof with an EXACT jti (Create substitutes a random
	// value for an empty jti, so it cannot mint the empty/malformed cases we
	// need to exercise the verifier). This is a same-package test, so it can use
	// the internal JWS primitives directly.
	htu, err := CanonicalHTU(url)
	if err != nil {
		t.Fatalf("CanonicalHTU: %v", err)
	}
	mk := func(jti string) string {
		h := header{Typ: typ, Alg: alg, JWK: newJWK(pub)}
		c := claims{JTI: jti, HTM: "GET", HTU: htu, IAT: now.Unix(), ATH: HashAccessToken(testToken)}
		eh, err := encodeJSON(h)
		if err != nil {
			t.Fatalf("encode header: %v", err)
		}
		ec, err := encodeJSON(c)
		if err != nil {
			t.Fatalf("encode claims: %v", err)
		}
		si := eh + "." + ec
		sig := ed25519.Sign(priv, []byte(si))
		return si + "." + b64.EncodeToString(sig)
	}
	verify := func(proof string) error {
		_, err := Verify(proof, VerifyParams{
			ExpectedMethod:          "GET",
			ExpectedURL:             url,
			ExpectedThumbprint:      Thumbprint(pub),
			ExpectedAccessTokenHash: HashAccessToken(testToken),
			Now:                     now,
			MaxAge:                  2 * time.Minute,
			MaxSkew:                 30 * time.Second,
		})
		return err
	}

	bad := []struct {
		name string
		jti  string
	}{
		{"empty", ""},
		{"one_char", "x"},
		{"fifteen_bytes", strings.Repeat("a", 15)},
		{"sixty_five_bytes", strings.Repeat("a", 65)},
		{"illegal_plus", strings.Repeat("a", 21) + "+"},
		{"illegal_slash", strings.Repeat("a", 21) + "/"},
		{"illegal_space", strings.Repeat("a", 21) + " "},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if err := verify(mk(c.jti)); !errors.Is(err, ErrJTIInvalid) {
				t.Fatalf("Verify(jti=%q) err=%v, want ErrJTIInvalid", c.jti, err)
			}
		})
	}

	// A valid 22-char base64url jti (the shape randomJTI mints) verifies.
	if err := verify(mk("abcDEF012345_-6789wxyz")); err != nil {
		t.Fatalf("valid bounded jti rejected: %v", err)
	}
}
