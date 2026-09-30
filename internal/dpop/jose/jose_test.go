package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func mustKey(t testing.TB, alg string) crypto.Signer {
	t.Helper()
	var (
		s   crypto.Signer
		err error
	)
	if alg == AlgRS256 {
		s, err = rsa.GenerateKey(rand.Reader, 2048) // smaller than production for test speed
	} else {
		s, err = GenerateKey(rand.Reader, alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustJWK(t testing.TB, s crypto.Signer, alg string) JWK {
	t.Helper()
	k, err := PublicJWK(s.Public(), alg, "k1")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSignVerifyRoundTripPerAlg(t *testing.T) {
	for _, alg := range []string{AlgEdDSA, AlgES256, AlgRS256} {
		t.Run(alg, func(t *testing.T) {
			s := mustKey(t, alg)
			k := mustJWK(t, s, alg)
			tok, err := Sign(s, Header{Typ: "at+jwt", Alg: alg, Kid: "k1"}, []byte(`{"a":1}`))
			if err != nil {
				t.Fatal(err)
			}
			j, err := Parse(tok, 0)
			if err != nil {
				t.Fatal(err)
			}
			if j.Header.Typ != "at+jwt" || j.Header.Kid != "k1" {
				t.Fatalf("header = %+v", j.Header)
			}
			if err := j.Verify(DefaultAlgs(), k); err != nil {
				t.Fatalf("verify: %v", err)
			}
			// Tamper the payload -> signature failure.
			parts := strings.Split(tok, ".")
			bad := parts[0] + "." + b64.EncodeToString([]byte(`{"a":2}`)) + "." + parts[2]
			jb, err := Parse(bad, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := jb.Verify(DefaultAlgs(), k); !errors.Is(err, ErrSignature) {
				t.Fatalf("tampered verify err = %v, want ErrSignature", err)
			}
		})
	}
}

func TestAlgPolicy(t *testing.T) {
	for _, bad := range []string{"none", "HS256", "HS512", "PS256", "ES384", "", "eddsa"} {
		if _, err := NewAlgSet(bad); err == nil {
			t.Errorf("NewAlgSet(%q) accepted", bad)
		}
	}
	var zero AlgSet
	if zero.Allows(AlgEdDSA) || !zero.Empty() {
		t.Error("zero AlgSet must accept nothing")
	}
	only, _ := NewAlgSet(AlgEdDSA)
	s := mustKey(t, AlgES256)
	k := mustJWK(t, s, AlgES256)
	tok, err := Sign(s, Header{Alg: AlgES256}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	j, _ := Parse(tok, 0)
	if err := j.Verify(only, k); !errors.Is(err, ErrSignature) {
		t.Fatalf("off-allowlist verify err = %v", err)
	}
}

func TestAlgNoneAndHMACUnverifiable(t *testing.T) {
	s := mustKey(t, AlgEdDSA)
	k := mustJWK(t, s, AlgEdDSA)
	for _, alg := range []string{"none", "HS256"} {
		h, _ := json.Marshal(map[string]string{"alg": alg})
		tok := b64.EncodeToString(h) + "." + b64.EncodeToString([]byte(`{}`)) + "." + b64.EncodeToString([]byte("x"))
		j, err := Parse(tok, 0)
		if err != nil {
			t.Fatalf("%s: parse: %v", alg, err)
		}
		if err := j.Verify(DefaultAlgs(), k); !errors.Is(err, ErrSignature) {
			t.Fatalf("%s: verify err = %v, want ErrSignature", alg, err)
		}
	}
	// An empty signature segment (the classic alg:none shape) never parses.
	h, _ := json.Marshal(map[string]string{"alg": "none"})
	if _, err := Parse(b64.EncodeToString(h)+"."+b64.EncodeToString([]byte(`{}`))+".", 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty-signature parse err = %v", err)
	}
}

func TestKeyAlgConfusion(t *testing.T) {
	ed := mustKey(t, AlgEdDSA)
	if _, err := Sign(ed, Header{Alg: AlgES256}, []byte(`{}`)); err == nil {
		t.Fatal("signing an Ed25519 key as ES256 must fail")
	}
	// Token signed EdDSA, verified against an ES256-tagged key -> refused.
	tok, _ := Sign(ed, Header{Alg: AlgEdDSA}, []byte(`{}`))
	j, _ := Parse(tok, 0)
	ec := mustJWK(t, mustKey(t, AlgES256), AlgES256)
	if err := j.Verify(DefaultAlgs(), ec); !errors.Is(err, ErrSignature) {
		t.Fatalf("err = %v", err)
	}
	// A JWK whose alg tag disagrees with its key type is refused.
	k := mustJWK(t, ed, AlgEdDSA)
	k.Alg = AlgRS256
	if err := j.Verify(DefaultAlgs(), k); !errors.Is(err, ErrSignature) {
		t.Fatalf("mis-tagged key err = %v", err)
	}
}

func TestParseRejects(t *testing.T) {
	s := mustKey(t, AlgEdDSA)
	good, _ := Sign(s, Header{Alg: AlgEdDSA}, []byte(`{}`))
	enc := func(v string) string { return b64.EncodeToString([]byte(v)) }
	sig := strings.Split(good, ".")[2]
	cases := map[string]string{
		"two segments":  enc(`{"alg":"EdDSA"}`) + "." + enc(`{}`),
		"four segments": good + ".x",
		"padded header": enc(`{"alg":"EdDSA"}`) + "=." + enc(`{}`) + "." + sig,
		// Deterministic: a signature segment in the STANDARD alphabet ('+', '/')
		// that no random token can accidentally make valid base64url.
		"std alphabet":      strings.Join(strings.Split(good, ".")[:2], ".") + ".+/+/" + sig[4:],
		"jku header":        enc(`{"alg":"EdDSA","jku":"https://evil"}`) + "." + enc(`{}`) + "." + sig,
		"x5u header":        enc(`{"alg":"EdDSA","x5u":"https://evil"}`) + "." + enc(`{}`) + "." + sig,
		"crit header":       enc(`{"alg":"EdDSA","crit":["exp"]}`) + "." + enc(`{}`) + "." + sig,
		"dup header member": enc(`{"alg":"EdDSA","alg":"none"}`) + "." + enc(`{}`) + "." + sig,
		"no alg":            enc(`{"typ":"x"}`) + "." + enc(`{}`) + "." + sig,
		"header not object": enc(`[1]`) + "." + enc(`{}`) + "." + sig,
		"private jwk":       enc(`{"alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}}`) + "." + enc(`{}`) + "." + sig,
		"trailing header":   enc(`{"alg":"EdDSA"}{}`) + "." + enc(`{}`) + "." + sig,
	}
	for name, tok := range cases {
		if _, err := Parse(tok, 0); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
	if _, err := Parse(good, 10); !errors.Is(err, ErrMalformed) {
		t.Error("size cap not enforced")
	}
}

func TestDecodeClaimsRejectsDuplicates(t *testing.T) {
	var v map[string]any
	if err := DecodeClaims([]byte(`{"aud":"a","aud":"b"}`), &v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v", err)
	}
	if err := DecodeClaims([]byte(`{"aud":"a"} x`), &v); !errors.Is(err, ErrMalformed) {
		t.Fatalf("trailing err = %v", err)
	}
	if err := DecodeClaims([]byte(`{"aud":"a"}`), &v); err != nil {
		t.Fatal(err)
	}
}

// TestRFC8037Vectors pins the published RFC 8037 Appendix A vectors: the
// Ed25519 JWK thumbprint (A.3) and the deterministic EdDSA JWS (A.4).
func TestRFC8037Vectors(t *testing.T) {
	d, err := b64.DecodeString("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A")
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(d)
	k := JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	if got := b64.EncodeToString(priv.Public().(ed25519.PublicKey)); got != k.X {
		t.Fatalf("x = %s", got)
	}
	tp, err := k.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if tp != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Fatalf("thumbprint = %s", tp)
	}
	const want = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
	got, err := Sign(priv, Header{Alg: AlgEdDSA}, []byte("Example of Ed25519 signing"))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("jws = %s", got)
	}
	j, err := Parse(want, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Verify(DefaultAlgs(), k); err != nil {
		t.Fatal(err)
	}
}

// TestRFC7638Vector pins the RFC 7638 §3.1 RSA thumbprint example.
func TestRFC7638Vector(t *testing.T) {
	k := JWK{
		Kty: "RSA", E: "AQAB", Kid: "2011-04-29", Alg: AlgRS256,
		N: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
	}
	tp, err := k.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	if tp != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Fatalf("thumbprint = %s", tp)
	}
}

func TestJWKValidation(t *testing.T) {
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := PublicJWK(&small.PublicKey, AlgRS256, ""); err == nil {
		t.Error("1024-bit RSA accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := PublicJWK(&p384.PublicKey, AlgES256, ""); err == nil {
		t.Error("P-384 accepted as ES256")
	}
	ec := mustJWK(t, mustKey(t, AlgES256), AlgES256)
	// Deterministic off-curve point: the RFC 9449 §4.1 example key's x with
	// its y replaced by x (a fixed, verified-not-on-curve pair).
	onCurve := JWK{Kty: "EC", Crv: "P-256", X: "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs", Y: "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"}
	if _, err := onCurve.PublicKey(); err != nil {
		t.Fatalf("fixed on-curve vector refused: %v", err)
	}
	off := onCurve
	off.Y = off.X
	if _, err := off.PublicKey(); err == nil {
		t.Error("off-curve point accepted")
	}
	raw, _ := json.Marshal(ec)
	back, err := DecodeJWK(raw)
	if err != nil || back != ec {
		t.Fatalf("roundtrip = %+v %v", back, err)
	}
	if _, err := DecodeJWK([]byte(`{"kty":"oct","k":"c2VjcmV0"}`)); err == nil {
		t.Error("symmetric JWK accepted")
	}
	a, _ := ec.Thumbprint()
	tagged := ec
	tagged.Kid, tagged.Use = "other", "sig"
	b, _ := tagged.Thumbprint()
	if a != b {
		t.Error("thumbprint must ignore kid/alg/use")
	}
}

// rawECSigner is a KMS-shaped signer that returns fixed-width R||S instead of
// DER; Sign must accept both shapes.
type rawECSigner struct{ *ecdsa.PrivateKey }

func (r rawECSigner) Sign(rnd io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	rr, ss, err := ecdsa.Sign(rnd, r.PrivateKey, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	rr.FillBytes(out[:32])
	ss.FillBytes(out[32:])
	return out, nil
}

func TestECDSASignatureShapes(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := mustJWK(t, priv, AlgES256)
	tok, err := Sign(rawECSigner{priv}, Header{Alg: AlgES256}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	j, _ := Parse(tok, 0)
	if err := j.Verify(DefaultAlgs(), k); err != nil {
		t.Fatal(err)
	}
	der, err := ECDSARawToDER(j.Signature)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ecdsaToJWS(der)
	if err != nil || string(back) != string(j.Signature) {
		t.Fatal("DER <-> raw conversion is not lossless")
	}
}

// mismatchedSigner's Public() and Sign() disagree - Sign must refuse to emit.
type mismatchedSigner struct {
	pub  crypto.PublicKey
	priv crypto.Signer
}

func (m mismatchedSigner) Public() crypto.PublicKey { return m.pub }
func (m mismatchedSigner) Sign(r io.Reader, d []byte, o crypto.SignerOpts) ([]byte, error) {
	return m.priv.Sign(r, d, o)
}

func TestSignSelfVerifies(t *testing.T) {
	a := mustKey(t, AlgEdDSA)
	b := mustKey(t, AlgEdDSA)
	if _, err := Sign(mismatchedSigner{pub: a.Public(), priv: b}, Header{Alg: AlgEdDSA}, []byte(`{}`)); err == nil {
		t.Fatal("a signer whose public half disagrees must not emit a token")
	}
}

func FuzzParse(f *testing.F) {
	s, _ := GenerateKey(rand.Reader, AlgEdDSA)
	tok, _ := Sign(s, Header{Typ: "at+jwt", Alg: AlgEdDSA, Kid: "k"}, []byte(`{"sub":"x"}`))
	f.Add(tok)
	f.Add("a.b.c")
	f.Add("")
	k, _ := PublicJWK(s.Public(), AlgEdDSA, "k")
	f.Fuzz(func(t *testing.T, in string) {
		j, err := Parse(in, 0)
		if err != nil {
			return
		}
		_ = j.Verify(DefaultAlgs(), k)
		var v map[string]any
		_ = DecodeClaims(j.Payload, &v)
	})
}
