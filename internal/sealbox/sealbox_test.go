package sealbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestDeriveKeyPairIsDeterministicAndSeedBound(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	a, err := DeriveKeyPair(priv.Seed())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveKeyPair(priv.Seed())
	if !bytes.Equal(a.PublicBytes(), b.PublicBytes()) {
		t.Fatal("same seed derived different seal keys")
	}
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	c, _ := DeriveKeyPair(priv2.Seed())
	if bytes.Equal(a.PublicBytes(), c.PublicBytes()) {
		t.Fatal("different seeds derived the same seal key")
	}
	if _, err := DeriveKeyPair([]byte("short")); !errors.Is(err, ErrBadSeed) {
		t.Fatalf("short seed: err=%v, want ErrBadSeed", err)
	}
}

func TestSealOpenRoundTripAndBindings(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	node, _ := DeriveKeyPair(priv.Seed())
	pub, err := ParsePublicB64(node.PublicB64())
	if err != nil {
		t.Fatal(err)
	}
	aad := LeaseAAD("org-1", "scim-42", "anthropic-prod")
	blob, err := Seal(nil, pub, []byte("sk-ant-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(node, blob, aad)
	if err != nil || string(got) != "sk-ant-secret" {
		t.Fatalf("open: %q %v", got, err)
	}

	cases := map[string]func() ([]byte, error){
		"different upstream aad": func() ([]byte, error) {
			return Open(node, blob, LeaseAAD("org-1", "scim-42", "openai-prod"))
		},
		"different node key": func() ([]byte, error) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			k, _ := DeriveKeyPair(other.Seed())
			return Open(k, blob, aad)
		},
		"tampered blob": func() ([]byte, error) {
			b := []byte(blob)
			b[len(b)-3] ^= 'x'
			return Open(node, string(b), aad)
		},
	}
	for name, fn := range cases {
		if _, err := fn(); err == nil {
			t.Errorf("%s: opened, want failure", name)
		}
	}
	if _, err := Open(node, "not-base64!", aad); !errors.Is(err, ErrBadBlob) {
		t.Fatalf("garbage blob: %v, want ErrBadBlob", err)
	}
	if _, err := ParsePublicB64("AAAA"); !errors.Is(err, ErrBadPublicKey) {
		t.Fatalf("short pub: %v, want ErrBadPublicKey", err)
	}
	if !KnownScheme(SchemeV1) || KnownScheme("other") {
		t.Fatal("KnownScheme vocabulary wrong")
	}
}

func TestSealIsRandomizedPerCall(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	node, _ := DeriveKeyPair(priv.Seed())
	pub, _ := ParsePublicB64(node.PublicB64())
	a, _ := Seal(nil, pub, []byte("x"), nil)
	b, _ := Seal(nil, pub, []byte("x"), nil)
	if a == b {
		t.Fatal("two seals of the same plaintext produced identical blobs")
	}
}
