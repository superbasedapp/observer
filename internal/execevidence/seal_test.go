package execevidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

func sealKey(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }

// TestSealVerifies and fails on a changed fact (its digest moves), a
// changed digest, a changed key id and a changed signature.
func TestSealVerifies(t *testing.T) {
	env := sample()
	digest := env.Digest()
	s, err := SignSeal(sealKey(1), digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySeal(s, digest); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if StateOf(&s, digest) != SealSelfAttested {
		t.Fatal("a good seal is not self_attested")
	}
	changed := env
	changed.Isolation.EgressTier = vocab.TierNone
	otherKey, _ := SignSeal(sealKey(2), digest)
	cases := map[string]struct {
		s      Seal
		digest string
		want   error
	}{
		"changed fact":      {s, changed.Digest(), ErrSealSig},
		"changed digest":    {s, digest[:63] + "0", ErrSealSig},
		"changed key id":    {Seal{KeyID: otherKey.KeyID, PublicKey: s.PublicKey, Sig: s.Sig}, digest, ErrSealKey},
		"swapped key":       {Seal{KeyID: otherKey.KeyID, PublicKey: otherKey.PublicKey, Sig: s.Sig}, digest, ErrSealSig},
		"changed signature": {Seal{KeyID: s.KeyID, PublicKey: s.PublicKey, Sig: otherKey.Sig}, digest, ErrSealSig},
		"not a digest":      {s, "abc", ErrSealDigest},
		"bad key encoding":  {Seal{KeyID: s.KeyID, PublicKey: "!!", Sig: s.Sig}, digest, ErrSealKey},
	}
	for name, c := range cases {
		if err := VerifySeal(c.s, c.digest); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if c.digest == digest || name == "changed fact" || name == "changed digest" {
			if st := StateOf(&c.s, c.digest); st != SealInvalid {
				t.Errorf("%s: state %s", name, st)
			}
		}
	}
	if StateOf(nil, digest) != SealUnsealed || StateOf(&Seal{}, digest) != SealUnsealed {
		t.Fatal("a missing seal is not unsealed")
	}
	if _, err := SignSeal(sealKey(1), "nope"); !errors.Is(err, ErrSealDigest) {
		t.Fatal("sealed a non-digest")
	}
}

// TestSealMessagesAreDomainSeparated: the three messages never collide,
// and a field boundary cannot move.
func TestSealMessagesAreDomainSeparated(t *testing.T) {
	a := SealMessage("ab", "c")
	b := SealMessage("a", "bc")
	if bytes.Equal(a, b) {
		t.Fatal("a field boundary moved without changing the message")
	}
	if bytes.Equal(CountersignMessage("o", "r", "d", "k", "s", "t"), RegisterMessage("o", "r", "d", "k", "s")) {
		t.Fatal("domains collide")
	}
	pub, _ := sealKey(3).Public().(ed25519.PublicKey)
	if len(SealKeyID(pub)) != 32 {
		t.Fatal("key id length")
	}
	if _, err := base64.StdEncoding.DecodeString(mustSeal(t).Sig); err != nil {
		t.Fatal(err)
	}
}

func mustSeal(t *testing.T) Seal {
	t.Helper()
	s, err := SignSeal(sealKey(4), sample().Digest())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
