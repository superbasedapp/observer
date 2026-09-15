package orgcontract

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestAgentKeyFingerprint(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	fp := AgentKeyFingerprint(pub)
	if len(fp) != agentKeyFingerprintHexLen {
		t.Fatalf("fingerprint = %q (%d chars), want %d", fp, len(fp), agentKeyFingerprintHexLen)
	}
	if fp != AgentKeyFingerprint(pub) {
		t.Error("fingerprint is not stable across calls")
	}
	if fp == AgentKeyFingerprint(other) {
		t.Error("two different keys produced the same fingerprint")
	}
	// It must be a HASH, never a prefix of the key itself — a label that leaked
	// key bytes would be a different (if minor) disclosure than intended.
	if enc := base64.RawURLEncoding.EncodeToString(pub); len(enc) >= len(fp) && enc[:len(fp)] == fp {
		t.Error("fingerprint is a prefix of the encoded key, not a hash")
	}
	if AgentKeyFingerprint(nil) != "" {
		t.Error("nil key must yield an empty fingerprint")
	}
}

func TestAgentKeyFingerprintEncodedMatchesRaw(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(pub)
	if got, want := AgentKeyFingerprintEncoded(encoded), AgentKeyFingerprint(pub); got != want {
		t.Errorf("AgentKeyFingerprintEncoded = %q, want %q — the two ends must agree", got, want)
	}
	// A label computation must never fail loudly; both ends log it best-effort.
	for _, bad := range []string{"", "!!!not base64!!!"} {
		if got := AgentKeyFingerprintEncoded(bad); got != "" {
			t.Errorf("AgentKeyFingerprintEncoded(%q) = %q, want empty", bad, got)
		}
	}
}
