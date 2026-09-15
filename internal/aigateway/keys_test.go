package aigateway

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestMintHashFormat(t *testing.T) {
	// Deterministic entropy so the mint is reproducible.
	r := bytes.NewReader(bytes.Repeat([]byte{0x5a}, virtualKeyRandomBytes))
	k, err := MintVirtualKey(r)
	if err != nil {
		t.Fatalf("MintVirtualKey: %v", err)
	}
	if !strings.HasPrefix(k, VirtualKeyPrefix) {
		t.Errorf("minted key %q lacks prefix %q", k, VirtualKeyPrefix)
	}
	if !ValidVirtualKeyFormat(k) {
		t.Errorf("minted key %q failed ValidVirtualKeyFormat", k)
	}
	// Hash is stable and not the plaintext.
	h1, h2 := HashVirtualKey(k), HashVirtualKey(k)
	if h1 != h2 {
		t.Error("HashVirtualKey not stable")
	}
	if strings.Contains(h1, k) || h1 == k {
		t.Error("hash must not be the plaintext")
	}
	if len(h1) != 64 {
		t.Errorf("hash len = %d, want 64 hex chars", len(h1))
	}
}

func TestValidVirtualKeyFormat(t *testing.T) {
	good, _ := MintVirtualKey(bytes.NewReader(bytes.Repeat([]byte{1}, virtualKeyRandomBytes)))
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"minted", good, true},
		{"empty", "", false},
		{"no prefix", "vk-abc", false},
		{"prefix only", VirtualKeyPrefix, false},
		{"wrong length", VirtualKeyPrefix + "aaaa", false},
		{"provider key shape", "sk-ant-123", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidVirtualKeyFormat(tc.in); got != tc.want {
				t.Errorf("ValidVirtualKeyFormat(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestEvaluateKey(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	base := VirtualKey{
		MachineFingerprint: "machine-A",
		ExpiresAt:          now.Add(time.Hour),
	}
	tests := []struct {
		name    string
		mutate  func(k *VirtualKey)
		machine string
		thin    bool
		want    KeyRejectReason
	}{
		{"valid", nil, "machine-A", false, RejectNone},
		{"revoked", func(k *VirtualKey) { k.RevokedAt = now.Add(-time.Minute) }, "machine-A", false, RejectRevoked},
		{"expired", func(k *VirtualKey) { k.ExpiresAt = now.Add(-time.Second) }, "machine-A", false, RejectExpired},
		{"machine mismatch", nil, "machine-B", false, RejectMachineMismatch},
		{"thin denied", nil, "machine-A", true, RejectThinDenied},
		{"thin allowed", func(k *VirtualKey) { k.ThinAllowed = true }, "machine-A", true, RejectNone},
		{"no machine binding", func(k *VirtualKey) { k.MachineFingerprint = "" }, "anything", false, RejectNone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := base
			if tc.mutate != nil {
				tc.mutate(&k)
			}
			if got := EvaluateKey(k, tc.machine, tc.thin, now); got != tc.want {
				t.Errorf("EvaluateKey = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthCacheWatermark(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	entry := AuthCacheEntry{
		Key:       VirtualKey{MachineFingerprint: "m", ExpiresAt: now.Add(time.Hour)},
		Watermark: 5,
		FilledAt:  now,
	}

	// Fresh entry, watermark unchanged: valid.
	if got := entry.Verdict("m", false, now, time.Minute, 5); got != RejectNone {
		t.Errorf("fresh entry verdict = %q, want RejectNone", got)
	}
	// Sol S9: the store's watermark advanced past the entry's stamp — a
	// revocation happened since fill, so the cached "active" must be rejected
	// as stale rather than resurrected.
	if got := entry.Verdict("m", false, now, time.Minute, 6); got != RejectStaleWatermark {
		t.Errorf("advanced-watermark verdict = %q, want RejectStaleWatermark", got)
	}
	// TTL expiry forces a re-fetch.
	if got := entry.Verdict("m", false, now.Add(2*time.Minute), time.Minute, 5); got != RejectUnknown {
		t.Errorf("expired-TTL verdict = %q, want RejectUnknown", got)
	}
	// Watermark check precedes TTL AND the key's own fields.
	if got := entry.Verdict("m", false, now.Add(2*time.Minute), time.Minute, 9); got != RejectStaleWatermark {
		t.Errorf("watermark should win over TTL, got %q", got)
	}
}
