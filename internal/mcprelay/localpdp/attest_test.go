package localpdp

import "testing"

// TestAttestationTable pins transport -> attestation (R2).
func TestAttestationTable(t *testing.T) {
	cases := []struct {
		transport Transport
		want      string
		product   bool
	}{
		{TransportStdioWrapper, AttestProcess, true},
		{TransportIPC, AttestIPC, true},
		{TransportLoopbackHTTP, AttestConfigured, false},
		{TransportUnknown, AttestClaimed, false},
		{"", AttestClaimed, false},
		{"tcp", AttestClaimed, false},
	}
	for _, c := range cases {
		if got := AttestationFor(c.transport); got != c.want {
			t.Errorf("AttestationFor(%q) = %q, want %q", c.transport, got, c.want)
		}
		if got := ProductScopedHonoured(AttestationFor(c.transport)); got != c.product {
			t.Errorf("ProductScopedHonoured(%q) = %v, want %v", c.transport, got, c.product)
		}
	}
}

// TestEffectiveAttestation pins "a claim can lower, never raise".
func TestEffectiveAttestation(t *testing.T) {
	cases := []struct {
		name      string
		transport Transport
		claimed   string
		want      string
	}{
		{"empty claim defers to transport", TransportStdioWrapper, "", AttestProcess},
		{"claim equal to transport", TransportIPC, AttestIPC, AttestIPC},
		{"claim above transport is clamped", TransportLoopbackHTTP, AttestProcess, AttestConfigured},
		{"claim above unknown transport is clamped to claimed", TransportUnknown, AttestIPC, AttestClaimed},
		{"claim below transport lowers", TransportStdioWrapper, AttestConfigured, AttestConfigured},
		{"claimed on stdio lowers to claimed", TransportStdioWrapper, AttestClaimed, AttestClaimed},
		{"unknown claim value is claimed", TransportStdioWrapper, "hardware", AttestClaimed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := EffectiveAttestation(c.transport, c.claimed); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}
