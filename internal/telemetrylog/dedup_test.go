package telemetrylog

import "testing"

func TestDedupIDStableAcrossCalls(t *testing.T) {
	org, subj, payload := "acme", PushSubject("acme"), []byte(`{"a":1}`)
	a := DedupID(org, subj, payload)
	b := DedupID(org, subj, payload)
	if a != b {
		t.Fatalf("DedupID not stable: %q != %q", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("DedupID = %q, want 64 hex chars (sha256)", a)
	}
}

func TestDedupIDVariesByPart(t *testing.T) {
	base := DedupID("acme", PushSubject("acme"), []byte("body"))
	cases := []struct {
		name      string
		org, subj string
		payload   []byte
	}{
		{"different payload", "acme", PushSubject("acme"), []byte("body2")},
		{"different org", "beta", PushSubject("acme"), []byte("body")},
		{"different subject", "acme", OTLPSubject("acme", SignalTraces), []byte("body")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DedupID(c.org, c.subj, c.payload); got == base {
				t.Errorf("DedupID(%q,%q,%q) collided with base %q", c.org, c.subj, c.payload, base)
			}
		})
	}
}

// TestDedupIDNoBoundaryAmbiguity pins the 0x1F separator: shifting a byte across
// the org/subject boundary must change the id (org "a"+subj "bc" vs org
// "ab"+subj "c" would collide without a separator).
func TestDedupIDNoBoundaryAmbiguity(t *testing.T) {
	x := DedupID("a", "bc", []byte("p"))
	y := DedupID("ab", "c", []byte("p"))
	if x == y {
		t.Fatalf("boundary ambiguity: DedupID(a,bc) == DedupID(ab,c) == %q", x)
	}
}

// TestDedupIDEmptyPayloadDistinct pins that even an empty payload hashes to a
// stable, distinct id (ValidateRecord, not DedupID, is what rejects empties).
func TestDedupIDEmptyPayload(t *testing.T) {
	if DedupID("acme", "s", nil) != DedupID("acme", "s", []byte{}) {
		t.Fatal("nil and empty payload should hash identically")
	}
	if DedupID("acme", "s", nil) == DedupID("acme", "s", []byte("x")) {
		t.Fatal("empty and non-empty payload should differ")
	}
}
