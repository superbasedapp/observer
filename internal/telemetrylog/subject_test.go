package telemetrylog

import "testing"

func TestPushSubjectRoundTrip(t *testing.T) {
	subj := PushSubject("acme")
	if subj != "sbo.push.acme" {
		t.Fatalf("PushSubject = %q, want sbo.push.acme", subj)
	}
	kind, ok := KindOf(subj)
	if !ok || kind != KindPush {
		t.Fatalf("KindOf(%q) = %q,%v, want %q,true", subj, kind, ok, KindPush)
	}
	if org, ok := OrgOf(subj); !ok || org != "acme" {
		t.Fatalf("OrgOf(%q) = %q,%v, want acme,true", subj, org, ok)
	}
	if _, ok := SignalOf(subj); ok {
		t.Fatalf("SignalOf on a push subject should be false")
	}
}

func TestOTLPSubjectRoundTrip(t *testing.T) {
	for _, sig := range []string{SignalTraces, SignalLogs, SignalMetrics} {
		subj := OTLPSubject("acme", sig)
		kind, ok := KindOf(subj)
		if !ok || kind != KindOTLP {
			t.Fatalf("KindOf(%q) = %q,%v, want %q,true", subj, kind, ok, KindOTLP)
		}
		gotSig, ok := SignalOf(subj)
		if !ok || gotSig != sig {
			t.Fatalf("SignalOf(%q) = %q,%v, want %q,true", subj, gotSig, ok, sig)
		}
		if org, ok := OrgOf(subj); !ok || org != "acme" {
			t.Fatalf("OrgOf(%q) = %q,%v, want acme,true", subj, org, ok)
		}
	}
}

// TestOrgTokenRoundTripHostile pins that every org id — including ones full of
// bytes that would otherwise split or wildcard a subject — encodes to a safe
// token and decodes back exactly.
func TestOrgTokenRoundTripHostile(t *testing.T) {
	cases := []string{
		"acme",
		"a.b",       // "." would split the subject
		"a b",       // space
		"*",         // NATS single-token wildcard
		">",         // NATS multi-token wildcard
		"a>b.c*d e", // a mix
		"café",      // non-ASCII (multi-byte UTF-8)
		"100%pure",  // a literal percent must itself be encoded
		"UPPER_lower-9",
		"", // empty round-trips to empty
	}
	for _, org := range cases {
		t.Run(org, func(t *testing.T) {
			subj := PushSubject(org)
			// The encoded token must contain no NATS-hostile byte.
			for i := len("sbo.push."); i < len(subj); i++ {
				switch subj[i] {
				case ' ', '*', '>':
					t.Fatalf("encoded subject %q contains hostile byte %q", subj, subj[i])
				}
			}
			// Exactly three tokens: the org token never introduces a ".".
			if got := countByte(subj, '.'); got != 2 {
				t.Fatalf("subject %q has %d dots, want 2 (org token leaked a separator)", subj, got)
			}
			back, ok := OrgOf(subj)
			if !ok || back != org {
				t.Fatalf("OrgOf(%q) = %q,%v, want %q,true", subj, back, ok, org)
			}
		})
	}
}

func TestKindOfRejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"sbo",
		"sbo.push",
		"sbo.push.a.b",   // too many segments for push
		"sbo.otlp.a",     // missing signal
		"sbo.otlp.a.b.c", // too many segments for otlp
		"other.push.a",   // wrong root
		"sbo.unknown.a",  // unknown kind
	}
	for _, s := range bad {
		if kind, ok := KindOf(s); ok {
			t.Errorf("KindOf(%q) = %q,true, want false", s, kind)
		}
		if _, ok := OrgOf(s); ok {
			t.Errorf("OrgOf(%q) = ok, want false", s)
		}
	}
}

func TestSignalOfRejectsUnknownSignal(t *testing.T) {
	if sig, ok := SignalOf(OTLPSubject("acme", "bogus")); ok {
		t.Fatalf("SignalOf on unknown signal = %q,true, want false", sig)
	}
}

func TestDecodeTokenMalformed(t *testing.T) {
	for _, s := range []string{"%", "%1", "%zz", "ab%1g"} {
		if _, ok := decodeToken(s); ok {
			t.Errorf("decodeToken(%q) = ok, want false", s)
		}
	}
}

func TestFilterConstants(t *testing.T) {
	if PushFilter != "sbo.push.*" {
		t.Errorf("PushFilter = %q", PushFilter)
	}
	if OTLPFilter != "sbo.otlp.>" {
		t.Errorf("OTLPFilter = %q", OTLPFilter)
	}
}

func countByte(s string, b byte) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			n++
		}
	}
	return n
}
