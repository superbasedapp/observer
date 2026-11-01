package orgcontract

import (
	"strings"
	"testing"
)

// TestNormalizeChangeEnvelopeDropsUnknownFields (SEC-F2B merge audit
// finding 7): an unknown top-level or signature field never reaches the
// server's store; the known fields survive in DSSE order.
func TestNormalizeChangeEnvelopeDropsUnknownFields(t *testing.T) {
	in := `{"extra":"sbo-canary","payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"keyid":"k","sig":"AA==","more":"sbo-canary"}]}`
	got := NormalizeChangeEnvelope(in)
	want := `{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"keyid":"k","sig":"AA=="}]}`
	if got != want {
		t.Fatalf("normalized %s, want %s", got, want)
	}
	if strings.Contains(NormalizeChangeEnvelope(`{"payloadType":"t","payload":"p","signatures":[]}`), "t") {
		t.Fatal("an envelope without a signature survived")
	}
}
