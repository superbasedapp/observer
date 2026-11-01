package sandboxmxc

import (
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestClassifyUIClass (WINFIX4 audit finding 4): the box's UI class report
// is a POST with the run's token and exactly 8 hex digits, open on every
// tier.
func TestClassifyUIClass(t *testing.T) {
	tok, _ := EncodeToken(make([]byte, 32))
	for _, tier := range Tiers() {
		r := Classify(Request{Method: "POST", RequestURI: UIClassPath(tok, 0xFF)}, tok, tier)
		if r.Refused() || r.Stream != StreamUIClass || r.UIClass != 0xFF {
			t.Fatalf("%s: %+v", tier, r)
		}
	}
	other, _ := EncodeToken([]byte("0123456789abcdef0123456789abcdef"))
	for _, bad := range []Request{
		{Method: "GET", RequestURI: UIClassPath(tok, 0xFF)},
		{Method: "POST", RequestURI: UIClassPath(other, 0xFF)},
		{Method: "POST", RequestURI: "/uiclass/" + tok + "/FF"},
		{Method: "POST", RequestURI: "/uiclass/" + tok + "/0000000G"},
		{Method: "POST", RequestURI: "/uiclass/" + tok},
	} {
		if r := Classify(bad, tok, vocab.TierNone); !r.Refused() {
			t.Fatalf("%s %s was routed: %+v", bad.Method, bad.RequestURI, r)
		}
	}
	if c, ok := parseUIClass("000000ff"); !ok || c != 0xFF {
		t.Fatalf("parseUIClass lower case: 0x%X %v", c, ok)
	}
}
