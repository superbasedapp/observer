package entitlements

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func issued(t *testing.T) Body {
	t.Helper()
	b, err := Compose("team", 1, "org-a", 10, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestStructuralRules: one row per structural rule.
func TestStructuralRules(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		rule string
		mut  func(*Body)
	}{
		{"schema", func(b *Body) { b.Schema = "v0" }},
		{"kind", func(b *Body) { b.Kind = "galactic" }},
		{"plan", func(b *Body) { b.Plan.Name = "Team" }},
		{"plan", func(b *Body) { b.Plan.Version = 0 }},
		{"plan", func(b *Body) { b.Plan.Label = "" }},
		{"capabilities", func(b *Body) { b.Capabilities = []string{"org.saml", "org.saml"} }},
		{"capabilities", func(b *Body) { b.Capabilities = []string{"org.core"} }},
		{"capabilities", func(b *Body) { b.Capabilities = []string{"has space"} }},
		{"caps", func(b *Body) { b.Caps[CapSeatsMin] = -2 }},
		{"terms", func(b *Body) { b.Terms = map[TermName]string{TermEnrichmentTier: ""} }},
		{"window", func(b *Body) { b.NotBefore, b.NotAfter = 10, 10 }},
		{"window", func(b *Body) { b.IssuedAt = -1 }},
		{"licensee", func(b *Body) { b.Licensee = strings.Repeat("x", 81) }},
	} {
		b := issued(t)
		tc.mut(&b)
		err := b.Validate()
		if !errors.Is(err, ErrBody) || !strings.Contains(err.Error(), tc.rule+":") {
			t.Errorf("rule %s: Validate = %v", tc.rule, err)
		}
	}
	if err := issued(t).Validate(); err != nil {
		t.Fatalf("a composed body fails Validate: %v", err)
	}
}

// TestIssuableRules: one row per vocabulary and issued rule; the
// structural rules accept every one of these (an older host must not
// refuse a newer issuer's additive value).
func TestIssuableRules(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		rule string
		mut  func(*Body)
	}{
		{"capability mapping", func(b *Body) { b.Capabilities = []string{"org.future"} }},
		{"capability mapping", func(b *Body) { b.Capabilities = []string{"org.email"} }},
		{"capability mapping", func(b *Body) { b.Capabilities = []string{"org.scim", "org.saml"} }},
		{"cap vocabulary", func(b *Body) { b.Caps["future.cap"] = 1 }},
		{"cap vocabulary", func(b *Body) { b.Caps[CapSeatsIncluded] = 1 }},
		{"cap vocabulary", func(b *Body) { b.Caps[CapRetentionDays] = 90 }},
		{"term vocabulary", func(b *Body) { b.Terms = map[TermName]string{"future.term": "x"} }},
		{"term vocabulary", func(b *Body) { b.Terms = map[TermName]string{TermEnrichmentTier: "paid"} }},
		{"issued org", func(b *Body) { b.Org = "" }},
		{"issued org", func(b *Body) { b.Org = "platform" }},
		{"issued at", func(b *Body) { b.IssuedAt = 0 }},
	} {
		b := issued(t)
		tc.mut(&b)
		err := b.CheckIssuable()
		if !errors.Is(err, ErrBody) || !strings.Contains(err.Error(), tc.rule+":") {
			t.Errorf("rule %s: CheckIssuable = %v", tc.rule, err)
		}
		if tc.rule != "issued org" && tc.rule != "issued at" {
			if err := b.Validate(); err != nil {
				t.Errorf("rule %s: a host would refuse it: %v", tc.rule, err)
			}
		}
	}
	retention := issued(t)
	retention.Caps[CapRetentionDays] = Unlimited
	if err := retention.CheckIssuable(); err != nil {
		t.Errorf("Unlimited retention refused: %v", err)
	}
}

// TestTemplateRules: a template names no org and no time.
func TestTemplateRules(t *testing.T) {
	t.Parallel()
	b := issued(t)
	if err := b.CheckTemplate(); err == nil || !strings.Contains(err.Error(), "template org:") {
		t.Fatalf("an issued body passes CheckTemplate: %v", err)
	}
}

// TestEncodeIsCanonical: equal bodies encode to equal bytes whatever the
// capability order, and Decode reads them back.
func TestEncodeIsCanonical(t *testing.T) {
	t.Parallel()
	a := issued(t)
	b := issued(t)
	b.Capabilities = []string{"org.security", "org.digest", "org.assistant", "org.digest"}
	ea, err := a.Encode()
	if err != nil {
		t.Fatal(err)
	}
	eb, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ea, eb) {
		t.Fatalf("encodings differ:\n%s\n%s", ea, eb)
	}
	got, err := Decode(ea)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Plan != a.Plan || got.Org != a.Org || len(got.Caps) != len(a.Caps) {
		t.Fatalf("round trip = %+v", got)
	}
	bad := a
	bad.Schema = ""
	if _, err := bad.Encode(); !errors.Is(err, ErrBody) {
		t.Fatalf("Encode of an invalid body: %v", err)
	}
}

// TestDecodeIgnoresUnknownFieldsAndRefusesJunk.
func TestDecodeIgnoresUnknownFieldsAndRefusesJunk(t *testing.T) {
	t.Parallel()
	raw, _ := issued(t).Encode()
	extended := append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"future_field":{"x":1}}`)...)
	if _, err := Decode(extended); err != nil {
		t.Fatalf("an unknown field was refused: %v", err)
	}
	for _, junk := range [][]byte{nil, []byte("not json"), []byte(`{"schema":"x"}`), bytes.Repeat([]byte{' '}, 129<<10)} {
		if _, err := Decode(junk); !errors.Is(err, ErrBody) {
			t.Errorf("Decode(%.20q) = %v", junk, err)
		}
	}
}

// TestVocabularyTables pins each table's shape.
func TestVocabularyTables(t *testing.T) {
	t.Parallel()
	seen := map[CapName]bool{}
	for _, r := range capRules() {
		if seen[r.name] || r.unit == "" || len(r.kinds) == 0 || !r.name.Known() || r.name.Unit() == "" {
			t.Errorf("cap row %s: duplicate, unitless or kindless", r.name)
		}
		seen[r.name] = true
		for _, k := range r.kinds {
			if !k.Valid() {
				t.Errorf("cap row %s names unknown kind %s", r.name, k)
			}
		}
	}
	if len(CapNames()) != len(seen) || CapName("x").Known() || CapName("x").Unit() != "" {
		t.Error("CapNames or Known disagree with the table")
	}
	for _, n := range TermNames() {
		if !n.Known() {
			t.Errorf("term %s not known", n)
		}
	}
	if TermName("x").Known() || Kind("x").Valid() {
		t.Error("an unknown name is known")
	}
}
