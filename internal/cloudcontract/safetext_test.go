package cloudcontract

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeTextRejectsHostileOutput(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"nul", "a\x00b"},
		{"newline_log_forge", "line1\nFAKE LOG line2"},
		{"carriage_return", "a\rb"},
		{"tab", "a\tb"},
		{"ansi_escape", "\x1b[31mred\x1b[0m"},
		{"osc_escape", "\x1b]0;title\x07"},
		{"del", "a\x7fb"},
		{"c1_csi", "a" + string(rune(0x9b)) + "b"},
		{"bidi_rlo", "a" + string(rune(0x202E)) + "evil"},
		{"bidi_isolate", "a" + string(rune(0x2066)) + "b" + string(rune(0x2069))},
		{"bidi_rlm", "a" + string(rune(0x200F)) + "b"},
		{"bidi_alm", "a" + string(rune(0x061C)) + "b"},
		{"invalid_utf8", "a\xffb"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := NormalizeText("f", c.in, 4096, true); err == nil {
				t.Fatalf("NormalizeText(%q) = nil error, want rejection", c.in)
			}
		})
	}
}

func TestNormalizeTextAcceptsAndNFCs(t *testing.T) {
	// "e" + U+0301 (combining acute) NFC-composes to U+00E9.
	in := "caf" + "e" + string(rune(0x0301))
	got, err := NormalizeText("title", in, 4096, true)
	if err != nil {
		t.Fatalf("NormalizeText: %v", err)
	}
	want := "caf" + string(rune(0x00E9))
	if got.String() != want {
		t.Fatalf("NFC normalization failed: got %q want %q", got.String(), want)
	}
}

func TestNormalizeTextBounds(t *testing.T) {
	if _, err := NormalizeText("f", strings.Repeat("a", 10), 5, true); err == nil {
		t.Fatal("oversize value accepted")
	}
	if _, err := NormalizeText("f", "", 5, true); err == nil {
		t.Fatal("empty required value accepted")
	}
	if v, err := NormalizeText("f", "", 5, false); err != nil || !v.Empty() {
		t.Fatalf("empty optional value: v=%q err=%v", v.String(), err)
	}
}

func TestForCSVNeutralizesFormula(t *testing.T) {
	for _, p := range []string{"=cmd", "+cmd", "-cmd", "@cmd"} {
		st, err := NormalizeText("f", p, 64, true)
		if err != nil {
			t.Fatalf("NormalizeText(%q): %v", p, err)
		}
		if got := st.ForCSV(); !strings.HasPrefix(got, "'") {
			t.Fatalf("ForCSV(%q) = %q, want leading quote", p, got)
		}
	}
	st, _ := NormalizeText("f", "hello", 64, true)
	if st.ForCSV() != "hello" {
		t.Fatalf("ForCSV mangled benign value: %q", st.ForCSV())
	}
}

// TestSafeTextOpaqueSelfValidatingJSON proves the FE1 opaque contract: a
// SafeText decoded from JSON normalizes+validates on the way in, so a hostile
// stored row or wire message can never yield a SafeText holding control/bidi
// bytes or invalid UTF-8. Construction with raw bytes is impossible at compile
// time (the value field is unexported), which is the other half of the contract.
func TestSafeTextOpaqueSelfValidatingJSON(t *testing.T) {
	// Build each hostile input from explicit runes, then JSON-encode it so the
	// wire form is VALID JSON that decodes back to the dangerous string.
	hostile := []string{
		"a\x00b",                         // NUL
		"\x1b[31mred",                    // ANSI/OSC escape introducer
		"a" + string(rune(0x202E)) + "x", // bidi RLO (Trojan Source)
		"line1\nFAKE",                    // LF ⇒ log forge
		"a" + string(rune(0x9b)) + "b",   // C1 CSI
	}
	for _, raw := range hostile {
		enc, err := json.Marshal(raw) // valid JSON string with \uXXXX escapes
		if err != nil {
			t.Fatalf("marshal fixture: %v", err)
		}
		var st SafeText
		if err := json.Unmarshal(enc, &st); err == nil {
			t.Fatalf("SafeText.UnmarshalJSON(%s) = nil error, want rejection (got %q)", enc, st.String())
		}
	}
	// A benign value round-trips and marshals back to a plain JSON string.
	var st SafeText
	if err := json.Unmarshal([]byte(`"hello world"`), &st); err != nil {
		t.Fatalf("benign unmarshal: %v", err)
	}
	b, err := json.Marshal(st)
	if err != nil || string(b) != `"hello world"` {
		t.Fatalf("marshal round-trip: %q err=%v", string(b), err)
	}
	// A non-string JSON value is rejected (no silent zero value).
	if err := json.Unmarshal([]byte(`123`), &st); err == nil {
		t.Fatal("SafeText.UnmarshalJSON(number) accepted, want rejection")
	}
}

// TestSafeTextPerSinkEncoders proves each context-specific sink neutralizes the
// payloads dangerous for THAT sink (FE1). The value itself is benign text (no
// control/bidi), so it constructs fine; the escaping is the point.
func TestSafeTextPerSinkEncoders(t *testing.T) {
	xss, err := NormalizeText("f", `<script>alert("x")&'</script>`, 256, true)
	if err != nil {
		t.Fatalf("NormalizeText: %v", err)
	}
	if got := xss.ForHTMLText(); strings.Contains(got, "<script>") || !strings.Contains(got, "&lt;script&gt;") {
		t.Fatalf("ForHTMLText did not escape: %q", got)
	}
	if got := xss.ForHTMLAttr(); strings.Contains(got, `"`) || strings.Contains(got, "<") {
		t.Fatalf("ForHTMLAttr did not escape quote/angle: %q", got)
	}
	if got := xss.ForURLQuery(); strings.Contains(got, "<") || strings.Contains(got, " ") {
		t.Fatalf("ForURLQuery did not percent-encode: %q", got)
	}
	formula, _ := NormalizeText("f", "=SUM(A1)", 64, true)
	if got := formula.ForCSV(); !strings.HasPrefix(got, "'") {
		t.Fatalf("ForCSV did not neutralize formula: %q", got)
	}
}

func TestResultValidateRejectsControlAndBidiFields(t *testing.T) {
	base := Result{
		Title:         "ok",
		Confidence:    ConfidenceLow,
		SchemaVersion: ResultSchemaVersion,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("clean result rejected: %v", err)
	}
	// Bidi override in the title.
	bad := base
	bad.Title = "a" + string(rune(0x202E)) + "b"
	if err := bad.Validate(); err == nil {
		t.Fatal("bidi title accepted")
	}
	// Control char in a tag.
	bad2 := base
	bad2.TaxonomyTags = []string{"good", "ba\x00d"}
	if err := bad2.Validate(); err == nil {
		t.Fatal("control-char tag accepted")
	}
	// A stored-XSS-shaped description carries no control/bidi ⇒ accepted as TEXT
	// (HTML escaping is the renderer's job via SafeText.ForHTMLText); the byte
	// bound still applies.
	xss := base
	xss.Description = `<script>alert(1)</script>`
	if err := xss.Validate(); err != nil {
		t.Fatalf("benign-but-XSS-shaped description rejected: %v", err)
	}
}

// TestResultNormalizeReturnsOpaqueValue proves Normalize returns the validated
// value (not just an error), and that its SafeText fields marshal back to the
// original wire strings.
func TestResultNormalizeReturnsOpaqueValue(t *testing.T) {
	r := Result{
		Title:         "hi",
		Description:   "d",
		TaxonomyTags:  []string{"auth"},
		Confidence:    ConfidenceLow,
		SchemaVersion: ResultSchemaVersion,
	}
	nr, err := r.Normalize()
	if err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if nr.Title.String() != "hi" || len(nr.TaxonomyTags) != 1 || nr.TaxonomyTags[0].String() != "auth" {
		t.Fatalf("normalized value wrong: %+v", nr)
	}
	b, err := json.Marshal(nr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"title":"hi"`) || !strings.Contains(string(b), `"taxonomy_tags":["auth"]`) {
		t.Fatalf("normalized result marshaled unexpectedly: %s", b)
	}
}
