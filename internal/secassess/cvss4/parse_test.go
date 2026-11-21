package cvss4

import (
	"errors"
	"strings"
	"testing"
)

const goodVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

func TestParseAcceptsBaseVectorsAndRoundTrips(t *testing.T) {
	for _, v := range []string{
		goodVector,
		"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
		"CVSS:4.0/AV:A/AC:L/AT:P/PR:L/UI:P/VC:N/VI:L/VA:H/SC:H/SI:L/SA:N",
	} {
		b, err := Parse(v)
		if err != nil {
			t.Errorf("Parse(%q): %v", v, err)
			continue
		}
		if got := b.Vector(); got != v {
			t.Errorf("Vector() = %q, want %q", got, v)
		}
	}
	b, err := Parse(goodVector)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"AV": "N", "VC": "H", "SA": "N"} {
		if got, ok := b.Value(key); !ok || got != want {
			t.Errorf("Value(%s) = %q, %v; want %q", key, got, ok, want)
		}
	}
	if _, ok := b.Value("E"); ok {
		t.Error("Value(E) answered for a metric that is not a base metric")
	}
}

func TestParseRefusals(t *testing.T) {
	long := goodVector + strings.Repeat("/AV:N", 40)
	cases := []struct {
		name   string
		vector string
		code   ErrorCode
		metric string
	}{
		{"empty", "", CodeEmpty, ""},
		{"too long", long, CodeTooLong, ""},
		{"no header", "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", CodeBadPrefix, ""},
		{"CVSS 3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CodeBadPrefix, ""},
		{"lower case header", "cvss:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", CodeBadPrefix, ""},
		{"header only", "CVSS:4.0/", CodeBadSyntax, ""},
		{"surrounding space", " " + goodVector, CodeBadPrefix, ""},
		{"trailing newline", goodVector + "\n", CodeBadValue, "SA"},
		{"trailing slash", goodVector + "/", CodeBadSyntax, ""},
		{"part without colon", strings.Replace(goodVector, "AC:L", "ACL", 1), CodeBadSyntax, ""},
		{"empty value", strings.Replace(goodVector, "AC:L", "AC:", 1), CodeBadSyntax, ""},
		{"two colons", strings.Replace(goodVector, "AC:L", "AC:L:L", 1), CodeBadSyntax, ""},
		{"short", "CVSS:4.0/AV:N/AC:L/AT:N", CodeMissingMetric, "PR"},
		{"one metric", "CVSS:4.0/AV:N", CodeMissingMetric, "AC"},
		{"swapped order", "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", CodeBadMetric, "AV"},
		{"repeated metric", "CVSS:4.0/AV:N/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", CodeBadMetric, "AC"},
		{"unknown metric", "CVSS:4.0/AV:N/ZZ:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", CodeBadMetric, "AC"},
		{"unknown extra metric", goodVector + "/ZZ:L", CodeBadMetric, ""},
		{"exploit maturity", goodVector + "/E:A", CodeNotBase, ""},
		{"exploit maturity not defined", goodVector + "/E:X", CodeNotBase, ""},
		{"requirement", goodVector + "/CR:H", CodeNotBase, ""},
		{"modified metric", goodVector + "/MAV:N", CodeNotBase, ""},
		{"supplemental metric", goodVector + "/S:P", CodeNotBase, ""},
		{"threat metric in the middle", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/E:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", CodeNotBase, ""},
		{"value of another metric", strings.Replace(goodVector, "AC:L", "AC:N", 1), CodeBadValue, "AC"},
		{"lower case value", strings.Replace(goodVector, "AV:N", "AV:n", 1), CodeBadValue, "AV"},
		{"unknown value", strings.Replace(goodVector, "VC:H", "VC:X", 1), CodeBadValue, "VC"},
		{"safety is not a base value", strings.Replace(goodVector, "SI:N", "SI:S", 1), CodeBadValue, "SI"},
		{"long value", strings.Replace(goodVector, "VC:H", "VC:HIGH", 1), CodeBadValue, "VC"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.vector)
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("Parse(%q) error = %v, want a *ParseError", c.vector, err)
			}
			if pe.Code != c.code || pe.Metric != c.metric {
				t.Errorf("Parse(%q) = code %q metric %q, want %q %q", c.vector, pe.Code, pe.Metric, c.code, c.metric)
			}
			// The refusal never repeats the agent's text.
			if c.vector != "" && strings.Contains(pe.Error(), c.vector) {
				t.Errorf("the error repeats the vector: %q", pe.Error())
			}
			if _, cerr := Compute(c.vector); cerr == nil {
				t.Errorf("Compute(%q) scored a refused vector", c.vector)
			}
		})
	}
}

func TestEveryErrorCodeIsExercised(t *testing.T) {
	// A new code must come with a refusal case above.
	all := []ErrorCode{CodeEmpty, CodeTooLong, CodeBadPrefix, CodeBadSyntax, CodeNotBase, CodeBadMetric, CodeMissingMetric, CodeBadValue}
	seen := map[ErrorCode]bool{}
	for _, v := range []string{
		"", goodVector + strings.Repeat("/AV:N", 40), "x", "CVSS:4.0/", goodVector + "/E:A",
		"CVSS:4.0/AC:L", "CVSS:4.0/AV:N", strings.Replace(goodVector, "AV:N", "AV:n", 1),
	} {
		_, err := Parse(v)
		var pe *ParseError
		if errors.As(err, &pe) {
			seen[pe.Code] = true
		}
	}
	for _, c := range all {
		if !seen[c] {
			t.Errorf("no probe produced code %q", c)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{goodVector, "", "CVSS:4.0/", "CVSS:4.0/AV:N/AC:L", "CVSS:3.1/AV:N", goodVector + "/E:A"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := Parse(s)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("a refusal that is not a *ParseError: %v", err)
			}
			return
		}
		// The grammar is exact, so an accepted vector is already canonical.
		if got := b.Vector(); got != s {
			t.Fatalf("accepted %q but its canonical form is %q", s, got)
		}
		r, err := Compute(s)
		if err != nil {
			t.Fatalf("an accepted vector did not score: %v", err)
		}
		if r.Score < 0 || r.Score > 10 {
			t.Fatalf("score %v out of range", r.Score)
		}
	})
}
