package sandboxopenshell

import (
	"strings"
	"testing"
)

// TestLabelGrammar: accepted and refused keys and values, one case each.
func TestLabelGrammar(t *testing.T) {
	t.Parallel()
	keys := []struct {
		k  string
		ok bool
	}{
		{LabelRun, true},
		{LabelInstall, true},
		{"observer-o0", true},
		{"observer-o0-row", true},
		{"a", true},
		{strings.Repeat("a", 63), true},
		{strings.Repeat("a", 64), false},
		{"", false},
		{"-lead", false},
		{"trail.", false},
		{"has space", false},
		{"k=v", false},
		{"a,b", false},
		{"example.com/run", false},
	}
	for _, tc := range keys {
		if got := ValidLabelKey(tc.k); got != tc.ok {
			t.Errorf("key %q: %v, want %v", tc.k, got, tc.ok)
		}
	}
	values := []struct {
		v  string
		ok bool
	}{
		{"oAbc-_123o", true},
		{"0123abcd", true},
		{"", false},
		{"-x", false},
		{"x_", false},
		{"a=b", false},
		{"a,b", false},
		{"a b", false},
		{"!x", false},
		{strings.Repeat("v", 64), false},
	}
	for _, tc := range values {
		if got := ValidLabelValue(tc.v); got != tc.ok {
			t.Errorf("value %q: %v, want %v", tc.v, got, tc.ok)
		}
	}
}

func TestEncodeID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		id string
		ok bool
	}{
		{"Zm9vYmFyLWJhel9xdXV4", true},
		{"-leadingdash_x", true},
		{"trailing_x_", true},
		{"0123456789abcdef", true},
		{"short", false},
		{"has space here", false},
		{"a=b=c=d=e", false},
		{strings.Repeat("x", 62), false},
	}
	for _, tc := range cases {
		v, err := EncodeID(tc.id)
		if (err == nil) != tc.ok {
			t.Errorf("%q: err %v, want ok %v", tc.id, err, tc.ok)
			continue
		}
		if !tc.ok {
			continue
		}
		if !ValidLabelValue(v) {
			t.Errorf("%q: encoded %q fails the value grammar", tc.id, v)
		}
		if back, ok := DecodeID(v); !ok || back != tc.id {
			t.Errorf("%q: decode %q, %v", tc.id, back, ok)
		}
	}
	for _, bad := range []string{"", "o", "xabcdefghx", "oshorto"} {
		if _, ok := DecodeID(bad); ok {
			t.Errorf("DecodeID(%q) accepted", bad)
		}
	}
}

func TestRunLabelsAndSelector(t *testing.T) {
	t.Parallel()
	labels, err := RunLabels("0123456789abcdef", "-runid_base64url-")
	if err != nil {
		t.Fatal(err)
	}
	sel, err := Selector(labels)
	if err != nil {
		t.Fatal(err)
	}
	if want := "observer.superbased.install=o0123456789abcdefo,observer.superbased.run=o-runid_base64url-o"; sel != want {
		t.Errorf("selector %q, want %q", sel, want)
	}
	inst, _ := InstallLabels("0123456789abcdef")
	if s, _ := Selector(inst); s != "observer.superbased.install=o0123456789abcdefo" {
		t.Errorf("install selector %q", s)
	}
	refused := []struct {
		name   string
		labels []Label
	}{
		{"empty", nil},
		{"bad key", []Label{{"bad key", "ov1o"}}},
		{"bad value", []Label{{LabelRun, "a,b"}}},
		{"key twice", []Label{{LabelRun, "oaaaaaaaao"}, {LabelRun, "obbbbbbbbo"}}},
	}
	for _, tc := range refused {
		if _, err := Selector(tc.labels); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
	if _, err := RunLabels("short", "0123456789abcdef"); err == nil {
		t.Error("a bad install id was accepted")
	}
	if _, err := RunLabels("0123456789abcdef", "bad id"); err == nil {
		t.Error("a bad run id was accepted")
	}
}
