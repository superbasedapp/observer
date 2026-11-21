package otelident

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestClamp(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"  a  ", 10, "a"},
		{"abcdef", 3, "abc"},
		{"héllo", 2, "h"}, // é is 2 bytes; never split a rune
		{"x", 0, "x"},
	}
	for _, c := range cases {
		if got := Clamp(c.in, c.max); got != c.want {
			t.Errorf("Clamp(%q,%d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
	if got := ClampValue(strings.Repeat("u", 1000)); len(got) != MaxValueLen {
		t.Errorf("ClampValue len = %d", len(got))
	}
}

func TestParseAndNormalizeTags(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`["b","a","a",1]`, []string{"1", "a", "b"}},
		{"b, a ,,a", []string{"a", "b"}},
		{"solo", []string{"solo"}},
		{"", nil},
		{"[not json", []string{"[not json"}},
	}
	for _, c := range cases {
		if got := NormalizeTags(ParseTags(c.in)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("tags(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	var many []string
	for i := 0; i < MaxTags+10; i++ {
		many = append(many, fmt.Sprintf("t%03d", i))
	}
	got := NormalizeTags(many)
	if len(got) != MaxTags || got[0] != "t000" {
		t.Errorf("cap: len=%d first=%q", len(got), got[0])
	}
}

func TestNormalizeMetadataPrecedenceAndCap(t *testing.T) {
	got := NormalizeMetadata(map[string]string{"plan": "span"}, map[string]string{"plan": "resource", "region": "eu", "": "x"})
	want := map[string]string{"plan": "span", "region": "eu"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	big := map[string]string{}
	for i := 0; i < MaxMetadataKeys+5; i++ {
		big[fmt.Sprintf("k%03d", i)] = strings.Repeat("v", MaxMetadataValueLen+9)
	}
	n := NormalizeMetadata(big)
	if len(n) != MaxMetadataKeys {
		t.Fatalf("cap = %d", len(n))
	}
	if _, ok := n["k000"]; !ok {
		t.Error("cap must keep the lexically smallest keys")
	}
	if len(n["k000"]) != MaxMetadataValueLen {
		t.Error("value not clamped")
	}
	if NormalizeMetadata(nil) != nil {
		t.Error("empty must be nil")
	}
}

func TestParseMetadataJSON(t *testing.T) {
	got := ParseMetadataJSON(`{"a":"x","n":2,"b":true,"o":{"z":1}}`)
	want := map[string]string{"a": "x", "n": "2", "b": "true", "o": `{"z":1}`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if ParseMetadataJSON("plain") != nil || ParseMetadataJSON("{bad") != nil {
		t.Error("non-object must be nil")
	}
}

func TestMetadataKeyFor(t *testing.T) {
	cases := []struct {
		key  string
		want string
		ok   bool
	}{
		{"langfuse.trace.metadata.plan", "plan", true},
		{"traceloop.association.properties.region", "region", true},
		{"traceloop.association.properties.user_id", "", false}, // identity, not metadata
		{"sbo.metadata.", "", false},
		{"gen_ai.request.model", "", false},
	}
	for _, c := range cases {
		got, ok := MetadataKeyFor(c.key)
		if got != c.want || ok != c.ok {
			t.Errorf("MetadataKeyFor(%q) = %q,%v", c.key, got, ok)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tags := []string{"b", "a"}
	if got := DecodeTags(EncodeTags(tags)); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Errorf("tags round trip = %v", got)
	}
	if EncodeTags(nil) != "" || EncodeMetadata(nil) != "" {
		t.Error("empty encodes to empty string")
	}
	m := map[string]string{"k": "v"}
	if got := DecodeMetadata(EncodeMetadata(m)); !reflect.DeepEqual(got, m) {
		t.Errorf("metadata round trip = %v", got)
	}
	if DecodeTags("{") != nil || DecodeMetadata("[") != nil {
		t.Error("malformed must decode to nil")
	}
}

func TestFieldSet(t *testing.T) {
	var s FieldSet
	s = s.With(FieldUser).With(FieldRelease)
	if !s.Has(FieldUser) || !s.Has(FieldRelease) || s.Has(FieldTenant) {
		t.Fatalf("FieldSet = %b", s)
	}
	if s.Without(FieldUser).Has(FieldUser) {
		t.Fatal("Without")
	}
}

// TestIdentityKeyListsDisjoint: one key, one meaning. A key in two lists
// would be read as two identity fields at once.
func TestIdentityKeyListsDisjoint(t *testing.T) {
	lists := map[string][]string{
		"tenant": TenantKeys, "user": UserKeys, "session": SessionKeys, "service": ServiceKeys,
		"environment": EnvironmentKeys, "release": ReleaseKeys, "tags": TagKeys, "metadata": MetadataKeys,
	}
	owner := map[string]string{}
	for name, l := range lists {
		for _, k := range l {
			if prev, ok := owner[k]; ok {
				t.Errorf("key %q in both %s and %s", k, prev, name)
			}
			owner[k] = name
		}
	}
}
