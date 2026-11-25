package vendorapi

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// TestDrift pins the drift error's text and that it wraps ErrSchemaDrift.
func TestDrift(t *testing.T) {
	err := Drift(vendorsurface.SurfaceID("acme.users"), "field %q is %d", "seats", 3)
	if !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("Drift does not wrap ErrSchemaDrift: %v", err)
	}
	if got, want := err.Error(), `vendorapi: schema drift: acme.users: field "seats" is 3`; got != want {
		t.Fatalf("Drift text = %q, want %q", got, want)
	}
}

// TestDecodeNumbers pins that numbers decode as json.Number.
func TestDecodeNumbers(t *testing.T) {
	var v map[string]any
	if err := DecodeNumbers([]byte(`{"n": 12345678901234567890}`), &v); err != nil {
		t.Fatalf("DecodeNumbers: %v", err)
	}
	if n, ok := v["n"].(json.Number); !ok || n.String() != "12345678901234567890" {
		t.Fatalf("n = %#v, want json.Number 12345678901234567890", v["n"])
	}
	if err := DecodeNumbers([]byte(`{`), &v); err == nil {
		t.Fatal("DecodeNumbers accepted a truncated body")
	}
}

// TestStr pins the nil-safe string reads.
func TestStr(t *testing.T) {
	s := "  x  "
	cases := []struct {
		name      string
		in        *string
		str, trim string
	}{
		{"nil", nil, "", ""},
		{"padded", &s, "  x  ", "x"},
	}
	for _, tc := range cases {
		if got := Str(tc.in); got != tc.str {
			t.Errorf("%s: Str = %q, want %q", tc.name, got, tc.str)
		}
		if got := TrimStr(tc.in); got != tc.trim {
			t.Errorf("%s: TrimStr = %q, want %q", tc.name, got, tc.trim)
		}
	}
}
