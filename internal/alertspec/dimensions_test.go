package alertspec

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDimensionsRefuseUnknownKeys pins review finding E-80: a key outside
// DimensionNames is refused, never dropped (dropping it widened the rule to
// the whole org); the known keys and null values decode as before.
func TestDimensionsRefuseUnknownKeys(t *testing.T) {
	var d Dimensions
	if err := json.Unmarshal([]byte(`{"end_user":"alice"}`), &d); err == nil || !strings.Contains(err.Error(), `"end_user"`) {
		t.Fatalf("unknown key: err = %v", err)
	}
	if err := json.Unmarshal([]byte(`{"model":"m","user":"u","tag":"t","service":"s"}`), &d); err != nil ||
		d != (Dimensions{Model: "m", User: "u", Tag: "t", Service: "s"}) {
		t.Fatalf("known keys: %+v %v", d, err)
	}
	if err := json.Unmarshal([]byte(`{"model":null}`), &d); err != nil || !d.IsZero() {
		t.Fatalf("null value: %+v %v", d, err)
	}
	var body struct {
		Dimensions *Dimensions `json:"dimensions"`
	}
	if err := json.Unmarshal([]byte(`{"dimensions":{"service":"api","end_user":"x"}}`), &body); err == nil {
		t.Fatal("nested unknown key accepted")
	}
	if err := json.Unmarshal([]byte(`{"dimensions":{"service":7}}`), &body); err == nil {
		t.Fatal("non-string value accepted")
	}
}
