package jsonv1compat

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestUnmarshalObject pins the Go 1.26 results. Every row must pass with
// GOEXPERIMENT=nojsonv2 (the Go 1.26 decoder, where UnmarshalObject is
// json.Unmarshal) and with the default Go 1.27 build.
func TestUnmarshalObject(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		prefill map[string]any
		want    map[string]any
		wantErr bool
	}{
		{"plain object", `{"a":1,"b":"x"}`, nil, map[string]any{"a": 1.0, "b": "x"}, false},
		{"overflow is nil", `{"a":1e400,"b":"x"}`, nil, map[string]any{"a": nil, "b": "x"}, true},
		{"negative overflow is nil", `{"a":-1e400,"b":"x"}`, nil, map[string]any{"a": nil, "b": "x"}, true},
		{"underflow is zero, no error", `{"a":1e-400}`, nil, map[string]any{"a": 0.0}, false},
		{"overflow nested in an object", `{"a":{"c":1e400,"d":2}}`, nil, map[string]any{"a": map[string]any{"c": nil, "d": 2.0}}, true},
		{"overflow in an array", `{"a":[1e400,2,"s",null,true]}`, nil, map[string]any{"a": []any{nil, 2.0, "s", nil, true}}, true},
		{"big integer is a float", `{"a":12345678901234567890}`, nil, map[string]any{"a": 1.2345678901234567e19}, false},
		{"overflow merges into a prefilled map", `{"a":1e400}`, map[string]any{"a": "old", "z": 1.0}, map[string]any{"a": nil, "z": 1.0}, true},
		{"duplicate name, last wins", `{"a":1e400,"a":"x"}`, nil, map[string]any{"a": "x"}, true},
		{"duplicate name, overflow last", `{"a":"x","a":1e400}`, nil, map[string]any{"a": nil}, true},
		{"array at the top stores nothing", `[1e400]`, map[string]any{}, map[string]any{}, true},
		{"syntax error stores nothing", `{"a":1e400,`, map[string]any{}, map[string]any{}, true},
		{"trailing data stores nothing", `{"a":1e400} x`, map[string]any{}, map[string]any{}, true},
		{"null leaves a nil map nil", `null`, nil, nil, false},
		{"invalid UTF-8 is replaced", "{\"a\":\"x\xff\",\"b\":1e400}", nil, map[string]any{"a": "x�", "b": nil}, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.prefill
			err := UnmarshalObject([]byte(tc.in), &got)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestUnmarshalObjectMatchesStdlibWithoutOverflow pins that, away from an
// out-of-range number, UnmarshalObject is exactly json.Unmarshal.
func TestUnmarshalObjectMatchesStdlibWithoutOverflow(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		`{"a":1,"b":[1,2.5,-0,null,true,"s",{}],"c":{"d":1e-400}}`,
		`{"a":"x","A":"y"}`,
		`{}`,
		`{"a":7}`,
		`"str"`,
		`{"a":`,
	} {
		var want, got map[string]any
		wantErr := json.Unmarshal([]byte(in), &want)
		gotErr := UnmarshalObject([]byte(in), &got)
		if (wantErr != nil) != (gotErr != nil) || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %#v (%v), json.Unmarshal %#v (%v)", in, got, gotErr, want, wantErr)
		}
	}
}
