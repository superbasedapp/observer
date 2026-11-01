package jsonv1compat

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// UnmarshalObject decodes data into *m like json.Unmarshal(data, m),
// with the Go 1.26 result for a number outside the float64 range: the
// value it lands in is nil, not 0. The error is json.Unmarshal's own (its
// text may differ from Go 1.26, which callers must not depend on).
func UnmarshalObject(data []byte, m *map[string]any) error {
	err := json.Unmarshal(data, m)
	if err == nil || !json.Valid(data) {
		// A syntax error leaves *m untouched in both versions.
		return err
	}
	// Valid JSON that failed to decode into a map of untyped values: the
	// top level is not an object (nothing was stored, the same in both
	// versions) or a number is out of range. Decode again keeping every
	// number as written, then convert the way Go 1.26 did.
	var exact map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if dec.Decode(&exact) != nil || exact == nil {
		return err
	}
	if *m == nil {
		*m = make(map[string]any, len(exact))
	}
	for k, v := range exact {
		(*m)[k] = numbersAsV1(v)
	}
	return err
}

// numbersAsV1 replaces every json.Number in v by the float64 Go 1.26
// stored for it, or by nil when the number does not fit a float64.
func numbersAsV1(v any) any {
	switch x := v.(type) {
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil {
			return nil
		}
		return f
	case map[string]any:
		for k, e := range x {
			x[k] = numbersAsV1(e)
		}
		return x
	case []any:
		for i, e := range x {
			x[i] = numbersAsV1(e)
		}
		return x
	default:
		return v
	}
}
