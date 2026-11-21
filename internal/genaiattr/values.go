package genaiattr

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// maxValueDepth bounds the recursion of a structured value's rendering. A
// deeper subtree renders as null (the OTLP decoder already bounds nesting;
// this keeps the renderer total on any input).
const maxValueDepth = 64

// Attrs indexes one record's attributes by key. A repeated key keeps its LAST
// value (the mappers' shipped behaviour).
type Attrs map[string]*commonpb.AnyValue

// Index builds an Attrs from an OTLP key-value list. A nil entry is skipped.
func Index(kvs []*commonpb.KeyValue) Attrs {
	m := make(Attrs, len(kvs))
	for _, kv := range kvs {
		if kv == nil {
			continue
		}
		m[kv.GetKey()] = kv.GetValue()
	}
	return m
}

// Text renders a value as text. A string is returned verbatim; an int,
// double or bool in its decimal / literal form; bytes as standard base64; an
// ARRAY or KVLIST as its compact JSON rendering (an array value is never
// flattened to empty: findings F19/F20). A nil or empty value is "".
func Text(v *commonpb.AnyValue) string {
	if v == nil {
		return ""
	}
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(x.IntValue, 10)
	case *commonpb.AnyValue_DoubleValue:
		return strconv.FormatFloat(x.DoubleValue, 'g', -1, 64)
	case *commonpb.AnyValue_BoolValue:
		return strconv.FormatBool(x.BoolValue)
	case *commonpb.AnyValue_BytesValue:
		if len(x.BytesValue) == 0 {
			return ""
		}
		return base64.StdEncoding.EncodeToString(x.BytesValue)
	case *commonpb.AnyValue_ArrayValue, *commonpb.AnyValue_KvlistValue:
		b, err := json.Marshal(JSONValue(v))
		if err != nil {
			return ""
		}
		return string(b)
	}
	return ""
}

// JSONValue converts a value to the Go value encoding/json renders: a kvlist
// becomes a map (key order is then sorted by the encoder, so the rendering
// is canonical), an array a slice, bytes a base64 string, a scalar itself. A
// nil or empty value is nil.
func JSONValue(v *commonpb.AnyValue) any { return jsonValue(v, 0) }

func jsonValue(v *commonpb.AnyValue, depth int) any {
	if v == nil || depth > maxValueDepth {
		return nil
	}
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_IntValue:
		return x.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return x.DoubleValue
	case *commonpb.AnyValue_BoolValue:
		return x.BoolValue
	case *commonpb.AnyValue_BytesValue:
		return base64.StdEncoding.EncodeToString(x.BytesValue)
	case *commonpb.AnyValue_ArrayValue:
		vals := x.ArrayValue.GetValues()
		out := make([]any, 0, len(vals))
		for _, e := range vals {
			out = append(out, jsonValue(e, depth+1))
		}
		return out
	case *commonpb.AnyValue_KvlistValue:
		kvs := x.KvlistValue.GetValues()
		out := make(map[string]any, len(kvs))
		for _, kv := range kvs {
			if kv == nil {
				continue
			}
			out[kv.GetKey()] = jsonValue(kv.GetValue(), depth+1)
		}
		return out
	}
	return nil
}

// Strings renders a value as a list of strings: an array's elements (each
// through Text, empty ones skipped), or a single non-empty scalar as a
// one-element list. A string holding a JSON array of strings is decoded.
func Strings(v *commonpb.AnyValue) []string {
	if v == nil {
		return nil
	}
	if arr, ok := v.GetValue().(*commonpb.AnyValue_ArrayValue); ok {
		var out []string
		for _, e := range arr.ArrayValue.GetValues() {
			if s := strings.TrimSpace(Text(e)); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	s := strings.TrimSpace(Text(v))
	if s == "" {
		return nil
	}
	if strings.HasPrefix(s, "[") {
		var list []string
		if err := json.Unmarshal([]byte(s), &list); err == nil {
			var out []string
			for _, e := range list {
				if e = strings.TrimSpace(e); e != "" {
					out = append(out, e)
				}
			}
			return out
		}
	}
	return []string{s}
}

// Value returns the first present, non-empty value among keys.
func (a Attrs) Value(keys []string) *commonpb.AnyValue {
	for _, k := range keys {
		if v, ok := a[k]; ok && v != nil && v.GetValue() != nil {
			return v
		}
	}
	return nil
}

// Str returns the Text of key, "" when absent.
func (a Attrs) Str(key string) string { return Text(a[key]) }

// First returns the Text of the first key whose Text is non-empty.
func (a Attrs) First(keys []string) string {
	for _, k := range keys {
		if s := Text(a[k]); s != "" {
			return s
		}
	}
	return ""
}

// Int reads the first parseable integer among keys: an int, a double
// (truncated) or a decimal string. Nil when none is present, so an absent
// count stays an honest NULL.
func (a Attrs) Int(keys []string) *int64 {
	for _, k := range keys {
		v, ok := a[k]
		if !ok || v == nil {
			continue
		}
		switch x := v.GetValue().(type) {
		case *commonpb.AnyValue_IntValue:
			n := x.IntValue
			return &n
		case *commonpb.AnyValue_DoubleValue:
			n := int64(x.DoubleValue)
			return &n
		case *commonpb.AnyValue_StringValue:
			if n, err := strconv.ParseInt(strings.TrimSpace(x.StringValue), 10, 64); err == nil {
				return &n
			}
		}
	}
	return nil
}

// Float reads the first parseable number among keys: a double, an int or a
// decimal string. Nil when none is present.
func (a Attrs) Float(keys []string) *float64 {
	for _, k := range keys {
		v, ok := a[k]
		if !ok || v == nil {
			continue
		}
		switch x := v.GetValue().(type) {
		case *commonpb.AnyValue_DoubleValue:
			f := x.DoubleValue
			return &f
		case *commonpb.AnyValue_IntValue:
			f := float64(x.IntValue)
			return &f
		case *commonpb.AnyValue_StringValue:
			if f, err := strconv.ParseFloat(strings.TrimSpace(x.StringValue), 64); err == nil {
				return &f
			}
		}
	}
	return nil
}
