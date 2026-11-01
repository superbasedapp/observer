package otlpvendor

import (
	"strconv"
	"strings"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// attrs is an attribute slice indexed by key.
type attrs map[string]*commonpb.AnyValue

// attrMap indexes an attribute slice by key. A repeated key keeps its FIRST
// value, matching how the original Claude Code parser resolved event.name.
func attrMap(kvs []*commonpb.KeyValue) attrs {
	m := make(attrs, len(kvs))
	for _, kv := range kvs {
		if _, seen := m[kv.GetKey()]; !seen {
			m[kv.GetKey()] = kv.GetValue()
		}
	}
	return m
}

// view is the lookup scope of one record: its own attributes first, then
// (only for a rule that sets Fields.FromSpanEvents) the attributes of the
// span's events, then its resource's attributes as the fallback (session ids
// often live on the resource).
type view struct {
	rec, res attrs
	// evt holds the span's event attributes, first value per key; nil for a
	// log record or a rule that does not read events.
	evt attrs
}

// scopes is the lookup order of one view.
func (v view) scopes() []attrs {
	if v.evt != nil {
		return []attrs{v.rec, v.evt, v.res}
	}
	return []attrs{v.rec, v.res}
}

// withEvents returns v reading evt between the record and the resource.
func (v view) withEvents(evt attrs) view {
	v.evt = evt
	return v
}

// lookup returns the first value present across the candidate keys, record
// before resource for each key.
func (v view) lookup(keys []string) (*commonpb.AnyValue, bool) {
	for _, k := range keys {
		for _, m := range v.scopes() {
			if val, ok := m[k]; ok && val != nil && val.GetValue() != nil {
				return val, true
			}
		}
	}
	return nil, false
}

// str returns the first non-empty STRING value across the candidate keys.
// Only string-typed values count, as in the original Claude Code parser: an
// id never arrives as a number.
func (v view) str(keys []string) string {
	for _, k := range keys {
		for _, m := range v.scopes() {
			if s := m[k].GetStringValue(); s != "" {
				return s
			}
		}
	}
	return ""
}

// num returns the first numeric value across the candidate keys. Integers,
// doubles and numeric STRINGS are all accepted: Codex encodes its token
// counts as strings ("1234") on the wire, while Claude Code and the GenAI
// exporters use integers.
func (v view) num(keys []string) (float64, bool) {
	for _, k := range keys {
		for _, m := range v.scopes() {
			if f, ok := numVal(m[k]); ok {
				return f, true
			}
		}
	}
	return 0, false
}

// int64Of returns num() as an int64, 0 when absent.
func (v view) int64Of(keys []string) int64 {
	f, _ := v.num(keys)
	return int64(f)
}

// boolOf reads a boolean across the candidate keys: a bool value, or the
// strings "true"/"false" (Codex), or 1/0. ok is false when absent or
// unparseable.
func (v view) boolOf(keys []string) (val, ok bool) {
	raw, present := v.lookup(keys)
	if !present {
		return false, false
	}
	switch x := raw.GetValue().(type) {
	case *commonpb.AnyValue_BoolValue:
		return x.BoolValue, true
	case *commonpb.AnyValue_StringValue:
		b, err := strconv.ParseBool(strings.TrimSpace(x.StringValue))
		return b, err == nil
	case *commonpb.AnyValue_IntValue:
		return x.IntValue != 0, true
	}
	return false, false
}

// has reports whether any candidate key is present with a non-nil value.
func (v view) has(keys []string) bool {
	_, ok := v.lookup(keys)
	return ok
}

// numVal decodes one value as a number.
func numVal(v *commonpb.AnyValue) (float64, bool) {
	if v == nil {
		return 0, false
	}
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_IntValue:
		return float64(x.IntValue), true
	case *commonpb.AnyValue_DoubleValue:
		return x.DoubleValue, true
	case *commonpb.AnyValue_StringValue:
		s := strings.TrimSpace(x.StringValue)
		if s == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	}
	return 0, false
}

// parseTimestamp reads an RFC 3339 event.timestamp attribute value.
func parseTimestamp(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}
