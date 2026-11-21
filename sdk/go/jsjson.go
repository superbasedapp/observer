package superbased

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// jsNumber is ECMAScript Number::toString for a float (what JSON.stringify
// writes): the shortest round-trip digits, plain between 1e-7 and 1e21,
// exponent form outside; NaN and infinities are null.
func jsNumber(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null"
	}
	if f == 0 {
		return "0"
	}
	abs := math.Abs(f)
	if abs >= 1e21 || abs < 1e-6 {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		mant, exp, _ := strings.Cut(s, "e")
		sign := exp[0]
		exp = strings.TrimLeft(exp[1:], "0")
		if exp == "" {
			exp = "0"
		}
		return mant + "e" + string(sign) + exp
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// jsJSON renders v as compact JSON the way JSON.stringify writes it: no
// spaces, ECMAScript numbers (1.0 -> 1), non-ASCII kept, no HTML escaping.
// Object keys keep their order where Go has one (a struct's fields, a
// json.RawMessage's text); a Go map has none, so its keys are sorted. With
// sortKeys every object's keys are sorted (the canonical form).
func jsJSON(v any, sortKeys bool) string {
	var b strings.Builder
	writeJS(&b, v, sortKeys)
	return b.String()
}

func jsString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	out := strings.TrimRight(buf.String(), "\n")
	// JSON.stringify does not escape U+2028 / U+2029; encoding/json does.
	out = strings.ReplaceAll(out, ` `, " ")
	return strings.ReplaceAll(out, ` `, " ")
}

// orderedPair is one member of a decoded JSON object, in source order.
type orderedPair struct {
	key string
	val any
}

type orderedObject []orderedPair

// decodeOrdered decodes JSON keeping object member order (numbers as json.Number).
func decodeOrdered(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return readOrdered(dec)
}

func readOrdered(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			var obj orderedObject
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				val, err := readOrdered(dec)
				if err != nil {
					return nil, err
				}
				obj = append(obj, orderedPair{kt.(string), val})
			}
			_, err := dec.Token()
			return obj, err
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := readOrdered(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			_, err := dec.Token()
			return arr, err
		}
	}
	return tok, nil
}

func writeJS(b *strings.Builder, v any, sortKeys bool) {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
		return
	case bool:
		b.WriteString(strconv.FormatBool(t))
		return
	case string:
		b.WriteString(jsString(t))
		return
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			b.WriteString("null")
			return
		}
		b.WriteString(jsNumber(f))
		return
	case json.RawMessage:
		dv, err := decodeOrdered(t)
		if err != nil {
			b.WriteString("null")
			return
		}
		writeJS(b, dv, sortKeys)
		return
	case orderedObject:
		pairs := t
		if sortKeys {
			pairs = append(orderedObject(nil), t...)
			sort.SliceStable(pairs, func(i, j int) bool { return pairs[i].key < pairs[j].key })
		}
		b.WriteByte('{')
		for i, p := range pairs {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(jsString(p.key))
			b.WriteByte(':')
			writeJS(b, p.val, sortKeys)
		}
		b.WriteByte('}')
		return
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		b.WriteString(strconv.FormatInt(rv.Int(), 10))
		return
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		b.WriteString(strconv.FormatUint(rv.Uint(), 10))
		return
	case reflect.Float32, reflect.Float64:
		b.WriteString(jsNumber(rv.Float()))
		return
	case reflect.Pointer, reflect.Interface:
		if rv.IsNil() {
			b.WriteString("null")
			return
		}
	case reflect.Map:
		if rv.Type().Key().Kind() == reflect.String {
			keys := make([]string, 0, rv.Len())
			for _, k := range rv.MapKeys() {
				keys = append(keys, k.String())
			}
			sort.Strings(keys)
			b.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					b.WriteByte(',')
				}
				b.WriteString(jsString(k))
				b.WriteByte(':')
				writeJS(b, rv.MapIndex(reflect.ValueOf(k).Convert(rv.Type().Key())).Interface(), sortKeys)
			}
			b.WriteByte('}')
			return
		}
	case reflect.Slice, reflect.Array:
		if rv.Kind() == reflect.Slice && rv.IsNil() {
			b.WriteString("null")
			return
		}
		if rv.Type().Elem().Kind() != reflect.Uint8 {
			b.WriteByte('[')
			for i := 0; i < rv.Len(); i++ {
				if i > 0 {
					b.WriteByte(',')
				}
				writeJS(b, rv.Index(i).Interface(), sortKeys)
			}
			b.WriteByte(']')
			return
		}
	}
	// Structs and anything else: encoding/json's text (struct fields in
	// declaration order), re-rendered for the number form.
	raw, err := marshalCompact(v)
	if err != nil {
		b.WriteString(jsString(fmt.Sprint(v)))
		return
	}
	dv, err := decodeOrdered(raw)
	if err != nil {
		b.WriteString(jsString(fmt.Sprint(v)))
		return
	}
	writeJS(b, dv, sortKeys)
}
