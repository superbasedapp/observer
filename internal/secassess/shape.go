package secassess

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
)

// The shape pass of row V2 (hardening after the first live retest, 2026-11-16).
// Before the typed decode every field of an item is read once from the generic
// JSON by its Go type and two things the model structs say about it:
//
//	lone:"list"  a single value written where a list belongs reads as a list of
//	             one: "evidence": "p3" is ["p3"], "refs": {...} is [{...}], and in
//	             a list a number or true/false reads as the text written. An entry
//	             that cannot be read that way is left out and counted.
//	omitempty    the field is optional. A value of the wrong kind in an optional
//	             LEAF field (text, a number, true or false, or a list of those) is
//	             left out and said so, so one mistyped optional field no longer
//	             refuses the whole file. The live retest lost all six labels to
//	             "evidence": "p3" on one result.
//
// What stays fatal (V2 bad_shape, as before): a wrong kind in a field the file
// must carry (no omitempty), and in anything that is not a leaf (an object, or a
// list of objects). Those hold the substance of the file, an empty list of
// findings would read as a clean result, and guessing at them would invent data.
//
// A tag is the table: the reflective tests (shape_test.go) walk every model
// struct and fail on a list field that is neither tagged nor named in
// loneExcluded, so a new list field cannot be added without choosing.

// loneExcluded names the list-of-text fields that are NOT read from a lone
// text, with the reason, so the choice is on the page. The key is the struct's
// type name and the field's JSON name.
var loneExcluded = map[string]string{
	// A start command is a list of words; one text would be one word with spaces
	// in it (the start command's own rules, ValidStartArgv, refuse it as such).
	"PTStart.argv": "a lone text is a command line, not one word of one",
}

// unmarshalerType is the interface of the types that read themselves (the
// lenient types of lenient.go): the shape pass leaves them to it.
var unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// readsItself reports whether a type decodes itself.
func readsItself(t reflect.Type) bool {
	return t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType)
}

// isNumberKind reports whether k is an integer or a floating point kind.
func isNumberKind(k reflect.Kind) bool {
	return isIntKind(k) || k == reflect.Float32 || k == reflect.Float64
}

// isLeaf reports whether a field of type t is a leaf of the model: text, a
// number, true or false, or a list of those.
func isLeaf(t reflect.Type) bool {
	t = indirect(t)
	if readsItself(t) {
		return false
	}
	switch k := t.Kind(); {
	case k == reflect.String || k == reflect.Bool || isNumberKind(k):
		return true
	case k == reflect.Slice:
		return isLeaf(t.Elem()) && indirect(t.Elem()).Kind() != reflect.Slice
	}
	return false
}

// leafWords says what a leaf field asks for, for the sentence that reports a
// value that was left out.
func leafWords(t reflect.Type) string {
	t = indirect(t)
	switch k := t.Kind(); {
	case k == reflect.String:
		return "text"
	case k == reflect.Bool:
		return "true or false"
	case isIntKind(k):
		return "a whole number"
	case k == reflect.Float32 || k == reflect.Float64:
		return "a number"
	case k == reflect.Slice:
		return "a list of " + strings.TrimPrefix(strings.TrimPrefix(leafWords(t.Elem()), "a "), "an ") + "s"
	}
	return "another kind of value"
}

// fits reports whether a generic JSON value (numbers are json.Number) decodes
// into the leaf type t.
func fits(val any, t reflect.Type) bool {
	t = indirect(t)
	if val == nil {
		return true
	}
	switch k := t.Kind(); {
	case k == reflect.String:
		_, ok := val.(string)
		return ok
	case k == reflect.Bool:
		_, ok := val.(bool)
		return ok
	case isIntKind(k):
		n, ok := val.(json.Number)
		return ok && intFits(n, t)
	case k == reflect.Float32 || k == reflect.Float64:
		n, ok := val.(json.Number)
		if !ok {
			return false
		}
		_, err := strconv.ParseFloat(string(n), t.Bits())
		return err == nil
	case k == reflect.Slice:
		items, ok := val.([]any)
		if !ok {
			return false
		}
		for _, it := range items {
			if !fits(it, t.Elem()) {
				return false
			}
		}
		return true
	}
	return true
}

// intFits reports whether a number decodes into the integer type t, a whole
// number written as a float ("3.0") counting as the integer it is.
func intFits(n json.Number, t reflect.Type) bool {
	s := string(n)
	if whole, ok := wholeNumber(n); ok {
		s = string(whole)
	}
	var err error
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		_, err = strconv.ParseInt(s, 10, t.Bits())
	default:
		_, err = strconv.ParseUint(s, 10, t.Bits())
	}
	return err == nil
}

// joinAt appends a field name to a position path ("results[3]" and "evidence"
// make "results[3].evidence").
func joinAt(at, key string) string {
	if at == "" {
		return key
	}
	return at + "." + key
}

// shapeField is the shape pass for one field of an item: it returns the value
// to keep in the field's place, which is nil when the field was left out. at is
// the field's position in the file ("results[3].evidence").
func (v *validator) shapeField(child any, f fieldInfo, at string) any {
	if f.lone {
		child = v.loneList(child, f.typ, at)
	}
	if f.optional && isLeaf(f.typ) && !fits(child, f.typ) {
		v.shapeLeftOut(at, "field_dropped", "This value was left out: the result model asks for "+leafWords(f.typ)+" here.")
		return nil
	}
	return child
}

// shapeLeftOut records something the shape pass left out: one dropped issue at
// the position, and the count that makes the validation partial.
func (v *validator) shapeLeftOut(at, code, msg string) {
	v.shaped++
	v.issue("V2", code, SevDropped, at, msg)
}

// loneItem reads one value as an entry of a list whose entries are elem: text
// for a list of texts (a number or true or false reads as the text written), an
// object for a list of objects.
func loneItem(val any, elem reflect.Type) (any, bool) {
	switch elem.Kind() {
	case reflect.String:
		switch x := val.(type) {
		case string:
			return x, true
		case json.Number:
			return string(x), true
		case bool:
			return strconv.FormatBool(x), true
		}
	case reflect.Struct:
		if m, ok := val.(map[string]any); ok {
			return m, true
		}
	}
	return nil, false
}

// loneList reads a field tagged lone:"list": a list keeps the entries it can
// read as one, and any other value that reads as one entry becomes a list of it
// (an empty text is a list of nothing). A value that is neither is returned
// unchanged, for the rules after this one to decide.
func (v *validator) loneList(child any, t reflect.Type, at string) any {
	t = indirect(t)
	if t.Kind() != reflect.Slice {
		return child
	}
	elem := indirect(t.Elem())
	switch c := child.(type) {
	case nil:
		return nil
	case []any:
		out := make([]any, 0, len(c))
		unread := 0
		for _, it := range c {
			if it == nil {
				continue
			}
			x, ok := loneItem(it, elem)
			if !ok {
				unread++
				continue
			}
			out = append(out, x)
		}
		if unread > 0 {
			v.shapeLeftOut(at, "list_entries_dropped", "Some entries of this list were not "+entryWords(elem)+", as the result model asks, so they were left out.")
		}
		return out
	}
	item, ok := loneItem(child, elem)
	if !ok {
		return child
	}
	if s, isText := item.(string); isText && strings.TrimSpace(s) == "" {
		return []any{}
	}
	return []any{item}
}

// entryWords says what an entry of a list is, for the sentence about entries
// that were left out.
func entryWords(elem reflect.Type) string {
	if elem.Kind() == reflect.Struct {
		return "objects"
	}
	return "text"
}
