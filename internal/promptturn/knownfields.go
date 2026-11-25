package promptturn

import (
	"reflect"
	"sort"
	"strings"
	"sync"
)

// knownFieldTypes are every struct this package decodes a request body into.
var knownFieldTypes = []any{
	AnthropicMessage{},
	anthropicBlock{},
	ChatMessage{},
	ChatToolCall{},
	ResponsesItem{},
	GeminiPart{},
	GeminiContent{},
	admMessage{},
	admBlock{},
	admSource{},
	admTypedText{},
	admGeminiContent{},
}

var (
	knownFieldsOnce sync.Once
	knownFields     []string
)

// KnownFields lists, sorted, every JSON object key this package's decoders
// read by struct field (so under Go's case-insensitive, Unicode-folding
// match) plus the top-level content fields. The AI gateway's strict body
// reader (finding M1, L-180) refuses a key that equals one of them only under
// folding, so the gateway and a case-sensitive upstream read the same body.
// It is derived from the structs themselves, so a new field cannot be missed.
func KnownFields() []string {
	knownFieldsOnce.Do(func() {
		set := map[string]bool{}
		for _, f := range contentFields {
			set[f] = true
		}
		for _, v := range knownFieldTypes {
			StructJSONFields(reflect.TypeOf(v), set)
		}
		for k := range set {
			knownFields = append(knownFields, k)
		}
		sort.Strings(knownFields)
	})
	return append([]string(nil), knownFields...)
}

// StructJSONFields adds the json names of t's fields, and of the fields of
// every struct t nests (by value, pointer, slice or array), to set. An
// untagged exported field adds its Go name; a field tagged "-" adds nothing.
func StructJSONFields(t reflect.Type, set map[string]bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch name {
		case "-":
			continue
		case "":
			name = f.Name
		}
		set[name] = true
		StructJSONFields(f.Type, set)
	}
}
