package oteldirect

import (
	"reflect"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// admittedFamilies is the closed allow-list of push-envelope families (by
// JSON name) an OTel-direct batch may land: exactly what MapLogs produces.
// Everything else is dropped with a count; an exporter is not a node, so no
// node inventory, posture, aggregate, deletion or manifest family can ride
// in (the shiptoken.Admit precedent, narrower). A new envelope family is
// dropped until it is classified (TestEveryEnvelopeFamilyClassified).
var admittedFamilies = map[string]bool{
	"sessions":     true,
	"actions":      true,
	"api_turns":    true,
	"otel_content": true,
}

// keptScalars are the non-family fields Admit keeps as sent.
var keptScalars = map[string]bool{
	"agent_version": true,
}

// clearedScalars are the non-family fields Admit always clears: an exporter
// holds no machine identity, no node key and no push cursor.
var clearedScalars = map[string]bool{
	"machine_identity": true,
	"source_node_key":  true,
	"cursor_from":      true,
	"cursor_to":        true,
}

// AdmittedFamilies returns the allow-list, sorted.
func AdmittedFamilies() []string {
	out := make([]string, 0, len(admittedFamilies))
	for k := range admittedFamilies {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Admitted is the result of Admit.
type Admitted struct {
	// Envelope holds only the admitted families and agent_version.
	Envelope orgcontract.PushEnvelope
	// Dropped counts the rows of each dropped family (by JSON name); a
	// pointer family counts as one row. Empty families are not listed.
	Dropped map[string]int
	// Rows is the number of admitted rows.
	Rows int
}

// DroppedTotal sums Dropped.
func (a Admitted) DroppedTotal() int {
	n := 0
	for _, v := range a.Dropped {
		n += v
	}
	return n
}

// Admit filters env through the admission table. It never mutates env.
func Admit(env orgcontract.PushEnvelope) Admitted {
	out := Admitted{Dropped: map[string]int{}}
	src := reflect.ValueOf(env)
	dst := reflect.ValueOf(&out.Envelope).Elem()
	t := src.Type()
	for i := 0; i < t.NumField(); i++ {
		name := jsonName(t.Field(i))
		v := src.Field(i)
		switch {
		case admittedFamilies[name]:
			dst.Field(i).Set(copySlice(v))
			out.Rows += rowCount(v)
		case keptScalars[name]:
			dst.Field(i).Set(v)
		case clearedScalars[name]:
			// left zero
		default:
			if n := rowCount(v); n > 0 {
				out.Dropped[name] += n
			}
		}
	}
	return out
}

// jsonName is a struct field's JSON key.
func jsonName(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
	if name == "" {
		return f.Name
	}
	return name
}

// rowCount counts a field's rows: a slice's length, one for a non-nil
// pointer, zero otherwise.
func rowCount(v reflect.Value) int {
	switch v.Kind() {
	case reflect.Slice:
		return v.Len()
	case reflect.Pointer:
		if v.IsNil() {
			return 0
		}
		return 1
	}
	return 0
}

// copySlice returns a shallow copy of a slice, so later edits to the
// admitted envelope never reach the caller's.
func copySlice(v reflect.Value) reflect.Value {
	if v.Kind() != reflect.Slice || v.IsNil() {
		return v
	}
	c := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
	reflect.Copy(c, v)
	return c
}
