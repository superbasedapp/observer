package secassess

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The write-time half of the redaction claim. What Observer keeps of a model is
// redacted when it is written: every free-text field. The ids, the references
// between items, the vocabulary words and the project paths are keys and are
// stored as the agent wrote them (they are limited to a closed alphabet and
// length, and redact.go says why they are not rewritten). This test fills every
// free-text spot of a real model with a secret, runs the real validator with a
// redactor, and fails when the stored result still holds the secret anywhere or
// when a free-text field of the model types was never exercised.

// rwSecret is the text every free-text spot holds.
const rwSecret = "x " + rxFake + " y"

// rwFreeFields lists "Type.Field" for every string or string-list field of the
// type (and the types under it) that the display pass would redact: not a
// computed field and not a key.
func rwFreeFields(t reflect.Type, seen map[reflect.Type]bool, out map[string]bool) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return
	}
	seen[t] = true
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Tag.Get("computed") == "true" || redactKept(t, f.Name) {
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		switch ft.Kind() {
		case reflect.String:
			out[t.Name()+"."+f.Name] = true
		case reflect.Struct:
			rwFreeFields(ft, seen, out)
		}
	}
}

// rwHidden collects "Type.Field" for every string (or string in a list) of v
// that carries the redactor's marker, and counts the strings that still hold
// the secret.
func rwHidden(v reflect.Value, typ string, got map[string]bool, leaked *[]string, path string) {
	switch v.Kind() {
	case reflect.String:
		s := v.String()
		if strings.Contains(s, rxFake) {
			*leaked = append(*leaked, path+": "+s)
		}
		if strings.Contains(s, "[hidden]") {
			got[typ] = true
		}
	case reflect.Pointer:
		if !v.IsNil() {
			rwHidden(v.Elem(), typ, got, leaked, path)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			rwHidden(v.Index(i), typ, got, leaked, path)
		}
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			rwHidden(it.Value(), typ, got, leaked, path)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			rwHidden(v.Field(i), t.Name()+"."+t.Field(i).Name, got, leaked, path+"."+t.Field(i).Name)
		}
	}
}

// rwFillThreatModel puts the secret in every free-text spot of the threat model.
func rwFillThreatModel(m map[string]any) {
	s := rwSecret
	m["summary"], m["prompt_version"] = s, s
	obj(m["generator"])["tool"], obj(m["generator"])["model"] = s, s
	obj(m["scope"])["assumptions"] = []any{s}
	m["open_questions"], m["limits"] = []any{s}, []any{s}
	sy := sys(m)
	for _, c := range arr(sy["components"]) {
		c := obj(c)
		c["name"], c["description"], c["tech"] = s, s, []any{s}
		if ps, ok := c["paths"]; ok {
			for _, p := range arr(ps) {
				obj(p)["needle"] = s
			}
		}
	}
	for _, z := range arr(sy["zones"]) {
		obj(z)["name"], obj(z)["description"] = s, s
	}
	for _, a := range arr(sy["actors"]) {
		obj(a)["name"] = s
	}
	for _, a := range arr(sy["assets"]) {
		obj(a)["name"], obj(a)["data_classes"] = s, []any{s}
	}
	for _, e := range arr(sy["entry_points"]) {
		obj(obj(e)["ref"])["needle"] = s
	}
	for _, f := range arr(sy["flows"]) {
		obj(f)["protocol"] = s
	}
	for _, th := range arr(m["threats"]) {
		th := obj(th)
		th["title"], th["description"] = s, s
		for _, mit := range arr(orNil(th["existing"])) {
			obj(mit)["text"] = s
			for _, r := range arr(orNil(obj(mit)["refs"])) {
				obj(r)["needle"] = s
			}
		}
		for _, mis := range arr(orNil(th["missing"])) {
			obj(mis)["text"], obj(mis)["control"] = s, s
			for _, r := range arr(orNil(obj(mis)["refs"])) {
				obj(r)["needle"] = s
			}
		}
		if ac, ok := th["abuse_case"]; ok {
			obj(ac)["actor"], obj(ac)["goal"], obj(ac)["steps"] = s, s, []any{s}
		}
	}
	for _, n := range arr(m["no_threat"]) {
		obj(n)["reason"] = s
	}
	for _, tr := range arr(m["attack_trees"]) {
		obj(tr)["root"] = s
		for _, n := range arr(obj(tr)["nodes"]) {
			obj(n)["label"] = s
		}
	}
	m["a key "+rxFake] = 1 // an unknown key, listed among the ignored ones
}

// rwFillPentest puts the secret in every free-text spot of the pen test.
func rwFillPentest(m map[string]any) {
	s := rwSecret
	m["summary"], m["prompt_version"] = s, s
	obj(m["generator"])["tool"], obj(m["generator"])["model"] = s, s
	obj(m["method"])["standard"] = s
	m["exercise"] = map[string]any{"objective": s, "chain": []any{map[string]any{"step": s, "finding": "F-1", "result": "achieved", "stop": s}}}
	m["limits"] = []any{s}
	tg := obj(m["target"])
	tg["url"] = s
	st := obj(tg["start"])
	st["argv"], st["source"] = []any{s}, s
	obj(st["health"])["path"] = s
	for _, a := range arr(tg["accounts"]) {
		obj(a)["label"], obj(a)["role"] = s, s
	}
	for _, c := range arr(m["coverage"]) {
		obj(c)["reason"], obj(c)["notes"] = s, s
	}
	for _, f := range arr(m["findings"]) {
		f := obj(f)
		f["title"], f["route"], f["impact"], f["fix"] = s, s, s, s
		for _, r := range arr(obj(f["where"])["refs"]) {
			obj(r)["needle"] = s
		}
		f["reproduction"] = []any{map[string]any{"step": s, "request": map[string]any{
			"method": "POST", "path": "/p?k=" + rxFake, "body": s,
			"headers": []any{map[string]any{"name": "Accept", "value": s}},
		}}}
		f["indicator"] = map[string]any{"attack": "p2", "control": "p1", "when": map[string]any{
			"status": 200, "body_contains": []any{s}, "body_not_contains": []any{s},
			"header_present": []any{"X-Probe"}, "header_absent": []any{"X-Other"},
			"header_contains": []any{map[string]any{"name": "Accept", "value": s}},
		}}
	}
	m["a key "+rxFake] = 1
}

// orNil lets a missing list range as empty.
func orNil(v any) any {
	if v == nil {
		return []any{}
	}
	return v
}

func TestValidatorRedactsEveryFreeTextFieldWhenStoring(t *testing.T) {
	tests := []struct {
		name string
		c    Contract
		doc  string
		fill func(map[string]any)
		root reflect.Type
	}{
		{"threat model", ContractThreatModel, baseThreatModel, rwFillThreatModel, reflect.TypeOf(ThreatModelDoc{})},
		{"pen test", ContractPentest, basePentest, rwFillPentest, reflect.TypeOf(PentestDoc{})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := optsFor(tc.c)
			o.Exercise = tc.c == ContractPentest
			o.Redact = rxRedactor
			res := Validate(edit(t, tc.doc, tc.fill), o)
			if res.Report.State == ValidationInvalid {
				t.Fatalf("the filled model was refused: %+v", res.Report)
			}
			// Nothing of the stored result, as it would be written, holds the secret.
			stored, err := json.Marshal(res)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(stored), rxFake) {
				i := strings.Index(string(stored), rxFake)
				lo := i - 80
				if lo < 0 {
					lo = 0
				}
				t.Errorf("the stored result holds the secret: ...%s...", stored[lo:i+len(rxFake)+40])
			}
			// Every free-text field of the model types was filled and came out hidden.
			want := map[string]bool{}
			rwFreeFields(tc.root, map[reflect.Type]bool{}, want)
			got := map[string]bool{}
			var leaked []string
			doc := reflect.ValueOf(res.TM)
			if tc.c == ContractPentest {
				doc = reflect.ValueOf(res.PT)
			}
			rwHidden(doc, tc.root.Name(), got, &leaked, tc.root.Name())
			rwHidden(reflect.ValueOf(res.Report), "Report", got, &leaked, "Report")
			if len(leaked) > 0 {
				t.Errorf("fields still hold the secret: %v", leaked)
			}
			var missing []string
			for f := range want {
				if !got[f] {
					missing = append(missing, f)
				}
			}
			sort.Strings(missing)
			if len(missing) > 0 {
				t.Errorf("free-text fields with no hidden value (the fixture does not fill them, or the validator does not redact them): %v", missing)
			}
			if !got["Report.IgnoredKeys"] {
				t.Error("the ignored key was not redacted")
			}
			names := make([]string, 0, len(want))
			for f := range want {
				names = append(names, f)
			}
			sort.Strings(names)
			t.Logf("%d free-text fields exercised: %s", len(names), strings.Join(names, " "))
			if len(want) < 15 {
				t.Errorf("only %d free-text fields found for %s: the reflection did not reach the model", len(want), tc.name)
			}
		})
	}
}

// TestKeysAreStoredAsWritten pins the other half of the claim: an id, a
// reference or a path is a key and is stored as the agent wrote it, not
// redacted (the redactor of this test would rewrite them).
func TestKeysAreStoredAsWritten(t *testing.T) {
	const idLike = "sk-live-FAKE0123456789abcd" // a valid item id that holds the test secret's start
	redact := func(s string) string { return strings.ReplaceAll(s, "sk-live-FAKE", "[hidden]") }
	o := optsFor(ContractThreatModel)
	o.Redact = redact
	doc := edit(t, baseThreatModel, func(m map[string]any) {
		c := arr(sys(m)["components"])[0]
		obj(c)["id"] = idLike
		obj(c)["name"] = "API " + idLike
		for _, th := range arr(m["threats"]) {
			if e := obj(obj(th)["element"]); e["id"] == "api" {
				e["id"] = idLike
			}
		}
		for _, f := range arr(sys(m)["flows"]) {
			f := obj(f)
			if f["to"] == "api" {
				f["to"] = idLike
			}
			if f["from"] == "api" {
				f["from"] = idLike
			}
		}
		for _, e := range arr(sys(m)["entry_points"]) {
			obj(e)["component"] = idLike
		}
	})
	res := Validate(doc, o)
	if res.TM == nil {
		t.Fatalf("refused: %+v", res.Report)
	}
	c := res.TM.System.Components[0]
	if c.ID != idLike || strings.Contains(c.Name, "sk-live-FAKE") {
		t.Errorf("component id %q name %q: the id is a key and stays, the name is text and is hidden", c.ID, c.Name)
	}
	if res.TM.Threats[0].Element.ID != idLike || res.TM.System.Flows[0].To != idLike {
		t.Errorf("references = %q %q", res.TM.Threats[0].Element.ID, res.TM.System.Flows[0].To)
	}
	if got := c.Paths[0].Path; got != "cmd/api/main.go" {
		t.Errorf("path = %q", got)
	}
}
