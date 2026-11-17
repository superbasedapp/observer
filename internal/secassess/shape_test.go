package secassess

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Tests of the shape pass of row V2 (shape.go): a lone value where a list
// belongs reads as a list of one, and a value of the wrong kind in an optional
// leaf field is left out (said, counted, the file kept) instead of refusing the
// file. What the pass must NOT touch stays fatal.

// shapeProbe is a struct with each field shape the pass rules on.
type shapeProbe struct {
	Ids   []string `json:"ids,omitempty" lone:"list"`
	Refs  []Ref    `json:"refs,omitempty" lone:"list"`
	Words []string `json:"words,omitempty"`
	Need  []string `json:"need" lone:"list"`
	Name  string   `json:"name,omitempty"`
	N     int      `json:"n,omitempty"`
	Small uint8    `json:"small,omitempty"`
	On    bool     `json:"on,omitempty"`
	F     float64  `json:"f,omitempty"`
	Must  string   `json:"must"`
	Sub   struct {
		X int `json:"x,omitempty"`
	} `json:"sub,omitempty"`
}

// shapeRun prunes a document against shapeProbe the way the validator does,
// decodes it the way the validator does and returns the result, the decode
// error and the issues the pass raised.
func shapeRun(t *testing.T, doc string) (shapeProbe, error, *validator) {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		t.Fatalf("fixture %s: %v", doc, err)
	}
	v := newValidator(nil, ValidateOptions{})
	v.prune(generic, reflect.TypeOf(shapeProbe{}), "")
	b, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("marshal %s: %v", doc, err)
	}
	var out shapeProbe
	err = json.Unmarshal(b, &out)
	return out, err, v
}

func TestShapePass(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want shapeProbe
		// issues is the codes the pass raised, in order, each with its path.
		issues []string
		// bad says the typed decode still refuses the file.
		bad bool
	}{
		// ---- a lone value where a list belongs ----
		{name: "a lone text is a list of one", doc: `{"ids":"p3","must":"m"}`, want: shapeProbe{Ids: []string{"p3"}, Must: "m"}},
		{name: "a lone empty text is a list of nothing", doc: `{"ids":"  ","must":"m"}`, want: shapeProbe{Ids: []string{}, Must: "m"}},
		{name: "a lone number reads as the text written", doc: `{"ids":7,"must":"m"}`, want: shapeProbe{Ids: []string{"7"}, Must: "m"}},
		{name: "a lone true reads as the text written", doc: `{"ids":true,"must":"m"}`, want: shapeProbe{Ids: []string{"true"}, Must: "m"}},
		{name: "a list keeps its texts", doc: `{"ids":["p1","p2"],"must":"m"}`, want: shapeProbe{Ids: []string{"p1", "p2"}, Must: "m"}},
		{name: "a number in a list reads as text", doc: `{"ids":["p1",2],"must":"m"}`, want: shapeProbe{Ids: []string{"p1", "2"}, Must: "m"}},
		{name: "a null entry is left out without a word", doc: `{"ids":["p1",null],"must":"m"}`, want: shapeProbe{Ids: []string{"p1"}, Must: "m"}},
		{
			name: "an object in a list of texts is left out and said", doc: `{"ids":["p1",{"a":1},["x"]],"must":"m"}`,
			want: shapeProbe{Ids: []string{"p1"}, Must: "m"}, issues: []string{"list_entries_dropped ids"},
		},
		{
			name: "an object where texts belong is left out and said", doc: `{"ids":{"a":1},"must":"m"}`,
			want: shapeProbe{Must: "m"}, issues: []string{"field_dropped ids"},
		},
		{name: "a lone object is a list of one reference", doc: `{"refs":{"path":"a.go","line":3},"must":"m"}`, want: shapeProbe{Refs: []Ref{{Path: "a.go", Line: 3}}, Must: "m"}},
		{
			name: "a text in a list of references is left out and said", doc: `{"refs":[{"path":"a.go"},"b.go:3"],"must":"m"}`,
			want: shapeProbe{Refs: []Ref{{Path: "a.go"}}, Must: "m"}, issues: []string{"list_entries_dropped refs"},
		},
		{name: "a lone text for a list of references is not a reference and still refuses", doc: `{"refs":"a.go:3","must":"m"}`, bad: true},
		{name: "a list with no lone tag reads no lone text", doc: `{"words":"one","must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped words"}},
		{name: "null is no value and no word", doc: `{"ids":null,"name":null,"n":null,"must":"m"}`, want: shapeProbe{Must: "m"}},
		// ---- a wrong kind in an optional leaf field ----
		{name: "a number where text belongs is left out", doc: `{"name":5,"must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped name"}},
		{name: "an object where text belongs is left out", doc: `{"name":{"a":1},"must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped name"}},
		{name: "a list where text belongs is left out", doc: `{"name":["a"],"must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped name"}},
		{name: "a text where a whole number belongs is left out", doc: `{"n":"12","must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped n"}},
		{name: "a fraction where a whole number belongs is left out", doc: `{"n":3.5,"must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped n"}},
		{name: "a whole number written as a float is read", doc: `{"n":3.0,"must":"m"}`, want: shapeProbe{N: 3, Must: "m"}},
		{name: "a number too large for its type is left out", doc: `{"small":300,"must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped small"}},
		{name: "a negative number for an unsigned type is left out", doc: `{"small":-1,"must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped small"}},
		{name: "a text where true or false belongs is left out", doc: `{"on":"true","must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped on"}},
		{name: "a text where a number belongs is left out", doc: `{"f":"1.5","must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped f"}},
		{name: "a number past a float's range is left out", doc: `{"f":1e999,"must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped f"}},
		{name: "two fields are left out and each is said", doc: `{"name":5,"on":"x","must":"m"}`, want: shapeProbe{Must: "m"}, issues: []string{"field_dropped name", "field_dropped on"}},
		{name: "the kinds that fit are read", doc: `{"name":"a","n":4,"small":9,"on":true,"f":1.5,"must":"m"}`, want: shapeProbe{Name: "a", N: 4, Small: 9, On: true, F: 1.5, Must: "m"}},
		// ---- what stays fatal ----
		{name: "a required text of the wrong kind still refuses the file", doc: `{"must":5}`, bad: true},
		{name: "a required list of the wrong kind still refuses the file", doc: `{"need":{"a":1},"must":"m"}`, bad: true},
		{name: "a required list read from a lone text is a list", doc: `{"need":"x","must":"m"}`, want: shapeProbe{Need: []string{"x"}, Must: "m"}},
		{name: "an optional object of the wrong kind is not a leaf and still refuses the file", doc: `{"sub":["a"],"must":"m"}`, bad: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err, v := shapeRun(t, c.doc)
			if (err != nil) != c.bad {
				t.Fatalf("decode error = %v, want an error: %v", err, c.bad)
			}
			if c.bad {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
			var issues []string
			for _, is := range v.rep.Issues {
				if is.Row != "V2" || is.Severity != SevDropped || is.Message == "" {
					t.Errorf("issue %+v is not a dropped V2 issue with a sentence", is)
				}
				issues = append(issues, is.Code+" "+is.Path)
			}
			if !reflect.DeepEqual(issues, c.issues) {
				t.Errorf("issues = %q, want %q", issues, c.issues)
			}
			if (v.shaped > 0) != (len(c.issues) > 0) {
				t.Errorf("shaped = %d with issues %q", v.shaped, c.issues)
			}
		})
	}
}

// TestShapePassPositions: the issue names the item's position in the file.
func TestShapePassPositions(t *testing.T) {
	doc := `{"results":[{"finding":"F-1","result":"reproduced"},{"finding":"F-2","result":"reproduced","attack":5,"note":{"a":1}}],"limits":[1,{"a":1}]}`
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	v := newValidator(nil, ValidateOptions{})
	v.prune(generic, reflect.TypeOf(RetestDoc{}), "")
	var got []string
	for _, is := range v.rep.Issues {
		got = append(got, is.Code+" "+is.Path)
	}
	want := []string{"list_entries_dropped limits", "field_dropped results[1].attack", "field_dropped results[1].note"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("issues = %q, want %q", got, want)
	}
}

// listField is a list field of a model struct the declaration test reads.
type listField struct {
	owner, json string
	typ         reflect.Type
	lone        bool
	optional    bool
}

// modelListFields walks the model structs a file is decoded into and lists
// every list of texts and every list of references, in a stable order. It does
// not enter a type that reads itself (lenient.go owns those) or a computed field.
func modelListFields(t *testing.T) []listField {
	t.Helper()
	var out []listField
	seen := map[reflect.Type]bool{}
	var walk func(rt reflect.Type)
	walk = func(rt reflect.Type) {
		rt = indirect(rt)
		if rt.Kind() == reflect.Slice {
			walk(rt.Elem())
			return
		}
		if rt.Kind() != reflect.Struct || seen[rt] || readsItself(rt) {
			return
		}
		seen[rt] = true
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if !f.IsExported() || name == "-" || f.Tag.Get("computed") == "true" {
				continue
			}
			if indirect(f.Type).Kind() == reflect.Slice {
				elem := indirect(indirect(f.Type).Elem())
				if elem.Kind() == reflect.String || elem == reflect.TypeOf(Ref{}) {
					out = append(out, listField{
						owner: rt.Name(), json: name, typ: f.Type, lone: f.Tag.Get("lone") == "list",
						optional: strings.Contains(","+opts+",", ",omitempty,"),
					})
				}
			}
			walk(f.Type)
		}
	}
	for _, root := range []any{ThreatModelDoc{}, PentestDoc{}, RetestDoc{}} {
		walk(reflect.TypeOf(root))
	}
	if len(out) < 20 {
		t.Fatalf("only %d list fields were found: the walk does not reach the model", len(out))
	}
	return out
}

// TestEveryListFieldChoosesLoneOrIsExcluded pins the table the shape pass reads
// (the tags): a list of texts or of references in a model struct either reads a
// lone value as a list of one (lone:"list") or is named in loneExcluded with
// the reason, never neither; a tagged field is an optional list of texts or
// references; an exclusion names a real field that is not tagged.
func TestEveryListFieldChoosesLoneOrIsExcluded(t *testing.T) {
	used := map[string]bool{}
	for _, f := range modelListFields(t) {
		key := f.owner + "." + f.json
		_, excluded := loneExcluded[key]
		switch {
		case f.lone && excluded:
			t.Errorf("%s is tagged lone:\"list\" and also excluded", key)
		case !f.lone && !excluded:
			t.Errorf("%s is a list that neither reads a lone value (tag lone:\"list\") nor is named in loneExcluded: choose", key)
		case f.lone && !f.optional:
			t.Errorf("%s is tagged lone:\"list\" but is not optional (omitempty): a required field's wrong shape stays fatal", key)
		}
		if excluded {
			used[key] = true
		}
	}
	for key, why := range loneExcluded {
		if !used[key] {
			t.Errorf("loneExcluded names %s, which is no list field of the model", key)
		}
		if strings.TrimSpace(why) == "" {
			t.Errorf("loneExcluded[%s] has no reason", key)
		}
	}
}

// TestEveryLoneListFieldReadsOneValueAsAList: for each declared list field, one
// lone value of the entry's own kind comes out as a list of one through the
// shape pass, whatever contract holds the field, and the pass raised no word.
func TestEveryLoneListFieldReadsOneValueAsAList(t *testing.T) {
	for _, f := range modelListFields(t) {
		if !f.lone {
			continue
		}
		t.Run(f.owner+"."+f.json, func(t *testing.T) {
			elem := indirect(indirect(f.typ).Elem())
			lone := any("one")
			if elem.Kind() == reflect.Struct {
				lone = map[string]any{"path": "a.go"}
			}
			v := newValidator(nil, ValidateOptions{})
			fi := fieldInfo{typ: f.typ, optional: f.optional, lone: true}
			got := v.shapeField(lone, fi, "x")
			list, ok := got.([]any)
			if !ok || len(list) != 1 || !reflect.DeepEqual(list[0], lone) {
				t.Fatalf("a lone %T read as %#v, want a list of that one value", lone, got)
			}
			if len(v.rep.Issues) != 0 || v.shaped != 0 {
				t.Errorf("a lone value raised %+v", v.rep.Issues)
			}
		})
	}
}

// TestLoneListInEveryContract: through Validate, the live defect in each
// contract that has a list of probe ids, and the same shape on the other list
// fields of the pen test and the threat model. The file is read, the lone value
// is a list of one, and no word is raised for the spelling.
func TestLoneListInEveryContract(t *testing.T) {
	t.Run("a pen test reads a lone evidence id, a lone cwe, a lone probe and a lone reference", func(t *testing.T) {
		doc := edit(t, basePentest, func(m map[string]any) {
			f := finding(m, 0)
			f["evidence"], f["cwe"] = "p1", "CWE-307"
			f["where"] = map[string]any{"refs": map[string]any{"path": "cmd/api/main.go", "line": 12, "needle": "func Login("}}
			obj(arr(m["coverage"])[0])["probes"] = "p1"
			m["limits"] = "Only the dev server."
		})
		r := Validate(doc, optsFor(ContractPentest))
		if r.Report.State == ValidationInvalid || r.PT == nil {
			t.Fatalf("refused: %s %s", r.Report.Fatal, issueCodes(r.Report))
		}
		if hasIssue(r.Report, "V2", "field_dropped") || hasIssue(r.Report, "V2", "list_entries_dropped") {
			t.Errorf("a lone value raised a word: %s", issueCodes(r.Report))
		}
		f := r.PT.Findings[0]
		if len(f.Evidence) != 1 || f.Evidence[0] != "p1" || len(f.CWE) != 1 || f.CWE[0] != "CWE-307" || len(f.Where.Refs) != 1 || f.Where.Refs[0].State != RefFound {
			t.Errorf("finding = %+v", f)
		}
		if got := r.PT.Coverage[0].Probes; len(got) != 1 || got[0] != "p1" {
			t.Errorf("probes = %v", got)
		}
		if len(r.PT.Limits) != 1 {
			t.Errorf("limits = %v", r.PT.Limits)
		}
	})
	t.Run("a red team file is the pen test's contract and reads the same", func(t *testing.T) {
		doc := edit(t, basePentest, func(m map[string]any) {
			finding(m, 0)["evidence"] = "p1"
			m["exercise"] = map[string]any{"objective": "Read user data", "chain": []any{map[string]any{"step": "Bypass sign-in", "finding": "F-1", "result": "achieved"}}}
		})
		o := optsFor(ContractPentest)
		o.Exercise = true
		r := Validate(doc, o)
		if r.Report.State == ValidationInvalid || r.PT == nil || len(r.PT.Findings[0].Evidence) != 1 {
			t.Fatalf("report %+v", r.Report)
		}
	})
	t.Run("a threat model reads lone ids, texts and references", func(t *testing.T) {
		doc := edit(t, baseThreatModel, func(m map[string]any) {
			s := obj(m["scope"])
			s["in_scope"], s["assumptions"] = "cmd/api", "Runs behind a proxy."
			asset := obj(arr(sys(m)["assets"])[0])
			asset["stored_in"] = "db"
			flow := obj(arr(sys(m)["flows"])[0])
			flow["data"], flow["crosses"] = "creds", "dmz"
			th := threat(m, 0)
			th["cwe"] = "CWE-307"
			obj(arr(th["missing"])[0])["refs"] = map[string]any{"path": "cmd/api/main.go", "line": 12, "needle": "func Login("}
			obj(th["abuse_case"])["steps"] = "Try leaked passwords"
			m["open_questions"], m["limits"] = "Is there an admin console?", "Read from code only."
		})
		r := Validate(doc, optsFor(ContractThreatModel))
		if r.Report.State == ValidationInvalid || r.TM == nil {
			t.Fatalf("refused: %s %s", r.Report.Fatal, issueCodes(r.Report))
		}
		if hasIssue(r.Report, "V2", "field_dropped") || hasIssue(r.Report, "V2", "list_entries_dropped") {
			t.Errorf("a lone value raised a word: %s", issueCodes(r.Report))
		}
		th := r.TM.Threats[0]
		if len(th.CWE) != 1 || len(th.Missing[0].Refs) != 1 || th.Missing[0].Refs[0].State != RefFound || len(th.AbuseCase.Steps) != 1 || len(r.TM.System.Flows[0].Crosses) != 1 {
			t.Errorf("threat = %+v", th)
		}
	})
	t.Run("a start command is not read from a lone text", func(t *testing.T) {
		doc := edit(t, basePentest, func(m map[string]any) {
			obj(obj(obj(m["target"])["start"]))["argv"] = "npm run dev"
		})
		r := Validate(doc, optsFor(ContractPentest))
		if got := r.PT; got != nil && len(got.Target.Start.Argv) != 0 {
			t.Errorf("argv = %v: a command line was read as one word", got.Target.Start.Argv)
		}
		if !hasIssue(r.Report, "V2", "field_dropped") {
			t.Errorf("the lone text for argv was not left out and said: %s", issueCodes(r.Report))
		}
	})
}

// TestRetestWrongKindOnOptionalFieldKeepsEveryLabel: one result's optional
// fields written in a kind the model does not ask for are left out and said;
// the file is read, partial, and every label is kept.
func TestRetestWrongKindOnOptionalFieldKeepsEveryLabel(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(r map[string]any)
		path string
	}{
		{"evidence as an object", func(r map[string]any) { r["evidence"] = map[string]any{"id": "p3"} }, "results[3].evidence"},
		{"the note as a list", func(r map[string]any) { r["note"] = []any{"a", "b"} }, "results[3].note"},
		{"the attack as a number", func(r map[string]any) { r["attack"] = 8 }, "results[3].attack"},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := liveRetestValidate(t, liveRetestFile(t, func(results []any) { c.edit(obj(results[3])) }))
			if r.Report.State != ValidationPartial || r.RT == nil || len(r.RT.Results) != 6 {
				t.Fatalf("state %s, results %v, issues %s", r.Report.State, r.RT != nil, issueCodes(r.Report))
			}
			var found bool
			for _, is := range r.Report.Issues {
				if is.Row == "V2" && is.Code == "field_dropped" && is.Severity == SevDropped && is.Path == c.path {
					found = true
				}
			}
			if !found {
				t.Errorf("no word at %s: %+v", c.path, r.Report.Issues)
			}
			if r.Report.RT == nil || r.Report.RT.Reproduced != 6 {
				t.Errorf("summary %+v", r.Report.RT)
			}
		})
	}
	t.Run("a result that is not an object still refuses the file", func(t *testing.T) {
		r := liveRetestValidate(t, liveRetestFile(t, func(results []any) { results[3] = "F-4 reproduced" }))
		if r.Report.State != ValidationInvalid || r.Report.Fatal != "bad_shape" {
			t.Errorf("state %s fatal %q", r.Report.State, r.Report.Fatal)
		}
	})
	t.Run("a finding that is not text still refuses the file", func(t *testing.T) {
		r := liveRetestValidate(t, liveRetestFile(t, func(results []any) { obj(results[3])["finding"] = 4 }))
		if r.Report.State != ValidationInvalid || r.Report.Fatal != "bad_shape" {
			t.Errorf("state %s fatal %q", r.Report.State, r.Report.Fatal)
		}
	})
}
