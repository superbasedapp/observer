package secassess

import (
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

const (
	// rxFake is a made-up secret; the redactor of these tests knows only it.
	rxFake = "sk-live-FAKE0123456789abcdef"
	// rxKeep fills the computed fields and the kept ones (ids, references,
	// vocabulary words, paths), which RedactResult must leave alone.
	rxKeep = "computed-value-kept"
)

// rxRedactor hides rxFake.
func rxRedactor(s string) string { return strings.ReplaceAll(s, rxFake, "[hidden]") }

// rxFixed reports whether the display pass leaves a field alone: computed by
// Observer, or listed as a key in redactKeep.
func rxFixed(t reflect.Type, f reflect.StructField) bool {
	return f.Tag.Get("computed") == "true" || redactKept(t, f.Name)
}

// rxFiller fills every field of a value by reflection: a string holding the
// fake secret (rxKeep in a computed field), two elements in a slice, one entry
// in a map, a pointer that points. It counts the strings it put the secret in,
// so the test knows how many values the redactor has to change.
type rxFiller struct{ secrets int }

func (f *rxFiller) fill(t *testing.T, v reflect.Value, computed bool) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		if computed {
			v.SetString(rxKeep)
			return
		}
		v.SetString("before " + rxFake + " after")
		f.secrets++
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		f.fill(t, v.Elem(), computed)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 2, 2)
		for i := 0; i < 2; i++ {
			f.fill(t, s.Index(i), computed)
		}
		v.Set(s)
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			t.Fatalf("a map with the key type %s: extend the filler", v.Type().Key())
		}
		m := reflect.MakeMap(v.Type())
		elem := reflect.New(v.Type().Elem()).Elem()
		f.fill(t, elem, computed)
		m.SetMapIndex(reflect.ValueOf("key").Convert(v.Type().Key()), elem)
		v.Set(m)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !v.Type().Field(i).IsExported() {
				t.Fatalf("%s has an unexported field %s: extend the filler", v.Type(), v.Type().Field(i).Name)
			}
			f.fill(t, v.Field(i), computed || rxFixed(v.Type(), v.Type().Field(i)))
		}
	case reflect.Int, reflect.Int64:
		v.SetInt(7)
	case reflect.Float64:
		v.SetFloat(7)
	case reflect.Bool:
		v.SetBool(true)
	default:
		t.Fatalf("a field of the kind %s: extend the filler", v.Kind())
	}
}

// rxFilled returns a fully populated result and the number of strings that
// hold the fake secret.
func rxFilled(t *testing.T) (Result, int) {
	t.Helper()
	var res Result
	f := &rxFiller{}
	f.fill(t, reflect.ValueOf(&res).Elem(), false)
	return res, f.secrets
}

// rxScan walks a value and reports what it finds: the paths of strings in a
// non-computed field that still hold the fake secret, the paths of computed
// strings that are not the kept value, the paths of strings that are empty
// (the filler missed them) and the number of non-computed strings it saw.
type rxScan struct {
	secret, changedComputed, empty []string
	strings                        int
}

func (s *rxScan) walk(v reflect.Value, computed bool, path string) {
	switch v.Kind() {
	case reflect.String:
		str := v.String()
		switch {
		case str == "":
			s.empty = append(s.empty, path)
		case computed && str != rxKeep:
			s.changedComputed = append(s.changedComputed, path)
		case !computed:
			s.strings++
			if strings.Contains(str, rxFake) {
				s.secret = append(s.secret, path)
			}
		}
	case reflect.Pointer:
		if !v.IsNil() {
			s.walk(v.Elem(), computed, path)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			s.walk(v.Index(i), computed, path+"[]")
		}
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			s.walk(it.Value(), computed, path+"{}")
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			s.walk(v.Field(i), computed || rxFixed(v.Type(), f), path+"."+f.Name)
		}
	}
}

func rxScanOf(res Result) *rxScan {
	s := &rxScan{}
	s.walk(reflect.ValueOf(res), false, "Result")
	return s
}

// TestRedactResultReachesEveryString fills every string field of a result with
// a fake secret and fails when one survives, so a field added to the model
// later and not reached by the walk is caught here.
func TestRedactResultReachesEveryString(t *testing.T) {
	res, secrets := rxFilled(t)

	before := rxScanOf(res)
	if len(before.empty) > 0 {
		t.Fatalf("the filler missed the strings %v", before.empty)
	}
	if len(before.secret) != secrets || before.strings != secrets {
		t.Fatalf("the filler put the secret in %d strings, the scan sees %d of %d", secrets, len(before.secret), before.strings)
	}
	if secrets < 100 {
		t.Fatalf("only %d strings were filled; the filler does not reach the model", secrets)
	}

	out, n := RedactResult(res, rxRedactor)
	after := rxScanOf(out)
	if len(after.secret) > 0 {
		t.Errorf("the secret survived in %d strings: %v", len(after.secret), after.secret)
	}
	if len(after.changedComputed) > 0 {
		t.Errorf("computed fields were changed: %v", after.changedComputed)
	}
	if len(after.empty) > 0 {
		t.Errorf("strings became empty: %v", after.empty)
	}
	if n != secrets {
		t.Errorf("RedactResult counted %d changed strings, want %d", n, secrets)
	}
	if after.strings != before.strings {
		t.Errorf("the copy holds %d strings, the original %d", after.strings, before.strings)
	}
}

// TestRedactResultComputedFieldsExist pins that the completeness test above
// covers the computed skip: the model does tag strings as computed.
func TestRedactResultComputedFieldsExist(t *testing.T) {
	res, _ := rxFilled(t)
	if res.TM.Threats[0].Band != rxKeep || res.TM.Threats[0].Title == rxKeep {
		t.Errorf("the filler does not tell computed and plain fields apart: band %q", res.TM.Threats[0].Band)
	}
	if res.PT.Findings[0].Band != rxKeep || res.TM.System.Components[0].Paths[0].State != rxKeep {
		t.Errorf("computed strings are not filled with the kept value")
	}
	out, _ := RedactResult(res, func(string) string { return "rewritten" })
	if out.TM.Threats[0].Band != rxKeep || out.TM.System.Components[0].Paths[0].State != RefState(rxKeep) {
		t.Errorf("a redactor that rewrites everything changed a computed field: %q %q",
			out.TM.Threats[0].Band, out.TM.System.Components[0].Paths[0].State)
	}
	if out.TM.Threats[0].ID != rxKeep || out.TM.Threats[0].Element.ID != rxKeep || out.TM.System.Components[0].Zone != rxKeep {
		t.Errorf("a redactor that rewrites everything changed a key: id %q element %q zone %q",
			out.TM.Threats[0].ID, out.TM.Threats[0].Element.ID, out.TM.System.Components[0].Zone)
	}
	if out.TM.Threats[0].Title != "rewritten" || out.Report.Issues[0].Message != "rewritten" || out.Report.IgnoredKeys[0] != "rewritten" {
		t.Errorf("a plain string was not rewritten: %q %q %q", out.TM.Threats[0].Title, out.Report.Issues[0].Message, out.Report.IgnoredKeys[0])
	}
}

// TestRedactResultLeavesTheInputAlone checks that res is not modified and that
// the copy shares no slice, map or pointer with it.
func TestRedactResultLeavesTheInputAlone(t *testing.T) {
	res, _ := rxFilled(t)
	pristine, _ := rxFilled(t)

	out, _ := RedactResult(res, rxRedactor)
	if !reflect.DeepEqual(res, pristine) {
		t.Fatal("RedactResult changed its input")
	}

	// Writing through the copy must not reach the input.
	out.TM.Threats[0].Title = "changed"
	out.TM.Threats[0].Existing[0].Refs[0].Path = "changed"
	out.TM.System.Components[0].Tech[0] = "changed"
	out.TM.System.EntryPoints[0].Ref.Path = "changed"
	out.PT.Findings[1].Where.Refs[0].Needle = "changed"
	out.PT.Target.Start.Argv[0] = "changed"
	out.Report.Issues[0].Message = "changed"
	out.Report.IgnoredKeys[0] = "changed"
	out.Report.Counts["added"] = Count{}
	for k := range out.Report.Counts {
		delete(out.Report.Counts, k)
	}
	out.Report.PT.Rows[0].Reason = "changed"
	out.Report.PT.Counts["added"] = 1
	out.Report.TM.AIThreats["added"] = 1
	out.Report.TM.Rows[0].Cells[0].Category = "changed"
	if !reflect.DeepEqual(res, pristine) {
		t.Error("the copy shares memory with the input")
	}
}

// TestRedactResultCount pins what counts as a changed string.
func TestRedactResultCount(t *testing.T) {
	build := func() Result {
		return Result{
			Report: Report{
				State:       ValidationPartial,
				Issues:      []Issue{{Row: "V1", Code: "x", Message: "alpha one"}, {Row: "V2", Code: "y", Message: "plain"}},
				IgnoredKeys: []string{"alpha", "beta"},
			},
			TM: &ThreatModelDoc{Summary: "alpha alpha", Limits: []string{"", "alpha"}},
		}
	}
	tests := []struct {
		name     string
		redact   func(string) string
		want     int
		wantSumm string
	}{
		{"only strings the redactor changes are counted", func(s string) string { return strings.ReplaceAll(s, "alpha", "A") }, 4, "A A"},
		{"an identity redactor changes nothing", func(s string) string { return s }, 0, "alpha alpha"},
		{"a redactor that rewrites everything counts every non-empty string of text (a state and a code are keys)", func(string) string { return "X" }, 6, "X"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := build()
			out, n := RedactResult(res, tc.redact)
			if n != tc.want {
				t.Errorf("changed = %d, want %d", n, tc.want)
			}
			if out.TM.Summary != tc.wantSumm {
				t.Errorf("summary = %q, want %q", out.TM.Summary, tc.wantSumm)
			}
			if !reflect.DeepEqual(res, build()) {
				t.Error("the input was modified")
			}
		})
	}
}

// TestRedactResultEmptyStringsAreNotRedacted pins that the redactor is never
// called with an empty string.
func TestRedactResultEmptyStringsAreNotRedacted(t *testing.T) {
	res := Result{TM: &ThreatModelDoc{Summary: "", Limits: []string{"", ""}}, Report: Report{Issues: []Issue{{}}}}
	calls := 0
	out, n := RedactResult(res, func(s string) string {
		calls++
		return "X"
	})
	if calls != 0 || n != 0 {
		t.Errorf("the redactor was called %d times and %d strings changed; want none", calls, n)
	}
	if !reflect.DeepEqual(out, res) {
		t.Errorf("a result of empty strings changed: %+v", out)
	}
}

// TestRedactResultNilRedactor pins that a nil redactor returns the result as it
// is.
func TestRedactResultNilRedactor(t *testing.T) {
	res, _ := rxFilled(t)
	out, n := RedactResult(res, nil)
	if n != 0 {
		t.Errorf("changed = %d with no redactor", n)
	}
	if !reflect.DeepEqual(out, res) {
		t.Error("a nil redactor changed the result")
	}
}

// TestRedactResultKeepsNilsNil pins that the copy tells nil from empty as the
// original does, so a nil slice or map does not turn into an empty one that
// encodes differently.
func TestRedactResultKeepsNilsNil(t *testing.T) {
	zero, n := RedactResult(Result{}, func(string) string { return "X" })
	if n != 0 || !reflect.DeepEqual(zero, Result{}) {
		t.Errorf("the zero result changed: %+v (%d)", zero, n)
	}
	if zero.TM != nil || zero.PT != nil || zero.Report.Issues != nil || zero.Report.Counts != nil || zero.Report.IgnoredKeys != nil || zero.Report.TM != nil {
		t.Errorf("a nil became non-nil: %+v", zero)
	}

	res := Result{
		Report: Report{Issues: []Issue{}, Counts: map[string]Count{}, IgnoredKeys: nil},
		TM:     &ThreatModelDoc{Threats: nil, NoThreat: []NoThreat{}, Scope: Scope{InScope: nil, OutOfScope: []string{}}},
	}
	out, _ := RedactResult(res, func(string) string { return "X" })
	switch {
	case out.Report.Issues == nil || len(out.Report.Issues) != 0:
		t.Errorf("an empty slice became %#v", out.Report.Issues)
	case out.Report.Counts == nil || len(out.Report.Counts) != 0:
		t.Errorf("an empty map became %#v", out.Report.Counts)
	case out.Report.IgnoredKeys != nil:
		t.Errorf("a nil slice became %#v", out.Report.IgnoredKeys)
	case out.TM.Threats != nil:
		t.Errorf("a nil slice in the model became %#v", out.TM.Threats)
	case out.TM.NoThreat == nil || out.TM.Scope.OutOfScope == nil:
		t.Error("an empty slice in the model became nil")
	case out.TM.Scope.InScope != nil:
		t.Errorf("a nil slice in a nested struct became %#v", out.TM.Scope.InScope)
	}
}

// TestRedactResultMapKeysAndComputedFields pins the two things the walk leaves
// as they are: a map's keys and the computed fields.
func TestRedactResultMapKeysAndComputedFields(t *testing.T) {
	res := Result{
		Report: Report{
			Counts: map[string]Count{"threats": {Read: 1, Kept: 1}},
			TM:     &TMCoverage{AIThreats: map[string]int{"owasp_llm": 1}},
			PT:     &PTCoverage{Counts: map[string]int{CovSkipped: 2}},
		},
		TM: &ThreatModelDoc{
			System: System{Components: []Component{{ID: "c", Paths: []Ref{{Path: "a/b.go", Needle: "in a/b.go", State: RefFound, MatchLine: 3}}}}},
			Threats: []Threat{
				{ID: "T-1", Band: BandHigh, Score: 12},
			},
		},
	}
	redact := func(s string) string {
		return strings.NewReplacer("threats", "X", "owasp_llm", "X", "skipped", "X", "found", "X", "high", "X", "a/b.go", "HIDDEN").Replace(s)
	}
	out, n := RedactResult(res, redact)
	if _, ok := out.Report.Counts["threats"]; !ok {
		t.Errorf("a map key was rewritten: %v", out.Report.Counts)
	}
	if _, ok := out.Report.TM.AIThreats["owasp_llm"]; !ok {
		t.Errorf("a map key was rewritten: %v", out.Report.TM.AIThreats)
	}
	if _, ok := out.Report.PT.Counts[CovSkipped]; !ok {
		t.Errorf("a map key was rewritten: %v", out.Report.PT.Counts)
	}
	ref := out.TM.System.Components[0].Paths[0]
	if ref.Path != "a/b.go" || ref.Needle != "in HIDDEN" || ref.State != RefFound || ref.MatchLine != 3 {
		t.Errorf("reference = %+v, want the path kept (a key), the quoted text hidden and the computed state and line kept", ref)
	}
	if th := out.TM.Threats[0]; th.Band != BandHigh || th.Score != 12 {
		t.Errorf("threat = %+v, want the computed band and score kept", th)
	}
	if n != 1 {
		t.Errorf("changed = %d, want 1 (the quoted text)", n)
	}
}

// TestRedactResultOfAValidation runs the walk over a result the validator
// made, with a redactor that hides a phrase in the model and in the report.
func TestRedactResultOfAValidation(t *testing.T) {
	res := rdValidated(t, ContractThreatModel, baseThreatModel, func(m map[string]any) {
		threat(m, 0)["description"] = "The login holds " + rxFake + " in a field."
	})
	if res.TM == nil {
		t.Fatalf("the model was refused: %+v", res.Report)
	}
	// The validator's own redactor was nil, so the secret is in the result.
	if !strings.Contains(res.TM.Threats[0].Description, rxFake) {
		t.Fatalf("the fixture lost its secret: %q", res.TM.Threats[0].Description)
	}
	out, n := RedactResult(res, rxRedactor)
	if n != 1 {
		t.Errorf("changed = %d, want 1", n)
	}
	if got := out.TM.Threats[0].Description; got != "The login holds [hidden] in a field." {
		t.Errorf("description = %q", got)
	}
	if !strings.Contains(res.TM.Threats[0].Description, rxFake) {
		t.Error("the input lost its text")
	}
	if out.Report.TM == nil || len(out.Report.TM.Rows) != len(res.Report.TM.Rows) {
		t.Errorf("the coverage rows were not copied: %+v", out.Report.TM)
	}
}

// TestRedactValue: the generic form reaches every string of a comparison of two
// models (titles and element names), copies, counts, and leaves a nil redactor
// and the input alone.
func TestRedactValue(t *testing.T) {
	// Split so the public tree carries no push-protection-shaped literal.
	const secret = "ghp_" + "0123456789abcdef0123456789abcdef0123"
	redact := func(s string) string { return strings.ReplaceAll(s, secret, "[REDACTED]") }
	in := ModelDiff{
		PrevRun: "run1",
		Added:   []DiffItem{{ID: "T-1", Title: "uses " + secret, Element: Element{Kind: "flow", ID: "f1"}}},
		Changed: []DiffChange{{ID: "T-2", Title: "plain", Element: Element{Kind: "component", ID: "c1"}}},
		System:  SystemDiff{Components: NameDiff{Added: []string{secret}}},
	}
	out, n := RedactValue(in, redact)
	if n != 2 {
		t.Fatalf("changed %d strings, want 2", n)
	}
	blob, _ := json.Marshal(out)
	if strings.Contains(string(blob), secret) {
		t.Fatalf("a secret survived: %s", blob)
	}
	if !strings.Contains(in.Added[0].Title, secret) || !strings.Contains(in.System.Components.Added[0], secret) {
		t.Fatal("the input was modified")
	}
	if same, n := RedactValue(in, nil); n != 0 || !reflect.DeepEqual(same, in) {
		t.Fatalf("a nil redactor changed something: %d", n)
	}
}

// TestRedactKeepTable: every row of the keep table names a struct and exported
// fields that exist, so a renamed field cannot silently stop being a key.
func TestRedactKeepTable(t *testing.T) {
	if p := redactKeepProblems(); len(p) > 0 {
		t.Fatalf("the keep table is out of step with the types: %v", p)
	}
	if redactKept(reflect.TypeOf(Threat{}), "Title") || !redactKept(reflect.TypeOf(Threat{}), "ID") {
		t.Error("the title of a threat is text and its id is a key")
	}
	bad := map[reflect.Type][]string{reflect.TypeOf(Threat{}): {"Missing", "Nope"}}
	saved := redactKeep
	defer func() { redactKeep = saved }()
	redactKeep = bad
	if p := redactKeepProblems(); len(p) != 1 {
		t.Errorf("a field that does not exist (or an unexported one) must be reported once: %v", p)
	}
}

// TestRedactKeepsKeysWhenARedactorMatchesInsideThem: a redactor that rewrites
// anything of the shape of the secret scrubber's key prefix (sk-, pk-, ak- then
// sixteen id characters, with no word boundary) must not merge two ids that
// share a kebab-case prefix: ids, references, vocabulary words and paths come
// out as they went in, and only the text is hidden.
func TestRedactKeepsKeysWhenARedactorMatchesInsideThem(t *testing.T) {
	hide := regexp.MustCompile(`(?i)(?:sk|pk|ak)[_-][A-Za-z0-9_-]{16,}`)
	redact := func(s string) string { return hide.ReplaceAllString(s, "[REDACTED:api_key_prefixed]") }
	const idA, idB = "task-queue-worker-alpha-one", "task-queue-worker-alpha-two"
	const path = "src/disk-encryption-layer.go"
	if redact(idA) == idA || redact(idA) != redact(idB) {
		t.Fatalf("the test redactor does not collapse the two ids: %q %q", redact(idA), redact(idB))
	}
	res := Result{TM: &ThreatModelDoc{
		System: System{
			Components: []Component{
				{ID: idA, Name: "Worker " + idA, Zone: "z-task-queue-worker-zone", Paths: []Ref{{Path: path, Needle: "see " + idA}}},
				{ID: idB, Name: "Worker B"},
			},
			Flows: []Flow{{ID: "f1", From: idA, To: idB, Crosses: []string{"z-task-queue-worker-zone"}}},
		},
		Threats: []Threat{{ID: "T-" + idA, Title: "About " + idA, Element: Element{Kind: "component", ID: idA}}},
	}}
	out, n := RedactResult(res, redact)
	tm := out.TM
	if tm.System.Components[0].ID != idA || tm.System.Components[1].ID != idB {
		t.Errorf("component ids = %q %q", tm.System.Components[0].ID, tm.System.Components[1].ID)
	}
	if f := tm.System.Flows[0]; f.From != idA || f.To != idB || f.Crosses[0] != "z-task-queue-worker-zone" {
		t.Errorf("flow = %+v", f)
	}
	if th := tm.Threats[0]; th.ID != "T-"+idA || th.Element.ID != idA {
		t.Errorf("threat = %+v", th)
	}
	if got := tm.System.Components[0].Paths[0].Path; got != path {
		t.Errorf("path = %q", got)
	}
	if tm.System.Components[0].Zone != "z-task-queue-worker-zone" {
		t.Errorf("zone = %q", tm.System.Components[0].Zone)
	}
	// The text is still hidden: the name, the needle and the title.
	if strings.Contains(tm.System.Components[0].Name, idA) || strings.Contains(tm.System.Components[0].Paths[0].Needle, idA) || strings.Contains(tm.Threats[0].Title, idA) {
		t.Errorf("text was not redacted: %q %q %q", tm.System.Components[0].Name, tm.System.Components[0].Paths[0].Needle, tm.Threats[0].Title)
	}
	if n != 3 {
		t.Errorf("changed = %d, want the 3 strings of text", n)
	}
}

// TestRedactValueOfNothing: a nil interface is returned as it is (reflecting on
// it would panic).
func TestRedactValueOfNothing(t *testing.T) {
	got, n := RedactValue[any](nil, func(string) string { return "X" })
	if got != nil || n != 0 {
		t.Errorf("RedactValue(nil) = %v, %d", got, n)
	}
}
