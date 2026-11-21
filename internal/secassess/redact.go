package secassess

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Redaction on the way out (plan W5a): what Observer shows or exports of a
// result passes the injected redactor, whatever the model of the day put in a
// string. The validator already redacts the free text it stores; this is the
// second pass, with the redactor in force when the answer is made (a pattern
// added since the run was checked still hides). The files in the project are as
// the agent wrote them and are not touched.
//
// What the pass does NOT rewrite is the model's own keys: the ids of items, the
// references one item makes to another (an element, a flow end, a zone, an
// actor, a component), the closed vocabulary words (a category, a status, a
// band) and project file paths. A key that is rewritten stops being the key:
// the secret scrubber matches inside ordinary words (the kebab-case
// "task-scheduler-service" holds a key-shaped run), so two different ids could
// collapse into one, the diagram would join the wrong boxes and a lookup would
// find the first of them. The agent's ids are limited to 48 letters, digits,
// dots, underscores and hyphens and its paths to project-relative paths, and
// neither is free text. redactKeep lists the fields, one row per type.

// redactKeep names, per type, the exported fields the display pass copies as
// they are. A field that is not listed is free text and is redacted: the
// default is to hide, so a field added later is covered until someone decides
// it is a key.
var redactKeep = map[reflect.Type][]string{
	reflect.TypeOf(Report{}):            {"State", "Contract", "Fatal", "Sets"},
	reflect.TypeOf(Issue{}):             {"Row", "Code", "Severity", "Path", "Item"},
	reflect.TypeOf(ThreatModelDoc{}):    {"Schema", "RunID"},
	reflect.TypeOf(Scope{}):             {"InScope", "OutOfScope"},
	reflect.TypeOf(Component{}):         {"ID", "Type", "Zone"},
	reflect.TypeOf(Ref{}):               {"Path"},
	reflect.TypeOf(Zone{}):              {"ID"},
	reflect.TypeOf(Actor{}):             {"ID", "Kind"},
	reflect.TypeOf(Asset{}):             {"ID", "Sensitivity", "StoredIn"},
	reflect.TypeOf(EntryPoint{}):        {"ID", "Component", "Kind", "Authn", "Exposure"},
	reflect.TypeOf(Flow{}):              {"ID", "From", "To", "Data", "Crosses", "Authn", "Encrypted"},
	reflect.TypeOf(Element{}):           {"Kind", "ID"},
	reflect.TypeOf(Missing{}):           {"Effort"},
	reflect.TypeOf(Threat{}):            {"ID", "Framework", "Category", "Element", "Actor", "Status", "CWE", "CAPEC", "ASVS"},
	reflect.TypeOf(NoThreat{}):          {"Element", "Category"},
	reflect.TypeOf(TreeNode{}):          {"ID", "Parent", "Op"},
	reflect.TypeOf(PentestDoc{}):        {"Schema", "RunID"},
	reflect.TypeOf(PTCoverageClaim{}):   {"Category", "Status", "Probes"},
	reflect.TypeOf(PTFinding{}):         {"ID", "Category", "CWE", "CVSS", "Basis", "Evidence", "Status"},
	reflect.TypeOf(PTIndicator{}):       {"Control", "Attack"},
	reflect.TypeOf(PTChainStep{}):       {"Finding", "Result"},
	reflect.TypeOf(RetestDoc{}):         {"Schema", "RunID"},
	reflect.TypeOf(RTResult{}):          {"Finding", "Result", "Attack", "Control", "Evidence"},
	reflect.TypeOf(PTHeader{}):          {"Name"},
	reflect.TypeOf(PTRequest{}):         {"Method"},
	reflect.TypeOf(PTMatch{}):           {"HeaderPresent", "HeaderAbsent"},
	reflect.TypeOf(EvidenceReport{}):    {"Mode", "Helper", "Log"},
	reflect.TypeOf(ProbeRecord{}):       {"ID", "TS", "Role", "WSTG", "Refused", "Replay"},
	reflect.TypeOf(ProbeHeader{}):       {"N"},
	reflect.TypeOf(CoverageRow{}):       {"Kind", "ID", "Class", "Cells"},
	reflect.TypeOf(FrameworkCoverage{}): {"Framework"},
	reflect.TypeOf(PTCoverageRow{}):     {"Category", "Title", "Agent", "Effective"},
	reflect.TypeOf(DiffItem{}):          {"ID", "Element", "Category", "Band"},
	reflect.TypeOf(DiffChange{}):        {"ID", "PrevID", "Element", "Category", "Match", "FromBand", "ToBand", "FromStatus", "ToStatus"},
	reflect.TypeOf(DiffSimilar{}):       {"ID", "PrevID", "Element", "Category", "PrevCategory", "FromBand", "ToBand", "Basis"},
	reflect.TypeOf(ModelDiff{}):         {"PrevRun", "Note"},
}

// redactKept reports whether the display pass leaves field of type t as it is.
func redactKept(t reflect.Type, field string) bool {
	for _, f := range redactKeep[t] {
		if f == field {
			return true
		}
	}
	return false
}

// redactKeepProblems checks the table against the types it names: every type
// is a struct and every field exists and is exported. It returns one line per
// problem (the table's test fails on any).
func redactKeepProblems() []string {
	var out []string
	types := make([]reflect.Type, 0, len(redactKeep))
	for t := range redactKeep {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return types[i].String() < types[j].String() })
	for _, t := range types {
		if t.Kind() != reflect.Struct {
			out = append(out, fmt.Sprintf("%s is not a struct", t))
			continue
		}
		for _, name := range redactKeep[t] {
			f, ok := t.FieldByName(name)
			if !ok || !f.IsExported() {
				out = append(out, fmt.Sprintf("%s has no exported field %s", t, name))
			}
		}
	}
	return out
}

// RedactResult returns a deep copy of res with every string value passed
// through redact, and how many string values the redactor changed. A nil
// redact returns res itself and 0. res is never modified.
//
// The walk is by reflection over every exported field, so a field added to the
// model later is reached without a change here (redact_test.go fills every
// string of a result and fails when one survives). Four things are left as they
// are: empty strings (nothing to hide, and the redactor is not called), the
// keys of a map (Observer's own words: the names of the counts and of the
// frameworks), the fields tagged computed:"true", which are Observer's own
// computation (a band, a reference state), and the fields listed in redactKeep:
// ids, references between items, vocabulary words and project paths.
func RedactResult(res Result, redact func(string) string) (Result, int) {
	return RedactValue(res, redact)
}

// RedactMarkerPrefix begins every marker the redactor leaves where it hid a
// secret: "[REDACTED]", or "[REDACTED:<type>]" when it names the kind.
const RedactMarkerPrefix = "[REDACTED"

// CountRedactionMarkers is how many markers of hidden secrets the strings of v
// hold, counted over the strings the display pass walks (the model's keys are
// not walked). It counts what a reader of the text can find by searching, which
// is more than what the display pass itself hid when the copy was already
// redacted as it was stored; an export says both so that "none hidden" is never
// read next to a text full of markers. v is never modified.
func CountRedactionMarkers[T any](v T) int {
	n := 0
	RedactValue(v, func(s string) string {
		n += strings.Count(s, RedactMarkerPrefix)
		return s
	})
	return n
}

// RedactValue is RedactResult for any value built of structs, slices, maps,
// pointers and strings (a comparison of two models, say): a deep copy with
// every string passed through redact, and how many it changed. A nil redact
// returns v itself and 0, and so does a nil interface value. v is never
// modified. v must not hold a pointer cycle (a decoded or validated model never
// does).
func RedactValue[T any](v T, redact func(string) string) (T, int) {
	rv := reflect.ValueOf(v)
	if redact == nil || !rv.IsValid() {
		return v, 0
	}
	w := redactWalk{redact: redact}
	out, _ := w.clone(rv, true).Interface().(T)
	return out, w.changed
}

// redactWalk is one deep copy: the redactor and the count of strings it
// changed.
type redactWalk struct {
	redact  func(string) string
	changed int
}

// clone returns a deep copy of v. With on set, every string in it goes through
// the redactor; with on clear it is copied as it is.
func (w *redactWalk) clone(v reflect.Value, on bool) reflect.Value {
	t := v.Type()
	switch v.Kind() {
	case reflect.String:
		s := v.String()
		if on && s != "" {
			if r := w.redact(s); r != s {
				s = r
				w.changed++
			}
		}
		out := reflect.New(t).Elem()
		out.SetString(s)
		return out
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.New(t.Elem())
		out.Elem().Set(w.clone(v.Elem(), on))
		return out
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.New(t).Elem()
		out.Set(w.clone(v.Elem(), on))
		return out
	case reflect.Slice:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.MakeSlice(t, v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(w.clone(v.Index(i), on))
		}
		return out
	case reflect.Array:
		out := reflect.New(t).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(w.clone(v.Index(i), on))
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return reflect.Zero(t)
		}
		out := reflect.MakeMapWithSize(t, v.Len())
		for it := v.MapRange(); it.Next(); {
			out.SetMapIndex(it.Key(), w.clone(it.Value(), on))
		}
		return out
	case reflect.Struct:
		// The shallow copy carries any unexported field; the exported ones are
		// then replaced by their deep copies.
		out := reflect.New(t).Elem()
		out.Set(v)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			out.Field(i).Set(w.clone(v.Field(i), on && f.Tag.Get("computed") != "true" && !redactKept(t, f.Name)))
		}
		return out
	}
	out := reflect.New(t).Elem()
	out.Set(v)
	return out
}
