package secassess

import (
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The hostile model: every string field of a result is filled, by reflection,
// with its own hostile payload, the way redact_test.go reaches every string. The
// payload carries a canary that survives escaping (CNRY<n>X) around each of the
// ways a string can change a document: markup, an image, a script link, a table
// bar, and injected lines that would be a heading, a list item, a quote, an
// ordered item, a thematic break, a fence and a block of HTML if the newline
// that precedes each survived. The test then asserts, over the whole document,
// that no raw payload is in it, that every field that is printed is printed in
// its escaped form, and that no line starts a block Observer did not write.

// exPayload is the hostile text of the n-th string field.
func exPayload(n int) string {
	return fmt.Sprintf("CNRY%dX <script>alert(1)</script> ![x](http://e/x.png) [l](javascript:alert(1)) | a | \n"+
		"# INJH%d\n- INJL%d\n> INJQ%d\n1. INJO%d\n---\n```\n<div>INJD%d</div> www.e.com a@b.com _u_ *e* &amp; \"q\" {{t}} $m$",
		n, n, n, n, n, n)
}

// exFill fills every field of a value: a payload in each string, two elements
// in a slice, one entry in a map, a pointer that points, 7 in a number and
// true in a flag.
type exFill struct{ n int }

func (f *exFill) fill(t *testing.T, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.String:
		f.n++
		v.SetString(exPayload(f.n))
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		f.fill(t, v.Elem())
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 2, 2)
		for i := 0; i < 2; i++ {
			f.fill(t, s.Index(i))
		}
		v.Set(s)
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			t.Fatalf("a map with the key type %s: extend the filler", v.Type().Key())
		}
		m := reflect.MakeMap(v.Type())
		elem := reflect.New(v.Type().Elem()).Elem()
		f.fill(t, elem)
		m.SetMapIndex(reflect.ValueOf("key").Convert(v.Type().Key()), elem)
		v.Set(m)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !v.Type().Field(i).IsExported() {
				t.Fatalf("%s has an unexported field %s: extend the filler", v.Type(), v.Type().Field(i).Name)
			}
			f.fill(t, v.Field(i))
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

// exField is one string of the filled result with the path that reaches it.
type exField struct{ path, value string }

// exFields lists the strings of a value that hold a payload, with their paths
// (a slice is "[]" and a map is "{}", as in redact_test.go).
func exFields(v reflect.Value, path string, out *[]exField) {
	switch v.Kind() {
	case reflect.String:
		if strings.HasPrefix(v.String(), "CNRY") {
			*out = append(*out, exField{path, v.String()})
		}
	case reflect.Pointer:
		if !v.IsNil() {
			exFields(v.Elem(), path, out)
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			exFields(v.Index(i), path+"[]", out)
		}
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			exFields(it.Value(), path+"{}", out)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			exFields(v.Field(i), path+"."+v.Type().Field(i).Name, out)
		}
	}
}

// exNotRendered lists the string fields the Markdown export does not print, by
// path, each with the reason. The JSON export carries them all. The test fails
// when a field not on this list is missing from the document, and when a field
// on it is in the document after all, so the list cannot go stale in either
// direction and a field added to the model is noticed.
var exNotRendered = map[string]string{
	"Result.Report.Contract":                       "used only to choose the limits that apply",
	"Result.Report.Issues[].Item":                  "the key the web view puts a note on a finding's row by; the message names the finding",
	"Result.Report.TM.Rows[].Kind":                 "the per-element coverage cells are in the JSON export",
	"Result.Report.TM.Rows[].ID":                   "the per-element coverage cells are in the JSON export",
	"Result.Report.TM.Rows[].Name":                 "the per-element coverage cells are in the JSON export",
	"Result.Report.TM.Rows[].Class":                "the per-element coverage cells are in the JSON export",
	"Result.Report.TM.Rows[].Cells[].Category":     "the per-element coverage cells are in the JSON export",
	"Result.Report.TM.Rows[].Cells[].State":        "the per-element coverage cells are in the JSON export",
	"Result.Report.Sets.Frameworks[]":              "the sets in force are in the JSON export",
	"Result.Report.Sets.MethodExtras[]":            "the sets in force are in the JSON export",
	"Result.Report.Sets.Categories[]":              "the sets in force are in the JSON export",
	"Result.TM.Schema":                             "the document says what it is in its own words",
	"Result.TM.RunID":                              "the run id comes from the export metadata, which checks it",
	"Result.TM.System.Components[].Paths[].Needle": "the quoted text is the agent's own code excerpt; the cited place and its state are printed",
	"Result.TM.System.Components[].Paths[].State":  "printed as Observer's state words, never as the stored word",
	"Result.TM.System.EntryPoints[].Ref.Needle":    "as for the component paths",
	"Result.TM.System.EntryPoints[].Ref.State":     "as for the component paths",
	"Result.TM.Threats[].Existing[].Refs[].Needle": "as for the component paths",
	"Result.TM.Threats[].Existing[].Refs[].State":  "as for the component paths",
	"Result.TM.Threats[].Missing[].Refs[].Needle":  "as for the component paths",
	"Result.TM.Threats[].Missing[].Refs[].State":   "as for the component paths",
	"Result.TM.AttackTrees[].Nodes[].ID":           "the node ids only link children to their parents",
	"Result.TM.AttackTrees[].Nodes[].Parent":       "the parent links make the nesting",
	"Result.PT.Schema":                             "the document says what it is in its own words",
	"Result.PT.RunID":                              "the run id comes from the export metadata, which checks it",
	"Result.PT.Coverage[].Category":                "the matrix is printed from the report's rows, which hold the same claim",
	"Result.PT.Coverage[].Status":                  "as for the category",
	"Result.PT.Coverage[].Reason":                  "as for the category",
	"Result.PT.Coverage[].Probes[]":                "the agent's probe ids per category are in the JSON export",
	"Result.PT.Coverage[].Notes":                   "the agent's notes per category are in the JSON export",
	"Result.PT.Findings[].CVSSBand":                "the export scores the vector itself when it writes the line; the stored band is in the JSON export",
	"Result.PT.Findings[].Where.Refs[].Needle":     "the quoted text is the agent's own code excerpt; the cited place and its state are printed",
	"Result.PT.Findings[].Where.Refs[].State":      "printed as Observer's state words, never as the stored word",

	// The red team exercise (depth plan W7.3): the narrative prints the steps in
	// the agent's words; the two closed words are printed as Observer's own words
	// for them (ChainResultWords, and who wrote the objective), never as stored.
	"Result.PT.Exercise.ObjectiveBy":    "printed as Observer's sentence about whose words the objective is",
	"Result.PT.Exercise.Chain[].Result": "printed as Observer's words for the result (ChainResultWords), never as the stored word",

	// The request helper's evidence (depth plan W5b). The Markdown export prints
	// no request log and no reading of one; the JSON export carries every one of
	// these fields.
	"Result.PT.Findings[].EvidenceState":                         "Observer's reading of the request helper's log for the finding; the JSON export carries it, the Markdown export prints no reading of a request log",
	"Result.PT.Findings[].EvidenceReason":                        "as for the evidence state",
	"Result.PT.Findings[].Indicator.Unread":                      "Observer's own note on a part of the indicator it could not read; the validation issues carry it",
	"Result.PT.Findings[].Indicator.When.BodyContains[]":         "the agent's response condition for the request log; the JSON export carries it",
	"Result.PT.Findings[].Indicator.When.BodyNotContains[]":      "as for the response condition",
	"Result.PT.Findings[].Indicator.When.HeaderPresent[]":        "as for the response condition",
	"Result.PT.Findings[].Indicator.When.HeaderAbsent[]":         "as for the response condition",
	"Result.PT.Findings[].Indicator.When.HeaderContains[].Name":  "as for the response condition",
	"Result.PT.Findings[].Indicator.When.HeaderContains[].Value": "as for the response condition",
	"Result.PT.Findings[].Indicator.When.Unread":                 "Observer's own note on a part of the condition it could not read; the validation issues carry it",
	"Result.PT.Findings[].Reproduction[].Request.Unread":         "Observer's own note on a part of the request it could not read; the validation issues carry it",
	"Result.Report.Evidence.Helper":                              "the report's evidence summary (the helper's mode and the log's reading) is in the JSON export",
	"Result.Report.Evidence.Log":                                 "as for the helper's mode",
	"Result.Report.Evidence.Mode":                                "as for the helper's mode",
}

// exNotRenderedPrefix lists whole subtrees the Markdown export does not print:
// a retest result (depth plan W7.2) has no export of its own, its labels are
// shown on the findings of the run it replayed and in its stored copy.
var exNotRenderedPrefix = map[string]string{
	"Result.RT.": "a retest has no Markdown export; its labels are on the earlier run's findings",
}

// exRawFragments are pieces of the payload that must not be in the document
// outside the diagram fence: each is the working part of a markup attack.
var exRawFragments = []string{
	"<script>", "</script>", "<div>", "![x](", "](http", "[l](javascript", "javascript:alert", "\n# INJH", "\n- INJL", "\n> INJQ",
	"\n1. INJO", "\n---\n", "\n```\n", "www.e.com", "a@b.com", " | a | ", "{{t}}", "$m$",
}

// exInjected are the line starts that would exist if a newline survived.
var exInjected = []string{"# INJH", "- INJL", "> INJQ", "1. INJO", "---", "```", "<div", "## INJH", "### INJH"}

// exStripFence removes the Mermaid fence, whose lines are Observer's source
// text and are inert inside it.
func exStripFence(out string) string {
	var keep []string
	in := false
	for _, l := range strings.Split(out, "\n") {
		switch {
		case l == "```mermaid":
			in = true
		case in && l == "```":
			in = false
		case !in:
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

// exHostileResult is a result with every string of a threat model and a pen
// test filled, and the diagram's flow joined to two components so a diagram is
// drawn from the hostile names.
func exHostileResult(t *testing.T) (Result, int) {
	t.Helper()
	var res Result
	f := &exFill{}
	f.fill(t, reflect.ValueOf(&res).Elem())
	c := res.TM.System.Components
	res.TM.System.Flows[0].From, res.TM.System.Flows[0].To = c[0].ID, c[1].ID
	return res, f.n
}

// TestRenderMarkdownHostileModel is the escaping test of the whole document.
func TestRenderMarkdownHostileModel(t *testing.T) {
	res, n := exHostileResult(t)
	if n < 200 {
		t.Fatalf("the filler reached only %d strings", n)
	}
	meta := exMeta(ThreatModel)
	meta.Project = exPayload(0)
	out := RenderMarkdown(meta, res)
	body := exStripFence(out)

	t.Run("no raw payload", func(t *testing.T) {
		for _, frag := range exRawFragments {
			if strings.Contains(body, frag) {
				t.Errorf("the document holds the raw fragment %q", frag)
			}
		}
		if strings.ContainsAny(body, "<>") {
			t.Error("the document holds a raw angle bracket outside the diagram")
		}
		for i := 0; i < len(body); i++ {
			if body[i] == '&' && !strings.HasPrefix(body[i:], "&amp;") && !strings.HasPrefix(body[i:], "&lt;") && !strings.HasPrefix(body[i:], "&gt;") {
				t.Fatalf("a raw ampersand at %d: %q", i, body[max(0, i-20):min(len(body), i+20)])
			}
		}
		if strings.ContainsAny(body, "\r\t") {
			t.Error("the document holds a carriage return or a tab")
		}
	})

	t.Run("every printed field is printed escaped", func(t *testing.T) {
		var fields []exField
		exFields(reflect.ValueOf(res), "Result", &fields)
		if len(fields) != n {
			t.Fatalf("%d payload fields found, %d filled", len(fields), n)
		}
		for _, fl := range fields {
			shown := strings.Contains(body, mdText(fl.value)) || strings.Contains(body, mdWords(fl.value))
			reason, listed := exNotRendered[fl.path]
			for prefix, why := range exNotRenderedPrefix {
				if strings.HasPrefix(fl.path, prefix) {
					reason, listed = why, true
				}
			}
			switch {
			case !shown && !listed:
				t.Errorf("%s is not in the document and is not on the list of fields the export leaves out", fl.path)
			case shown && listed:
				t.Errorf("%s is in the document, but the list says it is left out (%s)", fl.path, reason)
			}
		}
	})

	t.Run("no injected block", func(t *testing.T) {
		for _, line := range strings.Split(body, "\n") {
			s := strings.TrimLeft(line, " ")
			for _, p := range exInjected {
				if strings.HasPrefix(s, p) {
					t.Errorf("a line starts with %q: %q", p, line)
				}
			}
			switch k := mdBlockStart(s); k {
			case "", "heading", "bullet", "table row":
			default:
				t.Errorf("a line starts a %s: %q", k, line)
			}
		}
	})

	t.Run("headings are Observer's or carry an item's own text", func(t *testing.T) {
		h2 := map[string]bool{
			"Reading": true, "Validation": true, "Summary": true, "Scope": true, "System": true, "Threats": true,
			"Considered, no threat found": true, "Attack trees": true, "Open questions and the agent's own limits": true,
			"Data-flow diagram": true, "Target": true, "Coverage matrix": true, "Findings": true, "Exercise": true, "The agent's own limits": true,
			"What this does not tell you": true, "Model": true,
		}
		h3 := map[string]bool{"Components": true, "Trust zones": true, "Actors": true, "Assets": true, "Entry points": true, "Flows": true}
		h1 := 0
		for _, line := range strings.Split(body, "\n") {
			switch {
			case strings.HasPrefix(line, "### "):
				if txt := strings.TrimPrefix(line, "### "); !h3[txt] && !strings.Contains(txt, "CNRY") {
					t.Errorf("a heading that is neither Observer's nor an item's: %q", line)
				}
			case strings.HasPrefix(line, "## "):
				if txt := strings.TrimPrefix(line, "## "); !h2[txt] {
					t.Errorf("a section heading Observer does not write: %q", line)
				}
			case strings.HasPrefix(line, "# "):
				h1++
				if !strings.Contains(line, "CNRY0X") {
					t.Errorf("the title does not carry the project name: %q", line)
				}
			case strings.HasPrefix(line, "#"):
				t.Errorf("a heading of an unexpected shape: %q", line)
			}
		}
		if h1 != 1 {
			t.Errorf("%d level-one headings, want 1", h1)
		}
	})

	t.Run("one fence", func(t *testing.T) {
		if got := strings.Count(out, "```mermaid\n"); got != 1 {
			t.Errorf("%d diagrams, want 1", got)
		}
		if n := strings.Count(out, "`") - strings.Count(out, "\\`"); n != 6 {
			t.Errorf("%d backticks that are not escaped, want the 6 of the fence", n)
		}
	})
}

// TestRenderMarkdownNotRenderedListIsHonest: every path on the list of fields
// the export leaves out names a string field of the result, so a renamed field
// does not leave a dead row, and every row says why.
func TestRenderMarkdownNotRenderedListIsHonest(t *testing.T) {
	res, _ := exHostileResult(t)
	var fields []exField
	exFields(reflect.ValueOf(res), "Result", &fields)
	have := map[string]bool{}
	for _, f := range fields {
		have[f.path] = true
	}
	var missing []string
	for p, reason := range exNotRendered {
		if !have[p] {
			missing = append(missing, p)
		}
		if reason == "" {
			t.Errorf("%s has no reason", p)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("rows of exNotRendered that name no string field: %v", missing)
	}
}

// exBanned is the clearance pattern of testdata/clearance_words.json.
func exBanned(t *testing.T) *regexp.Regexp { return rdBannedPattern(t) }

// TestRenderMarkdownObserverWording runs the shared clearance pin over the
// whole document of every variant the renderer has. The fixtures' own text holds
// none of the words, so a hit is Observer's.
func TestRenderMarkdownObserverWording(t *testing.T) {
	banned := exBanned(t)
	anyway := exMeta(ThreatModel)
	anyway.Anyway = true
	off := exMeta(ThreatModel)
	off.RedactionOn = false
	cases := []struct {
		name string
		meta ExportMeta
		res  Result
	}{
		{"a threat model", exMeta(ThreatModel), exTM(t, nil)},
		{"a threat model checked early", anyway, exTM(t, nil)},
		{"a threat model with redaction off", off, exTM(t, nil)},
		{"a threat model with no threat", exMeta(ThreatModel), exTM(t, func(m map[string]any) { m["threats"] = nil })},
		{"a threat model with everything refused", exMeta(ThreatModel), exTM(t, func(m map[string]any) {
			threat(m, 0)["rating"] = map[string]any{"likelihood": 9, "impact": 9}
			threat(m, 1)["rating"] = map[string]any{"likelihood": 9, "impact": 9}
		})},
		{"a pen test", exMeta(PentestLocal), exPT(t, nil)},
		{"a pen test whose target did not start", exMeta(PentestLocal), exPT(t, func(m map[string]any) { obj(obj(m["target"])["start"])["started"] = false })},
		{"a pen test with no finding", exMeta(RedTeamLocal), exPT(t, func(m map[string]any) { m["findings"] = nil })},
		{"a refused file", exMeta(ThreatModel), Validate([]byte("{nope"), optsFor(ContractThreatModel))},
		{"a stored report only", exMeta(ThreatModel), rdStoredTM(&TMCoverage{Waived: 1, Empty: 2}, map[string]Count{"threats": {Read: 2, LeftOut: 2}})},
		{"a result with nothing", ExportMeta{}, Result{}},
		{"the hostile result", exMeta(ThreatModel), func() Result { r, _ := exHostileResult(t); return r }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderMarkdown(tc.meta, tc.res)
			if m := banned.FindAllString(out, -1); len(m) > 0 {
				i := banned.FindStringIndex(out)
				t.Errorf("the document uses the banned word %q: ...%s...", m[0], out[max(0, i[0]-60):min(len(out), i[1]+60)])
			}
		})
	}
	t.Run("the word tables", func(t *testing.T) {
		for _, r := range refStateWords {
			if m := banned.FindString(r.Words); m != "" {
				t.Errorf("the state words %q use %q", r.Words, m)
			}
		}
		for k, s := range basisWords {
			if m := banned.FindString(s); m != "" {
				t.Errorf("the basis words for %q use %q", k, m)
			}
		}
		for k, s := range validationStateWords {
			if m := banned.FindString(s); m != "" {
				t.Errorf("the validation words for %q use %q", k, m)
			}
		}
		if m := banned.FindString(mdBandNote + exportNote); m != "" {
			t.Errorf("a note uses %q", m)
		}
	})
}
