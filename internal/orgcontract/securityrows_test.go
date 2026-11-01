package orgcontract

import (
	"reflect"
	"strings"
	"testing"
)

// TestSecurityWireRowsAreFullyTagged pins plan 7.4's tag-driven contract:
// every field of every security wire row (and of every struct nested in one)
// carries wire:"always" or wire:"raw", and none is embedded.
func TestSecurityWireRowsAreFullyTagged(t *testing.T) {
	for _, rt := range SecurityWireRowTypes() {
		if err := CheckSecurityWireTags(rt); err != nil {
			t.Error(err)
		}
	}
}

// TestCheckSecurityWireTagsRefusesUnclassified proves the check catches the
// three ways a field could slip in unclassified.
func TestCheckSecurityWireTagsRefusesUnclassified(t *testing.T) {
	type inner struct {
		A string `wire:"always"`
		B string
	}
	type embedded struct{ X string }
	cases := map[string]any{
		"untagged": struct{ A string }{},
		"unknown class": struct {
			A string `wire:"sometimes"`
		}{},
		"embedded": struct {
			embedded `wire:"always"`
		}{},
		"nested untagged": struct {
			In []inner `wire:"always"`
		}{},
	}
	for name, v := range cases {
		if err := CheckSecurityWireTags(reflect.TypeOf(v)); err == nil {
			t.Errorf("%s: want a refusal", name)
		}
		if err := StripSecurityRaw(reflect.New(reflect.TypeOf(v)).Interface(), false); err == nil {
			t.Errorf("%s: the strip must refuse it too", name)
		}
	}
}

// TestStripSecurityRawZeroesOnlyRawFields fills every field and checks that
// the strip zeroes exactly the raw-class fields without raw content and
// nothing with it.
func TestStripSecurityRawZeroesOnlyRawFields(t *testing.T) {
	for _, rt := range SecurityWireRowTypes() {
		for _, raw := range []bool{false, true} {
			v := reflect.New(rt)
			fill(v.Elem())
			if err := StripSecurityRaw(v.Interface(), raw); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				zero := v.Elem().Field(i).IsZero()
				switch {
				case f.Tag.Get("wire") == SecurityWireRaw && !raw && !zero:
					t.Errorf("%s.%s is raw and survived the metadata-only strip", rt.Name(), f.Name)
				case f.Tag.Get("wire") == SecurityWireRaw && raw && zero:
					t.Errorf("%s.%s is raw and was zeroed under raw content", rt.Name(), f.Name)
				case f.Tag.Get("wire") == SecurityWireAlways && zero:
					t.Errorf("%s.%s is always-class and was zeroed", rt.Name(), f.Name)
				}
			}
		}
	}
}

// fill sets every field of a struct value to a non-zero value.
func fill(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Int, reflect.Int64:
		v.SetInt(1)
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(s.Index(0))
		v.Set(s)
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			fill(v.Field(i))
		}
	}
}

// TestSecurityWireRowsHaveNoNeverField walks the row types for the plan 7.4
// "never" column: no field may carry a secret value, file contents, a raw
// snippet, engine message text or prompt text.
func TestSecurityWireRowsHaveNoNeverField(t *testing.T) {
	never := []string{"secret", "content", "snippet", "message", "prompt", "body", "text", "fixhint", "hint", "source"}
	// Lineage ids are ids, not text: the action id of the prompt ships as
	// metadata (plan 4.5).
	allowed := map[string]bool{"PromptActionID": true}
	var walk func(rt reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		for rt.Kind() == reflect.Slice || rt.Kind() == reflect.Pointer {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if allowed[f.Name] {
				continue
			}
			name := strings.ToLower(f.Name + " " + strings.Split(f.Tag.Get("json"), ",")[0])
			for _, n := range never {
				if strings.Contains(strings.ReplaceAll(name, "_", ""), n) {
					t.Errorf("%s.%s looks like a never-ship field (%q)", path, f.Name, n)
				}
			}
			walk(f.Type, path+"."+f.Name)
		}
	}
	for _, rt := range SecurityWireRowTypes() {
		walk(rt, rt.Name())
	}
}

// TestSecurityPostureRowIsEnumsAndCounts pins the posture row (the
// BudgetPostureRow pattern): strings, ints, bools and lists of those or of
// nested enum-and-count structs, never a path or a name field.
func TestSecurityPostureRowIsEnumsAndCounts(t *testing.T) {
	var walk func(rt reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			lower := strings.ToLower(f.Name)
			for _, bad := range []string{"path", "name", "project_root", "rule", "ref", "session"} {
				if strings.Contains(lower, bad) && lower != "rule" {
					t.Errorf("%s.%s is not an enum or a count", path, f.Name)
				}
			}
			switch f.Type.Kind() {
			case reflect.String, reflect.Int64, reflect.Int, reflect.Bool:
			case reflect.Slice:
				if e := f.Type.Elem(); e.Kind() == reflect.Struct {
					walk(e, path+"."+f.Name)
				} else if e.Kind() != reflect.String {
					t.Errorf("%s.%s: unexpected list element %s", path, f.Name, e)
				}
			default:
				t.Errorf("%s.%s: unexpected kind %s", path, f.Name, f.Type.Kind())
			}
		}
	}
	walk(reflect.TypeOf(SecurityPostureRow{}), "SecurityPostureRow")
}

func TestNormalizeSecurityFindingHostile(t *testing.T) {
	good := SecurityFindingRow{
		FindingRef: strings.Repeat("a", 32), RuleID: "S-721.aws", Category: "secret", Severity: "high",
		Status: "open", LastSeen: "2026-10-21T10:00:00Z", RelPath: "src/a.go", EvidenceHash: strings.Repeat("b", 64),
	}
	if _, ok := NormalizeSecurityFinding(good); !ok {
		t.Fatalf("a good row was dropped")
	}
	hostile := good
	hostile.RuleID = "rule id with spaces; DROP TABLE"
	if _, ok := NormalizeSecurityFinding(hostile); ok {
		t.Errorf("a rule id outside its shape must drop the row")
	}
	hostile = good
	hostile.Category = "everything"
	if _, ok := NormalizeSecurityFinding(hostile); ok {
		t.Errorf("a category outside the vocabulary must drop the row")
	}
	for _, p := range []string{"/etc/passwd", "../x", "a/../b", "C:/x", "a\\b", "a\x00b", "a//b", strings.Repeat("a", 600)} {
		r := good
		r.RelPath, r.PathAliases = p, []string{p, "ok/path"}
		out, ok := NormalizeSecurityFinding(r)
		if !ok || out.RelPath != "" || len(out.PathAliases) != 1 {
			t.Errorf("path %q: got %q %v (ok=%v), want it cleared", p, out.RelPath, out.PathAliases, ok)
		}
	}
	r := good
	r.EvidenceRedacted = strings.Repeat("é", 500)
	r.Model = strings.Repeat("m", 500)
	r.CWE = []string{"CWE-79", "not a ref", "CWE-79"}
	r.FixTestExitCode = 9999
	r.StartLine = -4
	out, _ := NormalizeSecurityFinding(r)
	if n := len([]rune(out.EvidenceRedacted)); n != 240 {
		t.Errorf("evidence kept %d characters, want 240", n)
	}
	if out.Model != "" || len(out.CWE) != 1 || out.FixTestExitCode != 255 || out.StartLine != 0 {
		t.Errorf("caps not applied: %+v", out)
	}
}

func TestNormalizeSecurityPosture(t *testing.T) {
	r := SecurityPostureRow{
		Day: "2026-10-21", ShareLevel: "posture",
		Findings:   []SecurityPostureCount{{Category: "secret", Severity: "high", Status: "open", Count: 2}, {Category: "x", Severity: "high", Status: "open", Count: 1}},
		FloorKeys:  []SecurityFloorKeyState{{Key: "require.commit_gate", State: "not_applicable", Reason: "individual_node"}, {Key: "BAD KEY", State: "applied"}},
		CommitGate: []SecurityGateCount{{Rule: "S-791", Decision: "ask", Events: -3}, {Rule: "R-101", Decision: "deny"}},
		Projects:   -1,
	}
	out, ok := NormalizeSecurityPosture(r)
	if !ok || len(out.Findings) != 1 || len(out.FloorKeys) != 1 || len(out.CommitGate) != 1 || out.CommitGate[0].Events != 0 || out.Projects != 0 {
		t.Fatalf("got %+v ok=%v", out, ok)
	}
	for _, bad := range []SecurityPostureRow{{Day: "yesterday", ShareLevel: "posture"}, {Day: "2026-10-21", ShareLevel: "everything"}, {Day: "2026-13-41", ShareLevel: "posture"}} {
		if _, ok := NormalizeSecurityPosture(bad); ok {
			t.Errorf("%+v: want dropped", bad)
		}
	}
}

func TestNormalizeAIChangeRecord(t *testing.T) {
	if _, ok := NormalizeAIChangeRecord(AIChangeRecordRow{}); ok {
		t.Errorf("a record without a commit identity hash must drop")
	}
	out, ok := NormalizeAIChangeRecord(AIChangeRecordRow{CommitIdentityHash: strings.Repeat("c", 64), Paths: []string{"a.go", "/abs"}, AttestationLevel: "magic", Files: -2})
	if !ok || len(out.Paths) != 1 || out.AttestationLevel != "" || out.Files != 0 {
		t.Errorf("got %+v", out)
	}
}
