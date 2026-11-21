package secassess

import (
	"strings"
	"testing"
)

// bearerRedactor is a redactor shaped like the node's: it rewrites a word run
// that merely looks like a credential ("bearer" followed by a word), the way the
// shared scrubber's short bearer row rewrites the plain words "bearer tokens".
func bearerRedactor(s string) string {
	for _, w := range []string{"bearer tokens", "Bearer tokens"} {
		s = strings.ReplaceAll(s, w, "[REDACTED]")
	}
	return s
}

// tokenProject is a project whose file cites, at line 12, code that says
// "bearer tokens are decoded".
func tokenProject() *fakeProject {
	p := testProject()
	p.files["cmd/api/main.go"][11] = "// header: bearer tokens are decoded here"
	p.files["cmd/api/main.go"][12] = "tok := decode(bearer tokens are decoded here)"
	return p
}

// TestValidateRecordsHowTheReferencesWereChecked: the report says which match
// window the tally was made under and how many references quoted text the
// redactor changed, so the numbers can be read against their conditions (live
// defect 8: 192 found and 7 not found on the node's check, 198 and 1 on the kit
// scorer, on one file, because the node hides secrets in the quoted text first).
func TestValidateRecordsHowTheReferencesWereChecked(t *testing.T) {
	needle := func(n string) func(m map[string]any) {
		return func(m map[string]any) {
			th := obj(arr(m["threats"])[0])
			ref := obj(arr(obj(arr(th["missing"])[0])["refs"])[0])
			ref["line"], ref["needle"] = float64(13), n
		}
	}
	cases := []struct {
		name       string
		project    RefChecker
		window     int
		redact     func(string) string
		needle     string
		wantNil    bool
		wantWindow int
		wantHidden int
		wantFound  bool
	}{
		{"no checker: nothing was looked at, nothing is claimed", nil, 0, nil, "tok := decode(", true, 0, 0, false},
		{"the default window", tokenProject(), 0, nil, "tok := decode(", false, DefaultRefWindow, 0, true},
		{"a window named", tokenProject(), 20, nil, "tok := decode(", false, 20, 0, true},
		{"a window of one", tokenProject(), 1, nil, "tok := decode(", false, 1, 0, true},
		{"quoted text a redactor rewrites, no redactor: found", tokenProject(), 0, nil, "decode(bearer tokens are decoded here)", false, DefaultRefWindow, 0, true},
		{"quoted text a redactor rewrites: not found, and counted", tokenProject(), 0, bearerRedactor, "decode(bearer tokens are decoded here)", false, DefaultRefWindow, 1, false},
		{"quoted text a redactor leaves alone: found, not counted", tokenProject(), 0, bearerRedactor, "tok := decode(", false, DefaultRefWindow, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := DefaultValidateOptions(ContractThreatModel, modelRun)
			o.Refs, o.RefWindow, o.Redact = tc.project, tc.window, tc.redact
			if tc.project == nil {
				o.Refs = nil
			}
			res := Validate(edit(t, baseThreatModel, needle(tc.needle)), o)
			rc := res.Report.RefCheck
			if tc.wantNil != (rc == nil) {
				t.Fatalf("RefCheck = %+v, want nil %v", rc, tc.wantNil)
			}
			if rc == nil {
				return
			}
			if rc.WindowLines != tc.wantWindow || rc.TextHidden != tc.wantHidden {
				t.Errorf("RefCheck = %+v, want window %d hidden %d", rc, tc.wantWindow, tc.wantHidden)
			}
			th := res.TM.Threats[0].Missing[0].Refs[0]
			if (th.State == RefFound) != tc.wantFound {
				t.Errorf("the reference reads %q, found wanted %v", th.State, tc.wantFound)
			}
		})
	}
}

// TestValidateCountsEveryHiddenReferenceOnce: each reference that quotes
// changed text and did not read found counts once, whatever the others do, and
// a hidden reference that was still found does not count (its text matched).
func TestValidateCountsEveryHiddenReferenceOnce(t *testing.T) {
	o := DefaultValidateOptions(ContractThreatModel, modelRun)
	o.Refs, o.Redact = tokenProject(), bearerRedactor
	data := edit(t, baseThreatModel, func(m map[string]any) {
		th := obj(arr(m["threats"])[0])
		two := []any{
			map[string]any{"path": "cmd/api/main.go", "line": float64(13), "needle": "decode(bearer tokens are decoded here)"},
			map[string]any{"path": "cmd/api/main.go", "line": float64(13), "needle": "decode(Bearer tokens are decoded here)"},
			map[string]any{"path": "cmd/api/main.go", "line": float64(13), "needle": "tok := decode("},
		}
		obj(arr(th["missing"])[0])["refs"] = two
	})
	res := Validate(data, o)
	if rc := res.Report.RefCheck; rc == nil || rc.TextHidden != 2 {
		t.Fatalf("RefCheck = %+v, want 2 hidden", rc)
	}
}
