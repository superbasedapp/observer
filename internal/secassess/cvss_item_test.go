package secassess

import (
	"strings"
	"testing"
)

// A CVSS vector Observer left out is named by the finding it belonged to (fix
// round 4, N-9): the sentence under How checked says "finding F-4", never "this
// finding", and the issue carries the finding's id as its Item so the view can
// say so on the finding's own row. The id is one row V4 accepted (a closed
// alphabet), so it is Observer's key and not the agent's free text.

// twoFindings returns basePentest with a second finding whose id and vector
// the caller sets; the first finding keeps no vector.
func twoFindings(t *testing.T, id, vector string, extra func(first, second map[string]any)) []byte {
	t.Helper()
	return edit(t, basePentest, func(m map[string]any) {
		first := finding(m, 0)
		second := map[string]any{}
		for k, v := range first {
			second[k] = v
		}
		second["id"], second["cvss"] = id, vector
		m["findings"] = []any{first, second}
		if extra != nil {
			extra(first, second)
		}
	})
}

func cvssIssues(r Report) []Issue {
	var out []Issue
	for _, is := range r.Issues {
		if is.Code == "bad_cvss_dropped" || is.Code == "cvss_not_scored" {
			out = append(out, is)
		}
	}
	return out
}

func TestCVSSLeftOutNamesTheFinding(t *testing.T) {
	r := Validate(twoFindings(t, "F-4", cvssCritical+"/E:A", nil), optsFor(ContractPentest))
	got := cvssIssues(r.Report)
	if len(got) != 1 {
		t.Fatalf("issues = %+v", r.Report.Issues)
	}
	is := got[0]
	if is.Item != "F-4" {
		t.Errorf("Item = %q, want F-4", is.Item)
	}
	if !strings.Contains(is.Message, "The CVSS vector of finding F-4 carries a threat, environmental or supplemental metric") {
		t.Errorf("message does not name the finding: %q", is.Message)
	}
	if strings.Contains(is.Message, "this finding") {
		t.Errorf("message still says this finding: %q", is.Message)
	}
	// The vector is still never repeated.
	if strings.Contains(is.Message, "/E:A") || strings.Contains(is.Message, "CVSS:4.0/") {
		t.Errorf("message repeats the vector: %q", is.Message)
	}
	if is.Row != "V5" || is.Severity != SevDropped || is.Path != "findings[1]" {
		t.Errorf("issue = %+v", is)
	}
}

// TestCVSSItemIsTheIdNotThePosition: the path is the finding's place in the
// agent's file, which is not its place in the kept model once an earlier item
// was refused; the id is what a row can be matched on.
func TestCVSSItemIsTheIdNotThePosition(t *testing.T) {
	data := twoFindings(t, "F-7", cvssCritical+"/CR:H", func(first, _ map[string]any) {
		first["rating"] = map[string]any{"likelihood": 9, "impact": 1} // refused at V5: the first finding is gone
	})
	r := Validate(data, optsFor(ContractPentest))
	if len(r.PT.Findings) != 1 || r.PT.Findings[0].ID != "F-7" {
		t.Fatalf("kept findings = %+v", r.PT.Findings)
	}
	got := cvssIssues(r.Report)
	if len(got) != 1 {
		t.Fatalf("issues = %+v", r.Report.Issues)
	}
	// In the agent's file the finding is the second one; in the kept model it is the first.
	if got[0].Path != "findings[1]" || got[0].Item != "F-7" {
		t.Errorf("issue = %+v", got[0])
	}
}

// TestCVSSItemOfAFindingTheCheckRefusedIsNotRaised: a finding refused before
// row V5 reads its vector (a bad id) has no vector issue and so no Item.
func TestCVSSItemOfAFindingTheCheckRefusedIsNotRaised(t *testing.T) {
	r := Validate(twoFindings(t, "bad id with spaces", cvssCritical+"/E:A", nil), optsFor(ContractPentest))
	if got := cvssIssues(r.Report); len(got) != 0 {
		t.Fatalf("a refused finding raised a vector issue: %+v", got)
	}
	if len(r.PT.Findings) != 1 {
		t.Errorf("kept findings = %d", len(r.PT.Findings))
	}
}

func TestIssueItemKeepsOnlyAnIdTheCheckAccepts(t *testing.T) {
	v := newValidator(nil, ValidateOptions{})
	v.issueItem("V5", "x", SevWarn, "findings[0]", "F-1", "ok")
	v.issueItem("V5", "x", SevWarn, "findings[1]", "has spaces and \"quotes\"", "not an id")
	v.issueItem("V5", "x", SevWarn, "findings[2]", strings.Repeat("a", 49), "too long")
	v.issue("V5", "x", SevWarn, "findings[3]", "no item")
	want := []string{"F-1", "", "", ""}
	for i, is := range v.rep.Issues {
		if is.Item != want[i] {
			t.Errorf("issue %d Item = %q, want %q", i, is.Item, want[i])
		}
	}
}

func TestFindingWords(t *testing.T) {
	for _, c := range []struct{ id, want string }{
		{"F-4", "finding F-4"},
		{"a.b_c-1", "finding a.b_c-1"},
		{"", "this finding"},
		{"not an id", "this finding"},
		{"-leading", "this finding"},
	} {
		if got := findingWords(c.id); got != c.want {
			t.Errorf("findingWords(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}

func TestV10NotScoredNamesTheFinding(t *testing.T) {
	v := newValidator(nil, ValidateOptions{})
	v.pt = &PentestDoc{Findings: []PTFinding{{ID: "F-9", Rating: Rating{Likelihood: 2, Impact: 2}, CVSS: "not a vector"}}}
	ruleV10(v)
	got := cvssIssues(v.rep)
	if len(got) != 1 || got[0].Item != "F-9" || !strings.Contains(got[0].Message, "The CVSS vector of finding F-9 could not be scored") {
		t.Errorf("issues = %+v", got)
	}
}
