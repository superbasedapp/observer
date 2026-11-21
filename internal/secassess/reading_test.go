package secassess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// rdCounts builds a pen test coverage report whose rows are given by the
// effective-word counts; the rows are the sum of the counts.
func rdCounts(started bool, counts map[string]int) *PTCoverage {
	pt := &PTCoverage{Started: started, Counts: counts}
	for word, n := range counts {
		for i := 0; i < n; i++ {
			pt.Rows = append(pt.Rows, PTCoverageRow{Effective: word})
		}
	}
	return pt
}

// rdPTResult is a pen test result holding the checked model.
func rdPTResult(pt *PTCoverage, findings int) Result {
	doc := &PentestDoc{Findings: make([]PTFinding, findings)}
	return Result{Report: Report{State: ValidationValid, Contract: ContractPentest, PT: pt}, PT: doc}
}

// rdTMResult is a threat model result holding the checked model.
func rdTMResult(tm *TMCoverage, threats int) Result {
	doc := &ThreatModelDoc{Threats: make([]Threat, threats)}
	return Result{Report: Report{State: ValidationValid, Contract: ContractThreatModel, TM: tm}, TM: doc}
}

// rdStoredPT is a stored copy that did not fit: the report is kept, the model
// is nil, and the counts say how many findings the validation kept.
func rdStoredPT(pt *PTCoverage, counts map[string]Count) Result {
	return Result{Report: Report{State: ValidationPartial, Contract: ContractPentest, PT: pt, Counts: counts}}
}

// rdStoredTM is the threat model counterpart of rdStoredPT.
func rdStoredTM(tm *TMCoverage, counts map[string]Count) Result {
	return Result{Report: Report{State: ValidationPartial, Contract: ContractThreatModel, TM: tm, Counts: counts}}
}

// rdValidated validates a baseline document after an edit, with the test
// project behind the references.
func rdValidated(t *testing.T, c Contract, doc string, fn func(m map[string]any)) Result {
	t.Helper()
	return Validate(edit(t, doc, fn), optsFor(c))
}

const (
	rdExampleCounts = "5 of 8 categories claimed, 0 with a logged request, 1 skipped, 1 not applicable, 1 with a tool unavailable"
	rdTailPT        = "; this is not proof that none exists."
)

// rdCase is one row of the reading tables: a result and the two strings the
// functions return for it.
type rdCase struct {
	name     string
	res      Result
	reading  string
	coverage string
}

// rdCases is the one table every reading test walks, so the wording pin covers
// every case the functions tell apart.
func rdCases(t *testing.T) []rdCase {
	t.Helper()
	example := map[string]int{CovTestedClaimed: 5, CovSkipped: 1, CovNotApplicable: 1, CovToolUnavailable: 1}
	logged := map[string]int{CovTestedClaimed: 5, CovTestedLogged: 4, CovSkipped: 2, CovNotApplicable: 1}
	everyPart := map[string]int{CovTestedClaimed: 1, CovTestedLogged: 1, CovSkipped: 1, CovNotStarted: 1, CovNotApplicable: 1, CovToolUnavailable: 1, CovMissing: 1}
	notStarted12 := map[string]int{CovNotStarted: 12}
	return []rdCase{
		{
			name:     "pen test, target not started, 12 categories, no findings",
			res:      rdPTResult(rdCounts(false, notStarted12), 0),
			reading:  "The target was not started, so nothing was tested in a running application: all 12 categories read as skipped. No weakness was reported; this is not proof that none exists.",
			coverage: "Covered by the agent: 0 of 12 categories claimed, 0 with a logged request, 12 skipped (target not started).",
		},
		{
			name:     "pen test, target not started, one category",
			res:      rdPTResult(rdCounts(false, map[string]int{CovNotStarted: 1}), 0),
			reading:  "The target was not started, so nothing was tested in a running application: the 1 category reads as skipped. No weakness was reported; this is not proof that none exists.",
			coverage: "Covered by the agent: 0 of 1 categories claimed, 0 with a logged request, 1 skipped (target not started).",
		},
		{
			name:     "pen test, target not started, no coverage rows",
			res:      rdPTResult(rdCounts(false, map[string]int{}), 0),
			reading:  "The target was not started, so nothing was tested in a running application. No weakness was reported; this is not proof that none exists.",
			coverage: "Covered by the agent: 0 of 0 categories claimed, 0 with a logged request.",
		},
		{
			name:     "pen test, target not started, with a finding",
			res:      rdPTResult(rdCounts(false, notStarted12), 1),
			reading:  "",
			coverage: "Covered by the agent: 0 of 12 categories claimed, 0 with a logged request, 12 skipped (target not started).",
		},
		{
			name:     "pen test, started, claimed coverage only, no findings",
			res:      rdPTResult(rdCounts(true, example), 0),
			reading:  "No weakness was reported in what was tested (" + rdExampleCounts + ")" + rdTailPT,
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "pen test, started, logged and claimed coverage, no findings",
			res:      rdPTResult(rdCounts(true, logged), 0),
			reading:  "No weakness was reported in what was tested (9 of 12 categories claimed, 4 with a logged request, 2 skipped, 1 not applicable)" + rdTailPT,
			coverage: "Covered by the agent: 9 of 12 categories claimed, 4 with a logged request, 2 skipped, 1 not applicable.",
		},
		{
			name:     "pen test, started, a category with no row",
			res:      rdPTResult(rdCounts(true, map[string]int{CovTestedClaimed: 2, CovMissing: 10}), 0),
			reading:  "No weakness was reported in what was tested (2 of 12 categories claimed, 0 with a logged request, 10 with no row)" + rdTailPT,
			coverage: "Covered by the agent: 2 of 12 categories claimed, 0 with a logged request, 10 with no row.",
		},
		{
			name:     "pen test, started, every part of the counts line in order",
			res:      rdPTResult(rdCounts(true, everyPart), 0),
			reading:  "No weakness was reported in what was tested (2 of 7 categories claimed, 1 with a logged request, 1 skipped, 1 skipped (target not started), 1 not applicable, 1 with a tool unavailable, 1 with no row)" + rdTailPT,
			coverage: "Covered by the agent: 2 of 7 categories claimed, 1 with a logged request, 1 skipped, 1 skipped (target not started), 1 not applicable, 1 with a tool unavailable, 1 with no row.",
		},
		{
			name:     "pen test, started, with findings",
			res:      rdPTResult(rdCounts(true, example), 2),
			reading:  "",
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "stored copy without the model, report counts no findings",
			res:      rdStoredPT(rdCounts(true, example), map[string]Count{"findings": {Read: 0, Kept: 0}}),
			reading:  "No weakness was reported in what was tested (" + rdExampleCounts + ")" + rdTailPT,
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "stored copy without the model, report counts findings",
			res:      rdStoredPT(rdCounts(true, example), map[string]Count{"findings": {Read: 3, Kept: 3}}),
			reading:  "",
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "stored copy without the model, findings refused leave none kept",
			res:      rdStoredPT(rdCounts(true, example), map[string]Count{"findings": {Read: 2, Refused: 2, Kept: 0}}),
			reading:  "The agent wrote 2 findings, and none is shown here: the check refused 2. This says nothing about whether a weakness exists; the issues say why.",
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "stored copy without the model, one finding refused",
			res:      rdStoredPT(rdCounts(true, example), map[string]Count{"findings": {Read: 1, Refused: 1, Kept: 0}}),
			reading:  "The agent wrote 1 finding, and none is shown here: the check refused 1. This says nothing about whether a weakness exists; the issues say why.",
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "stored copy without the model, findings left out as well as refused",
			res:      rdStoredPT(rdCounts(true, example), map[string]Count{"findings": {Read: 5, Refused: 2, LeftOut: 3, Kept: 0}}),
			reading:  "The agent wrote 5 findings, and none is shown here: the check refused 2 and left out 3. This says nothing about whether a weakness exists; the issues say why.",
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "stored copy without the model, findings only left out",
			res:      rdStoredPT(rdCounts(true, example), map[string]Count{"findings": {Read: 4, LeftOut: 4, Kept: 0}}),
			reading:  "The agent wrote 4 findings, and none is shown here: the check left out 4. This says nothing about whether a weakness exists; the issues say why.",
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "stored copy without the model, some findings refused and some kept",
			res:      rdStoredPT(rdCounts(true, example), map[string]Count{"findings": {Read: 3, Refused: 1, Kept: 2}}),
			reading:  "",
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "stored copy without the model, findings refused and the target not started",
			res:      rdStoredPT(rdCounts(false, map[string]int{CovNotStarted: 12}), map[string]Count{"findings": {Read: 2, Refused: 2, Kept: 0}}),
			reading:  "The agent wrote 2 findings, and none is shown here: the check refused 2. This says nothing about whether a weakness exists; the issues say why. The target was not started, so nothing was tested in a running application.",
			coverage: "Covered by the agent: 0 of 12 categories claimed, 0 with a logged request, 12 skipped (target not started).",
		},
		{
			name: "validated pen test whose findings were all refused",
			res: rdValidated(t, ContractPentest, basePentest, func(m map[string]any) {
				for i := range arr(m["findings"]) {
					finding(m, i)["title"] = ""
				}
			}),
			reading:  "The agent wrote 1 finding, and none is shown here: the check refused 1. This says nothing about whether a weakness exists; the issues say why.",
			coverage: "Covered by the agent: 2 of 12 categories claimed, 0 with a logged request, 1 not applicable, 9 with no row.",
		},
		{
			name: "validated threat model whose threats were all refused",
			res: rdValidated(t, ContractThreatModel, baseThreatModel, func(m map[string]any) {
				for i := range arr(m["threats"]) {
					threat(m, i)["title"] = ""
				}
			}),
			reading:  "The agent wrote 2 threats, and none is shown here: the check refused 2. This says nothing about whether a threat exists; the issues say why.",
			coverage: "Covered by the agent: 0 element and category pairs analysed, 1 waived with a reason and 27 with neither.",
		},
		{
			name:     "stored copy without the model, the report does not name findings",
			res:      rdStoredPT(rdCounts(true, example), map[string]Count{"components": {Read: 1, Kept: 1}}),
			reading:  "",
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "threat model, no threats",
			res:      rdTMResult(&TMCoverage{Analysed: 0, Waived: 3, Empty: 4}, 0),
			reading:  "No threat was recorded (3 element and category pairs waived with a reason, 4 with neither). A threat model is read from code and documents only, so this is not proof that none exists.",
			coverage: "Covered by the agent: 0 element and category pairs analysed, 3 waived with a reason and 4 with neither.",
		},
		{
			name:     "threat model, with threats",
			res:      rdTMResult(&TMCoverage{Analysed: 5, Waived: 2, Empty: 9}, 3),
			reading:  "",
			coverage: "Covered by the agent: 5 element and category pairs analysed, 2 waived with a reason and 9 with neither.",
		},
		{
			name:     "stored threat model copy without the model, report counts no threats",
			res:      rdStoredTM(&TMCoverage{Waived: 1, Empty: 2}, map[string]Count{"threats": {Read: 0, Kept: 0}}),
			reading:  "No threat was recorded (1 element and category pair waived with a reason, 2 with neither). A threat model is read from code and documents only, so this is not proof that none exists.",
			coverage: "Covered by the agent: 0 element and category pairs analysed, 1 waived with a reason and 2 with neither.",
		},
		{
			name:     "stored threat model copy without the model, threats refused",
			res:      rdStoredTM(&TMCoverage{Waived: 1, Empty: 2}, map[string]Count{"threats": {Read: 3, Refused: 3, Kept: 0}}),
			reading:  "The agent wrote 3 threats, and none is shown here: the check refused 3. This says nothing about whether a threat exists; the issues say why.",
			coverage: "Covered by the agent: 0 element and category pairs analysed, 1 waived with a reason and 2 with neither.",
		},
		{
			name:     "stored threat model copy without the model, some threats refused and some kept",
			res:      rdStoredTM(&TMCoverage{Analysed: 2}, map[string]Count{"threats": {Read: 3, Refused: 1, Kept: 2}}),
			reading:  "",
			coverage: "Covered by the agent: 2 element and category pairs analysed, 0 waived with a reason and 0 with neither.",
		},
		{
			name:     "stored threat model copy without the model, report counts threats",
			res:      rdStoredTM(&TMCoverage{Analysed: 4}, map[string]Count{"threats": {Read: 4, Kept: 4}}),
			reading:  "",
			coverage: "Covered by the agent: 4 element and category pairs analysed, 0 waived with a reason and 0 with neither.",
		},
		{
			name:     "stored threat model copy without the model, the report does not name threats",
			res:      rdStoredTM(&TMCoverage{Analysed: 4}, nil),
			reading:  "",
			coverage: "Covered by the agent: 4 element and category pairs analysed, 0 waived with a reason and 0 with neither.",
		},
		{
			name:     "refused file",
			res:      Result{Report: Report{State: ValidationInvalid, Contract: ContractPentest, Fatal: "not_json"}},
			reading:  "",
			coverage: "",
		},
		{
			name:     "refused file that still carries a coverage report",
			res:      Result{Report: Report{State: ValidationInvalid, Contract: ContractPentest, PT: rdCounts(true, example)}},
			reading:  "",
			coverage: "Covered by the agent: " + rdExampleCounts + ".",
		},
		{
			name:     "result with no coverage report (a run from before the depth work)",
			res:      Result{Report: Report{State: ValidationValid, Contract: ContractSARIF}},
			reading:  "",
			coverage: "",
		},
		{
			name:     "the zero result",
			res:      Result{},
			reading:  "",
			coverage: "",
		},
		{
			name: "validated pen test with its finding dropped",
			res: rdValidated(t, ContractPentest, basePentest, func(m map[string]any) {
				delete(m, "findings")
			}),
			reading:  "No weakness was reported in what was tested (2 of 12 categories claimed, 0 with a logged request, 1 not applicable, 9 with no row)" + rdTailPT,
			coverage: "Covered by the agent: 2 of 12 categories claimed, 0 with a logged request, 1 not applicable, 9 with no row.",
		},
		{
			name:     "validated pen test with its finding",
			res:      rdValidated(t, ContractPentest, basePentest, func(m map[string]any) {}),
			reading:  "",
			coverage: "Covered by the agent: 2 of 12 categories claimed, 0 with a logged request, 1 not applicable, 9 with no row.",
		},
		{
			name: "validated pen test whose target did not start",
			res: rdValidated(t, ContractPentest, basePentest, func(m map[string]any) {
				delete(m, "findings")
				start := obj(obj(m["target"])["start"])
				start["started"] = false
			}),
			reading:  "The target was not started, so nothing was tested in a running application: all 12 categories read as skipped. No weakness was reported; this is not proof that none exists.",
			coverage: "Covered by the agent: 0 of 12 categories claimed, 0 with a logged request, 12 skipped (target not started).",
		},
		{
			name: "validated threat model with its threats dropped",
			res: rdValidated(t, ContractThreatModel, baseThreatModel, func(m map[string]any) {
				delete(m, "threats")
			}),
			reading:  "No threat was recorded (1 element and category pair waived with a reason, 27 with neither). A threat model is read from code and documents only, so this is not proof that none exists.",
			coverage: "Covered by the agent: 0 element and category pairs analysed, 1 waived with a reason and 27 with neither.",
		},
	}
}

func TestCleanReading(t *testing.T) {
	for _, c := range rdCases(t) {
		t.Run(c.name, func(t *testing.T) {
			if got := CleanReading(c.res); got != c.reading {
				t.Errorf("CleanReading\n got: %q\nwant: %q", got, c.reading)
			}
		})
	}
}

func TestCoverageLine(t *testing.T) {
	for _, c := range rdCases(t) {
		t.Run(c.name, func(t *testing.T) {
			if got := CoverageLine(c.res); got != c.coverage {
				t.Errorf("CoverageLine\n got: %q\nwant: %q", got, c.coverage)
			}
		})
	}
}

// TestCleanReadingValidatedModelKeepsItsThreats pins the other direction of
// the validated threat model row: with its threats the reading is empty.
func TestCleanReadingValidatedModelKeepsItsThreats(t *testing.T) {
	res := rdValidated(t, ContractThreatModel, baseThreatModel, func(m map[string]any) {})
	if got := CleanReading(res); got != "" {
		t.Errorf("a model with threats read as %q", got)
	}
	if got := CoverageLine(res); !strings.HasPrefix(got, "Covered by the agent: ") || !strings.HasSuffix(got, " with neither.") {
		t.Errorf("coverage line = %q", got)
	}
}

// TestCoverageLineCounts pins the counts line, with the example the TypeScript
// helper coverageCountsLine pins as well.
func TestCoverageLineCounts(t *testing.T) {
	tests := []struct {
		name   string
		counts map[string]int
		rows   int // 0 reads as the sum of the counts
		want   string
	}{
		{"the shared example", map[string]int{CovTestedClaimed: 5, CovSkipped: 1, CovNotApplicable: 1, CovToolUnavailable: 1}, 0, rdExampleCounts},
		{"the plan's example", map[string]int{CovTestedClaimed: 5, CovTestedLogged: 4, CovSkipped: 2, CovNotApplicable: 1}, 0, "9 of 12 categories claimed, 4 with a logged request, 2 skipped, 1 not applicable"},
		{"nothing", map[string]int{}, 0, "0 of 0 categories claimed, 0 with a logged request"},
		{"nil counts", nil, 3, "0 of 3 categories claimed, 0 with a logged request"},
		{"logged counts as claimed", map[string]int{CovTestedLogged: 3}, 0, "3 of 3 categories claimed, 3 with a logged request"},
		{"a zero part is left out", map[string]int{CovTestedClaimed: 1, CovSkipped: 0, CovMissing: 2}, 3, "1 of 3 categories claimed, 0 with a logged request, 2 with no row"},
		{"not started is its own part", map[string]int{CovNotStarted: 12}, 0, "0 of 12 categories claimed, 0 with a logged request, 12 skipped (target not started)"},
		{"total is the number of rows", map[string]int{CovTestedClaimed: 2}, 9, "2 of 9 categories claimed, 0 with a logged request"},
		{"an unknown effective word is not counted", map[string]int{CovTestedClaimed: 1, "something_new": 4}, 5, "1 of 5 categories claimed, 0 with a logged request"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pt := &PTCoverage{Counts: tc.counts}
			rows := tc.rows
			if rows == 0 {
				for _, n := range tc.counts {
					rows += n
				}
			}
			pt.Rows = make([]PTCoverageRow, rows)
			if got := coverageCounts(pt); got != tc.want {
				t.Errorf("coverageCounts = %q, want %q", got, tc.want)
			}
		})
	}
}

// clearanceList is the one list of clearance words and phrases (plan section 13,
// limit 3, and the wording rule of the web's model view), shared with the
// TypeScript pins: testdata/clearance_words.json. The output says what Observer
// checked, never that a result is clean, safe or passed.
type clearanceList struct {
	Words   []string `json:"words"`
	Phrases []string `json:"phrases"`
	Caught  []string `json:"caught"`
	Allowed []string `json:"allowed"`
}

// rdClearance reads the shared list.
func rdClearance(t *testing.T) clearanceList {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "clearance_words.json"))
	if err != nil {
		t.Fatal(err)
	}
	var l clearanceList
	if err := json.Unmarshal(data, &l); err != nil {
		t.Fatal(err)
	}
	if len(l.Words) < 5 || len(l.Phrases) < 5 || len(l.Caught) < 5 || len(l.Allowed) < 5 {
		t.Fatalf("the shared list looks cut short: %+v", l)
	}
	return l
}

// rdBannedPattern builds the pattern the wording pin uses: each word as a whole
// word, each phrase with any run of white space between its words, in any case.
func rdBannedPattern(t *testing.T) *regexp.Regexp {
	t.Helper()
	l := rdClearance(t)
	var alts []string
	for _, w := range l.Words {
		alts = append(alts, regexp.QuoteMeta(w))
	}
	for _, p := range l.Phrases {
		alts = append(alts, strings.Join(strings.Fields(regexp.QuoteMeta(p)), `\s+`))
	}
	return regexp.MustCompile(`(?i)\b(` + strings.Join(alts, "|") + `)\b`)
}

// TestReadingWording runs every function over every row of the case table and
// pins the words they never use.
func TestReadingWording(t *testing.T) {
	rdBanned := rdBannedPattern(t)
	check := func(t *testing.T, what, s string) {
		t.Helper()
		if m := rdBanned.FindString(s); m != "" {
			t.Errorf("%s uses the word %q: %q", what, m, s)
		}
	}
	for _, c := range rdCases(t) {
		t.Run(c.name, func(t *testing.T) {
			check(t, "CleanReading", CleanReading(c.res))
			check(t, "CoverageLine", CoverageLine(c.res))
		})
	}
	t.Run("the sentence constants", func(t *testing.T) {
		for name, s := range map[string]string{
			"ReadingNotStartedHead":   ReadingNotStartedHead,
			"ReadingNotStartedAll":    ReadingNotStartedAll,
			"ReadingNotStartedOne":    ReadingNotStartedOne,
			"ReadingNotStartedTail":   ReadingNotStartedTail,
			"ReadingNotStartedStop":   ReadingNotStartedStop,
			"ReadingRefused":          ReadingRefused,
			"ReadingPenTestStarted":   ReadingPenTestStarted,
			"ReadingThreatModel":      ReadingThreatModel,
			"CoverageLinePenTest":     CoverageLinePenTest,
			"CoverageLineThreatModel": CoverageLineThreatModel,
			"coverageCountsHead":      coverageCountsHead,
		} {
			check(t, name, s)
		}
		for _, p := range coverageCountParts {
			check(t, "the counts part for "+p.key, p.format)
		}
	})
	t.Run("the banned pattern", func(t *testing.T) {
		l := rdClearance(t)
		for _, s := range l.Caught {
			if rdBanned.FindString(s) == "" {
				t.Errorf("the pin does not catch %q", s)
			}
		}
		for _, s := range l.Allowed {
			if rdBanned.FindString(s) != "" {
				t.Errorf("the pin catches %q, which is not a banned word", s)
			}
		}
	})
}
