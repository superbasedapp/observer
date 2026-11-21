package secassess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess/cvss4"
)

// The CVSS 4.0 line of a pen test finding (depth plan W7.1, D30): optional,
// vetted at row V5, scored at row V10 from the vector alone, never trusted from
// the file, and without effect on the finding's band or on what an import
// carries.

const (
	cvssExampleVector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N" // the schema block example
	cvssCritical      = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" // 9.3
	cvssNone          = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N" // 0.0
	cvssMedium        = "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:H/SC:N/SI:L/SA:L" // 5.2
)

func setCVSS(v any) func(m map[string]any) {
	return func(m map[string]any) { finding(m, 0)["cvss"] = v }
}

func TestValidateCVSS(t *testing.T) {
	scored := func(want float64, band Band, vector string) func(t *testing.T, r Result) {
		return func(t *testing.T, r Result) {
			t.Helper()
			f := r.PT.Findings[0]
			if f.CVSS != vector {
				t.Errorf("vector = %q, want %q", f.CVSS, vector)
			}
			if f.CVSSScore == nil || *f.CVSSScore != want || f.CVSSBand != band {
				got := "nil"
				if f.CVSSScore != nil {
					got = FormatCVSSScore(*f.CVSSScore)
				}
				t.Errorf("score %s band %q, want %v %q", got, f.CVSSBand, want, band)
			}
			// The likelihood-times-impact band is its own computation.
			if f.Band != BandOf(f.Rating) || f.Score != f.Rating.Score() {
				t.Errorf("the vector moved the risk band: %q %d", f.Band, f.Score)
			}
		}
	}
	notScored := func(t *testing.T, r Result) {
		t.Helper()
		f := r.PT.Findings[0]
		if f.CVSS != "" || f.CVSSScore != nil || f.CVSSBand != "" {
			t.Errorf("a vector was kept: %q %v %q", f.CVSS, f.CVSSScore, f.CVSSBand)
		}
		if f.Band == "" || f.Score == 0 {
			t.Errorf("the finding lost its rating: %q %d", f.Band, f.Score)
		}
	}
	cases := []vcase{
		{name: "a base vector is scored", contract: ContractPentest, mut: setCVSS(cvssCritical), check: scored(9.3, BandCritical, cvssCritical)},
		{name: "a medium vector", contract: ContractPentest, mut: setCVSS(cvssMedium), check: scored(5.2, BandMedium, cvssMedium)},
		{name: "a vector with no impact scores 0.0 and has no band, and keeps its vector", contract: ContractPentest, mut: setCVSS(cvssNone), check: scored(0, "", cvssNone)},
		{name: "surrounding whitespace is trimmed", contract: ContractPentest, mut: setCVSS(" " + cvssCritical + "\n"), check: scored(9.3, BandCritical, cvssCritical)},
		{name: "no vector, no score", contract: ContractPentest, check: notScored},
		{name: "an empty vector is no vector", contract: ContractPentest, mut: setCVSS(""), check: notScored},
		{name: "a score and a band written by the agent are ignored and counted", contract: ContractPentest, mut: func(m map[string]any) {
			f := finding(m, 0)
			f["cvss"], f["cvss_score"], f["cvss_band"] = cvssMedium, 10.0, "critical"
		}, check: func(t *testing.T, r Result) {
			scored(5.2, BandMedium, cvssMedium)(t, r)
			joined := strings.Join(r.Report.IgnoredKeys, ";")
			for _, k := range []string{".findings[].cvss_score (1)", ".findings[].cvss_band (1)"} {
				if !strings.Contains(joined, k) {
					t.Errorf("ignored keys %q lack %q", joined, k)
				}
			}
		}},
		{name: "a score written without a vector is ignored too", contract: ContractPentest, mut: func(m map[string]any) {
			finding(m, 0)["cvss_score"] = 9.9
		}, check: notScored},
		// Every refusal code of the parser has a row at V5: the finding stays,
		// the vector goes, and the issue says why without repeating the text.
		{name: "wrong version", contract: ContractPentest, want: []string{"V5:bad_cvss_dropped"}, mut: setCVSS("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), check: notScored},
		{name: "no header", contract: ContractPentest, want: []string{"V5:bad_cvss_dropped"}, mut: setCVSS("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), check: notScored},
		{name: "threat metric", contract: ContractPentest, want: []string{"V5:bad_cvss_dropped"}, mut: setCVSS(cvssCritical + "/E:A"), check: notScored},
		{name: "environmental metric", contract: ContractPentest, want: []string{"V5:bad_cvss_dropped"}, mut: setCVSS(cvssCritical + "/CR:H"), check: notScored},
		{name: "missing metrics", contract: ContractPentest, want: []string{"V5:bad_cvss_dropped"}, mut: setCVSS("CVSS:4.0/AV:N/AC:L/AT:N"), check: notScored},
		{name: "metrics out of order", contract: ContractPentest, want: []string{"V5:bad_cvss_dropped"}, mut: setCVSS("CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), check: notScored},
		{name: "unknown value", contract: ContractPentest, want: []string{"V5:bad_cvss_dropped"}, mut: setCVSS("CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), check: notScored},
		{name: "lower case", contract: ContractPentest, want: []string{"V5:bad_cvss_dropped"}, mut: setCVSS(strings.ToLower(cvssCritical)), check: notScored},
		{name: "malformed part", contract: ContractPentest, want: []string{"V5:bad_cvss_dropped"}, mut: setCVSS("CVSS:4.0/AV"), check: notScored},
		{name: "too long", contract: ContractPentest, want: []string{"V5:bad_cvss_dropped"}, mut: setCVSS(cvssCritical + strings.Repeat("/AV:N", 40)), check: notScored},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidateCVSSRefusalNeverEchoesTheVector(t *testing.T) {
	const secret = "CVSS:4.0/AV:N/ZZ:sk-live-0123456789abcdef"
	data := edit(t, basePentest, func(m map[string]any) { finding(m, 0)["cvss"] = secret })
	r := Validate(data, optsFor(ContractPentest))
	var found bool
	for _, is := range r.Report.Issues {
		if is.Code != "bad_cvss_dropped" {
			continue
		}
		found = true
		if strings.Contains(is.Message, "sk-live") || strings.Contains(is.Message, "ZZ") {
			t.Errorf("the issue repeats the vector: %q", is.Message)
		}
		if is.Severity != SevDropped || is.Row != "V5" {
			t.Errorf("issue = %+v", is)
		}
		if !strings.Contains(is.Message, "keeps its likelihood and impact rating") {
			t.Errorf("the issue does not say the rating stays: %q", is.Message)
		}
	}
	if !found {
		t.Fatalf("no bad_cvss_dropped issue: %s", issueCodes(r.Report))
	}
	if r.PT.Findings[0].CVSS != "" {
		t.Error("the vector was kept")
	}
}

func TestValidateCVSSEveryParserCodeHasAWordAndWordsDoNotRepeat(t *testing.T) {
	codes := []cvss4.ErrorCode{cvss4.CodeEmpty, cvss4.CodeTooLong, cvss4.CodeBadPrefix, cvss4.CodeBadSyntax, cvss4.CodeNotBase, cvss4.CodeBadMetric, cvss4.CodeMissingMetric, cvss4.CodeBadValue}
	if len(cvssRefusal) != len(codes) {
		t.Errorf("%d phrases for %d parser codes", len(cvssRefusal), len(codes))
	}
	seen := map[string]cvss4.ErrorCode{}
	for _, c := range codes {
		w, ok := cvssRefusal[c]
		if !ok || w == "" {
			t.Errorf("no phrase for parser code %q", c)
		}
		if other, dup := seen[w]; dup {
			t.Errorf("codes %q and %q share the phrase %q", c, other, w)
		}
		seen[w] = c
	}
}

func TestCVSSVectorOnAnItemThatIsRefusedDoesNotLeakIntoTheModel(t *testing.T) {
	// A finding refused at V5 for its rating is gone with its vector.
	r := Validate(edit(t, basePentest, func(m map[string]any) {
		f := finding(m, 0)
		f["cvss"], f["rating"] = cvssCritical, map[string]any{"likelihood": 9, "impact": 1}
	}), optsFor(ContractPentest))
	if r.Report.State != ValidationPartial || len(r.PT.Findings) != 0 {
		t.Fatalf("state %s, %d findings", r.Report.State, len(r.PT.Findings))
	}
}

func TestApplyCVSSAndTheScoreV10GivesAnUnvettedVector(t *testing.T) {
	f := PTFinding{CVSS: "not a vector", CVSSBand: BandHigh}
	score := 3.0
	f.CVSSScore = &score
	if err := applyCVSS(&f); err == nil {
		t.Fatal("an invalid vector scored")
	}
	if f.CVSSScore != nil || f.CVSSBand != "" {
		t.Errorf("the old score and band were kept: %v %q", f.CVSSScore, f.CVSSBand)
	}
	// Row V10 on a vector V5 did not see: dropped with an issue, not shown.
	v := newValidator(nil, ValidateOptions{})
	v.pt = &PentestDoc{Findings: []PTFinding{{ID: "F-9", Rating: Rating{Likelihood: 2, Impact: 2}, CVSS: "not a vector"}}}
	ruleV10(v)
	got := v.pt.Findings[0]
	if got.CVSS != "" || got.CVSSScore != nil {
		t.Errorf("the finding keeps an unscored vector: %q %v", got.CVSS, got.CVSSScore)
	}
	if !hasIssue(v.rep, "V10", "cvss_not_scored") {
		t.Errorf("no cvss_not_scored issue: %s", issueCodes(v.rep))
	}
	if got.Band != BandLow {
		t.Errorf("band = %q", got.Band)
	}
}

func TestScoreCVSSBandMapping(t *testing.T) {
	for _, c := range []struct {
		vector string
		score  string
		band   Band
	}{
		{cvssCritical, "9.3", BandCritical},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H", "7.9", BandHigh},
		{cvssMedium, "5.2", BandMedium},
		{"CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", "1.0", BandLow},
		{cvssNone, "0.0", ""},
	} {
		score, band, err := ScoreCVSS(c.vector)
		if err != nil || FormatCVSSScore(score) != c.score || band != c.band {
			t.Errorf("ScoreCVSS(%s) = %s %q %v, want %s %q", c.vector, FormatCVSSScore(score), band, err, c.score, c.band)
		}
	}
	if _, _, err := ScoreCVSS("CVSS:4.0/AV:N"); err == nil {
		t.Error("a short vector scored")
	}
}

func TestCVSSStoredScoreIsNeverTrustedByTheExport(t *testing.T) {
	// A stored copy that says 10.0 for a medium vector: the export scores the
	// vector itself.
	score := 10.0
	f := PTFinding{
		ID: "F-1", Title: "t", Category: "ATHN", Rating: Rating{Likelihood: 3, Impact: 3}, Basis: "observed",
		CVSS: cvssMedium, CVSSScore: &score, CVSSBand: BandCritical,
	}
	line := mdCVSS(f)
	if !strings.Contains(line, "base score 5.2 (medium)") || strings.Contains(line, "10.0") || strings.Contains(line, "critical") {
		t.Errorf("line = %q", line)
	}
	if !strings.Contains(line, CVSSNote) {
		t.Errorf("the line lacks the base-score sentence: %q", line)
	}
	if !strings.Contains(line, CVSSApart) {
		t.Errorf("the line lacks the sentence that says it is apart from the band: %q", line)
	}
	// 0.0 keeps the vector and the score and says it has no band.
	f.CVSS = cvssNone
	if line := mdCVSS(f); !strings.Contains(line, "base score 0.0 (no band)") || !strings.Contains(line, mdText(cvssNone)) {
		t.Errorf("line = %q", line)
	}
	// A vector Observer cannot score is shown as the agent's, without a score.
	f.CVSS = "junk"
	if line := mdCVSS(f); !strings.Contains(line, "could not score it") || strings.Contains(line, "base score") || strings.Contains(line, CVSSApart) {
		t.Errorf("line = %q (no score, so nothing to set apart from the band)", line)
	}
	f.CVSS = ""
	if mdCVSS(f) != "" {
		t.Error("a finding with no vector has a CVSS line")
	}
}

func TestMarkdownExportCarriesTheCVSSLine(t *testing.T) {
	r := validated(t, ContractPentest, testProject(), setCVSS(cvssCritical))
	out := RenderMarkdown(exMeta(PentestLocal), r)
	for _, want := range []string{
		"CVSS 4.0 base vector, as the agent wrote it: " + mdText(cvssCritical),
		"base score 9.3 (critical), computed by Observer from the vector. " + CVSSNote + " " + CVSSApart,
		"Rating: likelihood 4, impact 3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the export lacks %q", want)
		}
	}
	// A finding with no vector has no CVSS line.
	if bare := RenderMarkdown(exMeta(PentestLocal), validated(t, ContractPentest, testProject(), nil)); strings.Contains(bare, "CVSS 4.0 base vector, as the agent wrote it") {
		t.Error("an export with no vector has a CVSS line")
	}
}

func TestJSONExportKeepsAZeroScore(t *testing.T) {
	r := validated(t, ContractPentest, testProject(), setCVSS(cvssNone))
	b, err := json.Marshal(r.PT.Findings[0])
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"cvss":"`+cvssNone+`"`) || !strings.Contains(s, `"cvss_score":0`) || strings.Contains(s, "cvss_band") {
		t.Errorf("finding JSON = %s", s)
	}
}

func TestCVSSDoesNotChangeWhatAnImportCarries(t *testing.T) {
	plain := validated(t, ContractPentest, testProject(), nil)
	rated := validated(t, ContractPentest, testProject(), setCVSS(cvssCritical))
	a := DeriveSARIF(plain, DeriveOptions{Tag: "pt", RunID: modelRun, Dedup: true})
	b := DeriveSARIF(rated, DeriveOptions{Tag: "pt", RunID: modelRun, Dedup: true})
	if a.Kept == 0 {
		t.Fatal("the baseline finding derives nothing: the test proves nothing")
	}
	if string(a.Doc) != string(b.Doc) {
		t.Errorf("a CVSS vector changed the derived SARIF:\n%s\n%s", a.Doc, b.Doc)
	}
	// The band, and so the level, is the likelihood-times-impact one: a critical
	// CVSS vector on a finding rated 4 x 3 stays a medium-or-lower risk band.
	if rated.PT.Findings[0].Band != BandOf(Rating{Likelihood: 4, Impact: 3}) {
		t.Errorf("band = %q", rated.PT.Findings[0].Band)
	}
	if strings.Contains(strings.ToLower(string(b.Doc)), "cvss") {
		t.Error("the derived SARIF mentions CVSS")
	}
}

func TestCVSSIsKeptByTheDisplayRedactionAndItsScoreIsComputed(t *testing.T) {
	r := validated(t, ContractPentest, testProject(), setCVSS(cvssMedium))
	out, _ := RedactResult(r, func(s string) string { return strings.ReplaceAll(s, "CVSS", "[x]") })
	if got := out.PT.Findings[0].CVSS; got != cvssMedium {
		t.Errorf("redaction changed the vector: %q", got)
	}
	if s := out.PT.Findings[0].CVSSScore; s == nil || *s != 5.2 {
		t.Errorf("redaction lost the score: %v", s)
	}
}

// TestCVSSApartMatchesTheWeb pins what the export's sentence and the view's
// share: the band is the agent's likelihood times impact, and neither reading
// changes the other. Only the place the band is named differs ("in the table"
// on the web, "in the rating above" in the export).
func TestCVSSApartMatchesTheWeb(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "lib", "secAssessModel.ts"))
	if err != nil {
		t.Skipf("the web sources are not in this tree: %v", err)
	}
	m := regexp.MustCompile(`export const CVSS_APART\s*=\s*("(?:[^"\
]|\.)*");`).FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("CVSS_APART was not found in secAssessModel.ts")
	}
	var web string
	if err := json.Unmarshal([]byte(m[1]), &web); err != nil {
		t.Fatal(err)
	}
	const tail = "which is the agent's likelihood times impact. Neither changes the other."
	for name, got := range map[string]string{"web": web, "export": CVSSApart} {
		if !strings.HasPrefix(strings.ToLower(got), "this is a separate reading from the band") || !strings.HasSuffix(got, tail) {
			t.Errorf("%s sentence %q does not share the pinned tail %q", name, got, tail)
		}
	}
}

func TestCVSSNoteMatchesTheWeb(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "lib", "secAssessModel.ts"))
	if err != nil {
		t.Skipf("the web sources are not in this tree: %v", err)
	}
	m := regexp.MustCompile(`export const CVSS_NOTE\s*=\s*("(?:[^"\\\n]|\\.)*");`).FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("CVSS_NOTE was not found in secAssessModel.ts")
	}
	var got string
	if err := json.Unmarshal([]byte(m[1]), &got); err != nil {
		t.Fatal(err)
	}
	if got != CVSSNote {
		t.Errorf("CVSS_NOTE\n web: %q\n  Go: %q", got, CVSSNote)
	}
}

func TestCVSSIsInTheSchemaExampleAndTheRulesOnlyForAPenTest(t *testing.T) {
	for _, helper := range []bool{true, false} {
		b, err := SchemaBlock(SchemaInput{Contract: ContractPentest, RunID: modelRun, PromptVersion: "pt.7", Helper: helper})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(b, `"cvss":"`+cvssExampleVector+`"`) || !strings.Contains(b, "cvss: optional, base metrics only.") {
			t.Errorf("helper %v: the pen test block lacks the vector or its rule", helper)
		}
	}
	tm, err := SchemaBlock(SchemaInput{Contract: ContractThreatModel, RunID: modelRun, PromptVersion: "tm.7"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(tm), "cvss") {
		t.Error("the threat model block mentions CVSS")
	}
	// The example's vector is itself a valid base vector.
	if _, err := cvss4.Parse(cvssExampleVector); err != nil {
		t.Errorf("the example vector: %v", err)
	}
}
