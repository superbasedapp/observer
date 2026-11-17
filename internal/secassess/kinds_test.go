package secassess

import (
	"slices"
	"strings"
	"testing"
)

// TestKindTable: one row per kind pins what the table says about it.
func TestKindTable(t *testing.T) {
	cases := []struct {
		id         ID
		tag        string
		launchable bool
		sandbox    SandboxPolicy
		target     TargetPolicy
		files      []string
		mode       string
	}{
		{ThreatModel, "tm", true, SandboxOptional, TargetNone, []string{FileReport, FileAssessment}, "Read-only"},
		{PentestLocal, "pt", true, SandboxRequired, TargetRequired, []string{FileReport, FileAssessment}, "Sandboxed"},
		{RedTeamLocal, "rt", true, SandboxRequired, TargetRequired, []string{FileReport, FileAssessment}, "Sandboxed"},
		{PentestRetest, "prt", true, SandboxRequired, TargetRequired, []string{FileReport, FileAssessment}, "Sandboxed"},
		{CSPMReadonly, "cspm", true, SandboxOptional, TargetNone, []string{FileReport, FileSARIF, FileCommands}, "Your cloud session"},
		{IASTInstrumentedTests, "iast", true, SandboxOptional, TargetNone, []string{FileReport, FileSARIF}, "Partial"},
		{RASP, "rasp", false, SandboxNA, TargetNone, nil, "Not agent-shaped"},
	}
	if got := len(Kinds()); got != len(cases) {
		t.Fatalf("%d kinds in the table, %d rows here", got, len(cases))
	}
	for _, tc := range cases {
		t.Run(string(tc.id), func(t *testing.T) {
			k, ok := KindByID(string(tc.id))
			if !ok {
				t.Fatal("kind missing")
			}
			if k.Tag != tc.tag || k.Launchable != tc.launchable || k.Sandbox != tc.sandbox || k.Target != tc.target || k.Mode != tc.mode {
				t.Errorf("kind = %+v", k)
			}
			if !slices.Equal(k.Files, tc.files) {
				t.Errorf("files = %v, want %v", k.Files, tc.files)
			}
			if k.Title == "" || k.Summary == "" {
				t.Error("no title or summary")
			}
			if tc.launchable {
				if k.Role == "" || (len(k.Steps) == 0 && len(k.Method) == 0) || len(k.Headings) == 0 || k.Note == "" {
					t.Errorf("a launchable kind lacks its words: %+v", k)
				}
				if k.Reason != "" || k.Pointer != "" {
					t.Error("a launchable kind carries a not-launchable reason")
				}
			} else if k.Reason == "" || k.Pointer == "" || k.Role != "" || len(k.Steps) != 0 || len(k.Method) != 0 {
				t.Errorf("a non-launchable kind must carry a reason and a pointer only: %+v", k)
			}
		})
	}
}

// TestRASPRowIsHonest: the runtime-protection row says why there is no launch
// and points at the runtime observability feature without claiming it is RASP,
// in words a developer reads: no package path and no plane name (the design
// system's copy rules: a UI text never names an internal component).
func TestRASPRowIsHonest(t *testing.T) {
	k, _ := KindByID(string(RASP))
	if !strings.Contains(k.Reason, "deployed application") {
		t.Errorf("reason = %q", k.Reason)
	}
	if !strings.Contains(k.Pointer, "not application self-protection") {
		t.Errorf("pointer = %q", k.Pointer)
	}
	for _, leak := range []string{"internal/", "Plane A", "Plane B", "obs)"} {
		if strings.Contains(k.Pointer, leak) || strings.Contains(k.Reason, leak) {
			t.Errorf("the row's words name an internal component (%q): %q", leak, k.Pointer)
		}
	}
	v := Eligible(RASP, Facts{ProjectOnDisk: true}, Request{Kind: RASP})
	if v.OK || v.Code != CodeNotLaunchable || v.Rule != "E1" || v.Reason != k.Reason {
		t.Errorf("verdict = %+v", v)
	}
}

// TestKindsAreUnique: ids and tags never repeat (a tag is part of a rule id).
func TestKindsAreUnique(t *testing.T) {
	ids, tags := map[ID]bool{}, map[string]bool{}
	for _, k := range Kinds() {
		if ids[k.ID] || tags[k.Tag] {
			t.Errorf("duplicate %s / %s", k.ID, k.Tag)
		}
		ids[k.ID], tags[k.Tag] = true, true
		if strings.ContainsAny(k.Tag, "./ ") || k.Tag == "" {
			t.Errorf("tag %q is not rule-id safe", k.Tag)
		}
	}
	if _, ok := KindByID("nope"); ok {
		t.Error("an unknown id resolved")
	}
}

// TestIASTIsLabelledPartial: the instrumented tests kind never reads as full
// IAST, anywhere its words appear.
func TestIASTIsLabelledPartial(t *testing.T) {
	k, _ := KindByID(string(IASTInstrumentedTests))
	for name, s := range map[string]string{"title": k.Title, "summary": k.Summary, "note": k.Note} {
		if !strings.Contains(strings.ToLower(s), "not full iast") {
			t.Errorf("%s = %q lacks the partial label", name, s)
		}
	}
	found := false
	for _, h := range k.Headings {
		if strings.Contains(h, "not full IAST") {
			found = true
		}
	}
	if !found {
		t.Error("the report headings lack the limits heading")
	}
}

// TestKindResultContractColumns: the contract, the SARIF source, the files and
// the prompt version of a kind agree, one row per kind.
func TestKindResultContractColumns(t *testing.T) {
	cases := []struct {
		id      ID
		cont    Contract
		source  SARIFSource
		version string
		sarif   bool
	}{
		{ThreatModel, ContractThreatModel, SARIFDerived, "tm.7", false},
		{PentestLocal, ContractPentest, SARIFDerived, "pt.7", false},
		{RedTeamLocal, ContractPentest, SARIFDerived, "pt.7", false},
		{CSPMReadonly, "", SARIFAgentFile, "", true},
		{IASTInstrumentedTests, "", SARIFAgentFile, "", true},
		{RASP, "", SARIFNone, "", false},
	}
	for _, tc := range cases {
		k, ok := KindByID(string(tc.id))
		if !ok {
			t.Fatalf("%s missing", tc.id)
		}
		if k.Contract != tc.cont || k.SARIFSource != tc.source || k.PromptVersion != tc.version {
			t.Errorf("%s: contract %q source %q version %q", tc.id, k.Contract, k.SARIFSource, k.PromptVersion)
		}
		if k.HasFile(FileSARIF) != tc.sarif {
			t.Errorf("%s: HasFile(sarif) = %v, want %v", tc.id, k.HasFile(FileSARIF), tc.sarif)
		}
		if k.ModelContract() != (tc.cont != "") || k.HasFile(FileAssessment) != k.ModelContract() {
			t.Errorf("%s: model contract and the assessment file disagree", tc.id)
		}
		if k.HasSARIF() != (tc.source != SARIFNone) {
			t.Errorf("%s: HasSARIF = %v", tc.id, k.HasSARIF())
		}
		// A kind whose findings are derived writes no SARIF of its own.
		if k.SARIFSource == SARIFDerived && k.HasFile(FileSARIF) {
			t.Errorf("%s: derives its SARIF and also lists the agent's file", tc.id)
		}
	}
}

// TestKindStepsOrMethod: a launchable kind carries its work as Steps or as a
// Method, never both (a kind with a Method renders it in place of Steps, so
// leftover Steps would be text nobody reads and that can drift from the
// method), and a kind with no launch carries neither.
func TestKindStepsOrMethod(t *testing.T) {
	for _, k := range Kinds() {
		t.Run(string(k.ID), func(t *testing.T) {
			switch {
			case !k.Launchable:
				if len(k.Steps) != 0 || len(k.Method) != 0 {
					t.Errorf("a kind with no launch carries steps (%d) or a method (%d)", len(k.Steps), len(k.Method))
				}
			case len(k.Method) > 0:
				if len(k.Steps) != 0 {
					t.Errorf("%d Steps are never rendered because Method is set", len(k.Steps))
				}
			default:
				if len(k.Steps) == 0 {
					t.Error("a launchable kind with no Method has no Steps")
				}
			}
		})
	}
}

// TestOtherRunsBoundary: every launchable kind's task tells the agent to leave
// other assessments' folders alone, with the folder named (depth plan D24: the
// earlier runs' files sit in the project folder the agent is told to read).
func TestOtherRunsBoundary(t *testing.T) {
	if !strings.Contains(otherRunsBoundary, ".observer/assessments/") || !strings.Contains(otherRunsBoundary, "your own run directory") {
		t.Fatalf("the boundary names neither the folder nor the run's own directory: %q", otherRunsBoundary)
	}
	if len(otherRunsBoundary) > 200 {
		t.Errorf("the boundary row is %d bytes: it is one short row", len(otherRunsBoundary))
	}
	if !slices.Contains(commonBoundary, otherRunsBoundary) {
		t.Fatal("the row is not in the common boundary")
	}
	target, _ := ParseTarget("http://localhost:3000/")
	for _, k := range Kinds() {
		if !k.Launchable {
			continue
		}
		in := PromptInput{Kind: k.ID, RunID: testRun, ProjectName: "p"}
		if k.Target == TargetRequired {
			in.Target = &target
		}
		if k.Retest {
			in.Replay = testReplayBasis()
		}
		p, err := BuildPrompt(in)
		if err != nil {
			t.Fatalf("%s: %v", k.ID, err)
		}
		if !strings.Contains(p, otherRunsBoundary) {
			t.Errorf("%s: the prompt lacks the other-runs boundary", k.ID)
		}
		if !slices.Contains(k.BoundaryLines(), otherRunsBoundary) {
			t.Errorf("%s: the plan dialog's boundary list lacks the row", k.ID)
		}
	}
}
