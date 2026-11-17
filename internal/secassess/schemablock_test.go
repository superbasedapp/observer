package secassess

import (
	"strings"
	"testing"
)

// TestSchemaExampleIsAValidModel: the example the prompt carries passes the
// validator with no item refused, left out or dropped, so the words of the
// prompt cannot drift from the rules. Run through the project the fixtures
// point into, the example's references are found and each yields one
// importable finding.
func TestSchemaExampleIsAValidModel(t *testing.T) {
	cases := []struct {
		name string
		in   SchemaInput
		tag  string
	}{
		{"threat model", SchemaInput{Contract: ContractThreatModel, RunID: modelRun, PromptVersion: "tm.2"}, "tm"},
		{"pen test", SchemaInput{Contract: ContractPentest, RunID: modelRun, PromptVersion: "pt.2", TargetURL: "http://localhost:3000/"}, "pt"},
		{"pen test with the helper", SchemaInput{Contract: ContractPentest, RunID: modelRun, PromptVersion: "pt.2", TargetURL: "http://localhost:3000/", Helper: true}, "pt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ex := SchemaExample(tc.in)
			if ex == "" || strings.Contains(ex, "RUNID") || strings.Contains(ex, "PVER") || strings.Contains(ex, "TARGET") {
				t.Fatalf("example = %q", ex)
			}
			o := optsFor(tc.in.Contract)
			o.TargetURL = tc.in.TargetURL
			res := Validate([]byte(ex), o)
			if res.Report.State != ValidationValid {
				t.Fatalf("state %s: %s", res.Report.State, issueCodes(res.Report))
			}
			for _, is := range res.Report.Issues {
				if is.Severity != SevWarn {
					t.Errorf("issue %s %s (%s): %s", is.Row, is.Code, is.Severity, is.Message)
				}
			}
			if res.Report.Ignored != 0 {
				t.Errorf("the example carries %d fields the validator ignores: %v", res.Report.Ignored, res.Report.IgnoredKeys)
			}
			if res.Report.Refs.Found == 0 || res.Report.Refs.Missing+res.Report.Refs.Invalid+res.Report.Refs.ClaimedNotFound != 0 {
				t.Errorf("refs = %+v", res.Report.Refs)
			}
			d := DeriveSARIF(res, DeriveOptions{Tag: tc.tag, RunID: modelRun})
			if d.Kept != 1 || d.Doc == nil {
				t.Errorf("the example derives %d findings, want 1 (%+v)", d.Kept, d.Excluded)
			}
		})
	}
}

// TestSchemaBlockBudget pins the block's size under the plan's caps (3.0 KiB
// for a penetration test, 4.0 KiB for a threat model), with every optional
// line on.
func TestSchemaBlockBudget(t *testing.T) {
	cases := []struct {
		c        Contract
		cap      int
		exercise bool
	}{{ContractThreatModel, 4 << 10, false}, {ContractPentest, 3 << 10, false}, {ContractPentest, 3 << 10, true}, {ContractRetest, 2 << 10, false}}
	for _, tc := range cases {
		fw, _ := ResolvePreset(FrameworkPresets, "all")
		ex, _ := ResolvePreset(MethodExtraPresets, "both")
		cat, _ := ResolvePreset(CategoryPresets, "all")
		b, err := SchemaBlock(SchemaInput{Contract: tc.c, RunID: modelRun, PromptVersion: "x.2", TargetURL: "http://localhost:3000/", Frameworks: fw, MethodExtras: ex, Categories: cat, Exercise: tc.exercise})
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > tc.cap {
			t.Errorf("%s (exercise %v): %d bytes, cap %d", tc.c, tc.exercise, len(b), tc.cap)
		}
	}
}

// TestSchemaBlockWordsAreTheVocab: every closed word the validator accepts
// appears in the block, because the lists are generated from the same tables.
func TestSchemaBlockWordsAreTheVocab(t *testing.T) {
	fw, _ := ResolvePreset(FrameworkPresets, "all")
	b, err := SchemaBlock(SchemaInput{Contract: ContractThreatModel, RunID: modelRun, PromptVersion: "tm.2", Frameworks: fw})
	if err != nil {
		t.Fatal(err)
	}
	for _, list := range [][]string{
		idsOfComponentTypes(), idsOfStride(), idsOfLinddun(),
		EnumActorKind, EnumSensitivity, EnumEntryKind, EnumAuthn, EnumExposure, EnumEncrypted, EnumElementKind, EnumThreatState, EnumEffort, EnumTreeOp,
	} {
		for _, w := range list {
			if !strings.Contains(b, w) {
				t.Errorf("the block lacks the word %q", w)
			}
		}
	}
	p, err := SchemaBlock(SchemaInput{Contract: ContractPentest, RunID: modelRun, PromptVersion: "pt.2"})
	if err != nil {
		t.Fatal(err)
	}
	line := categoriesLine(t, p)
	for _, c := range WSTGCategories {
		if !strings.Contains(line, c.ID) {
			t.Errorf("the block lacks the category %q", c.ID)
		}
	}
	for _, w := range append(append(append([]string(nil), EnumCoverageStatus...), EnumBasis...), EnumFindingState...) {
		if !strings.Contains(p, w) {
			t.Errorf("the block lacks the word %q", w)
		}
	}
}

// TestSchemaBlockFollowsTheSets: a setting changes the lines the block asks
// for, never the shape.
func TestSchemaBlockFollowsTheSets(t *testing.T) {
	build := func(c Contract, mut func(*SchemaInput)) string {
		in := SchemaInput{Contract: c, RunID: modelRun, PromptVersion: "x.2"}
		mut(&in)
		b, err := SchemaBlock(in)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	stride, _ := ResolvePreset(FrameworkPresets, "stride")
	b := build(ContractThreatModel, func(in *SchemaInput) { in.Frameworks = stride })
	for _, no := range []string{"framework linddun", "owasp_llm", "owasp_agentic", "an abuse_case on the five", "an attack_trees entry"} {
		if strings.Contains(b, no) {
			t.Errorf("stride only still names %q", no)
		}
	}
	both, _ := ResolvePreset(MethodExtraPresets, "both")
	all, _ := ResolvePreset(FrameworkPresets, "all")
	b = build(ContractThreatModel, func(in *SchemaInput) { in.Frameworks, in.MethodExtras = all, both })
	for _, yes := range []string{"framework linddun", "owasp_llm", "owasp_agentic", "an abuse_case on the five", "an attack_trees entry"} {
		if !strings.Contains(b, yes) {
			t.Errorf("the full sets lack %q", yes)
		}
	}
	auth, _ := ResolvePreset(CategoryPresets, "auth_access")
	b = build(ContractPentest, func(in *SchemaInput) { in.Categories = auth })
	line := categoriesLine(t, b)
	for _, c := range []string{"IDNT", "ATHN", "ATHZ", "SESS"} {
		if !strings.Contains(line, c) {
			t.Errorf("the auth preset lacks %q", c)
		}
	}
	for _, c := range []string{"INFO", "CRYP", "APIT", "INPV"} {
		if strings.Contains(line, c) {
			t.Errorf("the auth preset still asks for %q", c)
		}
	}
}

// categoriesLine returns the line of a penetration test block that lists the
// categories the run asks for.
func categoriesLine(t *testing.T, block string) string {
	t.Helper()
	for _, l := range strings.Split(block, "\n") {
		if strings.HasPrefix(l, "- categories, one coverage entry each") {
			return l
		}
	}
	t.Fatal("the block has no categories line")
	return ""
}

// TestSchemaBlockFollowsTheHelper: the helper changes the words about probe ids
// and the example's indicator, and nothing else of the shape.
func TestSchemaBlockFollowsTheHelper(t *testing.T) {
	build := func(helper bool) string {
		b, err := SchemaBlock(SchemaInput{Contract: ContractPentest, RunID: modelRun, PromptVersion: "pt.7", Helper: helper})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	off, on := build(false), build(true)
	for _, w := range []string{`"indicator"`, "indicator.when takes", "header_contains"} {
		if strings.Contains(off, w) {
			t.Errorf("the block without the helper names %q", w)
		}
		if !strings.Contains(on, w) {
			t.Errorf("the block with the helper lacks %q", w)
		}
	}
	if !strings.Contains(off, "your own short names") || strings.Contains(on, "your own short names") {
		t.Error("the probe id words do not follow the helper")
	}
}

// TestSchemaBlockRefusesAKindWithoutAModel: a SARIF contract has no block.
func TestSchemaBlockRefusesAKindWithoutAModel(t *testing.T) {
	for _, c := range []Contract{"", ContractSARIF} {
		if b, err := SchemaBlock(SchemaInput{Contract: c, RunID: modelRun}); err == nil || b != "" {
			t.Errorf("contract %q: block %q, err %v", c, b, err)
		}
	}
}

// TestSchemaExampleTargetIsClean: a target that carries a quote or a newline
// cannot break the JSON of the example.
func TestSchemaExampleTargetIsClean(t *testing.T) {
	ex := SchemaExample(SchemaInput{Contract: ContractPentest, RunID: modelRun, PromptVersion: "pt.2", TargetURL: "http://h:1/\"},\n{\"x\":1"})
	res := Validate([]byte(ex), DefaultValidateOptions(ContractPentest, modelRun))
	if res.Report.State == ValidationInvalid {
		t.Errorf("the example is no longer JSON: %s", res.Report.Fatal)
	}
}
