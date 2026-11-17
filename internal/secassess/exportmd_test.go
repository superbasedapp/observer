package secassess

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// exMeta is the export metadata the fixtures render with.
func exMeta(kind ID) ExportMeta {
	return ExportMeta{
		RunID: modelRun, Kind: kind, Project: "Shop",
		ValidatedAt: time.Date(2026, 11, 14, 8, 45, 0, 0, time.UTC),
		SourceSHA:   "a1b2c3d4e5f60718", RedactionOn: true, Hidden: 2,
	}
}

// exTM and exPT validate the baseline documents (after an optional edit) into
// the checked results the renderer takes.
func exTM(t *testing.T, fn func(m map[string]any)) Result {
	t.Helper()
	if fn == nil {
		fn = func(map[string]any) {}
	}
	res := rdValidated(t, ContractThreatModel, baseThreatModel, fn)
	if res.TM == nil {
		t.Fatalf("the threat model was refused: %+v", res.Report)
	}
	return res
}

func exPT(t *testing.T, fn func(m map[string]any)) Result {
	t.Helper()
	if fn == nil {
		fn = func(map[string]any) {}
	}
	res := rdValidated(t, ContractPentest, basePentest, fn)
	if res.PT == nil {
		t.Fatalf("the pen test was refused: %+v", res.Report)
	}
	return res
}

// exInOrder fails when the needles do not appear in the output in this order.
func exInOrder(t *testing.T, out string, needles ...string) {
	t.Helper()
	at := 0
	for _, n := range needles {
		i := strings.Index(out[at:], n)
		if i < 0 {
			t.Errorf("%q is not in the output after offset %d", n, at)
			continue
		}
		at += i + len(n)
	}
}

// exHas fails when the output lacks (or, with a "!" prefix, holds) a needle.
func exHas(t *testing.T, out string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if rest, absent := strings.CutPrefix(n, "!"); absent {
			if strings.Contains(out, rest) {
				t.Errorf("the output holds %q", rest)
			}
		} else if !strings.Contains(out, n) {
			t.Errorf("the output lacks %q", n)
		}
	}
}

// exLimitsPresent checks that every limit of the contract is in the output, in
// order, and that no limit of the other kind is.
func exLimitsPresent(t *testing.T, out string, c Contract) {
	t.Helper()
	i := strings.Index(out, "## What this does not tell you")
	if i < 0 {
		t.Fatal("the output has no limits section")
	}
	section := out[i:]
	var texts []string
	own := map[string]bool{}
	for _, l := range LimitsFor(c) {
		texts = append(texts, l.Text)
		own[l.ID] = true
	}
	exInOrder(t, section, texts...)
	for _, l := range HonestLimits {
		if !own[l.ID] && strings.Contains(out, l.Text) {
			t.Errorf("the output holds the limit %s, which is not for this contract", l.ID)
		}
	}
}

// TestRenderMarkdownThreatModel renders the checked baseline threat model and
// reads the document: sections in order, the numbers and words, and the limits
// of a threat model.
func TestRenderMarkdownThreatModel(t *testing.T) {
	res := exTM(t, nil)
	out := RenderMarkdown(exMeta(ThreatModel), res)
	exInOrder(t, out,
		"# Threat model: Shop", "## Reading", "## Validation", "## Summary", "## Scope", "## System",
		"### Components", "### Trust zones", "### Actors", "### Assets", "### Entry points", "### Flows",
		"## Threats", `### T\-1: Credential stuffing`, `### T\-2: Weak transport to the database`,
		"## Considered, no threat found", "## Attack trees", "## Open questions and the agent's own limits",
		"## Data-flow diagram", "```mermaid", "```", "## What this does not tell you")
	exHas(t, out,
		"Observer wrote this report from the checked copy of run "+modelRun+" that it kept.",
		"It was validated on 2026-11-14 08:45:00 UTC.",
		"The file that was checked has the fingerprint a1b2c3d4e5f60718.",
		"Secrets Observer recognises were hidden in 2 places of the text below.",
		"The agent wrote this, and Observer checked only its structure",
		"State: valid. The file was read and nothing was refused.",
		"2 threats in the model, all listed below: 0 critical, 1 high, 0 medium, 1 low.",
		"- Framework: STRIDE; category: Spoofing",
		"- Framework: STRIDE; category: Information disclosure",
		"- Element: component API (api)",
		"- Element: flow API to Database (f2)",
		"likelihood 4, impact 4 (the agent's ratings); band high, computed by Observer from the two ratings (score 16 of 25)",
		"The agent says: Login has no throttle"+`\.`,
		"Existing mitigations, as the agent says:",
		`Passwords are hashed\. Cited: cmd/api/main\.go\:20 (found near the cited line, the quoted text is on line 20).`,
		`(control: throttle; effort: s) Cited: cmd/api/main\.go\:12 (found near the cited line`,
		"Abuse case, as the agent says:", "- Goal: Take over an account",
		"| component Audit log (audit) | Repudiation | The audit log is append"+`\-`+"only"+`\.`+" |",
		"| Id | Name | Type | Zone |", "| api | API | Service or process | DMZ (dmz) |",
		"| f2 | API (api) | Database (db) | Credentials (creds) |",
		"- Guess a password (op: or; leaf)",
		"- Is there an admin console?",
		"Coverage as Observer counted it, by element and category: 2 element and category pairs with a threat, 1 element and category pair waived with a reason, and 25 element and category pairs with neither.",
		"| STRIDE | 2 | 1 | 18 |", "| LINDDUN | 0 | 0 | 7 |",
		"The agent's file names its generator as: tool claude"+`\-`+"code, model m, prompt version tm"+`\.`+"2.",
		"!Co-Authored")
	// The threats are listed highest score first.
	exInOrder(t, out, `### T\-1`, `### T\-2`)
	exLimitsPresent(t, out, ContractThreatModel)
	if strings.Contains(out, "\r") {
		t.Error("the document holds a carriage return")
	}
	if !strings.HasSuffix(out, "\n\n") && !strings.HasSuffix(out, "\n") {
		t.Error("the document does not end with a line break")
	}
}

// TestRenderMarkdownPenTest renders the checked baseline pen test.
func TestRenderMarkdownPenTest(t *testing.T) {
	res := exPT(t, func(m map[string]any) {
		f := finding(m, 0)
		f["indicator"] = map[string]any{"control": "p0", "attack": "p1"}
		f["evidence"] = []any{"p1", "p2"}
	})
	out := RenderMarkdown(exMeta(PentestLocal), res)
	exInOrder(t, out,
		"# Penetration test (your own app, local): Shop", "## Reading", "## Validation", "## Summary", "## Target",
		"## Coverage matrix", "## Findings", `### F\-1: No login throttle`, "## The agent's own limits", "## What this does not tell you")
	exHas(t, out,
		"Everything here is the agent's account of its own target. Observer does not see the target.",
		`- Address, as the agent says: http\://127\.0\.0\.1\:3000/`,
		"- Start command, as the agent says: npm run dev",
		"- The agent says the target started: yes (after 6 seconds)",
		"- Health check the agent says it used: path /health, status 200",
		"- Test accounts, by label only (no credential is kept): user1 (member)",
		"| Authentication (ATHN) | tested | tested claimed |",
		"| Weak cryptography (CRYP) | not applicable | not applicable | Loopback http only"+`\.`+" |",
		"| Information gathering (INFO) | no row | missing |  |",
		"- Category: Authentication (ATHN)",
		"band medium, computed by Observer from the two ratings (score 12 of 25)",
		"- Basis: the agent says it saw this in a request",
		`- Route, as the agent says: /login`,
		`- CWE, as the agent lists them: CWE\-307`,
		"- Probe ids of the attack and its control, as the agent names them: attack p1, control p0",
		"- Evidence ids, as the agent lists them: p1, p2",
		"- Status, as the agent says: open",
		"The agent says, about the impact: Account takeover"+`\.`,
		"The agent says, about the fix: Add a throttle"+`\.`,
		"- Step 1: Send 50 bad logins Request: POST /login",
		"- Only the dev server"+`\.`,
		"2 of 12 categories claimed, 0 with a logged request, 1 not applicable, 9 with no row",
		"1 finding in the model, all listed below: 0 critical, 0 high, 1 medium, 0 low.")
	exLimitsPresent(t, out, ContractPentest)
}

// TestRenderMarkdownPenTestVariants: the basis words, a target that did not
// start, an unknown basis, and a finding with nothing optional.
func TestRenderMarkdownPenTestVariants(t *testing.T) {
	tests := []struct {
		name string
		fn   func(m map[string]any)
		want []string
	}{
		{
			"inferred basis", func(m map[string]any) { finding(m, 0)["basis"] = "inferred" },
			[]string{"- Basis: the agent says it inferred this from the code"},
		},
		{"target not started", func(m map[string]any) {
			obj(obj(m["target"])["start"])["started"] = false
		}, []string{"- The agent says the target started: no", "skipped not started", "!the agent says it saw this in a request"}},
		{
			"no findings", func(m map[string]any) { m["findings"] = nil },
			[]string{"No finding is listed in this copy of the model.", "No weakness was reported in what was tested"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := RenderMarkdown(exMeta(PentestLocal), exPT(t, tc.fn))
			exHas(t, out, tc.want...)
		})
	}
	t.Run("an unknown basis is the agent's word, escaped", func(t *testing.T) {
		res := exPT(t, nil)
		res.PT.Findings[0].Basis = "dream_state *x*"
		exHas(t, RenderMarkdown(exMeta(PentestLocal), res), `- Basis: the agent gives the basis as: dream state \*x\*`)
		res.PT.Findings[0].Basis = ""
		exHas(t, RenderMarkdown(exMeta(PentestLocal), res), "- Basis: the agent gives no basis")
	})
}

// TestRenderMarkdownThreatModelVariants: a model with nothing in it says what
// the empty list means; a threat with no optional field renders; the waived
// section says so when empty.
func TestRenderMarkdownThreatModelVariants(t *testing.T) {
	t.Run("no threats", func(t *testing.T) {
		out := RenderMarkdown(exMeta(ThreatModel), exTM(t, func(m map[string]any) { m["threats"] = nil }))
		exHas(t, out, "No threat is listed in this copy of the model.", "No threat was recorded", "0 threats in the model",
			"is not proof that none exists")
	})
	t.Run("no waived pair and no tree", func(t *testing.T) {
		out := RenderMarkdown(exMeta(ThreatModel), exTM(t, func(m map[string]any) { m["no_threat"] = nil; m["attack_trees"] = nil }))
		exHas(t, out, "The agent listed no waived pair.", "!## Attack trees")
	})
	t.Run("a bare threat", func(t *testing.T) {
		res := exTM(t, nil)
		res.TM.Threats = []Threat{{ID: "T-9"}}
		out := RenderMarkdown(exMeta(ThreatModel), res)
		exHas(t, out, `### T\-9`, "no band, because the ratings are not both whole numbers from 1 to 5", "1 with no valid rating")
	})
	t.Run("a threat with no id and no title", func(t *testing.T) {
		res := exTM(t, nil)
		res.TM.Threats = []Threat{{}}
		exHas(t, RenderMarkdown(exMeta(ThreatModel), res), "### (no id)")
	})
	t.Run("a title with no id", func(t *testing.T) {
		res := exTM(t, nil)
		res.TM.Threats = []Threat{{Title: "Only a title"}}
		exHas(t, RenderMarkdown(exMeta(ThreatModel), res), "### Only a title")
	})
	t.Run("the stored band and score are used when present", func(t *testing.T) {
		res := exTM(t, nil)
		res.TM.Threats = []Threat{{ID: "T-1", Rating: Rating{Likelihood: 1, Impact: 1}, Band: BandCritical, Score: 25}}
		exHas(t, RenderMarkdown(exMeta(ThreatModel), res), "band critical, computed by Observer from the two ratings (score 25 of 25)")
	})
	t.Run("no scope and no agent lists", func(t *testing.T) {
		out := RenderMarkdown(exMeta(ThreatModel), exTM(t, func(m map[string]any) {
			delete(m, "scope")
			delete(m, "open_questions")
			delete(m, "limits")
		}))
		exHas(t, out, "!## Scope", "!## Open questions")
	})
}

// TestRenderMarkdownNamesAndWords: element names, categories and frameworks
// come from Observer's tables where they have the word, and are the agent's
// (escaped) where they do not.
func TestRenderMarkdownNamesAndWords(t *testing.T) {
	res := exTM(t, nil)
	tm := res.TM
	tm.System.EntryPoints[0].Kind = "http_route"
	tm.Threats = []Threat{
		{ID: "A", Framework: FrameworkSTRIDE, Category: "tampering", Element: Element{Kind: "entry_point", ID: "login"}, Actor: "user", Rating: Rating{Likelihood: 5, Impact: 5}},
		{ID: "B", Framework: FrameworkLINDDUN, Category: "linkability", Element: Element{Kind: "asset", ID: "creds"}, Rating: Rating{Likelihood: 5, Impact: 4}},
		{ID: "C", Framework: FrameworkOWASPLLM, Category: "LLM01", Element: Element{Kind: "actor", ID: "user"}, Rating: Rating{Likelihood: 4, Impact: 4}},
		{ID: "D", Framework: FrameworkOWASPAgentic, Category: "ASI04", Element: Element{Kind: "component", ID: "gone"}, Rating: Rating{Likelihood: 4, Impact: 3}},
		{ID: "E", Framework: "made_up", Category: "odd*cat", Element: Element{Kind: "zone", ID: "dmz"}, Rating: Rating{Likelihood: 2, Impact: 2}},
	}
	out := RenderMarkdown(exMeta(ThreatModel), res)
	exHas(t, out,
		"- Framework: STRIDE; category: Tampering",
		"- Element: entry point http route on API (login)",
		"- Actor: User (user)",
		"- Framework: LINDDUN; category: Linkability",
		"- Element: asset Credentials (creds)",
		"- Framework: OWASP Top 10 for LLM applications; category: LLM01",
		"- Element: actor User (user)",
		"- Framework: OWASP Top 10 for agentic applications; category: ASI04",
		"- Element: component gone",
		"- Framework: made up; category: odd"+`\*`+"cat",
		"- Element: zone dmz")
	// A waived pair names no framework, so its category is looked up in the
	// base frameworks' tables.
	tm.NoThreat = []NoThreat{
		{Element: Element{Kind: "flow", ID: "f1"}, Category: "non_repudiation", Reason: "r"},
		{Element: Element{Kind: "component", ID: "api"}, Category: "denial_of_service", Reason: "r"},
		{Element: Element{Kind: "component", ID: "api"}, Category: "LLM01", Reason: "r"},
	}
	out = RenderMarkdown(exMeta(ThreatModel), res)
	exHas(t, out, "| flow User to API (f1) | Non-repudiation | r |", "| component API (api) | Denial of service | r |", "| component API (api) | LLM01 | r |")
}

// TestRenderMarkdownSystemTables: every collection of the system is a table, a
// collection that is empty is not, the types use the type table, and ids that
// resolve show their name.
func TestRenderMarkdownSystemTables(t *testing.T) {
	res := exTM(t, nil)
	tm := res.TM
	tm.System.Components = append(tm.System.Components, Component{ID: "weird", Name: "Weird", Type: "mainframe_box", Zone: "nowhere", Tech: []string{"go", "c++"}, Description: "A | pipe"})
	tm.System.Assets[0].DataClasses = []string{"pii", "secrets"}
	out := RenderMarkdown(exMeta(ThreatModel), res)
	exHas(t, out,
		"| weird | Weird | mainframe box | nowhere | go, c"+`\+\+`+" |", "| A \\| pipe |",
		"| creds | Credentials | restricted | pii, secrets | Database (db) |",
		"| login | API (api) | http route | cmd/api/main"+`\.`+"go"+`\:`+"12 (location exists, nothing matched) | none | internet |")
	tm.System = System{}
	out = RenderMarkdown(exMeta(ThreatModel), res)
	exHas(t, out, "!### Components", "!### Flows", "## System")
}

// TestRenderMarkdownReportOnly: a result that kept only its report renders the
// report and says no model was kept; the reading still comes from the counts.
func TestRenderMarkdownReportOnly(t *testing.T) {
	counts := map[string]Count{"threats": {Read: 3, Refused: 3}}
	res := rdStoredTM(&TMCoverage{Analysed: 0, Waived: 2, Empty: 5}, counts)
	out := RenderMarkdown(exMeta(ThreatModel), res)
	exHas(t, out,
		"# Threat model: Shop", "## Model", "No model was kept in this copy", "The agent wrote 3 threats, and none is shown here",
		"State: partial.", "| threats | 3 | 0 | 3 | 0 |", "!## Threats", "!## System", "## What this does not tell you")
	exLimitsPresent(t, out, ContractThreatModel)
	pt := rdStoredPT(&PTCoverage{Started: true, Counts: map[string]int{CovTestedClaimed: 1}, Rows: make([]PTCoverageRow, 1)}, map[string]Count{"findings": {Read: 2, Kept: 2}})
	out = RenderMarkdown(exMeta(PentestLocal), pt)
	exHas(t, out, "No model was kept in this copy", "!## Findings", "!## Coverage matrix")
	exLimitsPresent(t, out, ContractPentest)
}

// TestRenderMarkdownRefusedFile: a file the validator refused renders its
// reason and the issue, and no model.
func TestRenderMarkdownRefusedFile(t *testing.T) {
	res := Validate([]byte("{nope"), optsFor(ContractThreatModel))
	out := RenderMarkdown(exMeta(ThreatModel), res)
	exHas(t, out, "State: invalid. The file was refused and no model was kept.", "The file was refused for this reason: not json.",
		"No model was kept in this copy", "| V2 | not\\_json | refused |", "Issues listed: 1.")
}

// TestRenderMarkdownReportlessResult: a result with no report at all (the zero
// value) still renders without a panic and says what it knows.
func TestRenderMarkdownReportlessResult(t *testing.T) {
	out := RenderMarkdown(ExportMeta{}, Result{})
	exHas(t, out, "# Security assessment", "an unnamed run", "at an unknown time", "State: not stated.", "No model was kept in this copy",
		"## What this does not tell you")
	exLimitsPresent(t, out, "")
}

// TestRenderMarkdownProvenance is the table of metadata and the sentences each
// value gives.
func TestRenderMarkdownProvenance(t *testing.T) {
	base := func(f func(m *ExportMeta)) ExportMeta {
		m := exMeta(ThreatModel)
		f(&m)
		return m
	}
	tests := []struct {
		name string
		meta ExportMeta
		want []string
	}{
		{"the baseline", base(func(m *ExportMeta) {}), []string{"validated on 2026-11-14 08:45:00 UTC.", "!before the run ended"}},
		{"an unknown time", base(func(m *ExportMeta) { m.ValidatedAt = time.Time{} }), []string{"It was validated at an unknown time.", "!1970", "!0001"}},
		{"a time in another zone is written in UTC", base(func(m *ExportMeta) {
			m.ValidatedAt = time.Date(2026, 11, 14, 23, 30, 0, 0, time.FixedZone("x", 5*3600))
		}), []string{"validated on 2026-11-14 18:30:00 UTC."}},
		{
			"validated before the run ended", base(func(m *ExportMeta) { m.Anyway = true }),
			[]string{"It was validated before the run ended, so the agent may not have finished writing the model."},
		},
		{"secrets hidden in one place", base(func(m *ExportMeta) { m.Hidden = 1 }), []string{"hidden in 1 place of the text below."}},
		{"secrets hidden in several places", base(func(m *ExportMeta) { m.Hidden = 40 }), []string{"hidden in 40 places of the text below."}},
		{
			"hiding on and nothing found", base(func(m *ExportMeta) { m.Hidden = 0 }),
			[]string{"Hiding recognised secrets was on, and Observer found none to hide in the text below.", "Only known secret shapes are recognised"},
		},
		{
			"hiding off", base(func(m *ExportMeta) { m.RedactionOn = false; m.Hidden = 0 }),
			[]string{"Hiding recognised secrets was off, so the text below is as stored and secrets Observer would recognise are not hidden.", "!were hidden in"},
		},
		{
			"hiding off with a stale count says nothing was hidden", base(func(m *ExportMeta) { m.RedactionOn = false; m.Hidden = 9 }),
			[]string{"secrets Observer would recognise are not hidden.", "!were hidden in"},
		},
		{"a run id that is not one", base(func(m *ExportMeta) { m.RunID = "../../etc/passwd" }), []string{"an unnamed run", "!etc/passwd"}},
		{"a short run id", base(func(m *ExportMeta) { m.RunID = "abc" }), []string{"an unnamed run", "!run abc"}},
		{"no run id", base(func(m *ExportMeta) { m.RunID = "" }), []string{"an unnamed run"}},
		{"a source fingerprint of one character", base(func(m *ExportMeta) { m.SourceSHA = "f" }), []string{"has the fingerprint f."}},
		{"an upper case fingerprint", base(func(m *ExportMeta) { m.SourceSHA = "ABCDEF" }), []string{"!fingerprint"}},
		{"a fingerprint that is too long", base(func(m *ExportMeta) { m.SourceSHA = "a1b2c3d4e5f607189" }), []string{"!fingerprint"}},
		{"a fingerprint with markup", base(func(m *ExportMeta) { m.SourceSHA = "ab<b>" }), []string{"!fingerprint", "!<b>"}},
		{"no fingerprint", base(func(m *ExportMeta) { m.SourceSHA = "" }), []string{"!fingerprint"}},
		{
			"a project name with markup", base(func(m *ExportMeta) { m.Project = "<img src=x> [a](b)\n# H" }),
			[]string{`# Threat model: &lt;img src\=x&gt; \[a\]\(b\) \# H`, "!<img"},
		},
		{"no project", base(func(m *ExportMeta) { m.Project = "" }), []string{"# Threat model\n", "!# Threat model:"}},
		{"a blank project", base(func(m *ExportMeta) { m.Project = " \n\t " }), []string{"# Threat model\n"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exHas(t, RenderMarkdown(tc.meta, exTM(t, nil)), tc.want...)
		})
	}
}

// TestRenderMarkdownKindTitles: the heading names the kind from the kind
// table, and falls back to the contract's plain name, then to a generic name.
func TestRenderMarkdownKindTitles(t *testing.T) {
	tests := []struct {
		name string
		kind ID
		res  func(t *testing.T) Result
		want string
	}{
		{"threat model", ThreatModel, func(t *testing.T) Result { return exTM(t, nil) }, "# Threat model: Shop\n"},
		{"pen test", PentestLocal, func(t *testing.T) Result { return exPT(t, nil) }, "# Penetration test (your own app, local): Shop\n"},
		{"red team", RedTeamLocal, func(t *testing.T) Result { return exPT(t, nil) }, "# Red team exercise (your own app, local): Shop\n"},
		{"an unknown kind with a threat model", "nope", func(t *testing.T) Result { return exTM(t, nil) }, "# Threat model: Shop\n"},
		{"an empty kind with a pen test", "", func(t *testing.T) Result { return exPT(t, nil) }, "# Penetration test: Shop\n"},
		{"an unknown kind and a SARIF contract", "nope", func(t *testing.T) Result { return Result{Report: Report{Contract: ContractSARIF}} }, "# Security assessment: Shop\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exHas(t, RenderMarkdown(exMeta(tc.kind), tc.res(t)), tc.want)
		})
	}
}

// TestRenderMarkdownContractFromTheModel: a result whose report names no
// contract reads the limits of the model it holds.
func TestRenderMarkdownContractFromTheModel(t *testing.T) {
	res := exPT(t, nil)
	res.Report.Contract = ""
	exLimitsPresent(t, RenderMarkdown(exMeta(PentestLocal), res), ContractPentest)
	res = exTM(t, nil)
	res.Report.Contract = ""
	exLimitsPresent(t, RenderMarkdown(exMeta(ThreatModel), res), ContractThreatModel)
	if exportContract(Result{}) != "" {
		t.Error("an empty result has no contract")
	}
}

// TestRefStateWord is the table of reference states and their words.
func TestRefStateWord(t *testing.T) {
	tests := []struct {
		state RefState
		want  string
	}{
		{RefFound, "found near the cited line"},
		{RefExists, "location exists, nothing matched"},
		{RefClaimedNotFound, "claimed, not found"},
		{RefUnchecked, "not checked"},
		{RefMissing, "cited place not found"},
		{RefInvalid, "cited place not found"},
		{"", "not checked"},
		{"something_new", "not checked"},
	}
	for _, tc := range tests {
		t.Run(string(tc.state), func(t *testing.T) {
			if got := refStateWord(tc.state); got != tc.want {
				t.Errorf("refStateWord(%q) = %q, want %q", tc.state, got, tc.want)
			}
		})
	}
	// Every state the validator can set has a row of its own.
	for _, s := range []RefState{RefFound, RefExists, RefClaimedNotFound, RefMissing, RefInvalid, RefUnchecked} {
		found := false
		for _, r := range refStateWords {
			found = found || r.State == s
		}
		if !found {
			t.Errorf("the state %q has no row", s)
		}
	}
}

// TestRenderMarkdownRefWords: a reference of each state reads with its words,
// and the document says nothing about a state it was not given.
func TestRenderMarkdownRefWords(t *testing.T) {
	res := exTM(t, nil)
	res.TM.Threats = []Threat{{ID: "T-1", Rating: Rating{Likelihood: 3, Impact: 3}, Existing: []Mitigation{
		{Text: "a", Refs: []Ref{{Path: "a.go", Line: 3, EndLine: 9, State: RefFound, MatchLine: 5}}},
		{Text: "b", Refs: []Ref{{Path: "b.go", Line: 3, State: RefExists}}},
		{Text: "c", Refs: []Ref{{Path: "c.go", State: RefClaimedNotFound}}},
		{Text: "d", Refs: []Ref{{Path: "d.go", State: RefUnchecked}}},
		{Text: "e", Refs: []Ref{{Path: "e.go", State: RefMissing}}},
		{Text: "f", Refs: []Ref{{Path: "f.go", State: RefInvalid}}},
		{Text: "g", Refs: []Ref{{Path: "g.go"}}},
		{Text: "h"},
	}}}
	out := RenderMarkdown(exMeta(ThreatModel), res)
	exHas(t, out,
		`- a Cited: a\.go\:3\-9 (found near the cited line, the quoted text is on line 5).`,
		`- b Cited: b\.go\:3 (location exists, nothing matched).`,
		`- c Cited: c\.go (claimed, not found).`,
		`- d Cited: d\.go (not checked).`,
		`- e Cited: e\.go (cited place not found).`,
		`- f Cited: f\.go (cited place not found).`,
		`- g Cited: g\.go (not checked).`,
		`- h Cited: no file or line cited.`)
}

// TestRenderMarkdownValidationReport: the counts, the reference tally, the
// ignored fields and every issue are written, with the issue messages escaped,
// and the number of issues the list did not keep.
func TestRenderMarkdownValidationReport(t *testing.T) {
	res := exTM(t, nil)
	res.Report.State = ValidationPartial
	res.Report.Refs = RefTally{Found: 4, Exists: 3, ClaimedNotFound: 2, Missing: 5, Invalid: 6, Unchecked: 7}
	res.Report.Ignored = 3
	res.Report.IgnoredKeys = []string{"password", "x<y"}
	res.Report.IssuesMore = 7
	res.Report.Issues = []Issue{
		{Row: "V5", Code: "bad_enum", Severity: SevDropped, Path: "threats[T-1].status", Message: "The value <b>x</b> is [not](http://e) known | at all"},
		{Row: "V8", Code: "ref_budget", Severity: SevWarn, Message: "2 references were not looked at."},
	}
	res.Report.Counts = map[string]Count{"threats": {Read: 5, Kept: 3, Refused: 1, LeftOut: 1}, "attack_trees": {Read: 1, Kept: 1}}
	out := RenderMarkdown(exMeta(ThreatModel), res)
	exHas(t, out,
		"State: partial. The file was read, and some items were refused or left out",
		"| attack trees | 1 | 1 | 0 | 0 |", "| threats | 5 | 3 | 1 | 1 |",
		"- found near the cited line: 4", "- location exists, nothing matched: 3", "- claimed, not found: 2",
		"- cited place not found (no such file, or the line is past its end): 5",
		"- cited place not found (the reference is malformed): 6", "- not checked: 7",
		"3 fields of the agent's file were not in the schema and were ignored (named by the agent as: password, x&lt;y, and others).",
		"Issues listed: 2.",
		`| V5 | bad\_enum | dropped | threats\[T\-1\]\.status | The value &lt;b&gt;x&lt;/b&gt; is \[not\]\(http\://e\) known \| at all |`,
		"| V8 | ref\\_budget | warn |  | 2 references were not looked at\\. |",
		"7 more issues were not listed.")
	exInOrder(t, out, "| attack trees |", "| threats |")
	res.Report.IssuesMore = 1
	res.Report.Ignored = 1
	res.Report.IgnoredKeys = nil
	out = RenderMarkdown(exMeta(ThreatModel), res)
	exHas(t, out, "1 more issue was not listed.", "1 field of the agent's file was not in the schema and was ignored.")
}

// TestRenderMarkdownTreeNesting: parent links make nested lists, a node whose
// parent is not in the tree is listed at the top, and a loop of parent links
// or a repeated id lists every node once and ends.
func TestRenderMarkdownTreeNesting(t *testing.T) {
	tests := []struct {
		name string
		tree Tree
		want []string
	}{
		{"a nested tree", Tree{Root: "Goal", Nodes: []TreeNode{
			{ID: "a", Label: "Top A", Op: "or"},
			{ID: "b", Parent: "a", Label: "Child B", Op: "and"},
			{ID: "c", Parent: "b", Label: "Leaf C", Leaf: true},
			{ID: "d", Parent: "a", Label: "Leaf D", Leaf: true},
			{ID: "e", Label: "Top E"},
		}}, []string{
			"- Top A (children: or)\n  - Child B (children: and)\n    - Leaf C (leaf)\n  - Leaf D (leaf)\n- Top E\n",
		}},
		{"an orphan is at the top", Tree{Root: "G", Nodes: []TreeNode{{ID: "a", Parent: "nope", Label: "Orphan"}}}, []string{"- Orphan\n"}},
		{
			"a loop",
			Tree{Root: "G", Nodes: []TreeNode{{ID: "a", Parent: "b", Label: "A"}, {ID: "b", Parent: "a", Label: "B"}}},
			[]string{"- A\n  - B\n"},
		},
		{"a node that is its own parent", Tree{Root: "G", Nodes: []TreeNode{{ID: "a", Parent: "a", Label: "Self"}}}, []string{"- Self\n"}},
		{
			"a repeated id",
			Tree{Root: "G", Nodes: []TreeNode{{ID: "a", Label: "One"}, {ID: "a", Label: "Two"}, {ID: "z", Parent: "a", Label: "Under"}}},
			[]string{"- One\n  - Under\n", "- Two\n"},
		},
		{"a tree with no node", Tree{Root: "Only a goal"}, []string{"### Goal, as the agent wrote it: Only a goal\n"}},
		{
			"an unknown op is the agent's word",
			Tree{Root: "G", Nodes: []TreeNode{{ID: "a", Label: "P", Op: "x*or"}, {ID: "b", Parent: "a", Label: "K"}}},
			[]string{`- P (children: x\*or)`},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := exTM(t, nil)
			res.TM.AttackTrees = []Tree{tc.tree}
			out := RenderMarkdown(exMeta(ThreatModel), res)
			exHas(t, out, tc.want...)
			// Every node is listed exactly once.
			for _, nd := range tc.tree.Nodes {
				if got := strings.Count(out, "- "+nd.Label); got < 1 {
					t.Errorf("node %q is not listed", nd.Label)
				}
			}
		})
	}
}

// TestRenderMarkdownDiagram: the diagram is the renderer's Mermaid source in a
// fence that nothing in it can close; its limits come from the options and its
// cut and omitted counts are said.
func TestRenderMarkdownDiagram(t *testing.T) {
	res := exTM(t, nil)
	meta := exMeta(ThreatModel)
	meta.DiagramMaxNodes, meta.DiagramLabelChars = 2, 10
	res.TM.System.Components[0].Name = "A very long component name with a backtick ` and a fence ```"
	out := RenderMarkdown(meta, res)
	want := RenderMermaidWith(res.TM, MermaidOptions{MaxNodes: 2, LabelChars: 10})
	if strings.Contains(want.Source, "`") {
		t.Fatalf("the diagram source holds a backtick: %q", want.Source)
	}
	exHas(t, out, "```mermaid\n"+strings.TrimRight(want.Source, "\n")+"\n```\n",
		"Its labels hold at most 10 characters of the agent's text",
		"2 of 4 nodes are drawn and 1 flow is not drawn", "the cap is the diagram size setting (2 nodes).")
	if want.LabelsCut > 0 {
		exHas(t, out, counted(want.LabelsCut, "label was", "labels were")+" shortened to 10 characters")
	}
	fences := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "```") {
			fences++
		}
	}
	if fences != 2 {
		t.Errorf("%d fence lines, want 2", fences)
	}
	// The agent's backticks are in the document too, each after a backslash;
	// the only others are the six of the fence.
	if n := strings.Count(out, "`") - strings.Count(out, "\\`"); n != 6 {
		t.Errorf("%d backticks that are not escaped, want the 6 of the fence", n)
	}
	// Defaults: zero options read as the diagram defaults.
	out = RenderMarkdown(exMeta(ThreatModel), exTM(t, nil))
	exHas(t, out, "hold at most 40 characters", "!nodes are drawn and")
	// No component: nothing to draw, and no fence. A model with components but
	// no flow still draws its boxes.
	res = exTM(t, nil)
	res.TM.System = System{}
	out = RenderMarkdown(exMeta(ThreatModel), res)
	exHas(t, out, "The model has no component and no flow, so there is nothing to draw.", "!```mermaid")
}

// TestRenderMarkdownNothingIsCapped renders 1,500 threats and 1,200 findings:
// every one is in the document, in score order, and the work takes a fraction
// of a second.
func TestRenderMarkdownNothingIsCapped(t *testing.T) {
	const nT, nF = 1500, 1200
	tm := &ThreatModelDoc{System: System{Components: []Component{{ID: "c", Name: "C", Type: "service"}}}}
	for i := 0; i < nT; i++ {
		r := Rating{Likelihood: 1 + i%5, Impact: 1 + (i/5)%5}
		tm.Threats = append(tm.Threats, Threat{
			ID: fmt.Sprintf("T-%04d", i), Title: "t", Framework: FrameworkSTRIDE, Category: "spoofing",
			Element: Element{Kind: "component", ID: "c"}, Rating: r, Band: BandOf(r), Score: r.Score(),
		})
	}
	pt := &PentestDoc{}
	for i := 0; i < nF; i++ {
		r := Rating{Likelihood: 1 + (i/3)%5, Impact: 1 + i%5}
		pt.Findings = append(pt.Findings, PTFinding{ID: fmt.Sprintf("F-%04d", i), Title: "f", Category: "INPV", Basis: "inferred", Rating: r, Band: BandOf(r), Score: r.Score()})
	}
	start := time.Now()
	out := RenderMarkdown(exMeta(ThreatModel), Result{TM: tm, PT: pt, Report: Report{State: ValidationValid, Contract: ContractThreatModel}})
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("rendering %d threats and %d findings took %v", nT, nF, elapsed)
	}
	t.Logf("rendered %d threats and %d findings (%d bytes) in %v", nT, nF, len(out), elapsed)
	exSorted(t, out, "### T", nT, func(i int) (string, int) { return tm.Threats[i].ID, tm.Threats[i].Score })
	exSorted(t, out, "### F", nF, func(i int) (string, int) { return pt.Findings[i].ID, pt.Findings[i].Score })
}

// exSorted reads the headings that start with prefix (an escaped "-" is the
// only escape in the ids of this test), checks that all n are there, once each,
// and that they come in score order then id order.
func exSorted(t *testing.T, out, prefix string, n int, item func(i int) (id string, score int)) {
	t.Helper()
	type row struct {
		id    string
		score int
	}
	want := make([]row, n)
	for i := range want {
		id, sc := item(i)
		want[i] = row{id, sc}
	}
	for i := 1; i < len(want); i++ { // insertion order is by id already; sort stably by score
		for j := i; j > 0 && want[j].score > want[j-1].score; j-- {
			want[j], want[j-1] = want[j-1], want[j]
		}
	}
	var got []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, prefix+`\-`) {
			got = append(got, strings.ReplaceAll(strings.TrimPrefix(l, "### "), `\-`, "-"))
		}
	}
	if len(got) != n {
		t.Fatalf("%d headings starting %q, want %d", len(got), prefix, n)
	}
	for i, g := range got {
		if !strings.HasPrefix(g, want[i].id+": ") {
			t.Fatalf("heading %d is %q, want the id %s", i, g, want[i].id)
		}
	}
}

// TestRenderMarkdownDiagramWithoutFlows: a model with boxes and no flow still
// draws the boxes, and says nothing about flows left out.
func TestRenderMarkdownDiagramWithoutFlows(t *testing.T) {
	out := RenderMarkdown(exMeta(ThreatModel), exTM(t, func(m map[string]any) { sys(m)["flows"] = nil }))
	exHas(t, out, "```mermaid\nflowchart LR", `c1["API"]`, "!not drawn")
}

// TestRenderMarkdownReproductionRequestForms: a reproduction request is one
// line in the export in every form the check keeps (the depth plan's W5b made
// it a structured request): the method and path alone, with headers, with a
// body, and with text that is markup, which the escaping makes inert.
func TestRenderMarkdownReproductionRequestForms(t *testing.T) {
	tests := []struct {
		name string
		req  *PTRequest
		want string
	}{
		{"none", nil, ""},
		{"method and path", &PTRequest{Method: "POST", Path: "/login"}, "POST /login"},
		{
			"headers", &PTRequest{Method: "GET", Path: "/api", Headers: []PTHeader{{Name: "Accept", Value: "text/html"}, {Name: " ", Value: "dropped"}, {Name: "X-Id", Value: "3"}}},
			"GET /api (headers: Accept: text/html; X-Id: 3)",
		},
		{"body", &PTRequest{Method: "POST", Path: "/login", Body: " user=a "}, "POST /login (body: user=a)"},
		{
			"headers and body", &PTRequest{Method: "POST", Path: "/x", Headers: []PTHeader{{Name: "Authorization", Value: "[REDACTED]"}}, Body: "{}"},
			"POST /x (headers: Authorization: [REDACTED], body: {})",
		},
		{"no method", &PTRequest{Path: "/only"}, "/only"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mdRequestText(tc.req); got != tc.want {
				t.Errorf("mdRequestText = %q, want %q", got, tc.want)
			}
		})
	}
	var w mdWriter
	mdPTRepro(&w, []PTRepro{{Step: "Try it", Request: &PTRequest{Method: "POST", Path: "/x", Body: "<script>alert(1)</script> [a](http://evil)"}}})
	out := w.String()
	exHas(t, out, `- Step 1: Try it Request: POST /x \(body\: &lt;script&gt;alert`, "!<script>", "!](http://evil)")
}

// TestRenderMarkdownStatesTheConditionsOfTheReferenceTally: the validation
// section says which match window the tally was made under and how many
// references quoted text that hiding secrets changed, so the counts are never
// read without them (live defect 8). A copy that predates them says nothing.
func TestRenderMarkdownStatesTheConditionsOfTheReferenceTally(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check *RefCheck
		has   []string
	}{
		{"a window", &RefCheck{WindowLines: 5}, []string{"References count as found when the quoted text is on a code line within 5 lines of the first cited line.", "!changed by hiding secrets"}},
		{"the cited line itself", &RefCheck{WindowLines: 1}, []string{"References count as found only when the quoted text is on the first cited line itself.", "!within 1 lines"}},
		{"one reference whose text was changed", &RefCheck{WindowLines: 5, TextHidden: 1}, []string{"1 reference quotes text that was changed by hiding secrets before the files were searched for it, so it could not read as found."}},
		{"six references whose text was changed", &RefCheck{WindowLines: 20, TextHidden: 6}, []string{"within 20 lines", "6 references quote text that was changed by hiding secrets before the files were searched for it, so they could not read as found."}},
		{"a copy that predates the record", nil, []string{"!within", "!first cited line", "!hiding secrets before"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := exTM(t, nil)
			res.Report.RefCheck = tc.check
			out := RenderMarkdown(exMeta(ThreatModel), res)
			exHas(t, out, tc.has...)
			exInOrder(t, out, "The references the agent cited, by what Observer found when it looked at each:", "Issues listed:")
		})
	}
}
