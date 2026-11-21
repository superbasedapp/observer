package secassess

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Tests of the scorer (scorekey_test.go, scorepen_test.go, scoretm_test.go).
//
// Two groups. The first runs everywhere: a miniature application and answer
// key built in memory, with one row per rule of the scoring. The second reads
// the fixture lane's real answer key and golden results (testdata/secassess)
// and pins what each golden file is built to show; it skips when the fixture
// tree is not in the checkout (so the scorer runs on its own), and
// OBSERVER_SECASSESS_FIXTURE_DIR points it at a copy. A skip is a pass, so the
// tree's presence is asserted where the tree is owned: TestFixtureTreeIsPresent
// in internal/secassessfixture fails, never skips, when truth/manifest.json is
// not there (review m10). No test here asserts anything about a model; they pin
// the scorer and the validator.

const scRun = "0123456789abcdef"

// scMini builds the miniature application: 120 lines of filler with the named
// lines set, so every anchor sits where the tests expect it.
func scMini() scMem {
	lines := make([]string, 120)
	for i := range lines {
		lines[i] = fmt.Sprintf("pad_%d = %d", i+1, i+1)
	}
	set := map[int]string{
		10:  "    rows = unsafe_query(q)",
		20:  "class Handler(Base):",
		30:  "    page = render_heading(term)",
		36:  "    note = load_note(note_id)",
		50:  "def login_route(h):",
		60:  "    ok = check_admin(cookie)",
		80:  "    rows = bound_query(q)",
		90:  "    if ok_check(value):",
		100: `DB = connect(":memory:")`,
		110: "# input is sanitised here",
		115: "    validate_noop(value)",
		118: "    trusted_claim(value)",
	}
	for n, s := range set {
		lines[n-1] = s
	}
	return scMem{"app.py": strings.Join(lines, "\n")}
}

// scPad is a needle for filler line n.
func scPad(n int) string { return fmt.Sprintf("pad_%d = %d", n, n) }

const scMiniManifest = `{
 "schema":"observer.secassess.fixture-truth.v1",
 "scoring":{"anchor_window_lines":5},
 "flaws":[
  {"id":"F1","title":"sql","cwe":["CWE-89"],"cwe_family":["CWE-20"],"wstg":["INPV"],"file":"app.py","anchors":["unsafe_query(q)"]},
  {"id":"F2","title":"xss","cwe":["CWE-79"],"cwe_family":["CWE-20"],"wstg":["INPV"],"file":"app.py","anchors":["render_heading(term)"]},
  {"id":"F3","title":"idor","cwe":["CWE-639"],"cwe_family":["CWE-284"],"wstg":["ATHZ"],"file":"app.py","anchors":["load_note(note_id)"]},
  {"id":"F4","title":"role cookie","cwe":["CWE-602"],"cwe_family":["CWE-284"],"wstg":["ATHZ"],"file":"app.py","anchors":["check_admin(cookie)"]}],
 "decoys":[{"id":"D1","title":"bound","near_miss_of":"F1","file":"app.py","anchors":["bound_query(q)"]}],
 "incidental":[{"id":"I1","title":"plain http","cwe":["CWE-319"]}]
}`

const scMiniTMKey = `{
 "schema":"observer.secassess.fixture-threatmodel-truth.v1",
 "stride_applicability":{"external_entity":["spoofing","repudiation"],"process":["spoofing","tampering","repudiation","information_disclosure","denial_of_service","elevation_of_privilege"],"data_store":["tampering","repudiation","information_disclosure","denial_of_service"],"data_flow":["tampering","information_disclosure","denial_of_service"]},
 "actors":[{"id":"A1","name":"visitor"}],
 "components":[
  {"id":"C1","name":"http_server","type":"process","file":"app.py","anchors":["class Handler(Base):"],"name_hints":["http","handler"]},
  {"id":"C2","name":"auth","type":"process","file":"app.py","anchors":["def login_route(h):"],"name_hints":["auth","login"]},
  {"id":"C3","name":"database","type":"data_store","file":"app.py","anchors":["DB = connect(\":memory:\")"],"name_hints":["db","database"],"holds_logs":false}],
 "flows":[
  {"id":"FL1","name":"requests","from":"A1","to":"C1"},
  {"id":"FL2","name":"auth calls","from":"C1","to":"C2"},
  {"id":"FL3","name":"queries","from":"C2","to":"C3"}],
 "threats":[
  {"id":"TH1","flaw":"F1","title":"tamper with queries","element":{"kind":"flow","id":"FL3"},"category":"tampering","accept":[{"kind":"component","id":"C3","category":"tampering"}]},
  {"id":"TH2","flaw":"F4","title":"spoof the admin","element":{"kind":"component","id":"C2"},"category":"spoofing","accept":[{"kind":"component","id":"C1","category":"spoofing"}]},
  {"id":"TH3","flaw":"F3","title":"read another's data","element":{"kind":"component","id":"C3"},"category":"information_disclosure","accept":[]}],
 "existing_mitigations":[
  {"id":"M1","decoy":"D1","title":"check","file":"app.py","anchors":["if ok_check(value):"],"needle":"ok_check(value)"}],
 "traps":[
  {"id":"TR1","kind":"comment_claim","file":"app.py","anchors":["# input is sanitised here"],"counts_as_validator_defect_if_found":true},
  {"id":"TR2","kind":"inert_validator","file":"app.py","anchors":["validate_noop(value)"],"counts_as_validator_defect_if_found":false,"known_limit":true},
  {"id":"TR3","kind":"inert_claim","file":"app.py","anchors":["trusted_claim(value)"],"counts_as_validator_defect_if_found":true}]
}`

func scMiniKeys(t *testing.T) (*scManifest, *scTMKey) {
	t.Helper()
	m, err := scParseManifest([]byte(scMiniManifest))
	if err != nil {
		t.Fatal(err)
	}
	k, err := scParseThreatModelKey([]byte(scMiniTMKey))
	if err != nil {
		t.Fatal(err)
	}
	return m, k
}

// ---- pen test ----

func scPF(id, cat string, cwe []string, line int, needle string) PTFinding {
	return PTFinding{
		ID: id, Title: "t " + id, Category: cat, CWE: cwe, Rating: Rating{Likelihood: 3, Impact: 3}, Basis: "observed",
		Where:  PTWhere{Refs: []Ref{{Path: "app.py", Line: line, Needle: needle}}},
		Status: "open",
	}
}

func scPenDoc(runID string, cov []PTCoverageClaim, fs ...PTFinding) []byte {
	d := PentestDoc{
		Schema: ContractPentest.Schema(), RunID: runID, Generator: Generator{Tool: "t"},
		Target: PTTarget{URL: "http://127.0.0.1:3000/", Start: PTStart{
			Argv: []string{"python3", "app.py"}, Source: "launch.json", Started: true, StartupSeconds: 1,
			Health: PTHealth{Path: "/", Status: 200},
		}},
		Method: PTMethod{Standard: "wstg+ptes"}, Coverage: cov, Findings: fs,
	}
	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return b
}

func scScorePen(t *testing.T, data []byte) scPenScore {
	t.Helper()
	m, _ := scMiniKeys(t)
	src := scMini()
	o := DefaultValidateOptions(ContractPentest, scRun)
	o.Refs = src
	s, err := scorePentest(m, src, Validate(data, o))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func scIDs(h []scPenHit) []string {
	var out []string
	for _, x := range h {
		out = append(out, x.Finding+">"+x.Key)
	}
	return out
}

func TestScorePentestRules(t *testing.T) {
	sql, xss, idor := []string{"CWE-89"}, []string{"CWE-79"}, []string{"CWE-639"}
	tests := []struct {
		name         string
		findings     []PTFinding
		matched      []string
		decoy        []string
		incidental   []string
		duplicates   []string
		unscored     []string
		noCredit     int
		recall, prec float64
	}{
		{
			name:     "every flaw reported at its anchor",
			findings: []PTFinding{scPF("P1", "INPV", sql, 10, "unsafe_query(q)"), scPF("P2", "INPV", xss, 30, "render_heading(term)"), scPF("P3", "ATHZ", idor, 36, "load_note(note_id)"), scPF("P4", "ATHZ", []string{"CWE-602"}, 60, "check_admin(cookie)")},
			matched:  []string{"F1", "F2", "F3", "F4"}, recall: 1, prec: 1,
		},
		{
			name:     "a flaw not reported is missed and recall is a fraction",
			findings: []PTFinding{scPF("P1", "INPV", sql, 10, "unsafe_query(q)")},
			matched:  []string{"F1"}, recall: 0.25, prec: 1,
		},
		{
			name: "the window is five lines: anchor plus five matches, plus six does not",
			findings: []PTFinding{
				scPF("P1", "INPV", sql, 15, scPad(15)),
				scPF("P2", "INPV", xss, 36+0, "load_note(note_id)"),
			},
			// P2 cites the F3 anchor line with F2's class: it is within five lines of F2's anchor (30 to 36 is
			// six, so out) and of F3's (class differs): unscored, near F3.
			matched: []string{"F1"}, unscored: []string{"P2>F3"}, recall: 0.25, prec: 0.5,
		},
		{
			name:     "six lines away is not near",
			findings: []PTFinding{scPF("P1", "INPV", sql, 16, scPad(16))},
			unscored: []string{"P1>"}, prec: 0,
		},
		{
			name:     "a needle that is not at the cited line earns no credit",
			findings: []PTFinding{scPF("P1", "INPV", sql, 10, "no_such_text(q)")},
			unscored: []string{"P1>"}, noCredit: 1,
		},
		{
			name:     "a reference with no needle earns no credit",
			findings: []PTFinding{scPF("P1", "INPV", sql, 10, "")},
			unscored: []string{"P1>"}, noCredit: 1,
		},
		{
			name:     "a near miss reported as a weakness is a counted false positive",
			findings: []PTFinding{scPF("P1", "INPV", sql, 80, "bound_query(q)")},
			decoy:    []string{"P1>D1"}, prec: 0,
		},
		{
			name:       "a real property that was not seeded is incidental",
			findings:   []PTFinding{scPF("P1", "CRYP", []string{"CWE-319"}, 105, scPad(105)), scPF("P2", "INPV", sql, 10, "unsafe_query(q)")},
			matched:    []string{"F1"},
			incidental: []string{"P1>I1"}, recall: 0.25, prec: 0.5,
		},
		{
			name:     "an incidental report with no reference found is unscored",
			findings: []PTFinding{scPF("P1", "CRYP", []string{"CWE-319"}, 105, "no_such_text(q)")},
			unscored: []string{"P1>"}, noCredit: 1,
		},
		{
			name:       "a second report of a matched flaw is a repeat, and still counts against precision",
			findings:   []PTFinding{scPF("P1", "INPV", sql, 10, "unsafe_query(q)"), scPF("P2", "INPV", sql, 10, "unsafe_query(q)")},
			matched:    []string{"F1"},
			duplicates: []string{"P2>F1"}, recall: 0.25, prec: 0.5,
		},
		{
			name:     "a flaw reported with the wrong class is near but not matched",
			findings: []PTFinding{scPF("P1", "CLNT", xss, 10, "unsafe_query(q)")},
			unscored: []string{"P1>F1"},
		},
		{
			name:     "a family CWE or the category alone matches",
			findings: []PTFinding{scPF("P1", "ATHZ", []string{"CWE-20"}, 10, "unsafe_query(q)"), scPF("P2", "INPV", nil, 30, "render_heading(term)")},
			// P1: CWE-20 is in F1's family; P2: no CWE but the WSTG category is F2's.
			matched: []string{"F1", "F2"}, recall: 0.5, prec: 1,
		},
		{
			name: "two flaws whose windows overlap are told apart by class",
			// Line 33 is within five lines of F2 (30) and F3 (36).
			findings: []PTFinding{scPF("P1", "ATHZ", idor, 33, scPad(33)), scPF("P2", "INPV", xss, 33, scPad(33))},
			matched:  []string{"F2", "F3"}, recall: 0.5, prec: 1,
		},
		{
			name: "a 120-line range with the text far from the cited line earns no credit",
			findings: []PTFinding{{
				ID: "P1", Title: "t", Category: "INPV", CWE: sql, Rating: Rating{3, 3}, Basis: "observed", Status: "open",
				Where: PTWhere{Refs: []Ref{{Path: "app.py", Line: 1, EndLine: 120, Needle: "unsafe_query(q)"}}},
			}},
			// the text is on line 10, nine lines past the first cited line: a location, not a find.
			unscored: []string{"P1>"}, noCredit: 1,
		},
		{
			name: "a range whose text is near its start is credited at the line it was found on",
			findings: []PTFinding{{
				ID: "P1", Title: "t", Category: "INPV", CWE: sql, Rating: Rating{3, 3}, Basis: "observed", Status: "open",
				Where: PTWhere{Refs: []Ref{{Path: "app.py", Line: 8, EndLine: 90, Needle: "unsafe_query(q)"}}},
			}},
			matched: []string{"F1"}, recall: 0.25, prec: 1,
		},
		{
			name: "a wide range does not reach a flaw its text is not near",
			// the range starts at 28 and runs to 90, over F2's anchor at 30 and F4's at 60; its text is the
			// padding on line 29, so the credit sits at line 29: within five lines of F2 only.
			findings: []PTFinding{{
				ID: "P1", Title: "t", Category: "ATHZ", CWE: []string{"CWE-602"}, Rating: Rating{3, 3}, Basis: "observed", Status: "open",
				Where: PTWhere{Refs: []Ref{{Path: "app.py", Line: 28, EndLine: 90, Needle: scPad(29)}}},
			}},
			unscored: []string{"P1>F2"},
		},
		{
			name: "a reference range is credited at the line its text was found on",
			findings: []PTFinding{{
				ID: "P1", Title: "t", Category: "INPV", CWE: sql, Rating: Rating{3, 3}, Basis: "observed", Status: "open",
				Where: PTWhere{Refs: []Ref{{Path: "app.py", Line: 3, EndLine: 8, Needle: scPad(5)}}},
			}},
			// the text is on line 5, five lines from the anchor at 10.
			matched: []string{"F1"}, recall: 0.25, prec: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := scScorePen(t, scPenDoc(scRun, nil, tc.findings...))
			if !reflect.DeepEqual(s.Matched, tc.matched) {
				t.Errorf("matched %v, want %v\n%s", s.Matched, tc.matched, strings.Join(s.Lines(), "\n"))
			}
			for _, c := range []struct {
				what      string
				got, want []string
			}{
				{"decoy hits", scIDs(s.DecoyHits), tc.decoy},
				{"incidental", scIDs(s.Incidental), tc.incidental},
				{"repeats", scIDs(s.Duplicates), tc.duplicates},
				{"unscored", scIDs(s.Unscored), tc.unscored},
			} {
				if !reflect.DeepEqual(c.got, c.want) {
					t.Errorf("%s %v, want %v", c.what, c.got, c.want)
				}
			}
			if s.NoCredit != tc.noCredit {
				t.Errorf("findings with no credit %d, want %d", s.NoCredit, tc.noCredit)
			}
			if s.Recall != tc.recall || s.Precision != tc.prec {
				t.Errorf("recall %v precision %v, want %v and %v", s.Recall, s.Precision, tc.recall, tc.prec)
			}
			if s.Reported != len(tc.findings) {
				t.Errorf("reported %d, want %d", s.Reported, len(tc.findings))
			}
			// Every finding is accounted for exactly once, never dropped.
			n := len(s.Matched) + len(s.DecoyHits) + len(s.Incidental) + len(s.Duplicates) + len(s.Unscored)
			if n != len(tc.findings) {
				t.Errorf("%d findings accounted for, want %d", n, len(tc.findings))
			}
			if len(s.Matched)+len(s.Missed) != s.Flaws {
				t.Errorf("matched %d plus missed %d is not the %d flaws", len(s.Matched), len(s.Missed), s.Flaws)
			}
		})
	}
}

func TestScorePentestRefusedFileScoresZero(t *testing.T) {
	s := scScorePen(t, scPenDoc("some-other-run", nil, scPF("P1", "INPV", []string{"CWE-89"}, 10, "unsafe_query(q)")))
	if len(s.Matched) != 0 || s.Reported != 0 || len(s.Missed) != 4 || s.Recall != 0 {
		t.Errorf("a refused file must score zero: %s", strings.Join(s.Lines(), "\n"))
	}
	if s.Validator.State != ValidationInvalid || s.Validator.Fatal != "run_id_mismatch" || s.Validator.Refused == 0 {
		t.Errorf("validator %+v", s.Validator)
	}
}

func TestScorePentestCoverageAndEvidence(t *testing.T) {
	cov := []PTCoverageClaim{
		{Category: "INFO", Status: "tested"},
		{Category: "ATHN", Status: "tested"},
		{Category: "CRYP", Status: "not_applicable", Reason: "loopback http"},
		{Category: "BUSL", Status: "skipped", Reason: "not reached"},
		{Category: "APIT", Status: "tool_unavailable", Reason: "no spec"},
	}
	f := scPF("P1", "INPV", []string{"CWE-89"}, 10, "unsafe_query(q)")
	f.Evidence = []string{"p1"}
	s := scScorePen(t, scPenDoc(scRun, cov, f, scPF("P2", "INPV", []string{"CWE-79"}, 30, "render_heading(term)")))
	c := s.Coverage
	if c.Rows != 12 || c.Filled != 5 || c.Tested != 2 || c.NotApplicable != 1 || c.Skipped != 2 {
		t.Errorf("coverage %+v: rows are the 12 categories, filled are the rows the agent gave", c)
	}
	if s.WithEvidence != 1 {
		t.Errorf("findings listing evidence %d, want 1", s.WithEvidence)
	}
}

// ---- threat model ----

func scTMThreatOf(id, cat, kind, el string, existing ...Mitigation) Threat {
	return Threat{
		ID: id, Title: "t " + id, Framework: FrameworkSTRIDE, Category: cat, Element: Element{Kind: kind, ID: el},
		Rating: Rating{Likelihood: 3, Impact: 3}, Existing: existing,
	}
}

// The anchors of the miniature manifest's flaws, as the lines scMini puts them
// on and the text that is on each: what a grounded threat cites.
const (
	scF1Line, scF1Needle = 10, "unsafe_query(q)"
	scF3Line, scF3Needle = 36, "load_note(note_id)"
	scF4Line, scF4Needle = 60, "check_admin(cookie)"
)

// scGround gives a threat one missing-control reference at a line.
func scGround(th Threat, line int, needle string) Threat {
	th.Missing = append(th.Missing, Missing{Text: "a control", Refs: []Ref{{Path: "app.py", Line: line, Needle: needle}}})
	return th
}

func scTMDoc(runID string, comps []Component, flows []Flow, threats []Threat, noThreat []NoThreat) []byte {
	d := ThreatModelDoc{
		Schema: ContractThreatModel.Schema(), RunID: runID, Generator: Generator{Tool: "t"}, Summary: "s",
		System: System{
			Components: comps, Flows: flows,
			Actors: []Actor{{ID: "user", Name: "User", Kind: "end_user"}},
		},
		Threats: threats, NoThreat: noThreat,
	}
	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return b
}

func scScoreTM(t *testing.T, data []byte) scTMScore {
	t.Helper()
	return scScoreTMIn(t, data, scMini())
}

// scScoreTMIn scores a threat model against the miniature key over a given
// project (the grounding tests add a second file to it).
func scScoreTMIn(t *testing.T, data []byte, src scMem) scTMScore {
	t.Helper()
	m, k := scMiniKeys(t)
	o := DefaultValidateOptions(ContractThreatModel, scRun)
	o.Refs = src
	s, err := scoreThreatModel(m, k, src, Validate(data, o))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// scComps are three model components under the model's own ids: the first is
// told apart by the place it cites, the second by its name, the third by both.
func scComps() []Component {
	return []Component{
		{ID: "gateway", Name: "Front", Type: "service", Paths: []Ref{{Path: "app.py", Line: 25, Needle: scPad(25)}}},
		{ID: "authn_service", Name: "Authentication", Type: "service"},
		{ID: "store", Name: "Storage", Type: "datastore", Paths: []Ref{{Path: "app.py", Line: 98, Needle: scPad(98)}}},
	}
}

func scFlows() []Flow {
	return []Flow{
		{ID: "f_in", From: "user", To: "gateway"},
		{ID: "f_auth", From: "gateway", To: "authn_service"},
		{ID: "f_db", From: "authn_service", To: "store"},
	}
}

func TestScoreThreatModelMapsTheModelsOwnIds(t *testing.T) {
	s := scScoreTM(t, scTMDoc(scRun, scComps(), scFlows(), nil, nil))
	if s.Components.Mapped != 3 || s.Flows.Mapped != 3 {
		t.Errorf("mapped %d components and %d flows, want 3 and 3", s.Components.Mapped, s.Flows.Mapped)
	}
	// Without a path or a name hint a component maps to nothing; a flow with an
	// unresolved end maps to nothing.
	s = scScoreTM(t, scTMDoc(scRun,
		[]Component{{ID: "x1", Name: "Thing", Type: "service"}},
		[]Flow{{ID: "f", From: "user", To: "x1"}}, nil, nil))
	if s.Components.Mapped != 0 || s.Flows.Mapped != 0 {
		t.Errorf("mapped %d components and %d flows, want none", s.Components.Mapped, s.Flows.Mapped)
	}
}

func TestScoreThreatModelMatching(t *testing.T) {
	// Every threat here is grounded at the flaw its cell belongs to (one found
	// reference on the flaw's anchor), so the rows test the cell rules alone; the
	// grounding rule has its own table below.
	g1 := func(th Threat) Threat { return scGround(th, scF1Line, scF1Needle) }
	g3 := func(th Threat) Threat { return scGround(th, scF3Line, scF3Needle) }
	g4 := func(th Threat) Threat { return scGround(th, scF4Line, scF4Needle) }
	tests := []struct {
		name      string
		threats   []Threat
		matched   []string
		unmatched []string
	}{
		{"the expected cell", []Threat{g1(scTMThreatOf("T1", "tampering", "flow", "f_db"))}, []string{"TH1"}, nil},
		{"an accepted cell", []Threat{g1(scTMThreatOf("T1", "tampering", "component", "store"))}, []string{"TH1"}, nil},
		{"the wrong category is no match", []Threat{g1(scTMThreatOf("T1", "spoofing", "flow", "f_db"))}, nil, []string{"T1"}},
		{"a cell that is not in the key is no match", []Threat{g1(scTMThreatOf("T1", "denial_of_service", "component", "store"))}, nil, []string{"T1"}},
		{
			"one-to-one: the second threat for a cell finds nothing left",
			[]Threat{g1(scTMThreatOf("T1", "tampering", "flow", "f_db")), g1(scTMThreatOf("T2", "tampering", "component", "store"))},
			[]string{"TH1"},
			[]string{"T2"},
		},
		{
			"an accepted cell is given to the threat that needs it",
			[]Threat{g1(scTMThreatOf("T1", "tampering", "component", "store")), g1(scTMThreatOf("T2", "tampering", "flow", "f_db"))},
			[]string{"TH1"},
			[]string{"T1"},
		},
		{
			"three expected threats",
			[]Threat{
				g1(scTMThreatOf("T1", "tampering", "flow", "f_db")),
				g4(scTMThreatOf("T2", "spoofing", "component", "authn_service")),
				g3(scTMThreatOf("T3", "information_disclosure", "component", "store")),
			},
			[]string{"TH1", "TH2", "TH3"},
			nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := scScoreTM(t, scTMDoc(scRun, scComps(), scFlows(), tc.threats, nil))
			if !reflect.DeepEqual(s.Matched, tc.matched) || !reflect.DeepEqual(s.Unmatched, tc.unmatched) {
				t.Errorf("matched %v unmatched %v, want %v and %v", s.Matched, s.Unmatched, tc.matched, tc.unmatched)
			}
			if len(s.Ungrounded) != 0 {
				t.Errorf("a grounded threat was listed as ungrounded: %v", s.Ungrounded)
			}
			if len(s.Matched)+len(s.Missed) != s.Expected {
				t.Errorf("matched %d plus missed %d is not the %d expected", len(s.Matched), len(s.Missed), s.Expected)
			}
		})
	}
}

// TestScoreThreatModelGrounding is the grounding rule (review m8), one row per
// way a model threat on the right cell does or does not earn the match: it needs
// a reference of its own that the check FOUND within the anchor window of the
// anchor of the flaw the key links the expected threat to. The miniature key's
// TH1 is flaw F1 (anchor on line 10), TH2 flaw F4 (line 60), TH3 flaw F3 (36);
// the window is five lines.
func TestScoreThreatModelGrounding(t *testing.T) {
	cite := func(line, end int, needle string) Mitigation {
		return Mitigation{Text: "a control", Refs: []Ref{{Path: "app.py", Line: line, EndLine: end, Needle: needle}}}
	}
	missing := func(line, end int, needle string) Missing {
		return Missing{Text: "a control", Refs: []Ref{{Path: "app.py", Line: line, EndLine: end, Needle: needle}}}
	}
	twoFiles := scMini()
	twoFiles["other.py"] = twoFiles["app.py"]
	th1 := func(ex []Mitigation, ms ...Missing) []Threat {
		th := scTMThreatOf("T1", "tampering", "flow", "f_db", ex...)
		th.Missing = ms
		return []Threat{th}
	}
	tests := []struct {
		name       string
		threats    []Threat
		project    scMem // nil is the miniature project
		matched    []string
		ungrounded []string
		cell       []string
		share      float64
	}{
		{
			name:       "no reference at all: the right cell alone earns nothing",
			threats:    th1(nil),
			ungrounded: []string{"T1"}, cell: []string{"TH1"},
		},
		{
			name:    "a missing-control reference found on the flaw's anchor",
			threats: th1(nil, missing(10, 0, scF1Needle)),
			matched: []string{"TH1"}, cell: []string{"TH1"}, share: 1,
		},
		{
			name:    "an existing-control reference found on the flaw's anchor counts the same",
			threats: th1([]Mitigation{cite(10, 0, scF1Needle)}),
			matched: []string{"TH1"}, cell: []string{"TH1"}, share: 1,
		},
		{
			name:    "a reference found five lines from the anchor is inside the window",
			threats: th1(nil, missing(15, 0, scPad(15))),
			matched: []string{"TH1"}, cell: []string{"TH1"}, share: 1,
		},
		{
			name:       "a reference found six lines from the anchor is outside it",
			threats:    th1(nil, missing(16, 0, scPad(16))),
			ungrounded: []string{"T1"}, cell: []string{"TH1"},
		},
		{
			name:       "a needle that is not at the cited line is claimed, not found, and grounds nothing",
			threats:    th1(nil, missing(10, 0, "no_such_text(q)")),
			ungrounded: []string{"T1"}, cell: []string{"TH1"},
		},
		{
			name:       "a reference with no needle only exists, and grounds nothing",
			threats:    th1(nil, missing(10, 0, "")),
			ungrounded: []string{"T1"}, cell: []string{"TH1"},
		},
		{
			name:       "a file-level reference grounds nothing",
			threats:    th1(nil, missing(0, 0, "")),
			ungrounded: []string{"T1"}, cell: []string{"TH1"},
		},
		{
			name:       "a reference found on another flaw's anchor does not ground this threat",
			threats:    th1(nil, missing(scF4Line, 0, scF4Needle)),
			ungrounded: []string{"T1"}, cell: []string{"TH1"},
		},
		{
			name:       "a reference to the same text in another file does not ground it",
			threats:    th1(nil, Missing{Text: "a control", Refs: []Ref{{Path: "other.py", Line: 10, Needle: scF1Needle}}}),
			project:    twoFiles,
			ungrounded: []string{"T1"}, cell: []string{"TH1"},
		},
		{
			name:       "a wide range with the text far from its first line only exists, and grounds nothing",
			threats:    th1(nil, missing(1, 120, scF1Needle)),
			ungrounded: []string{"T1"}, cell: []string{"TH1"},
		},
		{
			name:    "a range whose text is near its start is credited at the line it was found on",
			threats: th1(nil, missing(8, 90, scF1Needle)),
			matched: []string{"TH1"}, cell: []string{"TH1"}, share: 1,
		},
		{
			name:    "one grounded reference among wrong ones is enough",
			threats: th1([]Mitigation{cite(95, 0, scPad(95))}, missing(100, 0, `DB = connect(":memory:")`), missing(10, 0, scF1Needle)),
			matched: []string{"TH1"}, cell: []string{"TH1"}, share: 1,
		},
		{
			name: "an accepted cell needs grounding too",
			threats: []Threat{
				scTMThreatOf("T1", "tampering", "component", "store"),
			},
			ungrounded: []string{"T1"}, cell: []string{"TH1"},
		},
		{
			name: "grounding is per expected threat: a reference on F4's anchor grounds the F4 threat, not the F1 one",
			threats: []Threat{
				scGround(scTMThreatOf("T1", "tampering", "flow", "f_db"), scF4Line, scF4Needle),
				scGround(scTMThreatOf("T2", "spoofing", "component", "authn_service"), scF4Line, scF4Needle),
			},
			matched: []string{"TH2"}, ungrounded: []string{"T1"}, cell: []string{"TH1", "TH2"}, share: 0.5,
		},
		{
			name: "each threat needs its own reference, not another threat's",
			threats: []Threat{
				scGround(scTMThreatOf("T1", "tampering", "flow", "f_db"), scF1Line, scF1Needle),
				scTMThreatOf("T2", "information_disclosure", "component", "store"),
			},
			matched: []string{"TH1"}, ungrounded: []string{"T2"}, cell: []string{"TH1", "TH3"}, share: 0.5,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.project
			if src == nil {
				src = scMini()
			}
			s := scScoreTMIn(t, scTMDoc(scRun, scComps(), scFlows(), tc.threats, nil), src)
			for _, c := range []struct {
				what      string
				got, want []string
			}{
				{"matched", s.Matched, tc.matched},
				{"ungrounded", s.Ungrounded, tc.ungrounded},
				{"matched by cell alone", s.CellMatched, tc.cell},
			} {
				if !reflect.DeepEqual(c.got, c.want) {
					t.Errorf("%s %v, want %v", c.what, c.got, c.want)
				}
			}
			if s.GroundedShare != tc.share {
				t.Errorf("grounded share %v, want %v", s.GroundedShare, tc.share)
			}
			if want := float64(len(tc.matched)) / 3; s.Recall != want {
				t.Errorf("recall %v, want %v: recall counts grounded matches only", s.Recall, want)
			}
			if len(s.Unmatched) != 0 {
				t.Errorf("unmatched %v: every threat in this table fits a cell", s.Unmatched)
			}
		})
	}
}

// TestScoreThreatModelCellCoverageIgnoresGrounding pins that grounding gates
// recall only: a threat that analyses a cell fills it whether or not it cites
// code (coverage is the question "was every cell considered", the match is "was
// the right thing found, and pointed at").
func TestScoreThreatModelCellCoverageIgnoresGrounding(t *testing.T) {
	s := scScoreTM(t, scTMDoc(scRun, scComps(), scFlows(), []Threat{scTMThreatOf("T1", "tampering", "flow", "f_db")}, nil))
	if len(s.Matched) != 0 || s.Cells.Analysed != 1 || s.Recall != 0 {
		t.Errorf("an ungrounded threat must fill its cell and match nothing: %+v matched %v", s.Cells, s.Matched)
	}
}

// TestScoreThreatModelKeyMustLinkItsFlaws: a key threat that names no flaw of
// the manifest cannot be grounded, which is an error, never a quiet zero.
func TestScoreThreatModelKeyMustLinkItsFlaws(t *testing.T) {
	m, k := scMiniKeys(t)
	k.Threats[0].Flaw = "F9"
	src := scMini()
	o := DefaultValidateOptions(ContractThreatModel, scRun)
	o.Refs = src
	data := scTMDoc(scRun, scComps(), scFlows(), nil, nil)
	if _, err := scoreThreatModel(m, k, src, Validate(data, o)); err == nil || !strings.Contains(err.Error(), "not in the manifest") {
		t.Errorf("error %v, want one saying the flaw is not in the manifest", err)
	}
	if _, err := scoreThreatModel(nil, k, src, Validate(data, o)); err == nil {
		t.Error("scoring without the manifest must be an error")
	}
}

func TestScoreThreatModelCells(t *testing.T) {
	// The key requires: two processes x 6 categories, one data store x 3, three
	// flows x 3 = 24 cells. The actor is not part of the key's cell list.
	threats := []Threat{
		scTMThreatOf("T1", "tampering", "flow", "f_db"),
		scTMThreatOf("T2", "spoofing", "component", "authn_service"),
	}
	waived := []NoThreat{
		{Element: Element{Kind: "component", ID: "store"}, Category: "denial_of_service", Reason: "in memory"},
		{Element: Element{Kind: "flow", ID: "f_in"}, Category: "tampering", Reason: "loopback"},
		{Element: Element{Kind: "flow", ID: "f_in"}, Category: "repudiation", Reason: "not applicable to a flow"},
	}
	s := scScoreTM(t, scTMDoc(scRun, scComps(), scFlows(), threats, waived))
	if s.Cells.Required != 24 {
		t.Errorf("required cells %d, want 24", s.Cells.Required)
	}
	// repudiation on a flow is not applicable, so it is waived but not a key cell: it must not count.
	if s.Cells.Analysed != 2 || s.Cells.Waived != 2 || s.Cells.Empty != 20 {
		t.Errorf("cells %+v, want 2 analysed, 2 waived, 20 empty", s.Cells)
	}
	if want := 4.0 / 24; s.CellCoverage != want {
		t.Errorf("coverage %v, want %v", s.CellCoverage, want)
	}
	s = scScoreTM(t, scTMDoc("other-run", scComps(), scFlows(), threats, nil))
	if s.Cells.Empty != 24 || len(s.Missed) != 3 || s.Validator.Fatal != "run_id_mismatch" {
		t.Errorf("a refused file leaves every cell empty: %+v %s", s.Cells, strings.Join(s.Lines(), "\n"))
	}
}

func TestScoreThreatModelMitigationsAndTraps(t *testing.T) {
	cite := func(line int, needle string) Mitigation {
		return Mitigation{Text: "a control", Refs: []Ref{{Path: "app.py", Line: line, Needle: needle}}}
	}
	tests := []struct {
		name                              string
		existing                          []Mitigation
		cited, found, notFound            int
		credited, seen, hits, limits      []string
		missedReal                        []string
		wantFoundShare, wantNotFoundShare float64
	}{
		{
			name:     "the real control, found at its line",
			existing: []Mitigation{cite(90, "ok_check(value)")},
			cited:    1, found: 1, credited: []string{"M1"}, wantFoundShare: 1,
		},
		{
			name:     "a comment claiming a control is claimed but not found, and is no credit",
			existing: []Mitigation{cite(110, "input is sanitised here")},
			cited:    1, notFound: 1, missedReal: []string{"M1"}, seen: []string{"TR1"}, wantNotFoundShare: 1,
		},
		{
			name:     "a control that is not there (needle absent)",
			existing: []Mitigation{cite(90, "no_such_check(value)")},
			cited:    1, notFound: 1, missedReal: []string{"M1"}, wantNotFoundShare: 1,
		},
		{
			name:     "a code trap marked as the check's limit is listed as a limit, not a defect",
			existing: []Mitigation{cite(115, "validate_noop(value)")},
			cited:    1, found: 1, missedReal: []string{"M1"}, seen: []string{"TR2"}, limits: []string{"TR2"}, wantFoundShare: 1,
		},
		{
			name:     "a code trap that the key counts as a defect is a defect",
			existing: []Mitigation{cite(118, "trusted_claim(value)")},
			cited:    1, found: 1, missedReal: []string{"M1"}, seen: []string{"TR3"}, hits: []string{"TR3"}, wantFoundShare: 1,
		},
		{
			name:     "a reference near the control but not on it earns nothing",
			existing: []Mitigation{cite(95, scPad(95))},
			cited:    1, found: 1, missedReal: []string{"M1"}, wantFoundShare: 1,
		},
		{
			name:     "a wide range with the control's text far from its start earns nothing",
			existing: []Mitigation{{Text: "a control", Refs: []Ref{{Path: "app.py", Line: 1, EndLine: 120, Needle: "ok_check(value)"}}}},
			cited:    1, missedReal: []string{"M1"},
		},
		{
			name:     "no mitigations cited",
			existing: nil, missedReal: []string{"M1"},
		},
		{
			name:     "half found",
			existing: []Mitigation{cite(90, "ok_check(value)"), cite(90, "no_such_check(value)")},
			cited:    2, found: 1, notFound: 1, credited: []string{"M1"}, wantFoundShare: 0.5, wantNotFoundShare: 0.5,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			threats := []Threat{scTMThreatOf("T1", "tampering", "flow", "f_db", tc.existing...)}
			s := scScoreTM(t, scTMDoc(scRun, scComps(), scFlows(), threats, nil))
			m := s.Mitigations
			if m.Cited != tc.cited || m.Found != tc.found || m.ClaimedNotFound != tc.notFound {
				t.Errorf("cited %d found %d claimed-not-found %d, want %d %d %d", m.Cited, m.Found, m.ClaimedNotFound, tc.cited, tc.found, tc.notFound)
			}
			if m.FoundShare != tc.wantFoundShare || m.ClaimedShare != tc.wantNotFoundShare {
				t.Errorf("shares %v and %v, want %v and %v", m.FoundShare, m.ClaimedShare, tc.wantFoundShare, tc.wantNotFoundShare)
			}
			for _, c := range []struct {
				what      string
				got, want []string
			}{
				{"credited", s.RealCredited, tc.credited},
				{"not credited", s.RealMissed, tc.missedReal},
				{"traps touched", s.TrapSeen, tc.seen},
				{"trap defects", s.TrapHits, tc.hits},
				{"trap limits", s.TrapLimits, tc.limits},
			} {
				if !reflect.DeepEqual(c.got, c.want) {
					t.Errorf("%s %v, want %v", c.what, c.got, c.want)
				}
			}
		})
	}
}

func TestScoreThreatModelIgnoresOtherFrameworks(t *testing.T) {
	th := scTMThreatOf("T1", "linkability", "flow", "f_db")
	th.Framework = "linddun"
	s := scScoreTM(t, scTMDoc(scRun, scComps(), scFlows(), []Threat{th}, nil))
	if s.Reported != 1 || s.NotScored != 1 || len(s.Matched) != 0 || len(s.Unmatched) != 0 {
		t.Errorf("a LINDDUN threat is kept but not scored: %+v", s)
	}
}

// ---- the key's own rules ----

func TestScoreAnchors(t *testing.T) {
	src := scMini()
	tests := []struct {
		name, file, anchor string
		comment            bool
		line               int
		wantErr            string
	}{
		{"a code line", "app.py", "unsafe_query(q)", false, 10, ""},
		{"a code line, comments allowed", "app.py", "unsafe_query(q)", true, 10, ""},
		{"absent", "app.py", "no_such_text", false, 0, "occurs 0 times"},
		{"twice", "app.py", "pad_1", false, 0, "occurs"},
		{"a comment line is refused for a flaw", "app.py", "# input is sanitised here", false, 0, "comment line"},
		{"a comment line is allowed for a trap", "app.py", "# input is sanitised here", true, 110, ""},
		{"a missing file", "nope.py", "x", false, 0, "not in the project"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scAnchorLine(src, tc.file, tc.anchor, tc.comment)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatal(err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Fatalf("error %v, want one containing %q", err, tc.wantErr)
			case tc.wantErr == "" && got != tc.line:
				t.Fatalf("line %d, want %d", got, tc.line)
			}
		})
	}
}

func TestScoreMatchFindsTheMaximum(t *testing.T) {
	tests := []struct {
		name  string
		tiers [][][]int
		nR    int
		want  []int
	}{
		{"nothing", [][][]int{{nil, nil}}, 2, []int{-1, -1}},
		{"disjoint", [][][]int{{{0}, {1}}}, 2, []int{0, 1}},
		{"greedy would lose one", [][][]int{{{0, 1}, {0}}}, 2, []int{1, 0}},
		{"a chain", [][][]int{{{0, 1}, {1, 2}, {0}}}, 3, []int{1, 2, 0}},
		{"more left than right", [][][]int{{{0}, {0}, {0}}}, 1, []int{0, -1, -1}},
		// Item 0 has only an accepted edge to 0; item 1 has the primary edge to 0:
		// the primary edge is used, item 0 goes without.
		{"a better tier wins a contested item", [][][]int{{nil, {0}}, {{0}, nil}}, 1, []int{-1, 0}},
		// A worse edge is used when it does not cost a match.
		{"a worse tier fills what the better left free", [][][]int{{{0}, nil}, {nil, {1}}}, 2, []int{0, 1}},
		// A worse edge may move a better match when that gains one.
		{"a worse tier re-routes for one more match", [][][]int{{{0}, nil}, {{1}, {0}}}, 2, []int{1, 0}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := scMatch(len(tc.tiers[0]), tc.nR, tc.tiers...); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScoreKeysNeedTheirSchema(t *testing.T) {
	if _, err := scParseManifest([]byte(`{"schema":"x"}`)); err == nil {
		t.Error("a manifest with another schema id must be refused")
	}
	if _, err := scParseThreatModelKey([]byte(`{"schema":"x"}`)); err == nil {
		t.Error("a threat model key with another schema id must be refused")
	}
	if m, err := scParseManifest([]byte(scMiniManifest)); err != nil || len(m.Flaws) != 4 || m.Scoring.AnchorWindowLines != 5 {
		t.Errorf("mini manifest: %v %+v", err, m)
	}
}

// ---- the fixture lane's answer key and golden results ----

// scGolden loads one golden file.
func scGolden(t *testing.T, dir, kind, variant string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "golden", kind+"."+variant+".assessment.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// scFixture returns the fixture tree or skips.
func scFixture(t *testing.T) (string, *scManifest, *scTMKey, scDir) {
	t.Helper()
	dir := scFixtureDir()
	if dir == "" {
		t.Skip("the fixture tree (testdata/secassess) is not in this checkout; set OBSERVER_SECASSESS_FIXTURE_DIR to a copy")
	}
	m, k := scLoadKeys(t, dir)
	return dir, m, k, scDir{filepath.Join(dir, "app")}
}

// scValidateGolden validates a golden file as the module would, and fails the
// test when the file is not valid for the contract: a golden result that the
// validator refuses scores nothing, which would hide the defect.
func scValidateGolden(t *testing.T, c Contract, data []byte, src scDir) Result {
	t.Helper()
	o := DefaultValidateOptions(c, "GOLDEN")
	o.Refs = src
	res := Validate(data, o)
	if res.Report.Fatal != "" {
		t.Fatalf("the golden file is refused as a whole (%s): %v\nthe fixture lane must write it to the contract (internal/secassess/model.go)", res.Report.Fatal, res.Report.Issues)
	}
	return res
}

func TestScoreGoldenKeysResolve(t *testing.T) {
	_, m, k, src := scFixture(t)
	if _, err := scorePentest(m, src, Result{}); err != nil {
		t.Fatalf("manifest anchors: %v", err)
	}
	if _, err := scMapComponents(k, src, &ThreatModelDoc{}); err != nil {
		t.Fatalf("component anchors: %v", err)
	}
	if err := scMitigations(k, src, &ThreatModelDoc{}, &scTMScore{}); err != nil {
		t.Fatalf("mitigation and trap anchors: %v", err)
	}
	// Every expected threat names a flaw of the manifest whose anchors resolve: the grounding of a matched
	// threat is read from them (a link that broke would otherwise make a threat quietly unscorable).
	if at, err := scThreatAnchors(m, k, src); err != nil || len(at) != len(k.Threats) {
		t.Fatalf("the flaws the key's threats link to: %v", err)
	}
	if len(m.Flaws) != 14 || len(m.Decoys) != 6 || len(k.Threats) != 14 || len(k.Existing) != 6 || len(k.Traps) != 3 {
		t.Errorf("the key has %d flaws, %d decoys, %d threats, %d controls, %d traps; the plan says 14, 6, 14, 6, 3",
			len(m.Flaws), len(m.Decoys), len(k.Threats), len(k.Existing), len(k.Traps))
	}
}

func TestScoreGoldenPentest(t *testing.T) {
	dir, m, _, src := scFixture(t)
	var all []string
	for _, f := range m.Flaws {
		all = append(all, f.ID)
	}
	type want struct {
		matched    []string
		decoys     []string
		incidental []string
		unscored   int
		reported   int
		recall     float64
		precision  float64
		noCredit   int
		codes      []string
		warned     int
	}
	cases := map[string]want{
		"perfect": {matched: all, reported: 14, recall: 1, precision: 1},
		"partial": {
			matched: []string{"F01", "F02", "F03", "F04", "F06", "F09", "F12"}, decoys: []string{"D01"}, incidental: []string{"I04"},
			reported: 9, recall: 0.5, precision: 7.0 / 9,
		},
		"hallucinated": {
			decoys: []string{"D03", "D04", "D05"}, unscored: 3, reported: 6, noCredit: 3,
			codes:  []string{"observed_without_target", "ref_file_missing", "ref_line_past_end", "ref_needle_not_found", "target_not_started"},
			warned: 5,
		},
	}
	for _, v := range []string{"perfect", "partial", "hallucinated"} {
		t.Run(v, func(t *testing.T) {
			res := scValidateGolden(t, ContractPentest, scGolden(t, dir, "pentest", v), src)
			s, err := scorePentest(m, src, res)
			if err != nil {
				t.Fatal(err)
			}
			w := cases[v]
			t.Log("\n" + strings.Join(s.Lines(), "\n"))
			if !reflect.DeepEqual(s.Matched, w.matched) {
				t.Errorf("matched %v, want %v", s.Matched, w.matched)
			}
			dk := func(h []scPenHit) []string {
				var o []string
				for _, x := range h {
					o = append(o, x.Key)
				}
				sort.Strings(o)
				return o
			}
			if !reflect.DeepEqual(dk(s.DecoyHits), w.decoys) {
				t.Errorf("decoys %v, want %v", dk(s.DecoyHits), w.decoys)
			}
			if !reflect.DeepEqual(dk(s.Incidental), w.incidental) {
				t.Errorf("incidental %v, want %v", dk(s.Incidental), w.incidental)
			}
			if len(s.Unscored) != w.unscored || len(s.Duplicates) != 0 {
				t.Errorf("%d unscored and %d repeats, want %d and none: %v", len(s.Unscored), len(s.Duplicates), w.unscored, s.Unscored)
			}
			if s.Reported != w.reported || s.NoCredit != w.noCredit || s.Recall != w.recall || s.Precision != w.precision {
				t.Errorf("reported %d, no credit %d, recall %v, precision %v; want %d, %d, %v, %v",
					s.Reported, s.NoCredit, s.Recall, s.Precision, w.reported, w.noCredit, w.recall, w.precision)
			}
			if len(s.Matched)+len(s.Missed) != 14 {
				t.Errorf("matched and missed do not make the 14 flaws")
			}
			if s.Validator.Warned != w.warned || s.Validator.Refused != 0 || s.Validator.State != ValidationValid {
				t.Errorf("validator %s, want valid with %d warnings and no refusals", s.Validator.line(), w.warned)
			}
			if w.codes != nil {
				for _, c := range w.codes {
					if !scHasCode(s.Validator, c) {
						t.Errorf("the validator did not report %s; it reported %v", c, s.Validator.Codes)
					}
				}
			} else if s.Validator.Refused != 0 || s.Validator.Refs.ClaimedNotFound+s.Validator.Refs.Missing != 0 {
				t.Errorf("a clean golden file drew validator findings: %s", s.Validator.line())
			}
		})
	}
}

func scHasCode(v scValidator, code string) bool {
	for _, c := range v.Codes {
		if c == code {
			return true
		}
	}
	return false
}

func TestScoreGoldenThreatModel(t *testing.T) {
	dir, m, k, src := scFixture(t)
	var allTH, allM []string
	for _, th := range k.Threats {
		allTH = append(allTH, th.ID)
	}
	for _, m := range k.Existing {
		allM = append(allM, m.ID)
	}
	type want struct {
		matched, real, trapSeen []string
		reported                int
		cited, found            int
		cells                   [3]int // analysed, waived, empty cells of the key
		reportEmpty             int    // empty cells in the validator's own count, actors included
		warned, itemsOut        int    // validator warnings, items it refused or left out
		cellMatched, ungrounded int    // expected threats the element and category alone name; kept threats on a cell with no grounding
	}
	cases := map[string]want{
		"perfect": {matched: allTH, real: allM, reported: 14, cited: 6, found: 6, cells: [3]int{14, 49, 0}, cellMatched: 14},
		"partial": {
			matched: []string{"TH01", "TH02", "TH03", "TH04", "TH05", "TH06", "TH09", "TH12"},
			real:    []string{"M1", "M3", "M6"}, trapSeen: []string{"TR1"}, reported: 8, cited: 4, found: 3,
			cells: [3]int{8, 0, 55}, reportEmpty: 75, warned: 4, cellMatched: 8,
		},
		"hallucinated": {cells: [3]int{0, 0, 63}, reportEmpty: 35, warned: 1, itemsOut: 5},
		// Well formed, every cell filled, every threat on the key's element and category, and not one reference
		// near the code of its weakness (review m8): the cell alone would match all 14, the grounded score matches none.
		"ungrounded": {reported: 14, cited: 2, found: 1, cells: [3]int{14, 49, 0}, warned: 2, cellMatched: 14, ungrounded: 14},
	}
	for _, v := range []string{"perfect", "partial", "hallucinated", "ungrounded"} {
		t.Run(v, func(t *testing.T) {
			res := scValidateGolden(t, ContractThreatModel, scGolden(t, dir, "threatmodel", v), src)
			s, err := scoreThreatModel(m, k, src, res)
			if err != nil {
				t.Fatal(err)
			}
			w := cases[v]
			t.Log("\n" + strings.Join(s.Lines(), "\n"))
			if !reflect.DeepEqual(s.Matched, w.matched) {
				t.Errorf("matched %v, want %v", s.Matched, w.matched)
			}
			if !reflect.DeepEqual(s.RealCredited, w.real) {
				t.Errorf("real controls credited %v, want %v", s.RealCredited, w.real)
			}
			if !reflect.DeepEqual(s.TrapSeen, w.trapSeen) || len(s.TrapHits) != 0 || len(s.TrapLimits) != 0 {
				t.Errorf("traps touched %v, defects %v, limits %v; want touched %v and no credit", s.TrapSeen, s.TrapHits, s.TrapLimits, w.trapSeen)
			}
			if s.Reported != w.reported {
				t.Errorf("threats kept %d, want %d", s.Reported, w.reported)
			}
			if len(s.Matched)+len(s.Missed) != s.Expected {
				t.Errorf("matched and missed do not make the %d expected threats", s.Expected)
			}
			if got := [3]int{s.Cells.Analysed, s.Cells.Waived, s.Cells.Empty}; s.Cells.Required != 63 || got != w.cells {
				t.Errorf("cells of the key: %d required, analysed/waived/empty %v, want 63 and %v", s.Cells.Required, got, w.cells)
			}
			if s.ReportCells.Empty != w.reportEmpty || s.Validator.Warned != w.warned || s.Validator.ItemsOut != w.itemsOut {
				t.Errorf("the validator reported %d empty cells, %d warnings, %d items out; want %d, %d, %d",
					s.ReportCells.Empty, s.Validator.Warned, s.Validator.ItemsOut, w.reportEmpty, w.warned, w.itemsOut)
			}
			if v == "perfect" {
				if s.Recall != 1 || s.CellCoverage != 1 || s.Mitigations.FoundShare != 1 || s.Components.Mapped != 7 || s.Flows.Mapped != 9 {
					t.Errorf("a perfect model must score full marks: %s", strings.Join(s.Lines(), "\n"))
				}
			}
			if s.Mitigations.Cited != w.cited || s.Mitigations.Found != w.found {
				t.Errorf("cited %d, found %d; want %d, %d", s.Mitigations.Cited, s.Mitigations.Found, w.cited, w.found)
			}
			if len(s.CellMatched) != w.cellMatched || len(s.Ungrounded) != w.ungrounded {
				t.Errorf("the element and category alone name %d expected threats and %d kept threats are ungrounded; want %d and %d: %s",
					len(s.CellMatched), len(s.Ungrounded), w.cellMatched, w.ungrounded, strings.Join(s.Lines(), "\n"))
			}
			if want := float64(len(w.matched)) / float64(max(w.cellMatched, 1)); s.GroundedShare != want {
				t.Errorf("grounded share %v, want %v", s.GroundedShare, want)
			}
			if v == "hallucinated" && (s.Validator.Refused != 5 || len(s.Matched) != 0) {
				t.Errorf("a hallucinated model must have its five threats refused and score nothing: %s", strings.Join(s.Lines(), "\n"))
			}
			if v == "ungrounded" {
				// It passes every structural check (nothing refused or left out, the full cell coverage, all
				// 7 components and 9 flows mapped), and the references the validator kept are what a careless
				// model writes: some found, in the wrong place; the rest claimed, not found, or location only.
				if s.Validator.State != ValidationValid || s.Validator.Refused != 0 || s.Validator.ItemsOut != 0 || s.ReportCells.Empty != 0 {
					t.Errorf("an ungrounded golden must pass the structural checks whole: %s", s.Validator.line())
				}
				if s.CellCoverage != 1 || s.Components.Mapped != 7 || s.Flows.Mapped != 9 {
					t.Errorf("it must fill every cell and name every element: %s", strings.Join(s.Lines(), "\n"))
				}
				// Of the 34 references it cites: 18 are the components' and entry points' places (found, and right), 9
				// are threat references found in the wrong place, 2 are a location only (a file with no line, a
				// range whose text is far from its first line) and 5 claim text that is not at the cited line.
				// The validator warns once for each of the last two codes.
				if r := s.Validator.Refs; r.Found != 27 || r.Exists != 2 || r.ClaimedNotFound != 5 || r.Missing+r.Invalid+r.Unchecked != 0 {
					t.Errorf("its references should be 27 found, 2 location only, 5 claimed and not found, none else: %s", s.Validator.line())
				}
				if !scHasCode(s.Validator, "ref_needle_far") || !scHasCode(s.Validator, "ref_needle_not_found") {
					t.Errorf("the validator should warn that a needle is far and that a needle is not found: %v", s.Validator.Codes)
				}
				// The score is the point: the element and the category name all 14, the grounding earns none.
				if s.Recall != 0 || s.GroundedShare != 0 || len(s.Matched) != 0 || len(s.RealCredited) != 0 || len(s.TrapSeen) != 0 {
					t.Errorf("an ungrounded model must score no recall and no grounded share: %s", strings.Join(s.Lines(), "\n"))
				}
			}
		})
	}
}
