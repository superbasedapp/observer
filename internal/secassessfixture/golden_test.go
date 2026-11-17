package secassessfixture

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// The golden files are hand-written results in the module's assessment
// formats, for the scorer's own tests. This file checks them against the
// answer key with a small independent matcher (it is NOT the module's scorer):
// a reference is "verified" when the named file exists and the needle sits on
// the named line; a finding matches a flaw when a verified reference is within
// the anchor window of one of the flaw's anchors and its CWE or WSTG category
// is the flaw's; matching is one-to-one. The expectations below are what each
// file is built to show.

type goldenRef struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Needle string `json:"needle"`
}

type goldenFinding struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	CWE      []string `json:"cwe"`
	Where    struct {
		Refs []goldenRef `json:"refs"`
	} `json:"where"`
}

type goldenPentest struct {
	Schema   string          `json:"schema"`
	RunID    string          `json:"run_id"`
	Findings []goldenFinding `json:"findings"`
}

type goldenThreat struct {
	ID       string     `json:"id"`
	Category string     `json:"category"`
	Element  ElementRef `json:"element"`
	Existing []struct {
		Refs []goldenRef `json:"refs"`
	} `json:"existing"`
	Missing []struct {
		Refs []goldenRef `json:"refs"`
	} `json:"missing"`
}

type goldenThreatModel struct {
	Schema string `json:"schema"`
	RunID  string `json:"run_id"`
	System struct {
		Components []struct {
			ID string `json:"id"`
		} `json:"components"`
		Actors []struct {
			ID string `json:"id"`
		} `json:"actors"`
		Flows []struct {
			ID string `json:"id"`
		} `json:"flows"`
	} `json:"system"`
	Threats  []goldenThreat `json:"threats"`
	NoThreat []struct {
		Element  ElementRef `json:"element"`
		Category string     `json:"category"`
	} `json:"no_threat"`
}

var goldenVariants = []string{"perfect", "partial", "hallucinated"}

// goldenFileNames lists every golden file the fixture carries: the three
// variants of each kind, and the threat model that is well formed but cites no
// code where its weaknesses sit (threatmodel.ungrounded, the case that shows a
// scorer must not credit an element and a category alone).
func goldenFileNames() []string {
	var out []string
	for _, kind := range []string{"pentest", "threatmodel"} {
		for _, v := range goldenVariants {
			out = append(out, kind+"."+v+".assessment.json")
		}
	}
	return append(out, "threatmodel.ungrounded.assessment.json")
}

func loadGolden(t *testing.T, name string, v any) {
	t.Helper()
	if err := json.Unmarshal(readFixture(t, "golden/"+name), v); err != nil {
		t.Fatalf("golden/%s: %v", name, err)
	}
}

// verified reports whether a reference names the application file and a line
// that carries the needle.
func verified(t *testing.T, r goldenRef) bool {
	t.Helper()
	if r.Path != "server.py" || r.Needle == "" {
		return false
	}
	src := appFile(t, r.Path)
	if r.Line < 1 || r.Line > strings.Count(string(src), "\n")+1 {
		return false
	}
	return strings.Contains(LineText(src, r.Line), r.Needle)
}

func anchorLines(t *testing.T, file string, anchors []string) []int {
	t.Helper()
	src := appFile(t, file)
	var out []int
	for _, a := range anchors {
		ln, err := LineOf(src, a)
		if err != nil {
			t.Fatalf("anchor %q: %v", a, err)
		}
		out = append(out, ln)
	}
	return out
}

func near(lines []int, line, window int) bool {
	for _, l := range lines {
		if d := l - line; d >= -window && d <= window {
			return true
		}
	}
	return false
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

type penResult struct {
	matched    []string // flaw ids, sorted
	decoyHits  []string // decoy ids a non-matching finding sits on, sorted
	unscored   int      // findings that matched nothing and sit on no decoy
	unverified int      // findings with no verified reference
}

func scorePentest(t *testing.T, g goldenPentest) penResult {
	t.Helper()
	m := loadManifest(t)
	window := m.Scoring.AnchorWindowLines
	taken := map[string]bool{}
	var res penResult
	for _, f := range g.Findings {
		var lines []int
		for _, r := range f.Where.Refs {
			if verified(t, r) {
				lines = append(lines, r.Line)
			}
		}
		if len(lines) == 0 {
			res.unverified++
		}
		hit := false
		for _, fl := range m.Flaws {
			if taken[fl.ID] || hit {
				continue
			}
			var anchored bool
			for _, ln := range lines {
				if near(anchorLines(t, fl.File, fl.Anchors), ln, window) {
					anchored = true
				}
			}
			if anchored && (intersects(f.CWE, fl.CWE) || intersects(f.CWE, fl.CWEFamily) || intersects([]string{f.Category}, fl.WSTG)) {
				taken[fl.ID] = true
				res.matched = append(res.matched, fl.ID)
				hit = true
			}
		}
		if hit {
			continue
		}
		onDecoy := false
		for _, d := range m.Decoys {
			for _, ln := range lines {
				if near(anchorLines(t, d.File, d.Anchors), ln, window) {
					res.decoyHits = append(res.decoyHits, d.ID)
					onDecoy = true
				}
			}
		}
		if !onDecoy {
			res.unscored++
		}
	}
	sort.Strings(res.matched)
	sort.Strings(res.decoyHits)
	return res
}

// TestFixtureGoldenFilesAreWellFormed: all seven files exist, carry the module's
// schema ids and the GOLDEN run id placeholder, and hold agent-authored fields
// only (nothing the module computes).
func TestFixtureGoldenFilesAreWellFormed(t *testing.T) {
	computed := []string{"band", "score", "verified", "evidence_state", "ref_state", "recall", "computed", "scoring"}
	for _, name := range goldenFileNames() {
		kind, _, _ := strings.Cut(name, ".")
		var top map[string]json.RawMessage
		loadGolden(t, name, &top)
		var schema, runID string
		_ = json.Unmarshal(top["schema"], &schema)
		_ = json.Unmarshal(top["run_id"], &runID)
		want := "observer." + kind + ".v1"
		if schema != want {
			t.Errorf("%s: schema %q, want %q", name, schema, want)
		}
		if runID != "GOLDEN" {
			t.Errorf("%s: run_id %q, want the placeholder GOLDEN", name, runID)
		}
		for _, k := range computed {
			if _, ok := top[k]; ok {
				t.Errorf("%s: top-level %q is computed by the module, not authored by the agent", name, k)
			}
		}
	}
}

// TestFixtureGoldenPentest pins what each pen-test file is built to show.
func TestFixtureGoldenPentest(t *testing.T) {
	m := loadManifest(t)
	var all []string
	for _, f := range m.Flaws {
		all = append(all, f.ID)
	}
	sort.Strings(all)
	want := map[string]penResult{
		"perfect":      {matched: all},
		"partial":      {matched: []string{"F01", "F02", "F03", "F04", "F06", "F09", "F12"}, decoyHits: []string{"D01"}, unscored: 1},
		"hallucinated": {decoyHits: []string{"D03", "D04", "D05"}, unscored: 3, unverified: 3},
	}
	for _, v := range goldenVariants {
		var g goldenPentest
		loadGolden(t, "pentest."+v+".assessment.json", &g)
		got := scorePentest(t, g)
		w := want[v]
		if strings.Join(got.matched, ",") != strings.Join(w.matched, ",") {
			t.Errorf("%s: matched flaws %v, want %v", v, got.matched, w.matched)
		}
		if strings.Join(got.decoyHits, ",") != strings.Join(w.decoyHits, ",") {
			t.Errorf("%s: decoys reported %v, want %v", v, got.decoyHits, w.decoyHits)
		}
		if got.unscored != w.unscored {
			t.Errorf("%s: %d unscored findings, want %d", v, got.unscored, w.unscored)
		}
		if got.unverified != w.unverified {
			t.Errorf("%s: %d findings without a verified reference, want %d", v, got.unverified, w.unverified)
		}
	}
}

// truthElement maps an element id of a golden threat model to the answer key's
// element id (components and actors by name, flows by name with underscores).
func truthElement(tm ThreatModel, kind, id string) (string, bool) {
	switch kind {
	case "component":
		for _, c := range tm.Components {
			if c.Name == id {
				return c.ID, true
			}
		}
	case "actor":
		for _, a := range tm.Actors {
			if a.Name == id {
				return a.ID, true
			}
		}
	case "flow":
		for _, f := range tm.Flows {
			if strings.ReplaceAll(f.Name, " ", "_") == id {
				return f.ID, true
			}
		}
	}
	return "", false
}

type tmResult struct {
	matched    []string // expected threat ids, sorted
	dangling   int      // threats whose element is not in the model's own system
	trapRefs   int      // existing-mitigation references that sit on a trap
	realRefs   []string // existing-mitigation needles that are the six real controls, sorted
	unverified int      // references that do not verify
}

func scoreThreatModel(t *testing.T, g goldenThreatModel) tmResult {
	t.Helper()
	tm := loadThreatModel(t)
	known := map[string]bool{}
	for _, c := range g.System.Components {
		known["component/"+c.ID] = true
	}
	for _, a := range g.System.Actors {
		known["actor/"+a.ID] = true
	}
	for _, f := range g.System.Flows {
		known["flow/"+f.ID] = true
	}
	taken := map[string]bool{}
	var res tmResult
	real := map[string]bool{}
	for _, th := range g.Threats {
		if !known[th.Element.Kind+"/"+th.Element.ID] {
			res.dangling++
		}
		if id, ok := truthElement(tm, th.Element.Kind, th.Element.ID); ok {
			for _, want := range tm.Threats {
				if taken[want.ID] {
					continue
				}
				cell := want.Element.ID == id && want.Element.Kind == th.Element.Kind && want.Category == th.Category
				for _, a := range want.Accept {
					if a.ID == id && a.Kind == th.Element.Kind && a.Category == th.Category {
						cell = true
					}
				}
				if cell {
					taken[want.ID] = true
					res.matched = append(res.matched, want.ID)
					break
				}
			}
		}
		for _, e := range th.Existing {
			for _, r := range e.Refs {
				if !verified(t, r) {
					res.unverified++
					continue
				}
				text := LineText(appFile(t, r.Path), r.Line)
				onTrap := false
				for _, tr := range tm.Traps {
					for _, a := range tr.Anchors {
						if strings.Contains(text, a) {
							onTrap = true
						}
					}
				}
				if onTrap {
					res.trapRefs++
					continue
				}
				for _, mit := range tm.Existing {
					if r.Needle == mit.Needle {
						real[mit.Needle] = true
					}
				}
			}
		}
		for _, mi := range th.Missing {
			for _, r := range mi.Refs {
				if !verified(t, r) {
					res.unverified++
				}
			}
		}
	}
	sort.Strings(res.matched)
	for n := range real {
		res.realRefs = append(res.realRefs, n)
	}
	sort.Strings(res.realRefs)
	return res
}

// TestFixtureGoldenThreatModel pins what each threat-model file is built to
// show.
func TestFixtureGoldenThreatModel(t *testing.T) {
	tm := loadThreatModel(t)
	var allThreats, allNeedles, partialNeedles []string
	for _, th := range tm.Threats {
		allThreats = append(allThreats, th.ID)
	}
	for _, mit := range tm.Existing {
		allNeedles = append(allNeedles, mit.Needle)
		// the partial model keeps the threats TH01, TH03 and TH06, and with
		// them the controls of D01, D06 and D03
		switch mit.Decoy {
		case "D01", "D03", "D06":
			partialNeedles = append(partialNeedles, mit.Needle)
		}
	}
	sort.Strings(allThreats)
	sort.Strings(allNeedles)
	sort.Strings(partialNeedles)
	want := map[string]tmResult{
		"perfect":      {matched: allThreats, realRefs: allNeedles},
		"partial":      {matched: []string{"TH01", "TH02", "TH03", "TH04", "TH05", "TH06", "TH09", "TH12"}, trapRefs: 1, realRefs: partialNeedles},
		"hallucinated": {dangling: 5, trapRefs: 3, unverified: 2},
	}
	for _, v := range goldenVariants {
		var g goldenThreatModel
		loadGolden(t, "threatmodel."+v+".assessment.json", &g)
		got := scoreThreatModel(t, g)
		w := want[v]
		if strings.Join(got.matched, ",") != strings.Join(w.matched, ",") {
			t.Errorf("%s: matched threats %v, want %v", v, got.matched, w.matched)
		}
		if got.dangling != w.dangling {
			t.Errorf("%s: %d threats on an element outside the system, want %d", v, got.dangling, w.dangling)
		}
		if got.trapRefs != w.trapRefs {
			t.Errorf("%s: %d existing-mitigation references on a trap, want %d", v, got.trapRefs, w.trapRefs)
		}
		if strings.Join(got.realRefs, "|") != strings.Join(w.realRefs, "|") {
			t.Errorf("%s: real mitigations credited %v, want %v", v, got.realRefs, w.realRefs)
		}
		if got.unverified != w.unverified {
			t.Errorf("%s: %d references that do not verify, want %d", v, got.unverified, w.unverified)
		}
	}
}

// TestFixtureGoldenPerfectThreatModelCoversEveryCell: the perfect model either
// analyses or explicitly waives every applicable (element, STRIDE category)
// cell of every component, flow and actor, so the module's own coverage matrix
// has no empty cell, and names every component and flow.
func TestFixtureGoldenPerfectThreatModelCoversEveryCell(t *testing.T) {
	tm := loadThreatModel(t)
	var g goldenThreatModel
	loadGolden(t, "threatmodel.perfect.assessment.json", &g)
	covered := map[string]bool{}
	for _, th := range g.Threats {
		covered[th.Element.Kind+"/"+th.Element.ID+"/"+th.Category] = true
	}
	for _, n := range g.NoThreat {
		covered[n.Element.Kind+"/"+n.Element.ID+"/"+n.Category] = true
	}
	for _, c := range tm.Components {
		logs := c.HoldsLogs != nil && *c.HoldsLogs
		for _, cat := range tm.StrideApplicability.Categories(c.Type, logs) {
			if !covered["component/"+c.Name+"/"+cat] {
				t.Errorf("component %s category %s is neither analysed nor waived", c.Name, cat)
			}
		}
	}
	for _, f := range tm.Flows {
		for _, cat := range tm.StrideApplicability.Categories("data_flow", false) {
			if !covered["flow/"+strings.ReplaceAll(f.Name, " ", "_")+"/"+cat] {
				t.Errorf("flow %s category %s is neither analysed nor waived", f.Name, cat)
			}
		}
	}
	for _, a := range tm.Actors {
		for _, cat := range tm.StrideApplicability.Categories("external_entity", false) {
			if !covered["actor/"+a.Name+"/"+cat] {
				t.Errorf("actor %s category %s is neither analysed nor waived", a.Name, cat)
			}
		}
	}
	if len(g.System.Components) != len(tm.Components) || len(g.System.Flows) != len(tm.Flows) {
		t.Errorf("system lists %d components and %d flows, the answer key has %d and %d",
			len(g.System.Components), len(g.System.Flows), len(tm.Components), len(tm.Flows))
	}
}

// TestFixtureGoldenUngroundedThreatModelCitesNothingNearItsFlaw checks, with
// this package's own small matcher (not the module's scorer), what
// threatmodel.ungrounded is built to show: every one of its threats sits on the
// element and STRIDE category of an expected threat (so the cell alone would
// match all 14), and not one of them cites a reference, in an existing-control
// or missing-control entry, that carries its needle on the cited line within
// the anchor window of an anchor of the flaw its expected threat links to. The
// references it does make that are right about the text (needle on the cited
// line) are in the wrong place, so a scorer that only asked "was the reference
// found" would still be fooled; the module's scorer asks both.
func TestFixtureGoldenUngroundedThreatModelCitesNothingNearItsFlaw(t *testing.T) {
	tm, m := loadThreatModel(t), loadManifest(t)
	var g goldenThreatModel
	loadGolden(t, "threatmodel.ungrounded.assessment.json", &g)
	flaws := map[string]Flaw{}
	for _, f := range m.Flaws {
		flaws[f.ID] = f
	}
	var named, grounded []string
	verifiedElsewhere, unverified := 0, 0
	for _, th := range g.Threats {
		id, ok := truthElement(tm, th.Element.Kind, th.Element.ID)
		if !ok {
			t.Errorf("%s: element %s/%s is not an element of the key", th.ID, th.Element.Kind, th.Element.ID)
			continue
		}
		var want *Threat
		for i := range tm.Threats {
			if et := &tm.Threats[i]; et.Element.Kind == th.Element.Kind && et.Element.ID == id && et.Category == th.Category {
				want = et
			}
		}
		if want == nil {
			t.Errorf("%s: (%s/%s, %s) is not the cell of an expected threat", th.ID, th.Element.Kind, th.Element.ID, th.Category)
			continue
		}
		named = append(named, want.ID)
		fl := flaws[want.Flaw]
		anchors := anchorLines(t, fl.File, fl.Anchors)
		var refs []goldenRef
		for _, e := range th.Existing {
			refs = append(refs, e.Refs...)
		}
		for _, x := range th.Missing {
			refs = append(refs, x.Refs...)
		}
		if len(refs) == 0 {
			t.Errorf("%s: cites no reference at all; the golden shows wrong references, not none", th.ID)
		}
		for _, r := range refs {
			switch {
			case !verified(t, r):
				unverified++
			case near(anchors, r.Line, m.Scoring.AnchorWindowLines):
				grounded = append(grounded, th.ID)
			default:
				verifiedElsewhere++
			}
		}
	}
	sort.Strings(named)
	var all []string
	for _, et := range tm.Threats {
		all = append(all, et.ID)
	}
	sort.Strings(all)
	if strings.Join(named, ",") != strings.Join(all, ",") {
		t.Errorf("its threats sit on the cells of %v, want all of %v", named, all)
	}
	if len(grounded) != 0 {
		t.Errorf("threats %v cite a verified reference within %d lines of their flaw's anchor; the golden must be ungrounded", grounded, m.Scoring.AnchorWindowLines)
	}
	// 9 references name real code in the wrong place (so "found" alone proves nothing); 7 do not verify (5 name
	// text that is not on the cited line, one is a file with no line, one a range whose text is far from its
	// first line).
	if verifiedElsewhere != 9 || unverified != 7 {
		t.Errorf("%d references verify in the wrong place and %d do not verify; want 9 and 7 (the fixture source changed under the golden?)", verifiedElsewhere, unverified)
	}
}
