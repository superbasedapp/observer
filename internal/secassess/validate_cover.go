package secassess

import (
	"fmt"
	"sort"
	"strings"
)

// Rows V8 to V13 of the rule table: references, scope, the computed band and
// the coverage reports. These rows run on the compacted model, so their issue
// paths name items by id.

// isWSTG reports whether id is one of the twelve test categories.
func isWSTG(id string) bool {
	_, ok := WSTGCategoryByID(id)
	return ok
}

// ---- V8: source references ----

// refMessages says in words what each reference code or state means.
var refMessages = map[string]string{
	"ref_path_refused":      "%d references have a path that is not project-relative; they are marked invalid.",
	"ref_range_invalid":     "%d references have a backwards or negative line range; they are marked invalid.",
	"ref_range_long":        "%d references cover more than %d lines; they are marked invalid.",
	"ref_needle_far":        "%d references give a text that is in the cited range only past the first %d lines from the cited line; only the location was checked, and nothing there earns credit.",
	"ref_file_missing":      "%d references name a file that is not in the project; they are marked missing.",
	"ref_line_past_end":     "%d references cite a line past the end of the file; they are marked missing.",
	"ref_budget":            "%d references were not looked at because the check ran out of its read budget.",
	"ref_no_checker":        "%d references were not looked at because no check was available.",
	"ref_needle_weak":       "%d references gave a text to match that is too short or too plain to count; only the location was checked.",
	"ref_needle_needs_line": "%d references gave a text to match but no line; only the file was checked.",
	"ref_needle_not_found":  "%d references name a text that is not in the cited lines; they earn no credit.",
}

func (v *validator) checkRef(r *Ref, codes map[string]int) {
	k := refKey{r.Path, r.Needle, r.Line, r.EndLine}
	out, ok := v.memo[k]
	if !ok {
		out = ClassifyRef(*r, v.o.Refs, v.o.RefWindow)
		v.memo[k] = out
	}
	r.State, r.MatchLine = out.State, out.Line
	if out.State != RefFound && v.hidden[k] {
		v.refsHidden++
	}
	t := &v.rep.Refs
	switch out.State {
	case RefFound:
		t.Found++
	case RefExists:
		t.Exists++
	case RefClaimedNotFound:
		t.ClaimedNotFound++
	case RefMissing:
		t.Missing++
	case RefInvalid:
		t.Invalid++
	default:
		t.Unchecked++
	}
	code := out.Code
	if code == "" && out.State == RefClaimedNotFound {
		code = "ref_needle_not_found"
	}
	if code != "" {
		codes[code]++
	}
}

func ruleV8(v *validator) {
	codes := map[string]int{}
	if m := v.tm; m != nil {
		for i := range m.System.Components {
			for j := range m.System.Components[i].Paths {
				v.checkRef(&m.System.Components[i].Paths[j], codes)
			}
		}
		for i := range m.System.EntryPoints {
			if r := m.System.EntryPoints[i].Ref; r != nil {
				v.checkRef(r, codes)
			}
		}
		for i := range m.Threats {
			t := &m.Threats[i]
			for j := range t.Existing {
				for k := range t.Existing[j].Refs {
					v.checkRef(&t.Existing[j].Refs[k], codes)
				}
			}
			for j := range t.Missing {
				for k := range t.Missing[j].Refs {
					v.checkRef(&t.Missing[j].Refs[k], codes)
				}
			}
		}
	}
	if p := v.pt; p != nil {
		for i := range p.Findings {
			for j := range p.Findings[i].Where.Refs {
				v.checkRef(&p.Findings[i].Where.Refs[j], codes)
			}
		}
	}
	names := make([]string, 0, len(codes))
	for c := range codes {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		msg := refMessages[c]
		switch {
		case c == "ref_needle_far":
			msg = fmt.Sprintf(msg, codes[c], v.refWindow())
		case strings.Count(msg, "%d") == 2:
			msg = fmt.Sprintf(msg, codes[c], maxRefSpan)
		default:
			msg = fmt.Sprintf(msg, codes[c])
		}
		v.issue("V8", c, SevWarn, "refs", msg)
	}
}

// ---- V9: scope ----

// underScope reports whether rel is a scope path or inside one. An empty or
// root scope entry means the whole project.
func underScope(rel string, scope []string) bool {
	if len(scope) == 0 {
		return true
	}
	for _, s := range scope {
		s = strings.Trim(strings.ReplaceAll(s, "\\", "/"), "/")
		if s == "" || s == "." || rel == s || strings.HasPrefix(rel, s+"/") {
			return true
		}
	}
	return false
}

func ruleV9(v *validator) {
	if m := v.tm; m != nil {
		out := 0
		for _, p := range m.Scope.InScope {
			if !underScope(p, v.o.ScopePaths) {
				out++
			}
		}
		for _, c := range m.System.Components {
			for _, r := range c.Paths {
				if r.State.Located() && !underScope(r.Path, v.o.ScopePaths) {
					out++
				}
			}
		}
		if out > 0 {
			v.issue("V9", "scope_outside_plan", SevWarn, "scope",
				fmt.Sprintf("%d paths in the model are outside the scope the plan set.", out))
		}
	}
	if p := v.pt; p != nil && v.o.TargetURL != "" && p.Target.URL != "" && p.Target.URL != v.o.TargetURL {
		v.issue("V9", "target_differs", SevWarn, "target",
			"The target address in the file is not the address the developer confirmed.")
	}
}

// ---- V10: the inherent band ----

func ruleV10(v *validator) {
	if m := v.tm; m != nil {
		for i := range m.Threats {
			t := &m.Threats[i]
			t.Score, t.Band = t.Rating.Score(), BandOf(t.Rating)
		}
	}
	if p := v.pt; p != nil {
		for i := range p.Findings {
			f := &p.Findings[i]
			f.Score, f.Band = f.Rating.Score(), BandOf(f.Rating)
			if err := applyCVSS(f); err != nil {
				// Row V5 vetted the vector, so this does not happen; if it ever
				// does, the vector is dropped rather than shown without a score.
				f.CVSS = ""
				v.issueItem("V10", "cvss_not_scored", SevDropped, f.ID, f.ID, "The CVSS vector of "+findingWords(f.ID)+" could not be scored, so it was left out.")
			}
		}
	}
}

// ---- V11: threat model coverage ----

// CellState is the state of one element and category pair.
type CellState string

// The cell states. "Analysed" means at least one threat is recorded for the
// pair; "waived" means the agent wrote that it considered the pair and found
// none, with a reason; "empty" means neither. The three are reported as
// counts, never as one percentage.
const (
	CellAnalysed CellState = "analysed"
	CellWaived   CellState = "waived"
	CellEmpty    CellState = "empty"
)

// CoverageCell is one category of one element.
type CoverageCell struct {
	Category string    `json:"category"`
	State    CellState `json:"state"`
}

// CoverageRow is one element of the model with its cells.
type CoverageRow struct {
	Kind  string         `json:"kind"`
	ID    string         `json:"id"`
	Name  string         `json:"name,omitempty"`
	Class DFDClass       `json:"class"`
	Cells []CoverageCell `json:"cells"`
}

// FrameworkCoverage counts the cells of one framework.
type FrameworkCoverage struct {
	Framework string `json:"framework"`
	Analysed  int    `json:"analysed"`
	Waived    int    `json:"waived"`
	Empty     int    `json:"empty"`
}

// TMCoverage is the threat model coverage report.
type TMCoverage struct {
	Analysed    int                 `json:"analysed"`
	Waived      int                 `json:"waived"`
	Empty       int                 `json:"empty"`
	ByFramework []FrameworkCoverage `json:"by_framework,omitempty"`
	Rows        []CoverageRow       `json:"rows,omitempty"`
	// AIThreats counts the threats written under each AI framework; the cells
	// of those frameworks are filled by a later wave, so no denominator is
	// reported for them.
	AIThreats map[string]int `json:"ai_threats,omitempty"`
}

type cellKey struct{ kind, id, cat string }

func ruleV11(v *validator) {
	m := v.tm
	if m == nil {
		return
	}
	analysed, waived := map[cellKey]bool{}, map[cellKey]bool{}
	ai := map[string]int{}
	for _, t := range m.Threats {
		analysed[cellKey{t.Element.Kind, t.Element.ID, t.Category}] = true
		if t.Framework == FrameworkOWASPLLM || t.Framework == FrameworkOWASPAgentic {
			ai[t.Framework]++
		}
	}
	for _, n := range m.NoThreat {
		waived[cellKey{n.Element.Kind, n.Element.ID, n.Category}] = true
	}
	cov := &TMCoverage{}
	if len(ai) > 0 {
		cov.AIThreats = ai
	}
	per := map[string]*FrameworkCoverage{}
	cell := func(kind, id, cat, framework string) CoverageCell {
		k := cellKey{kind, id, cat}
		st := CellEmpty
		switch {
		case analysed[k]:
			st = CellAnalysed
		case waived[k]:
			st = CellWaived
		}
		fc := per[framework]
		if fc == nil {
			fc = &FrameworkCoverage{Framework: framework}
			per[framework] = fc
		}
		switch st {
		case CellAnalysed:
			cov.Analysed++
			fc.Analysed++
		case CellWaived:
			cov.Waived++
			fc.Waived++
		default:
			cov.Empty++
			fc.Empty++
		}
		return CoverageCell{Category: cat, State: st}
	}
	row := func(kind, id, name string, class DFDClass, holdsLogs, personal bool) {
		r := CoverageRow{Kind: kind, ID: id, Name: name, Class: class}
		for _, cat := range ApplicableStride(class, holdsLogs) {
			r.Cells = append(r.Cells, cell(kind, id, cat, FrameworkSTRIDE))
		}
		if personal && v.fw[FrameworkLINDDUN] {
			for _, c := range LinddunCategories {
				r.Cells = append(r.Cells, cell(kind, id, c.ID, FrameworkLINDDUN))
			}
		}
		cov.Rows = append(cov.Rows, r)
	}
	for _, c := range m.System.Components {
		t, _ := ComponentTypeByID(c.Type)
		row("component", c.ID, c.Name, t.Class, t.HoldsLogs, false)
	}
	for _, a := range m.System.Actors {
		row("actor", a.ID, a.Name, ClassExternalEntity, false, false)
	}
	for _, f := range m.System.Flows {
		row("flow", f.ID, f.From+" to "+f.To, ClassDataFlow, false, f.PersonalData)
	}
	for _, fw := range []string{FrameworkSTRIDE, FrameworkLINDDUN} {
		if fc := per[fw]; fc != nil {
			cov.ByFramework = append(cov.ByFramework, *fc)
		}
	}
	v.rep.TM = cov
	if cov.Empty > 0 {
		v.issue("V11", "coverage_empty_cells", SevWarn, "coverage",
			fmt.Sprintf("%d element and category pairs have neither a threat nor a reason that none applies.", cov.Empty))
	}
}

// ---- V12: abuse cases and attack trees ----

func ruleV12(v *validator) {
	m := v.tm
	if m == nil {
		return
	}
	idx := make([]int, len(m.Threats))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return m.Threats[idx[a]].Score > m.Threats[idx[b]].Score })
	high := 0
	for _, t := range m.Threats {
		if BandRank(t.Band) >= BandRank(BandHigh) {
			high++
		}
	}
	top := high
	if top < 5 {
		top = 5
	}
	if top > len(idx) {
		top = len(idx)
	}
	if v.extras[ExtraAbuseCases] {
		var missing []string
		for _, i := range idx[:top] {
			if m.Threats[i].AbuseCase == nil {
				missing = append(missing, m.Threats[i].ID)
			}
		}
		if len(missing) > 0 {
			shown := missing
			if len(shown) > 5 {
				shown = shown[:5]
			}
			v.issue("V12", "abuse_case_missing", SevWarn, "threats",
				fmt.Sprintf("%d of the top %d threats have no abuse case (for example %s).", len(missing), top, strings.Join(shown, ", ")))
		}
	}
	if v.extras[ExtraAttackTrees] && high >= 3 && len(m.AttackTrees) == 0 {
		v.issue("V12", "attack_tree_missing", SevWarn, "attack_trees",
			fmt.Sprintf("%d threats rate high or critical and the model has no attack tree.", high))
	}
}

// ---- V13: penetration test coverage ----

// The effective coverage words: the agent's claim as Observer reads it.
const (
	// CovTestedClaimed: the agent says it tested the category; no request log
	// backs it (a request log arrives with the evidence wave).
	CovTestedClaimed = "tested_claimed"
	// CovTestedLogged: tested, and a logged request backs it. Set by the
	// evidence wave; never set by this validator.
	CovTestedLogged    = "tested_logged"
	CovSkipped         = "skipped"
	CovNotApplicable   = "not_applicable"
	CovToolUnavailable = "tool_unavailable"
	// CovNotStarted: the target did not start, so every row reads as skipped.
	CovNotStarted = "skipped_not_started"
	// CovMissing: the agent gave no row for the category.
	CovMissing = "missing"
)

// PTCoverageRow is one test category.
type PTCoverageRow struct {
	Category  string `json:"category"`
	Title     string `json:"title"`
	Agent     string `json:"agent,omitempty"`
	Effective string `json:"effective"`
	Reason    string `json:"reason,omitempty"`
}

// PTCoverage is the penetration test coverage report.
type PTCoverage struct {
	// Started is the agent's claim that the target started.
	Started bool            `json:"started"`
	Rows    []PTCoverageRow `json:"rows"`
	Counts  map[string]int  `json:"counts"`
}

func ruleV13(v *validator) {
	p := v.pt
	if p == nil {
		return
	}
	byCat := map[string]PTCoverageRow{}
	for _, c := range p.Coverage {
		byCat[c.Category] = PTCoverageRow{Category: c.Category, Agent: c.Status, Reason: c.Reason}
	}
	cov := &PTCoverage{Started: p.Target.Start.Started, Counts: map[string]int{}}
	for _, c := range WSTGCategories {
		if !v.cats[c.ID] {
			continue
		}
		r := byCat[c.ID]
		r.Category, r.Title = c.ID, c.Title
		switch {
		case !cov.Started:
			r.Effective = CovNotStarted
		case r.Agent == "":
			r.Effective = CovMissing
		case r.Agent == "tested":
			r.Effective = CovTestedClaimed
		default:
			r.Effective = r.Agent
		}
		cov.Rows = append(cov.Rows, r)
		cov.Counts[r.Effective]++
	}
	v.rep.PT = cov
	if !cov.Started {
		down := 0
		for i := range p.Findings {
			if p.Findings[i].Basis == "observed" {
				p.Findings[i].Basis = "inferred"
				down++
			}
		}
		v.issue("V13", "target_not_started", SevWarn, "target",
			"The agent says the target did not start, so every test category reads as skipped.")
		if down > 0 {
			v.issue("V13", "observed_without_target", SevWarn, "findings",
				fmt.Sprintf("%d findings said they were observed in a request although the target did not start; they are shown as inferred from code.", down))
		}
	}
	if n := cov.Counts[CovMissing]; n > 0 {
		v.issue("V13", "coverage_missing_rows", SevWarn, "coverage",
			fmt.Sprintf("%d test categories have no coverage row.", n))
	}
}
