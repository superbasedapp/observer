package secassess

import (
	"fmt"
	"sort"
)

// The retest's own validator rows (depth plan W7.2). A retest's assessment.json
// is read through rows V1 and V2 like any model file, then through rows RT3 to
// RT6 below, which are the retest's counterparts of V3 to V7 and V14. They are
// pure: the options carry the retest's basis (the earlier run's findings that
// were replayed), the helper's facts and the redactor, and nothing is opened.
//
//	RT3  caps: results at MaxRetestFindings, limits, evidence ids
//	RT4  each result names a finding the retest replayed, once, with a label
//	     from the closed list
//	RT5  texts cleaned; probe ids kept only when they are item ids
//	RT6  the label's evidence from the request helper's log: the same table as
//	     row V14, with two rows of its own for a replay (E20 and E21)

// retestRules is the retest's ordered table.
var retestRules = []valRule{
	{"V1", EffectRefuseFile, "size and nesting caps", ruleV1},
	{"V2", EffectRefuseFile, "decode, schema and run id", ruleV2},
	{"RT3", EffectRefuseItem, "result and list caps", ruleRT3},
	{"RT4", EffectRefuseItem, "findings retested and the closed labels", ruleRT4},
	{"RT5", EffectDropField, "text cleaning", ruleRT5},
	{"RT6", EffectSet, "evidence from the request helper's log", ruleRT6},
}

// RetestRules lists the retest's validator rows in order.
func RetestRules() []RuleInfo {
	out := make([]RuleInfo, len(retestRules))
	for i, r := range retestRules {
		out[i] = RuleInfo{r.ID, r.Effect, r.Name}
	}
	return out
}

// flushTrims reports the per-item lists a rule cut, one issue per list path,
// in the order of the path names.
func (v *validator) flushTrims(row string) {
	paths := make([]string, 0, len(v.trims))
	for p := range v.trims {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		v.issue(row, "cap_exceeded", SevDropped, p,
			fmt.Sprintf("%s: %d entries past the per-item cap were left out.", p, v.trims[p]))
	}
}

func ruleRT3(v *validator) {
	rt := v.rt
	if v.o.Retest == nil || len(v.o.Retest.Findings) == 0 {
		v.fail("RT3", "no_retest_basis", "This retest has no stored findings to hold the file to, so it was not read.")
		return
	}
	v.read("results", len(rt.Results))
	if len(rt.Results) > MaxRetestFindings {
		v.leftOut("results", len(rt.Results)-MaxRetestFindings)
		v.issue("RT3", "cap_exceeded", SevRefused, "results",
			fmt.Sprintf("results: %d items past the cap of %d were left out.", len(rt.Results)-MaxRetestFindings, MaxRetestFindings))
		rt.Results = rt.Results[:MaxRetestFindings]
	}
	rt.Limits = trimNested(v, "limits", rt.Limits, maxLimits)
	for i := range rt.Results {
		rt.Results[i].Evidence = trimNested(v, "results.evidence", rt.Results[i].Evidence, maxSmallList)
	}
	v.flushTrims("RT3")
}

func ruleRT4(v *validator) {
	rt := v.rt
	seen := map[string]bool{}
	scan(v, "RT4", "results", rt.Results, func(_ int, r *RTResult) (string, string) {
		switch {
		case !ValidItemID(r.Finding):
			return "bad_id", "The finding id is empty, too long, or uses characters outside letters, digits, dot, underscore and hyphen."
		case seen[r.Finding]:
			return "duplicate_id", "Another result already covers the finding " + clip(r.Finding, 48) + "."
		}
		seen[r.Finding] = true
		if _, ok := v.o.Retest.Find(r.Finding); !ok {
			return "unknown_finding", "The finding " + clip(r.Finding, 48) + " is not one of the findings this retest replayed."
		}
		if !EnumRetestResult.Has(r.Result) {
			return "bad_enum", "The result " + clip(r.Result, 30) + " must be reproduced, not_reproduced or inconclusive."
		}
		return "", ""
	})
	rt.Results = compact(v, "results", rt.Results)
}

func ruleRT5(v *validator) {
	rt := v.rt
	rt.Summary = v.cleanText(rt.Summary, capSummary, "summary")
	rt.PromptVersion = v.cleanText(rt.PromptVersion, 20, "prompt_version")
	rt.Generator.Tool = v.cleanText(rt.Generator.Tool, capName, "generator")
	rt.Generator.Model = v.cleanText(rt.Generator.Model, capName, "generator")
	rt.Limits = v.cleanList(rt.Limits, capShort, "limit")
	for i := range rt.Results {
		r := &rt.Results[i]
		r.Note = v.cleanText(r.Note, capShort, "notes")
		r.Attack, r.Control = v.probeID(r.Attack), v.probeID(r.Control)
		r.Evidence = v.idList(r.Evidence)
	}
	v.flushTrims("RT5")
}

// The retest's two evidence rows of its own, beside the table of row V14
// (evidence.go): a result is read through that table with these in it. A
// result's attack request must be the helper's replay of the finding it names
// (E20), and a result that says the weakness is gone must not have the earlier
// condition holding for that replay in the log (E21). Every row has a test case
// (retest_test.go).
var retestOnlyRows = []evRow{
	{"E20", ReasonNotReplayed, EvidenceUnlogged, func(c *evCtx) bool { return c.attack != nil && c.attack.Replay != c.replay }},
	{"E23", ReasonReplayIncomplete, EvidenceUnlogged, func(c *evCtx) bool { return c.hidden }},
	{"E21", ReasonConditionStillHolds, EvidenceUnlogged, func(c *evCtx) bool { return c.holds(c.attack) }},
	{"E22", "", EvidenceLogged, func(*evCtx) bool { return true }},
}

// retestRowOrder is the order of the rows a result of each claim is read
// through. A claim of "reproduced" is the pen test's table with E20 after the
// attack is named; a claim of "not reproduced" needs the attack, the stored
// condition and a replay whose logged response does not hold it.
var retestRowOrder = map[string][]string{
	RetestReproduced:    {"E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "E10", "E11", "E12", "E13", "E14", "E20", "E15", "E16", "E17", "E18", "E19"},
	RetestNotReproduced: {"E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9", "E10", "E11", "E12", "E13", "E14", "E20", "E23", "E16", "E21", "E22"},
}

// evidenceRowByID indexes the shared table and the retest's rows by id.
var evidenceRowByID = func() map[string]evRow {
	m := map[string]evRow{}
	for _, r := range evidenceRows {
		m[r.ID] = r
	}
	for _, r := range retestOnlyRows {
		m[r.ID] = r
	}
	return m
}()

// retestWalk reads one result's evidence: the first row of its claim's order
// that holds.
func retestWalk(c *evCtx, claim string) (EvidenceState, string, string) {
	for _, id := range retestRowOrder[claim] {
		if r := evidenceRowByID[id]; r.Hit(c) {
			return r.State, r.Reason, r.ID
		}
	}
	return EvidenceUnlogged, ReasonNoProbe, ""
}

func ruleRT6(v *validator) {
	rt := v.rt
	b := v.evidenceBase()
	sum := &RetestSummary{Replayed: len(v.o.Retest.Findings)}
	covered := map[string]bool{}
	for i := range rt.Results {
		r := &rt.Results[i]
		bf, _ := v.o.Retest.Find(r.Finding)
		r.Title, r.Category = v.redactClean(bf.Title, capTitle), bf.Category
		covered[r.Finding] = true
		switch r.Result {
		case RetestReproduced:
			sum.Reproduced++
		case RetestNotReproduced:
			sum.NotReproduced++
		default:
			sum.Inconclusive++
			continue // a label of "inconclusive" claims nothing to back
		}
		f := &PTFinding{ID: r.Finding, Evidence: r.Evidence, Indicator: &PTIndicator{Control: r.Control, Attack: r.Attack, When: bf.When}}
		c := &evCtx{started: rt.Started, helper: b.rep.Helper, mode: b.mode, log: b.state, byID: b.byID, f: f, cited: citedProbes(f), view: b.view, replay: r.Finding, hidden: bf.Hidden}
		c.attack, c.control = b.byID[r.Attack], b.byID[r.Control]
		st, reason, _ := retestWalk(c, r.Result)
		r.EvidenceState, r.EvidenceReason = st, reason
		b.rep.tally(st, reason)
	}
	for _, f := range v.o.Retest.Findings {
		if !covered[f.ID] {
			sum.Missing++
		}
	}
	rt.Of = v.o.Retest.Of
	v.rep.Evidence, v.rep.RT = b.rep, sum
	if sum.Missing > 0 {
		v.issue("RT6", "finding_not_covered", SevWarn, "results",
			fmt.Sprintf("%d of the findings this retest replayed have no result.", sum.Missing))
	}
	if !rt.Started {
		v.issue("RT6", "target_not_started", SevWarn, "started", "The agent says the target did not start, so no label is backed by the request helper's log.")
	}
}

// CitedRetestProbes lists every probe id a retest's results name, sorted by
// their position in the log, without repeats.
func CitedRetestProbes(rt *RetestDoc) []string {
	seen := map[string]bool{}
	var ids []string
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, r := range rt.Results {
		add(r.Attack)
		add(r.Control)
		for _, id := range r.Evidence {
			add(id)
		}
	}
	sort.SliceStable(ids, func(i, j int) bool { return probeNumber(ids[i]) < probeNumber(ids[j]) })
	return ids
}

// StoredRetestProbes returns the log records a retest's results cite, in the
// log's order, in their stored form (StoredProbe).
func StoredRetestProbes(rt *RetestDoc, log ProbeLog, redact func(string) string) []ProbeRecord {
	if rt == nil {
		return nil
	}
	byID := log.byID()
	var out []ProbeRecord
	for _, id := range CitedRetestProbes(rt) {
		if r := byID[id]; r != nil {
			out = append(out, StoredProbe(*r, redact))
		}
	}
	return out
}
