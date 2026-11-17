package secassess

import (
	"fmt"
	"sort"
	"strings"
)

// The pen test scorer (depth plan section 7, "Scoring"). It scores what the
// validator kept, against manifest.json:
//
//   - a finding matches a flaw when one of its references that the check FOUND
//     at the cited line is within the anchor window of one of the flaw's
//     anchors in the same file, and its CWE is the flaw's CWE or in its family
//     or its WSTG category is the flaw's; matching is one-to-one and maximal;
//   - a finding that matches nothing and sits on a decoy's anchor is a counted
//     false positive; one that sits near no anchor but is a real property of
//     the fixture (an incidental entry, by CWE) is incidental, neither a hit
//     nor a false positive; every other finding is listed as unscored, never
//     dropped from the account;
//   - recall is matched over the flaws, precision is matched over the findings
//     the model kept.
//
// A reference that is only "exists" or worse earns no credit (plan section
// 3.4: only found earns the label "found near the cited line").
//
// Grounding is required here already, by construction: the places a finding is
// set against the key (scPenCtx.locs) are built from found references only, at
// the line the text was found on, and a flaw is a candidate only when one of
// them is within the manifest's anchor window of one of its anchors. The threat
// model scorer reads the same rule (scoretm_test.go scGrounded: a matched threat
// needs a found reference within that window of its flaw's anchor), so a model
// that names the right thing without pointing at the code scores nothing on
// either side.

// scPenHit is one finding set against one entry of the key.
type scPenHit struct {
	Finding string // the finding's id
	Key     string // the flaw, decoy or incidental id it was set against ("" when none)
	Why     string
}

// scPenScore is the account of one pen test against the key.
type scPenScore struct {
	Flaws    int
	Reported int // findings the validator kept
	Matched  []string
	// Taken is the flaw each matched finding took, by the finding's id (the retest
	// scorer reads it: a retest names the earlier run's findings).
	Taken     map[string]string
	Missed    []string
	Recall    float64
	Precision float64 // matched over reported

	DecoyHits  []scPenHit // false positives
	Incidental []scPenHit
	Duplicates []scPenHit // a second report of a flaw already matched
	Unscored   []scPenHit

	NoCredit     int // findings with no reference found at its cited line
	WithEvidence int // findings that list at least one probe id (a claim; not yet checked against a log)

	Coverage struct {
		Rows, Filled, Tested, NotApplicable, Skipped int
	}
	Validator scValidator
}

// scoreCoverage fills the coverage numbers from the validator's report.
func (s *scPenScore) scoreCoverage(rep Report) {
	if rep.PT == nil {
		return
	}
	s.Coverage.Rows = len(rep.PT.Rows)
	for _, r := range rep.PT.Rows {
		if r.Effective != CovMissing {
			s.Coverage.Filled++
		}
		switch r.Effective {
		case CovTestedClaimed, CovTestedLogged:
			s.Coverage.Tested++
		case CovNotApplicable:
			s.Coverage.NotApplicable++
		case CovSkipped, CovNotStarted, CovToolUnavailable:
			s.Coverage.Skipped++
		}
	}
}

// scLoc is a place a finding was found at, from a reference the check found.
type scLoc struct {
	file   string
	lo, hi int
}

// scNearAny reports whether any location is in file and within window of an
// anchor line.
func scNearAny(locs []scLoc, file string, anchors []int, window int) bool {
	for _, l := range locs {
		if l.file == file && scNear(anchors, l.lo, l.hi, window) {
			return true
		}
	}
	return false
}

// scMinDistance is the nearest any location of file comes to an anchor.
func scMinDistance(locs []scLoc, file string, anchors []int) int {
	best := 1 << 30
	for _, l := range locs {
		if l.file != file {
			continue
		}
		for _, a := range anchors {
			if d := scDistance(l.lo, l.hi, a); d < best {
				best = d
			}
		}
	}
	return best
}

// scPenCtx is the manifest with its anchors resolved against one project and
// the findings of one result with the places the check found them at.
type scPenCtx struct {
	m       *scManifest
	window  int
	flawAt  [][]int
	decoyAt [][]int
	fs      []PTFinding
	locs    [][]scLoc
}

// scPenAnchors resolves the manifest's flaw and decoy anchors.
func scPenAnchors(m *scManifest, src scSource) (flawAt, decoyAt [][]int, err error) {
	for _, f := range m.Flaws {
		l, err := scAnchorLines(src, f.File, f.Anchors, false)
		if err != nil {
			return nil, nil, fmt.Errorf("flaw %s: %w", f.ID, err)
		}
		flawAt = append(flawAt, l)
	}
	for _, d := range m.Decoys {
		l, err := scAnchorLines(src, d.File, d.Anchors, false)
		if err != nil {
			return nil, nil, fmt.Errorf("decoy %s: %w", d.ID, err)
		}
		decoyAt = append(decoyAt, l)
	}
	return flawAt, decoyAt, nil
}

// candidates are the flaws finding i may take: its reference is near the
// flaw's anchor and its class is the flaw's; the nearest comes first.
func (c *scPenCtx) candidates(i int) []int {
	f := c.fs[i]
	var out []int
	for j, fl := range c.m.Flaws {
		if !scNearAny(c.locs[i], fl.File, c.flawAt[j], c.window) {
			continue
		}
		if scIntersect(f.CWE, fl.CWE) || scIntersect(f.CWE, fl.CWEFamily) || scIntersect([]string{f.Category}, fl.WSTG) {
			out = append(out, j)
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		return scMinDistance(c.locs[i], c.m.Flaws[out[a]].File, c.flawAt[out[a]]) <
			scMinDistance(c.locs[i], c.m.Flaws[out[b]].File, c.flawAt[out[b]])
	})
	return out
}

// Where an unmatched finding goes in the account.
const (
	scUnscored = iota
	scDuplicate
	scDecoyHit
	scIncidentalHit
)

// classify says where an unmatched finding goes: never nowhere. cands are the
// flaws it qualified for (all of them taken by other findings).
func (c *scPenCtx) classify(i int, cands []int) (int, scPenHit) {
	hit := scPenHit{Finding: c.fs[i].ID}
	switch {
	case len(c.locs[i]) == 0:
		hit.Why = "no reference found at its cited line"
		return scUnscored, hit
	case len(cands) > 0:
		hit.Key, hit.Why = c.m.Flaws[cands[0]].ID, "repeats a flaw already matched"
		return scDuplicate, hit
	}
	if d := scNearDecoy(c.m, c.decoyAt, c.locs[i], c.window); d != "" {
		hit.Key, hit.Why = d, "reported a near miss as a weakness"
		return scDecoyHit, hit
	}
	for j, fl := range c.m.Flaws {
		if scNearAny(c.locs[i], fl.File, c.flawAt[j], c.window) {
			hit.Key, hit.Why = fl.ID, "near this flaw's anchor but not its class"
			return scUnscored, hit
		}
	}
	if inc := scIncidentalOf(c.m, c.fs[i].CWE); inc != "" {
		hit.Key, hit.Why = inc, "a real property of the fixture that was not seeded"
		return scIncidentalHit, hit
	}
	hit.Why = "near no anchor of the key"
	return scUnscored, hit
}

// scorePentest scores a validated pen test against the manifest. The project
// source resolves the manifest's anchors to lines; an anchor that cannot be
// resolved is an error (the key and the project copy disagree).
func scorePentest(m *scManifest, src scSource, res Result) (scPenScore, error) {
	s := scPenScore{Flaws: len(m.Flaws), Validator: scTally(res.Report), Taken: map[string]string{}}
	s.scoreCoverage(res.Report)
	flawAt, decoyAt, err := scPenAnchors(m, src)
	if err != nil {
		return s, err
	}
	if res.PT == nil {
		for _, f := range m.Flaws {
			s.Missed = append(s.Missed, f.ID)
		}
		return s, nil
	}

	c := &scPenCtx{m: m, window: m.Scoring.AnchorWindowLines, flawAt: flawAt, decoyAt: decoyAt, fs: res.PT.Findings}
	s.Reported = len(c.fs)
	c.locs = make([][]scLoc, len(c.fs))
	for i, f := range c.fs {
		for _, r := range f.Where.Refs {
			if r.State == RefFound {
				lo, hi := scRange(r)
				c.locs[i] = append(c.locs[i], scLoc{r.Path, lo, hi})
			}
		}
		if len(c.locs[i]) == 0 {
			s.NoCredit++
		}
		if len(f.Evidence) > 0 {
			s.WithEvidence++
		}
	}

	adj := make([][]int, len(c.fs))
	for i := range c.fs {
		adj[i] = c.candidates(i)
	}
	take := scMatch(len(c.fs), len(m.Flaws), adj)
	got := make([]bool, len(m.Flaws))
	for _, j := range take {
		if j >= 0 {
			got[j] = true
			s.Matched = append(s.Matched, m.Flaws[j].ID)
		}
	}
	for i, j := range take {
		if j >= 0 {
			s.Taken[c.fs[i].ID] = m.Flaws[j].ID
		}
	}
	for j, fl := range m.Flaws {
		if !got[j] {
			s.Missed = append(s.Missed, fl.ID)
		}
	}
	sort.Strings(s.Matched)

	for i := range c.fs {
		if take[i] >= 0 {
			continue
		}
		bucket, hit := c.classify(i, adj[i])
		switch bucket {
		case scDuplicate:
			s.Duplicates = append(s.Duplicates, hit)
		case scDecoyHit:
			s.DecoyHits = append(s.DecoyHits, hit)
		case scIncidentalHit:
			s.Incidental = append(s.Incidental, hit)
		default:
			s.Unscored = append(s.Unscored, hit)
		}
	}

	if s.Flaws > 0 {
		s.Recall = float64(len(s.Matched)) / float64(s.Flaws)
	}
	if s.Reported > 0 {
		s.Precision = float64(len(s.Matched)) / float64(s.Reported)
	}
	return s, nil
}

// scNearDecoy returns the id of a decoy any location sits on, or "".
func scNearDecoy(m *scManifest, decoyAt [][]int, locs []scLoc, w int) string {
	for j, d := range m.Decoys {
		if scNearAny(locs, d.File, decoyAt[j], w) {
			return d.ID
		}
	}
	return ""
}

// scIncidentalOf returns the incidental entry a CWE list matches, or "".
func scIncidentalOf(m *scManifest, cwe []string) string {
	for _, in := range m.Incidental {
		if scIntersect(cwe, in.CWE) {
			return in.ID
		}
	}
	return ""
}

// Lines renders the score for a person (the live check pastes this).
func (s scPenScore) Lines() []string {
	pct := func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) }
	out := []string{
		fmt.Sprintf("pen test: %d of %d seeded weaknesses matched (recall %s); %d findings kept, precision %s",
			len(s.Matched), s.Flaws, pct(s.Recall), s.Reported, pct(s.Precision)),
		"  matched: " + scList(s.Matched),
		"  missed:  " + scList(s.Missed),
		fmt.Sprintf("  false positives (a near miss reported as a weakness): %d%s", len(s.DecoyHits), scHits(s.DecoyHits)),
		fmt.Sprintf("  incidental (real, not seeded): %d%s", len(s.Incidental), scHits(s.Incidental)),
		fmt.Sprintf("  repeats of a matched flaw: %d%s", len(s.Duplicates), scHits(s.Duplicates)),
		fmt.Sprintf("  unscored (listed, never ignored): %d%s", len(s.Unscored), scHits(s.Unscored)),
		fmt.Sprintf("  findings with no reference found at its cited line: %d; findings that list evidence (a claim): %d",
			s.NoCredit, s.WithEvidence),
		fmt.Sprintf("  coverage: %d rows, %d filled, %d tested, %d not applicable, %d skipped or unavailable",
			s.Coverage.Rows, s.Coverage.Filled, s.Coverage.Tested, s.Coverage.NotApplicable, s.Coverage.Skipped),
		s.Validator.line(),
	}
	return out
}

func (v scValidator) line() string {
	fatal := ""
	if v.Fatal != "" {
		fatal = " fatal=" + v.Fatal
	}
	return fmt.Sprintf("  validator: %s%s; issues refused %d, dropped %d, warned %d; items left out %d; references found %d, exists %d, claimed not found %d, missing %d, invalid %d, unchecked %d; codes [%s]%s",
		v.State, fatal, v.Refused, v.Dropped, v.Warned, v.ItemsOut,
		v.Refs.Found, v.Refs.Exists, v.Refs.ClaimedNotFound, v.Refs.Missing, v.Refs.Invalid, v.Refs.Unchecked,
		strings.Join(v.Codes, " "), v.conditions())
}

// conditions is the line's tail: the settings the reference counts were made
// under, so a difference from the dashboard's check on the same file is read
// against them (live defect 8: 192 found and 7 not found on the node, 198 and 1
// here, with the same window; the node hides secrets in the quoted text before it
// searches the files and this scorer does not).
func (v scValidator) conditions() string {
	if v.Window == 0 {
		return ""
	}
	return fmt.Sprintf("\n  reference check: found means the quoted text is within %d lines of the first cited line (the node's setting ref_match_window_lines; this scorer uses the default, %d); no redactor is applied here, the node's check applies one, so on the node a reference whose quoted text hiding secrets rewrites reads not found (here: %d)",
		v.Window, DefaultRefWindow, v.Hidden)
}

func scList(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	return strings.Join(ids, " ")
}

func scHits(h []scPenHit) string {
	if len(h) == 0 {
		return ""
	}
	parts := make([]string, len(h))
	for i, x := range h {
		k := ""
		if x.Key != "" {
			k = " -> " + x.Key
		}
		parts[i] = x.Finding + k + " (" + x.Why + ")"
	}
	return ": " + strings.Join(parts, "; ")
}
