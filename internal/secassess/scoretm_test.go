package secassess

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The threat model scorer (depth plan section 7, "Scoring"). It scores what the
// validator kept, against threatmodel.json:
//
//   - a model's own ids mean nothing to the key, so model components are mapped
//     to the key's by the places their references cite (within scCompWindow
//     lines of an anchor of the key's component, nearest first) and then by the
//     key's name hints; model flows by their resolved endpoints (an actor on
//     either end is the one "client" of the key);
//   - a model threat matches an expected threat when its STRIDE category and the
//     element it resolves to are the expected (element, category), or are one of
//     its accepted cells, AND it is grounded: at least one reference of its own
//     (an existing-control or a missing-control reference) that the check FOUND
//     sits within the anchor window (the manifest's scoring.anchor_window_lines,
//     the pen test scorer's window) of an anchor of the flaw the key links the
//     expected threat to (review m8: before, the element and the category alone
//     earned recall, so a template-filled model with no references scored full
//     marks). Credit is local, as everywhere: the line a reference's text was
//     found on, never the range it cites. Matching is one-to-one and maximal over
//     the grounded edges. The cell-only match is still computed and reported
//     (CellMatched), so the gap between "named the right cell" and "named it and
//     pointed at the code" is visible; threats that fit a cell and are not
//     grounded are listed as Ungrounded, never dropped. The pen test scorer
//     reads the same rule (scorepen_test.go: a finding earns a flaw only through
//     a reference the check found, within the same window of the flaw's anchor);
//   - the cells an assessor must analyse or waive are every applicable STRIDE
//     category of the key's components and flows (the key's own applicability
//     chart; actors are not part of the key's cell list);
//   - a mitigation counts as credited only through a reference the check FOUND
//     at its cited line; the six real controls of the key are credited when a
//     found reference sits on their anchor, and a found reference at a trap is
//     a defect of the check (or, for a trap marked known_limit, the check's
//     stated limit: it proves a line exists, not that it works).

const (
	// scCompWindow is how near an anchor a model component's reference must
	// sit to map the component to the key's.
	scCompWindow = 40
	// scMitWindow is how near a mitigation's or trap's anchor a found
	// reference must sit to be set against it.
	scMitWindow = 2
)

// scTMScore is the account of one threat model against the key.
type scTMScore struct {
	Expected  int
	Reported  int // threats the validator kept, all frameworks
	NotScored int // kept threats of a framework the key does not cover
	Matched   []string
	Missed    []string
	// Unmatched are kept STRIDE threats that fit no expected threat's cell.
	Unmatched []string
	// Ungrounded are kept STRIDE threats whose element and category fit an
	// expected threat's cell but that cite no reference the check found within
	// the window of that threat's flaw anchor (review m8). They earn nothing.
	Ungrounded []string
	// CellMatched are the expected threats the model's elements and categories
	// alone would match, references or no (the rule before grounding); Matched
	// is a subset of it.
	CellMatched []string
	// GroundedShare is Matched over CellMatched: of the expected threats the
	// model named, the share it also pointed at the code for. Zero when it
	// named none.
	GroundedShare float64
	Recall        float64

	Components struct{ Expected, Mapped int }
	Flows      struct{ Expected, Mapped int }

	Cells struct {
		Required, Analysed, Waived, Empty int
	}
	CellCoverage float64 // (analysed + waived) over required

	Mitigations struct {
		Cited, Found, ClaimedNotFound int
		FoundShare, ClaimedShare      float64
	}
	RealCredited []string // the key's real controls a found reference sits on
	RealMissed   []string
	TrapSeen     []string // traps any cited reference sits on, whatever its state
	TrapHits     []string // credited at a trap that is a defect of the check
	TrapLimits   []string // credited at a trap that is the check's stated limit

	Validator scValidator
	// ReportCells are the validator's own coverage numbers, which count actors
	// as elements as well.
	ReportCells struct{ Analysed, Waived, Empty int }
}

// scCategories are the STRIDE categories the chart lists for a key element
// class. Repudiation applies to a data store only when it holds logs, so the
// chart's repudiation for a data store is kept for a store that does and
// dropped for one that does not.
func scCategories(k *scTMKey, class string, holdsLogs bool) []string {
	var src []string
	switch class {
	case "process":
		src = k.Applicability.Process
	case "data_store":
		src = k.Applicability.DataStore
	case "data_flow":
		src = k.Applicability.DataFlow
	case "external_entity":
		src = k.Applicability.ExternalEntity
	}
	var l []string
	for _, x := range src {
		if class == "data_store" && x == "repudiation" && !holdsLogs {
			continue
		}
		l = append(l, x)
	}
	if class == "data_store" && holdsLogs {
		has := false
		for _, x := range l {
			has = has || x == "repudiation"
		}
		if !has {
			l = append(l, "repudiation")
		}
	}
	return l
}

// scMapComponents maps each model component id to a key component id.
func scMapComponents(k *scTMKey, src scSource, doc *ThreatModelDoc) (map[string]string, error) {
	at := make([][]int, len(k.Components))
	for i, c := range k.Components {
		l, err := scAnchorLines(src, c.File, c.Anchors, false)
		if err != nil {
			return nil, fmt.Errorf("component %s: %w", c.ID, err)
		}
		at[i] = l
	}
	out := map[string]string{}
	for _, mc := range doc.System.Components {
		best, bestDist := -1, scCompWindow+1
		for i, kc := range k.Components {
			for _, r := range mc.Paths {
				if !r.State.Located() || r.Path != kc.File {
					continue
				}
				lo, hi := scRange(r)
				for _, a := range at[i] {
					if d := scDistance(lo, hi, a); d < bestDist {
						best, bestDist = i, d
					}
				}
			}
		}
		if best < 0 {
			text := strings.ToLower(mc.ID + " " + mc.Name)
			bestHints := 0
			for i, kc := range k.Components {
				n := 0
				for _, h := range kc.NameHints {
					if h != "" && strings.Contains(text, strings.ToLower(h)) {
						n++
					}
				}
				if n > bestHints {
					best, bestHints = i, n
				}
			}
		}
		if best >= 0 {
			out[mc.ID] = k.Components[best].ID
		}
	}
	return out, nil
}

// scTMAnchors is where an expected threat's flaw sits: the file and the lines of
// the flaw's anchors, resolved from the manifest against the project's own copy
// of the file (never stored).
type scTMAnchors struct {
	file  string
	lines []int
}

// scThreatAnchors resolves, for every expected threat of the key, the anchors of
// the flaw the key links it to. A threat that names no flaw of the manifest, or
// a flaw whose anchors do not resolve, is an error: the key and the manifest
// disagree, and a grounding rule that silently found nothing would make every
// threat unscorable.
func scThreatAnchors(m *scManifest, k *scTMKey, src scSource) ([]scTMAnchors, error) {
	flaws := map[string]scFlaw{}
	for _, f := range m.Flaws {
		flaws[f.ID] = f
	}
	out := make([]scTMAnchors, len(k.Threats))
	for j, t := range k.Threats {
		f, ok := flaws[t.Flaw]
		if !ok {
			return nil, fmt.Errorf("threat %s names the flaw %q, which is not in the manifest", t.ID, t.Flaw)
		}
		l, err := scAnchorLines(src, f.File, f.Anchors, false)
		if err != nil {
			return nil, fmt.Errorf("threat %s, flaw %s: %w", t.ID, f.ID, err)
		}
		if len(l) == 0 {
			return nil, fmt.Errorf("threat %s: flaw %s has no anchors", t.ID, f.ID)
		}
		out[j] = scTMAnchors{file: f.File, lines: l}
	}
	return out, nil
}

// scGrounded reports whether a threat is grounded at a flaw: one of its own
// references, in an existing-control or a missing-control entry, was FOUND by
// the check on a code line within window lines of one of the flaw's anchors in
// the same file. Only found counts; "exists" and "claimed not found" earn
// nothing, and the range a reference cites is not what is credited, the line its
// text was found on is (scRange).
func scGrounded(t Threat, at scTMAnchors, window int) bool {
	near := func(refs []Ref) bool {
		for _, r := range refs {
			if r.State != RefFound || r.Path != at.file {
				continue
			}
			if lo, hi := scRange(r); scNear(at.lines, lo, hi, window) {
				return true
			}
		}
		return false
	}
	for _, e := range t.Existing {
		if near(e.Refs) {
			return true
		}
	}
	for _, x := range t.Missing {
		if near(x.Refs) {
			return true
		}
	}
	return false
}

// scTMCtx resolves a model's elements to the key's.
type scTMCtx struct {
	key    *scTMKey
	comps  map[string]string // model component id -> key component id
	actors map[string]bool   // model actor ids
	flows  map[string]string // model flow id -> key flow id
	keyAct map[string]bool   // key actor ids
	// flawAt is, per expected threat of the key, where its flaw sits; window is
	// the manifest's anchor window.
	flawAt []scTMAnchors
	window int
}

func scNewCtx(m *scManifest, k *scTMKey, src scSource, doc *ThreatModelDoc) (*scTMCtx, error) {
	comps, err := scMapComponents(k, src, doc)
	if err != nil {
		return nil, err
	}
	flawAt, err := scThreatAnchors(m, k, src)
	if err != nil {
		return nil, err
	}
	c := &scTMCtx{
		key: k, comps: comps, actors: map[string]bool{}, flows: map[string]string{}, keyAct: map[string]bool{},
		flawAt: flawAt, window: m.Scoring.AnchorWindowLines,
	}
	for _, a := range k.Actors {
		c.keyAct[a.ID] = true
	}
	for _, a := range doc.System.Actors {
		c.actors[a.ID] = true
	}
	end := func(id string) string {
		if kc, ok := comps[id]; ok {
			return kc
		}
		if c.actors[id] {
			return "client"
		}
		return ""
	}
	keyEnd := func(id string) string {
		if c.keyAct[id] {
			return "client"
		}
		return id
	}
	for _, mf := range doc.System.Flows {
		from, to := end(mf.From), end(mf.To)
		if from == "" || to == "" {
			continue
		}
		for _, kf := range k.Flows {
			if keyEnd(kf.From) == from && keyEnd(kf.To) == to {
				c.flows[mf.ID] = kf.ID
				break
			}
		}
	}
	return c, nil
}

// resolve returns the key element a model element stands for ("" when it
// stands for none).
func (c *scTMCtx) resolve(e Element) (kind, id string) {
	switch e.Kind {
	case "component":
		if kc, ok := c.comps[e.ID]; ok {
			return "component", kc
		}
	case "flow":
		if kf, ok := c.flows[e.ID]; ok {
			return "flow", kf
		}
	}
	return "", ""
}

// scoreThreatModel scores a validated threat model against the key. The
// manifest supplies the flaws the key's threats link to (their anchors ground a
// matched threat) and the anchor window; the project source resolves the
// anchors to lines.
func scoreThreatModel(m *scManifest, k *scTMKey, src scSource, res Result) (scTMScore, error) {
	if m == nil {
		return scTMScore{}, errors.New("threat model scoring needs the manifest: a matched threat is grounded at its flaw's anchors")
	}
	s := scTMScore{Expected: len(k.Threats), Validator: scTally(res.Report)}
	s.Components.Expected, s.Flows.Expected = len(k.Components), len(k.Flows)
	if res.Report.TM != nil {
		s.ReportCells.Analysed, s.ReportCells.Waived, s.ReportCells.Empty = res.Report.TM.Analysed, res.Report.TM.Waived, res.Report.TM.Empty
	}
	doc := res.TM
	if doc == nil {
		for _, t := range k.Threats {
			s.Missed = append(s.Missed, t.ID)
		}
		for _, m := range k.Existing {
			s.RealMissed = append(s.RealMissed, m.ID)
		}
		s.Cells.Required, s.Cells.Empty = scRequiredCells(k), scRequiredCells(k)
		return s, nil
	}
	ctx, err := scNewCtx(m, k, src, doc)
	if err != nil {
		return s, err
	}
	s.Components.Mapped, s.Flows.Mapped = ctx.mapped()
	s.Reported = len(doc.Threats)
	analysed := ctx.matchThreats(doc, &s)
	ctx.cells(doc, analysed, &s)
	return s, scMitigations(k, src, doc, &s)
}

// mapped counts the distinct key components and flows the model reached.
func (c *scTMCtx) mapped() (comps, flows int) {
	mc, mf := map[string]bool{}, map[string]bool{}
	for _, kc := range c.comps {
		mc[kc] = true
	}
	for _, kf := range c.flows {
		mf[kf] = true
	}
	return len(mc), len(mf)
}

// matchThreats matches the model's STRIDE threats to the expected ones,
// one-to-one and maximal, a threat on the expected cell before one on an
// accepted cell, and only through a grounded edge: a model threat may take an
// expected threat only when it cites a reference the check found within the
// window of that threat's flaw anchor (scGrounded). It runs the same matching
// once over every cell edge (the cell-only account, CellMatched) and once over
// the grounded edges (the account that counts). It returns the cells the model
// analysed, which is a coverage fact and does not depend on grounding.
func (c *scTMCtx) matchThreats(doc *ThreatModelDoc, s *scTMScore) map[string]bool {
	k := c.key
	n := len(doc.Threats)
	cellPrimary, cellAccept := make([][]int, n), make([][]int, n)
	gndPrimary, gndAccept := make([][]int, n), make([][]int, n)
	hasCell, hasGrounded := make([]bool, n), make([]bool, n)
	analysed := map[string]bool{}
	for i, t := range doc.Threats {
		if t.Framework != FrameworkSTRIDE {
			s.NotScored++
			continue
		}
		kind, id := c.resolve(t.Element)
		if _, ok := StrideCategoryByID(t.Category); kind == "" || !ok {
			continue
		}
		analysed[kind+"/"+id+"/"+t.Category] = true
		for j, et := range k.Threats {
			primary := et.Element.Kind == kind && et.Element.ID == id && et.Category == t.Category
			if !primary && !scAccepts(et, scCell{kind, id, t.Category}) {
				continue
			}
			hasCell[i] = true
			grounded := scGrounded(t, c.flawAt[j], c.window)
			if grounded {
				hasGrounded[i] = true
			}
			switch {
			case primary:
				cellPrimary[i] = append(cellPrimary[i], j)
				if grounded {
					gndPrimary[i] = append(gndPrimary[i], j)
				}
			default:
				cellAccept[i] = append(cellAccept[i], j)
				if grounded {
					gndAccept[i] = append(gndAccept[i], j)
				}
			}
		}
	}
	for _, j := range scMatch(n, len(k.Threats), cellPrimary, cellAccept) {
		if j >= 0 {
			s.CellMatched = append(s.CellMatched, k.Threats[j].ID)
		}
	}
	sort.Strings(s.CellMatched)
	take := scMatch(n, len(k.Threats), gndPrimary, gndAccept)
	got := make([]bool, len(k.Threats))
	for i, j := range take {
		switch {
		case j >= 0:
			got[j] = true
			s.Matched = append(s.Matched, k.Threats[j].ID)
		case doc.Threats[i].Framework != FrameworkSTRIDE:
		case hasCell[i] && !hasGrounded[i]:
			s.Ungrounded = append(s.Ungrounded, doc.Threats[i].ID)
		default:
			s.Unmatched = append(s.Unmatched, doc.Threats[i].ID)
		}
	}
	for j, et := range k.Threats {
		if !got[j] {
			s.Missed = append(s.Missed, et.ID)
		}
	}
	sort.Strings(s.Matched)
	if s.Expected > 0 {
		s.Recall = float64(len(s.Matched)) / float64(s.Expected)
	}
	if len(s.CellMatched) > 0 {
		s.GroundedShare = float64(len(s.Matched)) / float64(len(s.CellMatched))
	}
	return analysed
}

// scAccepts reports whether a cell is one the expected threat also accepts.
func scAccepts(t scTMThreat, c scCell) bool {
	for _, a := range t.Accept {
		if a == c {
			return true
		}
	}
	return false
}

// cells counts, for every applicable STRIDE category of the key's components and
// flows, whether the model analysed it, waived it with a reason, or left it
// empty.
func (c *scTMCtx) cells(doc *ThreatModelDoc, analysed map[string]bool, s *scTMScore) {
	waived := map[string]bool{}
	for _, n := range doc.NoThreat {
		if kind, id := c.resolve(n.Element); kind != "" {
			if _, ok := StrideCategoryByID(n.Category); ok {
				waived[kind+"/"+id+"/"+n.Category] = true
			}
		}
	}
	cell := func(kind, id, category string) {
		s.Cells.Required++
		switch key := kind + "/" + id + "/" + category; {
		case analysed[key]:
			s.Cells.Analysed++
		case waived[key]:
			s.Cells.Waived++
		default:
			s.Cells.Empty++
		}
	}
	for _, comp := range c.key.Components {
		for _, l := range scCategories(c.key, comp.Type, comp.HoldsLogs != nil && *comp.HoldsLogs) {
			cell("component", comp.ID, l)
		}
	}
	for _, f := range c.key.Flows {
		for _, l := range scCategories(c.key, "data_flow", false) {
			cell("flow", f.ID, l)
		}
	}
	if s.Cells.Required > 0 {
		s.CellCoverage = float64(s.Cells.Analysed+s.Cells.Waived) / float64(s.Cells.Required)
	}
}

// scRequiredCells counts the cells the key requires.
func scRequiredCells(k *scTMKey) int {
	n := 0
	for _, c := range k.Components {
		n += len(scCategories(k, c.Type, c.HoldsLogs != nil && *c.HoldsLogs))
	}
	return n + len(k.Flows)*len(scCategories(k, "data_flow", false))
}

// scMitigations scores the references a model cites for existing controls.
func scMitigations(k *scTMKey, src scSource, doc *ThreatModelDoc, s *scTMScore) error {
	mitAt := make([][]int, len(k.Existing))
	for i, m := range k.Existing {
		l, err := scAnchorLines(src, m.File, m.Anchors, false)
		if err != nil {
			return fmt.Errorf("mitigation %s: %w", m.ID, err)
		}
		mitAt[i] = l
	}
	trapAt := make([][]int, len(k.Traps))
	for i, t := range k.Traps {
		l, err := scAnchorLines(src, t.File, t.Anchors, true)
		if err != nil {
			return fmt.Errorf("trap %s: %w", t.ID, err)
		}
		trapAt[i] = l
	}
	credited, seen, hits, limits := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, t := range doc.Threats {
		for _, m := range t.Existing {
			for _, r := range m.Refs {
				s.Mitigations.Cited++
				switch r.State {
				case RefFound:
					s.Mitigations.Found++
				case RefClaimedNotFound:
					s.Mitigations.ClaimedNotFound++
				}
				lo, hi := scRange(r)
				tlo, thi := scTouch(r)
				for i, tr := range k.Traps {
					if r.Path != tr.File || !scNear(trapAt[i], tlo, thi, 0) {
						continue
					}
					seen[tr.ID] = true
					if r.State != RefFound {
						continue
					}
					if tr.DefectIfFound && !tr.KnownLimit {
						hits[tr.ID] = true
					} else {
						limits[tr.ID] = true
					}
				}
				if r.State != RefFound {
					continue
				}
				for i, km := range k.Existing {
					if r.Path == km.File && scNear(mitAt[i], lo, hi, scMitWindow) {
						credited[km.ID] = true
					}
				}
			}
		}
	}
	if s.Mitigations.Cited > 0 {
		s.Mitigations.FoundShare = float64(s.Mitigations.Found) / float64(s.Mitigations.Cited)
		s.Mitigations.ClaimedShare = float64(s.Mitigations.ClaimedNotFound) / float64(s.Mitigations.Cited)
	}
	for _, km := range k.Existing {
		if credited[km.ID] {
			s.RealCredited = append(s.RealCredited, km.ID)
		} else {
			s.RealMissed = append(s.RealMissed, km.ID)
		}
	}
	for _, tr := range k.Traps {
		if seen[tr.ID] {
			s.TrapSeen = append(s.TrapSeen, tr.ID)
		}
		if hits[tr.ID] {
			s.TrapHits = append(s.TrapHits, tr.ID)
		}
		if limits[tr.ID] {
			s.TrapLimits = append(s.TrapLimits, tr.ID)
		}
	}
	return nil
}

// Lines renders the score for a person (the live check pastes this).
func (s scTMScore) Lines() []string {
	pct := func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) }
	return []string{
		fmt.Sprintf("threat model: %d of %d expected threats matched (recall %s); %d threats kept (%d of a framework the key does not cover)",
			len(s.Matched), s.Expected, pct(s.Recall), s.Reported, s.NotScored),
		"  matched: " + scList(s.Matched),
		"  missed:  " + scList(s.Missed),
		"  kept STRIDE threats matching nothing: " + scList(s.Unmatched),
		fmt.Sprintf("  grounding: %d of %d threats named by element and category alone also cite a reference the check found within the flaw's anchor window (%s); named but not grounded, earning nothing: %s",
			len(s.Matched), len(s.CellMatched), pct(s.GroundedShare), scList(s.Ungrounded)),
		fmt.Sprintf("  components mapped to the key's: %d of %d; flows: %d of %d", s.Components.Mapped, s.Components.Expected, s.Flows.Mapped, s.Flows.Expected),
		fmt.Sprintf("  cells of the key (components and flows): %d required, %d analysed, %d waived, %d empty (%s covered); the validator's own count, actors included: %d analysed, %d waived, %d empty",
			s.Cells.Required, s.Cells.Analysed, s.Cells.Waived, s.Cells.Empty, pct(s.CellCoverage), s.ReportCells.Analysed, s.ReportCells.Waived, s.ReportCells.Empty),
		fmt.Sprintf("  cited mitigations: %d, found at their line %d (%s), claimed but not found %d (%s)",
			s.Mitigations.Cited, s.Mitigations.Found, pct(s.Mitigations.FoundShare), s.Mitigations.ClaimedNotFound, pct(s.Mitigations.ClaimedShare)),
		"  real controls credited: " + scList(s.RealCredited) + "; not credited: " + scList(s.RealMissed),
		"  traps touched by a cited reference: " + scList(s.TrapSeen) + "; credited (a defect of the check): " + scList(s.TrapHits) + "; credited (its stated limit): " + scList(s.TrapLimits),
		s.Validator.line(),
	}
}
