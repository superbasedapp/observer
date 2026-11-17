package secassess

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"unicode"
)

// DiffModels is the Observer-side comparison of two checked threat models of
// the same project (depth plan W3.4): the earlier run's stored copy and the new
// run's. Nothing from the earlier model is ever given to an agent (D24: a
// re-fed model is a stored prompt injection, and ids without titles would not
// keep the agent's own ids stable anyway); the comparison is made after the new
// model is checked, from the two stored copies, and kept with the new copy.
//
// Matching is an ordered table of passes (diffPasses), strongest evidence
// first: the same element, category, title AND id; then the same element,
// category and title under another id (the agent numbers its threats in the
// order it writes them, so a renumbering is ordinary); then, for what is left,
// the scored pass (diffsimilar.go), which pairs two threats that cite nearly the
// same place in the code and agree on other signs, and lists them as "probably
// the same", never as unchanged; and only for what is still left, the same id
// when the element and the category agree. An element is compared by its NAME,
// resolved through the model's system (an agent chooses its component ids afresh
// each run), falling back to its id when no name resolves. That is weaker than a
// scheme that carries ids from run to run, and the result says so (DiffNote). A
// threat the agent both re-worded and renumbered, with nothing else in common,
// is reported as one removed and one added, and two threats of one element,
// category and title cannot be told apart, so they pair by id and then in order.

// DiffNote is the sentence a view prints with a diff.
const DiffNote = "Threats are matched by element, category and title first (an element by its name, so a renumbered component is the same element). What is left is paired when the two threats cite nearly the same place in the code and agree on other signs (the same weakness id, category or words in the title); those pairs are listed as probably the same, with what they have in common, and are never counted as unchanged. Last, a threat with the same id as one in the other run is paired when its element and category agree. A threat the agent renamed and renumbered, with nothing else in common, shows as one removed and one added. This compares what two runs reported; it does not say which is right."

// The ways a threat was matched. MatchBySimilarity (diffsimilar.go) is the
// scored pass, whose pairs are DiffSimilar, never DiffChange.
const (
	MatchByID    = "id"
	MatchByTitle = "title"
)

// DiffItem is a threat that is in only one of the two models.
type DiffItem struct {
	ID       string  `json:"id"`
	Title    string  `json:"title"`
	Element  Element `json:"element"`
	Category string  `json:"category"`
	Band     Band    `json:"band"`
	Score    int     `json:"score"`
}

// DiffChange is a threat that is in both models and differs.
type DiffChange struct {
	// ID is the id in the new model, PrevID the id in the earlier one (the same
	// unless the match was by title).
	ID       string  `json:"id"`
	PrevID   string  `json:"prev_id"`
	Title    string  `json:"title"`
	Element  Element `json:"element"`
	Category string  `json:"category"`
	// Match is MatchByID or MatchByTitle.
	Match string `json:"match"`
	// Band deltas. From and To are empty when the rating was not valid.
	FromBand  Band `json:"from_band,omitempty"`
	ToBand    Band `json:"to_band,omitempty"`
	FromScore int  `json:"from_score,omitempty"`
	ToScore   int  `json:"to_score,omitempty"`
	// TitleChanged: matched by id, and the title is not the same.
	TitleChanged bool `json:"title_changed,omitempty"`
	// FromStatus and ToStatus are set when the status word changed.
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
	// Missing and Existing are the counts of recommended and credited
	// mitigations in the earlier and the new model, set when they differ.
	MissingFrom  int `json:"missing_from,omitempty"`
	MissingTo    int `json:"missing_to,omitempty"`
	ExistingFrom int `json:"existing_from,omitempty"`
	ExistingTo   int `json:"existing_to,omitempty"`
}

// DiffSimilar is a pair the scored pass made: a threat of the new model and a
// threat of the earlier one that probably describe the same flaw, although no
// title, id or element name says so. It is a guess and is labelled one: it is
// never counted among the threats that read the same, and Basis says what the two
// have in common (the BasisLocation, BasisCWE, BasisWords, BasisCategory and
// BasisElement words), so a reader can judge it.
type DiffSimilar struct {
	// ID and Title are the new model's, PrevID and PrevTitle the earlier one's.
	ID        string  `json:"id"`
	PrevID    string  `json:"prev_id"`
	Title     string  `json:"title"`
	PrevTitle string  `json:"prev_title"`
	Element   Element `json:"element"`
	Category  string  `json:"category"`
	// PrevCategory is the earlier threat's category, set only when it differs.
	PrevCategory string `json:"prev_category,omitempty"`
	// Band deltas. From and To are empty when the rating was not valid.
	FromBand  Band `json:"from_band,omitempty"`
	ToBand    Band `json:"to_band,omitempty"`
	FromScore int  `json:"from_score,omitempty"`
	ToScore   int  `json:"to_score,omitempty"`
	// Basis lists the signals the pair shares, strongest first as the table
	// lists them; Points is the pair's score.
	Basis  []string `json:"basis"`
	Points int      `json:"points"`
}

// NameDiff lists the names of elements that are in only one of the two models,
// for one kind of element.
type NameDiff struct {
	Added   []string `json:"added,omitempty"`
	Removed []string `json:"removed,omitempty"`
}

// SystemDiff compares the decomposition: what the model says the application is
// made of. Components and zones are compared by their names, flows by their
// endpoints' names, so an agent's renumbered ids do not show as change.
type SystemDiff struct {
	Components NameDiff `json:"components"`
	Zones      NameDiff `json:"zones"`
	Flows      NameDiff `json:"flows"`
}

// ModelDiff is the comparison of two threat models.
type ModelDiff struct {
	// PrevRun is the run the earlier model belongs to.
	PrevRun string `json:"prev_run,omitempty"`
	// Added are threats only the new model has, Removed those only the earlier
	// one had, Changed those in both that differ; Unchanged counts the rest.
	Added     []DiffItem   `json:"added,omitempty"`
	Removed   []DiffItem   `json:"removed,omitempty"`
	Changed   []DiffChange `json:"changed,omitempty"`
	Unchanged int          `json:"unchanged"`
	// Similar are the pairs the scored pass made (diffsimilar.go): probably the
	// same threat, matched by the place it cites and other signs rather than by
	// its words. They are in neither Changed nor Unchanged and count in neither
	// Added nor Removed.
	Similar []DiffSimilar `json:"similar,omitempty"`
	// MatchedByID and MatchedByTitle count how the pairs were made.
	MatchedByID    int        `json:"matched_by_id"`
	MatchedByTitle int        `json:"matched_by_title"`
	System         SystemDiff `json:"system"`
	// Note is DiffNote.
	Note string `json:"note"`
}

// Empty reports whether the two models read the same at this level of
// comparison.
func (d ModelDiff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0 && len(d.Similar) == 0 &&
		len(d.System.Components.Added) == 0 && len(d.System.Components.Removed) == 0 &&
		len(d.System.Zones.Added) == 0 && len(d.System.Zones.Removed) == 0 &&
		len(d.System.Flows.Added) == 0 && len(d.System.Flows.Removed) == 0
}

// diffPass is one row of the matching table: a key built from a threat and its
// element, and the label a pair made by the row carries. A pass pairs the
// earlier and the new threats that are still unmatched and share a key,
// one to one, in the order each side lists them.
type diffPass struct {
	// key is the pass's identity of a threat; elem is the element's name key.
	// A scored pass has none.
	key func(t Threat, elem string) string
	// match is the label of a pair this pass makes.
	match string
	// scored marks the pass that pairs by points (similarPairs) instead of by
	// key: it sits where its evidence belongs in the order.
	scored bool
}

// diffPasses is the table of passes, strongest evidence first. A test row holds
// each one.
var diffPasses = []diffPass{
	// Everything the agent wrote about the threat's place agrees: element,
	// category, title and its own id.
	{key: func(t Threat, elem string) string { return titleKey(t, elem) + "\x00" + t.ID }, match: MatchByID},
	// The same threat under another id: element, category and title agree.
	{key: titleKey, match: MatchByTitle},
	// What two independent runs leave: the same place in the code and other
	// signs in common. It sits above the id-only row because an id is the order
	// the agent wrote its threats in, which says nothing about what a threat is
	// about, and a cited place does.
	{match: MatchBySimilarity, scored: true},
	// The agent's own id, when the element and the category agree (the title
	// may have been re-worded).
	{key: func(t Threat, elem string) string {
		return t.Framework + "\x00" + t.Category + "\x00" + elem + "\x00" + t.ID
	}, match: MatchByID},
}

// DiffModels compares the earlier model prev with the new model cur. A nil
// model on either side is treated as empty (every threat of the other side is
// then added or removed). The output is deterministic: items are ordered by
// score (highest first), then by id.
func DiffModels(prev, cur *ThreatModelDoc) ModelDiff {
	d := ModelDiff{Note: DiffNote}
	var pt, ct []Threat
	var pn, cn nameIndex
	if prev != nil {
		pt, pn = prev.Threats, newNameIndex(prev.System)
	}
	if cur != nil {
		ct, cn = cur.Threats, newNameIndex(cur.System)
	}
	// A kind of element is compared by name only when both models name some of
	// it; a model with no system (or none of that kind) gives no names to
	// compare, and the ids are all there is.
	byName := func(kind string) bool { return len(pn[kind]) > 0 && len(cn[kind]) > 0 }
	pk, ck := make([]string, len(pt)), make([]string, len(ct))
	for i, t := range pt {
		pk[i] = pn.elementKey(t.Element, byName(t.Element.Kind))
	}
	for i, t := range ct {
		ck[i] = cn.elementKey(t.Element, byName(t.Element.Kind))
	}
	matchedPrev := make([]bool, len(pt))
	matchedCur := make([]bool, len(ct))
	type pair struct {
		p, c  int
		match string
		sim   simResult
	}
	var pairs []pair
	for _, pass := range diffPasses {
		if pass.scored {
			for _, cd := range similarPairs(pt, ct, pk, ck, matchedPrev, matchedCur) {
				matchedPrev[cd.p], matchedCur[cd.c] = true, true
				pairs = append(pairs, pair{cd.p, cd.c, pass.match, cd.res})
			}
			continue
		}
		byKey := map[string][]int{}
		for i, t := range pt {
			if !matchedPrev[i] {
				k := pass.key(t, pk[i])
				byKey[k] = append(byKey[k], i)
			}
		}
		for ci, c := range ct {
			if matchedCur[ci] {
				continue
			}
			k := pass.key(c, ck[ci])
			cands := byKey[k]
			if len(cands) == 0 {
				continue
			}
			byKey[k] = cands[1:]
			matchedPrev[cands[0]], matchedCur[ci] = true, true
			pairs = append(pairs, pair{p: cands[0], c: ci, match: pass.match})
		}
	}

	for _, pr := range pairs {
		p, c := pt[pr.p], ct[pr.c]
		if pr.match == MatchBySimilarity {
			d.Similar = append(d.Similar, similarOf(p, c, pr.sim))
			continue
		}
		if pr.match == MatchByID {
			d.MatchedByID++
		} else {
			d.MatchedByTitle++
		}
		ch := DiffChange{
			ID: c.ID, PrevID: p.ID, Title: c.Title, Element: c.Element, Category: c.Category, Match: pr.match,
			FromBand: p.Band, ToBand: c.Band, FromScore: p.Score, ToScore: c.Score,
		}
		differs := false
		if p.Band != c.Band || p.Score != c.Score {
			differs = true
		}
		if titleNorm(p.Title) != titleNorm(c.Title) {
			ch.TitleChanged, differs = true, true
		}
		if p.Status != c.Status {
			ch.FromStatus, ch.ToStatus, differs = p.Status, c.Status, true
		}
		if len(p.Missing) != len(c.Missing) {
			ch.MissingFrom, ch.MissingTo, differs = len(p.Missing), len(c.Missing), true
		}
		if len(p.Existing) != len(c.Existing) {
			ch.ExistingFrom, ch.ExistingTo, differs = len(p.Existing), len(c.Existing), true
		}
		if differs {
			d.Changed = append(d.Changed, ch)
		} else {
			d.Unchanged++
		}
	}
	for i, t := range ct {
		if !matchedCur[i] {
			d.Added = append(d.Added, diffItem(t))
		}
	}
	for i, t := range pt {
		if !matchedPrev[i] {
			d.Removed = append(d.Removed, diffItem(t))
		}
	}
	sort.SliceStable(d.Added, func(i, j int) bool { return itemBefore(d.Added[i], d.Added[j]) })
	sort.SliceStable(d.Removed, func(i, j int) bool { return itemBefore(d.Removed[i], d.Removed[j]) })
	sort.SliceStable(d.Changed, func(i, j int) bool {
		a, b := d.Changed[i], d.Changed[j]
		if a.ToScore != b.ToScore {
			return a.ToScore > b.ToScore
		}
		return a.ID < b.ID
	})
	sort.SliceStable(d.Similar, func(i, j int) bool {
		a, b := d.Similar[i], d.Similar[j]
		if a.ToScore != b.ToScore {
			return a.ToScore > b.ToScore
		}
		return a.ID < b.ID
	})
	d.System = diffSystem(prev, cur)
	return d
}

// similarOf builds the entry of a pair the scored pass made.
func similarOf(p, c Threat, r simResult) DiffSimilar {
	s := DiffSimilar{
		ID: c.ID, PrevID: p.ID, Title: c.Title, PrevTitle: p.Title, Element: c.Element, Category: c.Category,
		FromBand: p.Band, ToBand: c.Band, FromScore: p.Score, ToScore: c.Score,
		Basis: r.basis(), Points: r.points,
	}
	if p.Category != c.Category || p.Framework != c.Framework {
		s.PrevCategory = p.Category
	}
	return s
}

func diffItem(t Threat) DiffItem {
	return DiffItem{ID: t.ID, Title: t.Title, Element: t.Element, Category: t.Category, Band: t.Band, Score: t.Score}
}

func itemBefore(a, b DiffItem) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	return a.ID < b.ID
}

// titleNorm lower-cases a title and keeps only letters and digits, single
// spaced, so punctuation and spacing do not break a match.
func titleNorm(s string) string {
	var b strings.Builder
	space := false
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteRune(r)
			continue
		}
		space = true
	}
	return b.String()
}

// titleKey is the content key of a threat: framework, category, the element's
// name key and the hash of the normalised title.
func titleKey(t Threat, elem string) string {
	h := sha256.Sum256([]byte(titleNorm(t.Title)))
	return t.Framework + "\x00" + t.Category + "\x00" + elem + "\x00" + hex.EncodeToString(h[:6])
}

// nameIndex maps an element kind and id to the name the model gives it.
type nameIndex map[string]map[string]string

// elementNameRows is the table that resolves the name of each kind of element a
// threat can be about (the closed EnumElementKind list): one row per kind, each
// reading the model's system. A kind with no row, or an id that does not resolve,
// keeps its id as its name.
var elementNameRows = []struct {
	kind string
	each func(s System, ends map[string]string, put func(id, name string))
}{
	{"component", func(s System, _ map[string]string, put func(id, name string)) {
		for _, c := range s.Components {
			put(c.ID, c.Name)
		}
	}},
	{"actor", func(s System, _ map[string]string, put func(id, name string)) {
		for _, a := range s.Actors {
			put(a.ID, a.Name)
		}
	}},
	{"asset", func(s System, _ map[string]string, put func(id, name string)) {
		for _, a := range s.Assets {
			put(a.ID, a.Name)
		}
	}},
	{"flow", func(s System, ends map[string]string, put func(id, name string)) {
		for _, f := range s.Flows {
			put(f.ID, flowLabel(ends, f))
		}
	}},
	// An entry point has no name of its own: it is its component's name and its
	// kind.
	{"entry_point", func(s System, ends map[string]string, put func(id, name string)) {
		for _, e := range s.EntryPoints {
			if name := ends[e.Component]; name != "" {
				put(e.ID, name+" "+e.Kind)
			}
		}
	}},
}

// endpointNames maps a component or actor id to its name, the endpoints a flow
// names.
func endpointNames(s System) map[string]string {
	m := map[string]string{}
	for _, c := range s.Components {
		m[c.ID] = c.Name
	}
	for _, a := range s.Actors {
		m[a.ID] = a.Name
	}
	return m
}

// flowLabel is "from to to" by the endpoints' names (an endpoint that does not
// resolve is written by its id).
func flowLabel(ends map[string]string, f Flow) string {
	from, to := ends[f.From], ends[f.To]
	if from == "" {
		from = f.From
	}
	if to == "" {
		to = f.To
	}
	return from + " to " + to
}

// newNameIndex resolves every element name of a system once. The first item
// of an id wins.
func newNameIndex(s System) nameIndex {
	ends := endpointNames(s)
	idx := nameIndex{}
	for _, row := range elementNameRows {
		m := map[string]string{}
		row.each(s, ends, func(id, name string) {
			if _, dup := m[id]; !dup {
				m[id] = name
			}
		})
		idx[row.kind] = m
	}
	return idx
}

// elementKey is the identity of an element across two runs: its kind and its
// normalised name, or its kind and id when byName is false or the model gives
// the element no name. An agent chooses its component ids afresh each run, so
// the name is the stronger evidence; the prefixes keep a name from ever equalling
// an id.
func (idx nameIndex) elementKey(e Element, byName bool) string {
	if byName {
		if name := titleNorm(idx[e.Kind][e.ID]); name != "" {
			return e.Kind + "\x00n:" + name
		}
	}
	return e.Kind + "\x00i:" + e.ID
}

// diffSystem compares the decomposition by names.
func diffSystem(prev, cur *ThreatModelDoc) SystemDiff {
	var ps, cs System
	if prev != nil {
		ps = prev.System
	}
	if cur != nil {
		cs = cur.System
	}
	names := func(s System) (comps, zones, flows []string) {
		ends := endpointNames(s)
		for _, c := range s.Components {
			comps = append(comps, c.Name)
		}
		for _, z := range s.Zones {
			zones = append(zones, z.Name)
		}
		for _, f := range s.Flows {
			flows = append(flows, flowLabel(ends, f))
		}
		return
	}
	pc, pz, pf := names(ps)
	cc, cz, cf := names(cs)
	return SystemDiff{Components: nameDiff(pc, cc), Zones: nameDiff(pz, cz), Flows: nameDiff(pf, cf)}
}

// nameDiff returns the names in only one side, compared as normalised text,
// each side once, sorted.
func nameDiff(prev, cur []string) NameDiff {
	set := func(xs []string) map[string]string {
		m := map[string]string{}
		for _, x := range xs {
			k := titleNorm(x)
			if k == "" {
				continue
			}
			if _, ok := m[k]; !ok {
				m[k] = x
			}
		}
		return m
	}
	pm, cm := set(prev), set(cur)
	var d NameDiff
	for k, v := range cm {
		if _, ok := pm[k]; !ok {
			d.Added = append(d.Added, v)
		}
	}
	for k, v := range pm {
		if _, ok := cm[k]; !ok {
			d.Removed = append(d.Removed, v)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	return d
}
