package secassess

import (
	"path"
	"sort"
	"strings"
)

// The scored second pass of the comparison (fix round 3, known defect 6).
//
// Two independent runs of an agent never share titles, ids or component names,
// so a comparison that pairs by element, category and title pairs almost
// nothing across them (the first live run: 50 added, 122 removed, 0 changed, 0
// read the same, although both models reported the same flaws). The pass here
// pairs what the exact passes left over, by evidence that survives a re-wording:
// the place in the code a threat cites, its CWE, its category and the words of
// its title. Each signal is a row of simSignals and adds points; a pair is made
// only when the points reach simMinPoints and the pair is anchored (simAnchored),
// and the pairs are taken best first, one to one.
//
// A pair made here is a guess, and the comparison says so: it is listed as
// "probably the same" with the signals that made it (DiffSimilar.Basis), and it
// is never counted as unchanged, however alike the two threats read.

// The signals a similar pair can carry (DiffSimilar.Basis), one word each, in
// the order of simSignals. They are a closed vocabulary the web words.
const (
	BasisLocation = "location"
	BasisCWE      = "cwe"
	BasisWords    = "words"
	BasisCategory = "category"
	BasisElement  = "element"
)

// MatchBySimilarity is the label of a pair the scored pass made (see
// DiffSimilar); the exact passes use MatchByID and MatchByTitle.
const MatchBySimilarity = "similar"

// The points table. A signal adds its points when it fires; the location
// signal also takes points away when both threats cite places and no two are
// near each other (they are about different code).
const (
	// diffLocationWindow is how many lines apart two cited places may be and
	// still read as the same place. It is the default of the reference match
	// window (setting ref_match_window_lines), kept fixed here: a person who
	// widens that window to credit more references must not also loosen what a
	// comparison calls the same flaw.
	diffLocationWindow = 5

	simPointsNear     = 4
	simPointsConflict = -3
	simPointsCWESome  = 2
	simPointsCWEMost  = 3
	simPointsCategory = 2
	simPointsElement  = 1

	// simCWEMostShare is the share of two CWE sets (intersection over union)
	// from which they read as "the same weakness" rather than "one in common".
	simCWEMostShare = 0.5

	// simMinPoints is the least a pair must score. With the table above no
	// single signal reaches it, and no pair of the weak ones (category and
	// element, 3 points) does either.
	simMinPoints = 6
)

// simWordRows maps the share of title words two threats have in common
// (intersection over union of the stemmed words) to points, best row first.
var simWordRows = []struct {
	share  float64
	points int
}{{0.6, 3}, {0.4, 2}, {0.25, 1}}

// simLoc is a place a threat cites: a project path and an inclusive line range.
type simLoc struct {
	path     string
	from, to int
}

// simFeat is what a threat is compared by, read once.
type simFeat struct {
	locs  []simLoc
	cwe   []string // sorted, unique
	words []string // sorted, unique, stemmed
	fw    string
	cat   string
	elem  string // the element key (diff.go elementKey)
}

// simResult is the account of scoring one pair.
type simResult struct {
	points int
	// fired has bit i set when row i of simSignals added points (basis reads it).
	fired uint8
	// near and wordShare feed the acceptance rule and the tie-break.
	near       bool
	wordShare  float64
	cweShare   float64
	wordPoints int
}

// simSignal is one row of the points table: the word a pair carries when the
// row fires, and the function that scores a pair of threats.
type simSignal struct {
	basis string
	score func(a, b *simFeat, r *simResult) int
}

// simSignals is the table, one row per signal, in the order the signals are
// listed on a pair. Each row has a test case.
var simSignals = []simSignal{
	{BasisLocation, simScoreLocation},
	{BasisCWE, simScoreCWE},
	{BasisWords, simScoreWords},
	{BasisCategory, simScoreCategory},
	{BasisElement, simScoreElement},
}

// simAnchored is the rule a scored pair must also pass: the pair must be tied
// by the code it cites or by the words of its title. The category, the element
// and the CWE alone only say two threats are of one kind.
func simAnchored(r simResult) bool { return r.near || r.wordPoints > 0 }

// simScoreLocation: +4 when a cited place of one is within the window of a
// cited place of the other in the same file; -3 when both cite places (with
// line numbers) and none are near, because they are then about different code.
// A threat that cites no line scores 0: it says nothing either way.
func simScoreLocation(a, b *simFeat, r *simResult) int {
	if len(a.locs) == 0 || len(b.locs) == 0 {
		return 0
	}
	for _, x := range a.locs {
		for _, y := range b.locs {
			if x.path != y.path {
				continue
			}
			gap := 0
			switch {
			case x.from > y.to:
				gap = x.from - y.to
			case y.from > x.to:
				gap = y.from - x.to
			}
			if gap <= diffLocationWindow {
				r.near = true
				return simPointsNear
			}
		}
	}
	return simPointsConflict
}

// simScoreCWE: 3 when the two CWE sets are mostly the same, 2 when they share
// one.
func simScoreCWE(a, b *simFeat, r *simResult) int {
	n := sortedOverlap(a.cwe, b.cwe)
	if n == 0 {
		return 0
	}
	r.cweShare = float64(n) / float64(len(a.cwe)+len(b.cwe)-n)
	if r.cweShare >= simCWEMostShare {
		return simPointsCWEMost
	}
	return simPointsCWESome
}

// simScoreWords: points by simWordRows, from the share of title words in
// common.
func simScoreWords(a, b *simFeat, r *simResult) int {
	n := sortedOverlap(a.words, b.words)
	if n == 0 {
		return 0
	}
	r.wordShare = float64(n) / float64(len(a.words)+len(b.words)-n)
	for _, row := range simWordRows {
		if r.wordShare >= row.share {
			r.wordPoints = row.points
			return row.points
		}
	}
	return 0
}

// simScoreCategory: 2 when the framework and the category are the same.
func simScoreCategory(a, b *simFeat, _ *simResult) int {
	if a.cat != "" && a.cat == b.cat && a.fw == b.fw {
		return simPointsCategory
	}
	return 0
}

// simScoreElement: 1 when the element is the same one by name.
func simScoreElement(a, b *simFeat, _ *simResult) int {
	if a.elem != "" && a.elem == b.elem {
		return simPointsElement
	}
	return 0
}

// simScore scores a pair. A negative total is possible (the location penalty).
// It allocates nothing: the pass scores every pair of what is left, and only the
// pairs it makes need their basis (simResult.basis).
func simScore(a, b *simFeat) simResult {
	var r simResult
	for i, row := range simSignals {
		p := row.score(a, b, &r)
		r.points += p
		if p > 0 {
			r.fired |= 1 << uint(i)
		}
	}
	return r
}

// basis lists the signals that added points, in the order of simSignals.
func (r simResult) basis() []string {
	var out []string
	for i, row := range simSignals {
		if r.fired&(1<<uint(i)) != 0 {
			out = append(out, row.basis)
		}
	}
	return out
}

// simCand is a pair that passed the acceptance rule.
type simCand struct {
	p, c int
	res  simResult
}

// similarPairs pairs the earlier threats pt and the new threats ct that the
// exact passes left over (matchedPrev and matchedCur say which), by the scored
// signals. The pairs are one to one and taken best first: more points, then a
// closer share of words, then a closer share of CWE, then the order the models
// list the threats in. The same two models always give the same pairs.
func similarPairs(pt, ct []Threat, pk, ck []string, matchedPrev, matchedCur []bool) []simCand {
	var pf, cf []*simFeat
	pidx, cidx := []int{}, []int{}
	for i := range pt {
		if !matchedPrev[i] {
			pidx = append(pidx, i)
			pf = append(pf, newSimFeat(pt[i], pk[i]))
		}
	}
	for i := range ct {
		if !matchedCur[i] {
			cidx = append(cidx, i)
			cf = append(cf, newSimFeat(ct[i], ck[i]))
		}
	}
	var cands []simCand
	for i, a := range pf {
		for j, b := range cf {
			r := simScore(a, b)
			if r.points < simMinPoints || !simAnchored(r) {
				continue
			}
			cands = append(cands, simCand{p: pidx[i], c: cidx[j], res: r})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		switch {
		case a.res.points != b.res.points:
			return a.res.points > b.res.points
		case a.res.wordShare != b.res.wordShare:
			return a.res.wordShare > b.res.wordShare
		case a.res.cweShare != b.res.cweShare:
			return a.res.cweShare > b.res.cweShare
		case a.p != b.p:
			return a.p < b.p
		}
		return a.c < b.c
	})
	usedP, usedC := map[int]bool{}, map[int]bool{}
	var out []simCand
	for _, cd := range cands {
		if usedP[cd.p] || usedC[cd.c] {
			continue
		}
		usedP[cd.p], usedC[cd.c] = true, true
		out = append(out, cd)
	}
	return out
}

// newSimFeat reads the features of a threat. elem is its element key.
func newSimFeat(t Threat, elem string) *simFeat {
	f := &simFeat{fw: t.Framework, cat: t.Category, elem: elem}
	add := func(refs []Ref) {
		for _, r := range refs {
			// A reference to a place that is not there, or is not a path,
			// says nothing about where the threat is.
			if r.Path == "" || r.Line <= 0 || r.State == RefMissing || r.State == RefInvalid {
				continue
			}
			from, to := r.Line, r.Line
			if r.EndLine > r.Line {
				to = r.EndLine
			}
			if r.State == RefFound && r.MatchLine > 0 {
				from, to = r.MatchLine, r.MatchLine
			}
			f.locs = append(f.locs, simLoc{path: simPath(r.Path), from: from, to: to})
		}
	}
	for _, m := range t.Existing {
		add(m.Refs)
	}
	for _, m := range t.Missing {
		add(m.Refs)
	}
	f.cwe = uniqueSorted(t.CWE, func(s string) string { return strings.ToUpper(strings.TrimSpace(s)) })
	f.words = uniqueSorted(strings.Fields(titleNorm(t.Title)), simStem)
	return f
}

// simPath is a cited path as one spelling: slashes forward, no ./ and no
// doubled separators. Case is kept (two paths that differ by case read as two).
func simPath(p string) string {
	return path.Clean(strings.ReplaceAll(p, "\\", "/"))
}

// uniqueSorted maps each item through norm, drops the empty ones and the
// repeats, and sorts the rest.
func uniqueSorted(in []string, norm func(string) string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = norm(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// sortedOverlap counts the items two sorted unique lists share.
func sortedOverlap(a, b []string) int {
	n := 0
	for i, j := 0, 0; i < len(a) && j < len(b); {
		switch {
		case a[i] == b[j]:
			n++
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return n
}

// simStopWords are the function words a title carries whatever it is about.
// "redacted" is the marker the display pass leaves where it hid a secret; two
// titles that both carry it say nothing about each other.
var simStopWords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "that": true, "this": true, "from": true, "into": true,
	"any": true, "are": true, "not": true, "can": true, "via": true, "all": true, "per": true, "its": true,
	"has": true, "have": true, "was": true, "were": true, "been": true, "but": true, "may": true, "than": true,
	"when": true, "where": true, "which": true, "who": true, "what": true, "over": true, "under": true,
	"without": true, "through": true, "their": true, "they": true, "them": true, "then": true, "also": true,
	"only": true, "such": true, "each": true, "both": true, "other": true, "does": true, "doesn": true,
	"redacted": true,
}

// simStem takes one word of a normalised title (titleNorm: lower case, letters
// and digits). It returns "" for a stop word or a word shorter than three
// characters, and otherwise the word with a common ending cut, so "tokens" and
// "token", "accepted" and "accepts" read as one word. It is crude on purpose:
// the same function runs on both sides, so what matters is that it is the
// same, not that it is right.
func simStem(w string) string {
	if len(w) < 3 || simStopWords[w] {
		return ""
	}
	switch {
	case len(w) > 4 && strings.HasSuffix(w, "ies"):
		w = w[:len(w)-3] + "y"
	case len(w) > 5 && strings.HasSuffix(w, "sses"):
		w = w[:len(w)-2]
	case len(w) > 5 && strings.HasSuffix(w, "ing"):
		w = w[:len(w)-3]
	case len(w) > 4 && strings.HasSuffix(w, "ed"):
		w = w[:len(w)-2]
	case len(w) > 4 && strings.HasSuffix(w, "es"):
		w = w[:len(w)-2]
	case len(w) > 3 && strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss") && !strings.HasSuffix(w, "us") && !strings.HasSuffix(w, "is"):
		w = w[:len(w)-1]
	}
	return w
}
