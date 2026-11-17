package secassess

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Validator row V15: the findings a developer can import are derived by
// Observer from the checked model, never authored by the agent. One authoring
// path removes the drift between what the model says and what the Findings tab
// holds, and the agent's own words never reach the store: the message of a
// derived result is built from Observer's tables and the grammar-checked ids.

// stableFingerprintName is the partial-fingerprint key of a result whose rule
// id carries no run id (RerunDedup on); a result that keeps the run id uses
// fingerprintName, the key PrepareSARIF uses.
const stableFingerprintName = "assess/stable/v1"

// DeriveOptions are the plain values a derivation needs.
type DeriveOptions struct {
	// Tag is the kind's rule-id tag (tm, pt, rt).
	Tag string
	// RunID is the run the model belongs to.
	RunID string
	// MinBand is the lowest band imported; empty means low (every located
	// item).
	MinBand Band
	// Cap is the most results imported, highest band first; 0 means no cap.
	Cap int
	// Dedup puts no run id in the rule id and fingerprints the content, so
	// the store's own upsert collapses a re-run. Off, every run stands
	// alone and the run id is in the rule id.
	Dedup bool
}

// DerivedResult is one result of the derivation.
type DerivedResult struct {
	RuleID      string `json:"rule_id"`
	Level       string `json:"level"`
	Path        string `json:"path"`
	Line        int    `json:"line,omitempty"`
	EndLine     int    `json:"end_line,omitempty"`
	Band        Band   `json:"band"`
	Score       int    `json:"score"`
	Fingerprint string `json:"fingerprint"`
	// Source is the id of the threat or finding the result comes from.
	Source string `json:"source"`
}

// Excluded counts the candidates a derivation left out, by closed reason.
// Nothing is left out silently: the card says each count.
type Excluded struct {
	// NoLocation: no reference of the item points at a place that exists and
	// whose file name an imported finding may carry (FixPathOK). A file name is
	// the one agent-chosen string a derived finding, and the Findings tab's fix
	// task built from it, place as the agent wrote it, so a name that could
	// carry a sentence (a space, an odd character, a very long name, a name in
	// the .observer or .git folder) counts here and not as a location.
	NoLocation int `json:"no_location"`
	// UnderMinBand: the item's band is under the developer's minimum.
	UnderMinBand int `json:"under_min_band"`
	// Duplicate: another candidate has the same fingerprint.
	Duplicate int `json:"duplicate"`
	// OverCap: past the developer's own cap.
	OverCap int `json:"over_cap"`
	// OverCeiling: past the import's own 1000-result ceiling.
	OverCeiling int `json:"over_ceiling"`
	// Unchecked: every reference of the item was never looked at (the check ran
	// out of its read budget, or no check was available), so whether the item
	// has a location is not known. It is not the same as NoLocation.
	Unchecked int `json:"unchecked,omitempty"`
}

// Derivation is what the model yields for the import.
type Derivation struct {
	// Considered is the number of candidates: missing mitigations of a threat
	// model, findings of a penetration test.
	Considered int             `json:"considered"`
	Kept       int             `json:"kept"`
	Excluded   Excluded        `json:"excluded"`
	Results    []DerivedResult `json:"results,omitempty"`
	// Doc is the SARIF 2.1.0 document in the shape the import takes (the shape
	// PrepareSARIF writes); nil when nothing was kept.
	Doc []byte `json:"-"`
}

// RuleIDStable is the imported rule id without a run id (before the import's
// own "other/" prefix): assess.<tag>.<cleaned suffix>.
func RuleIDStable(tag, suffix string) string {
	return "assess." + tag + "." + cleanRuleSuffix(suffix)
}

// candidate is one item that could become a result.
type candidate struct {
	order  int
	source string
	suffix string
	band   Band
	score  int
	ref    Ref
	// what is the Observer-worded phrase for the message.
	what string
}

// bestRef returns the first reference that names an existing place,
// preferring one whose needle was found. A found reference is narrowed to the
// line its needle was found on: that is the place the check stands behind. A
// reference whose file name FixPathOK refuses is never chosen: the derived
// finding's location, and the Findings tab's fix task built from it, would
// carry that name as the agent wrote it (review W6b-M1).
func bestRef(refs []Ref) (Ref, bool) {
	var first Ref
	have := false
	for _, r := range refs {
		if !FixPathOK(r.Path) {
			continue
		}
		switch r.State {
		case RefFound:
			if r.MatchLine > 0 {
				r.Line, r.EndLine = r.MatchLine, r.MatchLine
			}
			return r, true
		case RefExists:
			if !have {
				first, have = r, true
			}
		}
	}
	return first, have
}

// allUnchecked reports whether the item has references and none of them was
// ever looked at.
func allUnchecked(refs []Ref) bool {
	if len(refs) == 0 {
		return false
	}
	for _, r := range refs {
		if r.State != RefUnchecked {
			return false
		}
	}
	return true
}

// tmSuffix is the rule suffix of a threat: its first CWE, else the framework
// category. It is never the agent's own id.
func tmSuffix(t Threat) string {
	if len(t.CWE) > 0 {
		return strings.ToLower(t.CWE[0])
	}
	if t.Framework == FrameworkSTRIDE {
		if c, ok := StrideCategoryByID(t.Category); ok {
			return "stride-" + strings.ToLower(c.Letter)
		}
	}
	if t.Framework == FrameworkLINDDUN {
		return "linddun-" + t.Category
	}
	return strings.ToLower(t.Category)
}

// ptSuffix is the rule suffix of a finding: its first CWE, else the test
// category.
func ptSuffix(f PTFinding) string {
	if len(f.CWE) > 0 {
		return strings.ToLower(f.CWE[0])
	}
	return "wstg-" + strings.ToLower(f.Category)
}

// levelOfBand maps a band to the SARIF level words the import knows.
func levelOfBand(b Band) string { return levelFor(string(b)) }

// candidates collects the importable candidates of a result and counts those
// without a location.
func candidates(res Result, minBand Band, ex *Excluded) (cands []candidate, considered int) {
	floor := BandRank(minBand)
	if floor == 0 {
		floor = BandRank(BandLow)
	}
	add := func(src, suffix string, band Band, score int, refs []Ref, what string) {
		considered++
		ref, ok := bestRef(refs)
		switch {
		case BandRank(band) < floor:
			ex.UnderMinBand++
		case !ok && allUnchecked(refs):
			ex.Unchecked++
		case !ok:
			ex.NoLocation++
		default:
			cands = append(cands, candidate{order: len(cands), source: src, suffix: suffix, band: band, score: score, ref: ref, what: what})
		}
	}
	if res.TM != nil {
		for _, t := range res.TM.Threats {
			for _, m := range t.Missing {
				add(t.ID, tmSuffix(t), t.Band, t.Score, m.Refs, "a missing mitigation")
			}
		}
	}
	if res.PT != nil {
		for _, f := range res.PT.Findings {
			add(f.ID, ptSuffix(f), f.Band, f.Score, f.Where.Refs, "a reported weakness")
		}
	}
	return cands, considered
}

// fingerprint is the content fingerprint of a candidate. With dedup on it is
// over the suffix, the path and the needle (its hash) or else the line; with
// dedup off it is over the rule id, the path and the line, as PrepareSARIF
// computes it. Bands, evidence and anything else that can change between runs
// stay out of it.
func fingerprint(c candidate, ruleID string, dedup bool) string {
	var key string
	if dedup {
		anchor := "l:" + strconv.Itoa(c.ref.Line)
		if c.ref.State == RefFound && c.ref.Needle != "" {
			n := sha256.Sum256([]byte(c.ref.Needle))
			anchor = "n:" + hex.EncodeToString(n[:6])
		}
		key = "assess/stable/v1\x00" + c.suffix + "\x00" + c.ref.Path + "\x00" + anchor
	} else {
		key = ruleID + "\x00" + c.ref.Path + "\x00" + strconv.Itoa(c.ref.Line)
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

// message builds a result's text from Observer's own words and ids that passed
// the id grammar; nothing the agent wrote as prose is in it.
func message(c candidate, runID string) string {
	return fmt.Sprintf("Assessment %s (%s risk): the agent reports %s here (item %s). Open the assessment for the agent's own text.",
		runID, c.band, c.what, c.source)
}

// DeriveSARIF derives the importable results of a checked model and the SARIF
// document that carries them. The document is already in the prepared shape
// (rule id, level, one project-relative location, fingerprint), built from the
// same types and helpers PrepareSARIF writes with, so the import takes it as
// it is.
func DeriveSARIF(res Result, o DeriveOptions) Derivation {
	var d Derivation
	cands, considered := candidates(res, o.MinBand, &d.Excluded)
	d.Considered = considered
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		return cands[i].order < cands[j].order
	})
	seen := map[string]bool{}
	var out []outResult
	for _, c := range cands {
		ruleID := RuleID(o.Tag, o.RunID, c.suffix)
		fpName := fingerprintName
		if o.Dedup {
			ruleID, fpName = RuleIDStable(o.Tag, c.suffix), stableFingerprintName
		}
		fp := fingerprint(c, ruleID, o.Dedup)
		switch {
		case seen[fp]:
			d.Excluded.Duplicate++
			continue
		case o.Cap > 0 && len(out) >= o.Cap:
			d.Excluded.OverCap++
			continue
		case len(out) >= MaxKeptResults:
			d.Excluded.OverCeiling++
			continue
		}
		seen[fp] = true
		end := c.ref.EndLine
		if end < c.ref.Line {
			end = c.ref.Line
		}
		var loc outLocation
		loc.Physical.Artifact.URI = c.ref.Path
		if c.ref.Line > 0 {
			loc.Physical.Region = &outRegion{StartLine: c.ref.Line, EndLine: end}
		}
		out = append(out, outResult{
			RuleID: ruleID, Level: levelOfBand(c.band),
			Message:   outText{Text: message(c, o.RunID)},
			Locations: []outLocation{loc},
			Partial:   map[string]string{fpName: fp},
		})
		d.Results = append(d.Results, DerivedResult{
			RuleID: ruleID, Level: levelOfBand(c.band), Path: c.ref.Path, Line: c.ref.Line, EndLine: end,
			Band: c.band, Score: c.score, Fingerprint: fp, Source: c.source,
		})
	}
	d.Kept = len(out)
	if len(out) == 0 {
		return d
	}
	doc := outLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []outRun{{Results: out}}}
	doc.Runs[0].Tool.Driver.Name = "observer-assessment"
	doc.Runs[0].Tool.Driver.Version = o.Tag
	if b, err := json.Marshal(doc); err == nil {
		d.Doc = b
	}
	return d
}
