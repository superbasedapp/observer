package admissionmark

// Mark is the admission decision a trace list row carries: the most
// restrictive verdict recorded for the trace, its criterion and the mode it
// was decided under (an "observe" deny did not block), plus how many verdicts
// the trace has.
type Mark struct {
	Decision    string `json:"decision"`
	CriterionID string `json:"criterion_id,omitempty"`
	Mode        string `json:"mode,omitempty"`
	Count       int    `json:"count"`
}

// Verdict is one recorded admission verdict for a trace, as read from an
// admission events table.
type Verdict struct {
	Decision    string
	CriterionID string
	Mode        string
}

// decisionRank orders the admission vocabulary (allow | flag | ask | deny)
// from least to most restrictive. A decision not in the table ranks 0, so a
// known decision always wins over it.
var decisionRank = map[string]int{
	"allow": 1,
	"flag":  2,
	"ask":   3,
	"deny":  4,
}

// Rank returns the restrictiveness of decision (0 when unknown).
func Rank(decision string) int { return decisionRank[decision] }

// Fold returns the Mark for one trace's verdicts, or nil when there are none.
// The most restrictive decision wins; on a tie the earlier verdict in vs is
// kept, so a caller that passes verdicts newest first gets the newest one.
func Fold(vs []Verdict) *Mark {
	if len(vs) == 0 {
		return nil
	}
	best := 0
	for i := 1; i < len(vs); i++ {
		if Rank(vs[i].Decision) > Rank(vs[best].Decision) {
			best = i
		}
	}
	return &Mark{
		Decision:    vs[best].Decision,
		CriterionID: vs[best].CriterionID,
		Mode:        vs[best].Mode,
		Count:       len(vs),
	}
}

// FoldByTrace groups verdicts by trace id (in input order) and folds each
// group. Verdicts with an empty trace id are skipped.
func FoldByTrace(traceIDs []string, vs []Verdict) map[string]*Mark {
	groups := map[string][]Verdict{}
	for i, v := range vs {
		if traceIDs[i] == "" {
			continue
		}
		groups[traceIDs[i]] = append(groups[traceIDs[i]], v)
	}
	out := make(map[string]*Mark, len(groups))
	for id, g := range groups {
		out[id] = Fold(g)
	}
	return out
}
