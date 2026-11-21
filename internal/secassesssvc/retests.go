package secassesssvc

import (
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// The retests of a run, for the earlier run's model view (depth plan W7.2,
// decision D38: labels only). A retest is a run of its own kind that replays the
// stored requests of findings from an earlier penetration test or red team run;
// its labels are joined to that earlier run's findings here, at read time, from
// the retest runs' own stored models. Nothing is written to the earlier run, no
// finding's status changes and nothing crosses the organization wire: this is a
// read of what node-local side data already holds.

// MaxRetestViews is the most retests listed for one run, newest first.
const MaxRetestViews = 20

// RetestResultView is one finding's label in a retest, with Observer's reading
// of the request helper's log for it (EvidenceState and EvidenceReason, empty
// for an inconclusive label, which claims nothing) and the two probe ids the
// agent cited. Note is the agent's own short sentence.
type RetestResultView struct {
	Finding        string                  `json:"finding"`
	Result         string                  `json:"result"`
	EvidenceState  secassess.EvidenceState `json:"evidence_state,omitempty"`
	EvidenceReason string                  `json:"evidence_reason,omitempty"`
	Attack         string                  `json:"attack,omitempty"`
	Control        string                  `json:"control,omitempty"`
	Note           string                  `json:"note,omitempty"`
}

// RetestView is one retest of a run: the run that did it, when it was launched
// (the date its labels are shown under, and the order they are listed in), when
// its model was checked, the checked file's state, whether the agent says the
// target started, the findings it was asked to replay and the labels it gave.
type RetestView struct {
	Run string `json:"run"`
	// LaunchedAt is when the retest run started. A label is dated by it, and the
	// retests are listed newest first by it: the check time (At) moves when a run
	// is checked again, so a retest checked late would otherwise sit above a later
	// one under an earlier-looking date.
	LaunchedAt time.Time `json:"launched_at"`
	// At is when the retest's model was last checked.
	At      time.Time                `json:"at"`
	State   string                   `json:"state"`
	Started bool                     `json:"started"`
	Asked   []string                 `json:"asked"`
	Summary *secassess.RetestSummary `json:"summary,omitempty"`
	Results []RetestResultView       `json:"results"`
}

// ReadRetests lists the retests of the run of: the runs whose RetestOf is of and
// whose stored model holds a retest result that was kept, newest first (by
// launch time), at most MaxRetestViews. A retest whose model was not validated
// yet, was refused or was too large to keep is not listed: it has no labels.
func ReadRetests(side *SideData, runs []Run, of string) []RetestView {
	if side == nil || of == "" {
		return nil
	}
	var mine []Run
	for _, r := range runs {
		if r.RetestOf == of && r.IsStarted() {
			mine = append(mine, r)
		}
	}
	sort.SliceStable(mine, func(i, j int) bool { return mine[i].CreatedAt.After(mine[j].CreatedAt) })
	var out []RetestView
	for _, r := range mine {
		if len(out) == MaxRetestViews {
			break
		}
		rec, ok := ReadModel(side, r.ID)
		if !ok || rec.Result.RT == nil || rec.Result.Report.State == secassess.ValidationInvalid {
			continue
		}
		rt := rec.Result.RT
		v := RetestView{
			Run: r.ID, LaunchedAt: r.CreatedAt, At: rec.ValidatedAt, State: string(rec.Result.Report.State), Started: rt.Started,
			Asked: append([]string{}, r.RetestFindings...), Summary: rec.Result.Report.RT, Results: []RetestResultView{},
		}
		for _, x := range rt.Results {
			v.Results = append(v.Results, RetestResultView{
				Finding: x.Finding, Result: x.Result, EvidenceState: x.EvidenceState, EvidenceReason: x.EvidenceReason,
				Attack: x.Attack, Control: x.Control, Note: x.Note,
			})
		}
		out = append(out, v)
	}
	return out
}
