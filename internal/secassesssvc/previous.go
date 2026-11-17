package secassesssvc

import (
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// The earlier threat models a new threat model run can be compared with (depth
// plan W3.4). The comparison is made by Observer after the new model is checked;
// nothing from the earlier run is given to the agent.

// MaxPreviousOptions is how many of the newest earlier runs the plan offers (a
// default older than these is offered besides them).
const MaxPreviousOptions = 10

// PreviousOption is an earlier checked threat model of one project.
type PreviousOption struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	// Scope is the scope paths the run was started with (empty: the whole
	// project).
	Scope []string `json:"scope,omitempty"`
	// State is how the run's model was checked: "valid" or "partial". A partial
	// model is offered as an option and labelled, but is never the default pick
	// (see PreviousChoices).
	State string `json:"state,omitempty"`
}

// previousCandidates lists every earlier run a new threat model of the project
// can be compared with, newest first: a threat model run of the same project
// that started, whose model was checked (valid or partial) and whose checked
// copy is still stored with a model in it. exclude is a run id left out (the run
// being planned). It applies no cap.
func previousCandidates(runs []Run, side *SideData, projectHash, exclude string) []PreviousOption {
	var out []PreviousOption
	for _, r := range runs {
		if r.ID == exclude || r.Kind != string(secassess.ThreatModel) || r.ProjectRootHash != projectHash || !r.IsStarted() {
			continue
		}
		if r.Validation == nil || (r.Validation.State != string(secassess.ValidationValid) && r.Validation.State != string(secassess.ValidationPartial)) {
			continue
		}
		if side != nil {
			if rec, ok := ReadModel(side, r.ID); !ok || rec.Result.TM == nil {
				continue
			}
		}
		out = append(out, PreviousOption{ID: r.ID, CreatedAt: r.CreatedAt, Scope: append([]string(nil), r.ScopePaths...), State: r.Validation.State})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// defaultPreviousIn is the newest candidate that is valid (not partial) and has
// the same scope as the run being planned: -1 when there is none.
func defaultPreviousIn(candidates []PreviousOption, scope []string) int {
	for i, o := range candidates {
		if o.State == string(secassess.ValidationValid) && secassess.SameScope(o.Scope, scope) {
			return i
		}
	}
	return -1
}

// PreviousChoices is what the plan offers for a new threat model run of a
// project: the options and the id picked when the developer chose nothing.
//
// The options are the newest MaxPreviousOptions earlier runs (see
// previousCandidates), newest first. A partial model is an option, labelled by
// its State, because the developer may well want to see it; it is never the
// default.
//
// The default is the newest run of the same project that is "valid" (its model
// was checked whole; the plan says the latest validated run of the same scope)
// and has the same scope as the run being planned (a different scope is a
// different model, so nothing is picked for it); "" when there is none. It is
// chosen over EVERY earlier run, before the list is cut to ten: when it is older
// than the ten shown it is appended as one more option, so the picker can show
// the run it has selected.
func PreviousChoices(runs []Run, side *SideData, projectHash, exclude string, scope []string) (options []PreviousOption, def string) {
	all := previousCandidates(runs, side, projectHash, exclude)
	di := defaultPreviousIn(all, scope)
	options = all
	if len(options) > MaxPreviousOptions {
		options = all[:MaxPreviousOptions]
		if di >= MaxPreviousOptions {
			options = append(append([]PreviousOption(nil), options...), all[di])
		}
	}
	if di >= 0 {
		def = all[di].ID
	}
	return options, def
}

// PreviousOptions lists the newest MaxPreviousOptions earlier runs of the
// project (previousCandidates cut to ten). It does not offer a default that is
// older than those ten: PreviousChoices does, and is what a plan uses.
func PreviousOptions(runs []Run, side *SideData, projectHash, exclude string) []PreviousOption {
	out := previousCandidates(runs, side, projectHash, exclude)
	if len(out) > MaxPreviousOptions {
		out = out[:MaxPreviousOptions]
	}
	return out
}

// DefaultPrevious is the pick among a list of options already cut to ten: the
// newest valid one with the same scope as the run being planned, "" when none
// has it. Because it sees only the list it is given, it cannot find a default
// older than that list; PreviousChoices can, and is what a plan uses.
func DefaultPrevious(options []PreviousOption, scope []string) string {
	if i := defaultPreviousIn(options, scope); i >= 0 {
		return options[i].ID
	}
	return ""
}

// PreviousModel reads the checked threat model of an earlier run: nil when the
// copy is gone, was too large to keep or is not a threat model.
func PreviousModel(side *SideData, runID string) *secassess.ThreatModelDoc {
	if side == nil || runID == "" {
		return nil
	}
	rec, ok := ReadModel(side, runID)
	if !ok {
		return nil
	}
	return rec.Result.TM
}
