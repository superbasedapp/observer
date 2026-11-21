package promptreg

import (
	"strconv"
	"strings"
	"time"
)

// Selector picks one version of a prompt: by label, or by version number.
// The zero value is not valid; ParseSelector builds one.
type Selector struct {
	Label   string
	Version int
}

// ResolvedBy is the selector's wire form: "label:<label>" or "version:<n>".
func (s Selector) ResolvedBy() string {
	if s.Version > 0 {
		return "version:" + strconv.Itoa(s.Version)
	}
	return "label:" + s.Label
}

// ParseSelector reads the label and version query parameters (contract
// section 2): at most one; neither is DefaultLabel.
func ParseSelector(label, version string) (Selector, error) {
	label, version = strings.TrimSpace(label), strings.TrimSpace(version)
	switch {
	case label != "" && version != "":
		return Selector{}, badRequest("give label or version, not both")
	case version != "":
		n, err := strconv.Atoi(version)
		if err != nil || n < 1 {
			return Selector{}, badRequest("version is a positive integer")
		}
		return Selector{Version: n}, nil
	case label != "":
		if !ValidLabel(label) {
			return Selector{}, badRequest("unknown label %q; the labels are %s", label, strings.Join(Labels(), ", "))
		}
		return Selector{Label: label}, nil
	}
	return Selector{Label: DefaultLabel}, nil
}

// Resolve returns the version number sel picks, given the prompt's latest
// version and current labels. latest 0 means the prompt does not exist.
func Resolve(sel Selector, latest int, labels LabelState) (int, error) {
	if latest < 1 {
		return 0, ErrPromptNotFound
	}
	if sel.Version > 0 {
		if sel.Version > latest {
			return 0, ErrVersionNotFound
		}
		return sel.Version, nil
	}
	if !ValidLabel(sel.Label) {
		return 0, badRequest("unknown label %q", sel.Label)
	}
	v, ok := labels[sel.Label]
	if !ok || v < 1 {
		return 0, ErrLabelNotSet
	}
	return v, nil
}

// PlanMove plans moving label to version to on a prompt whose latest version
// is latest. Moving a label to the version it already holds is ErrNoChange
// (with a rollout too: setting it to 0% is how a rollout ends). A move ends
// the label's rollout, if any (the returned move carries no rollout).
func PlanMove(labels LabelState, latest int, label string, to int, actor string, at time.Time) (Move, error) {
	if latest < 1 {
		return Move{}, ErrPromptNotFound
	}
	if !ValidLabel(label) {
		return Move{}, badRequest("unknown label %q; the labels are %s", label, strings.Join(Labels(), ", "))
	}
	if to < 1 || to > latest {
		return Move{}, ErrVersionNotFound
	}
	if labels[label] == to {
		return Move{}, ErrNoChange
	}
	return Move{Label: label, From: labels[label], To: to, Actor: actor, At: at.UTC()}, nil
}

// PlanRollback plans rolling label back (contract sections 6 and 9.1). A
// label with a rollout first ends it (everyone back on the base, recorded as
// a rollback rollout step: "rollback means 0%"). Otherwise the newest move of
// that label that was neither a rollback nor a rollout step and that set the
// label to its current version names the target, its From. history is the
// label's moves, oldest first (moves of other labels are ignored). An unset
// label, or one first set to its current version, has nothing to roll back
// to.
func PlanRollback(labels LabelState, rollouts Rollouts, history []Move, label string, actor string, at time.Time) (Move, error) {
	if !ValidLabel(label) {
		return Move{}, badRequest("unknown label %q; the labels are %s", label, strings.Join(Labels(), ", "))
	}
	current := labels[label]
	if current < 1 {
		return Move{}, ErrLabelNotSet
	}
	if rollouts.Active(label) {
		return Move{Label: label, From: current, To: current, Rollback: true, Rollout: true, Actor: actor, At: at.UTC()}, nil
	}
	for i := len(history) - 1; i >= 0; i-- {
		m := history[i]
		if m.Label != label || m.Rollback || m.Rollout || m.To != current {
			continue
		}
		if m.From < 1 {
			return Move{}, ErrNothingToRollBack
		}
		return Move{Label: label, From: current, To: m.From, Rollback: true, Actor: actor, At: at.UTC()}, nil
	}
	return Move{}, ErrNothingToRollBack
}

// Apply returns labels with m applied (a new map; labels is unchanged).
func (s LabelState) Apply(m Move) LabelState {
	out := LabelState{}
	for k, v := range s {
		out[k] = v
	}
	out[m.Label] = m.To
	return out
}
