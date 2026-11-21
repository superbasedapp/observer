package promptreg

import (
	"strings"
	"time"
	"unicode/utf8"
)

// Settings are an org's prompt registry settings (contract section 9.6).
// The machine has one user and no settings: its zero value applies there.
type Settings struct {
	// RequireProductionApproval: a change that raises what production
	// serves is proposed by one member and approved by another.
	RequireProductionApproval bool   `json:"require_production_approval"`
	UpdatedBy                 string `json:"updated_by"`
	UpdatedAt                 string `json:"updated_at"`
}

// The change kinds a proposal carries.
const (
	// ChangeMove points the label at Version (PlanMove).
	ChangeMove = "move"
	// ChangeRollout sets the label's rollout to candidate Version at
	// Percent (PlanRollout; 100 promotes, 0 ends it).
	ChangeRollout = "rollout"
)

// ValidChangeKind reports whether k is a change kind.
func ValidChangeKind(k string) bool { return k == ChangeMove || k == ChangeRollout }

// The proposal statuses.
const (
	ProposalPending  = "pending"
	ProposalApproved = "approved"
	ProposalRejected = "rejected"
	// ProposalStale: the label changed between the proposal and its
	// approval, so the approval moved nothing.
	ProposalStale = "stale"
)

// MaxNoteBytes bounds a proposal's or a decision's note.
const MaxNoteBytes = 500

// PlanChange plans one label change of kind on the prompt's current state:
// a move to version, or a rollout of candidate version at percent.
func PlanChange(labels LabelState, rollouts Rollouts, latest int, kind, label string, version, percent int, actor string, at time.Time) (Move, error) {
	switch kind {
	case ChangeMove:
		return PlanMove(labels, latest, label, version, actor, at)
	case ChangeRollout:
		return PlanRollout(labels, rollouts, latest, label, version, percent, actor, at)
	}
	return Move{}, badRequest("kind is %q or %q", ChangeMove, ChangeRollout)
}

// approvalRow is one row of the approval table: when match holds, the row
// decides (need).
type approvalRow struct {
	why   string
	match func(s Settings, cur Rollouts, m Move) bool
	need  bool
}

// approvalRows decide whether a planned move needs approval, walked
// top-down, first match wins (one test case per row). Only production is
// gated, only when the org asks, and never the levers that return
// production to what it served before: a rollback, ending a rollout, or
// lowering one.
var approvalRows = []approvalRow{
	{"only production is gated", func(_ Settings, _ Rollouts, m Move) bool { return m.Label != LabelProduction }, false},
	{"the org does not require approval", func(s Settings, _ Rollouts, _ Move) bool { return !s.RequireProductionApproval }, false},
	{"a rollback returns production to what it served", func(_ Settings, _ Rollouts, m Move) bool { return m.Rollback }, false},
	{"ending a rollout serves only the base", func(_ Settings, _ Rollouts, m Move) bool { return m.Rollout && m.RolloutPercent == 0 }, false},
	{"lowering a rollout serves the candidate to fewer keys", func(_ Settings, cur Rollouts, m Move) bool {
		c, ok := cur[m.Label]
		return m.Rollout && ok && cur.Active(m.Label) && c.Version == m.RolloutVersion && m.RolloutPercent < c.Percent
	}, false},
	{"anything else raises what production serves", func(Settings, Rollouts, Move) bool { return true }, true},
}

// NeedsApproval reports whether move m, planned against the label's current
// rollouts cur, needs a second member's approval under s.
func NeedsApproval(s Settings, cur Rollouts, m Move) bool {
	for _, r := range approvalRows {
		if r.match(s, cur, m) {
			return r.need
		}
	}
	return true
}

// Proposal is one proposed label change awaiting a second member.
type Proposal struct {
	ID      string
	Name    string
	Label   string
	Kind    string
	Version int
	Percent int
	// The label when proposed: an approval applies only while it still
	// holds (the stale rule).
	BaseVersion        int
	BaseRolloutVersion int
	BaseRolloutPercent int
	Note               string
	Status             string
	ProposedBy         string
	ProposedAt         time.Time
	DecidedBy          string
	DecidedAt          time.Time
	DecisionNote       string
}

// snapshotMatches reports whether the label is as it was when p was
// proposed.
func (p Proposal) snapshotMatches(labels LabelState, rollouts Rollouts) bool {
	cur := Rollout{}
	if rollouts.Active(p.Label) {
		cur = rollouts[p.Label]
	}
	return labels[p.Label] == p.BaseVersion && cur.Version == p.BaseRolloutVersion && cur.Percent == p.BaseRolloutPercent
}

func checkNote(note string) error {
	if len(note) > MaxNoteBytes || !utf8.ValidString(note) {
		return badRequest("note is at most %d bytes of UTF-8", MaxNoteBytes)
	}
	return nil
}

// NewProposal validates a proposed change by planning it on the current
// state (a change that would be refused now is refused as a proposal) and
// records the label's state for the stale rule. id is the store's.
func NewProposal(id, name string, labels LabelState, rollouts Rollouts, latest int, kind, label string, version, percent int, note, actor string, at time.Time) (Proposal, error) {
	if !ValidName(name) {
		return Proposal{}, badRequest("not a prompt name")
	}
	if err := checkNote(note); err != nil {
		return Proposal{}, err
	}
	if _, err := PlanChange(labels, rollouts, latest, kind, label, version, percent, actor, at); err != nil {
		return Proposal{}, err
	}
	p := Proposal{
		ID: id, Name: name, Label: label, Kind: kind, Version: version, Percent: percent,
		BaseVersion: labels[label], Note: strings.TrimSpace(note), Status: ProposalPending,
		ProposedBy: actor, ProposedAt: at.UTC().Truncate(time.Second),
	}
	if kind == ChangeMove {
		p.Percent = 0
	}
	if rollouts.Active(label) {
		p.BaseRolloutVersion, p.BaseRolloutPercent = rollouts[label].Version, rollouts[label].Percent
	}
	return p, nil
}

// Decision is the outcome of an approval: the proposal's new state and, for
// an applied approval, the move to write.
type Decision struct {
	Proposal Proposal
	// Apply is false for a stale approval: the store records the status
	// and returns ErrProposalStale, and nothing moves.
	Apply bool
	Move  Move
}

// PlanApprove plans approver approving p against the prompt's current
// state. The approver must differ from the proposer; a label that changed
// since the proposal makes it stale.
func PlanApprove(p Proposal, labels LabelState, rollouts Rollouts, latest int, approver, note string, at time.Time) (Decision, error) {
	if p.Status != ProposalPending {
		return Decision{}, ErrProposalClosed
	}
	if strings.TrimSpace(approver) == "" || approver == p.ProposedBy {
		return Decision{}, ErrSelfApproval
	}
	if err := checkNote(note); err != nil {
		return Decision{}, err
	}
	p.DecidedBy, p.DecidedAt, p.DecisionNote = approver, at.UTC().Truncate(time.Second), strings.TrimSpace(note)
	if !p.snapshotMatches(labels, rollouts) {
		p.Status = ProposalStale
		return Decision{Proposal: p}, nil
	}
	m, err := PlanChange(labels, rollouts, latest, p.Kind, p.Label, p.Version, p.Percent, approver, at)
	if err != nil {
		// The label is as proposed and versions are immutable, so the plan
		// that validated the proposal holds; anything else is stale.
		p.Status = ProposalStale
		return Decision{Proposal: p}, nil
	}
	p.Status = ProposalApproved
	return Decision{Proposal: p, Apply: true, Move: m}, nil
}

// PlanReject plans actor rejecting p: any member with the write key may,
// the proposer included (a withdrawal).
func PlanReject(p Proposal, actor, note string, at time.Time) (Proposal, error) {
	if p.Status != ProposalPending {
		return Proposal{}, ErrProposalClosed
	}
	if err := checkNote(note); err != nil {
		return Proposal{}, err
	}
	p.Status, p.DecidedBy, p.DecidedAt, p.DecisionNote = ProposalRejected, actor, at.UTC().Truncate(time.Second), strings.TrimSpace(note)
	return p, nil
}

// ProposalView is a proposal on the wire.
type ProposalView struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Label              string `json:"label"`
	Kind               string `json:"kind"`
	Version            int    `json:"version"`
	Percent            int    `json:"percent"`
	BaseVersion        int    `json:"base_version"`
	BaseRolloutVersion int    `json:"base_rollout_version"`
	BaseRolloutPercent int    `json:"base_rollout_percent"`
	Note               string `json:"note"`
	Status             string `json:"status"`
	ProposedBy         string `json:"proposed_by"`
	ProposedAt         string `json:"proposed_at"`
	DecidedBy          string `json:"decided_by"`
	DecidedAt          string `json:"decided_at"`
	DecisionNote       string `json:"decision_note"`
	// Summary says the change in words ("production -> version 4",
	// "production: 20% on version 4").
	Summary string `json:"summary"`
}

// View renders p.
func (p Proposal) View() ProposalView {
	return ProposalView{
		ID: p.ID, Name: p.Name, Label: p.Label, Kind: p.Kind, Version: p.Version, Percent: p.Percent,
		BaseVersion: p.BaseVersion, BaseRolloutVersion: p.BaseRolloutVersion, BaseRolloutPercent: p.BaseRolloutPercent,
		Note: p.Note, Status: p.Status, ProposedBy: p.ProposedBy, ProposedAt: formatTime(p.ProposedAt),
		DecidedBy: p.DecidedBy, DecidedAt: formatTime(p.DecidedAt), DecisionNote: p.DecisionNote,
		Summary: ChangeSummary(p.Label, p.Kind, p.Version, p.Percent),
	}
}

// ChangeSummary says a change in words, for proposal lists, audit details
// and assistant previews.
func ChangeSummary(label, kind string, version, percent int) string {
	if kind == ChangeRollout {
		switch {
		case percent <= 0:
			return label + ": end the rollout"
		case percent >= 100:
			return label + ": promote version " + itoa(version)
		}
		return label + ": " + itoa(percent) + "% on version " + itoa(version)
	}
	return label + " -> version " + itoa(version)
}
