package accessgrant

import (
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// cover.go - "is this already granted": the ONE answer to whether a grant in
// force already gives everything a new ask (a developer's request, or an
// approver's proposal) would give. The request route, the approval decision
// and the node's own request form all ask it, so a developer is told "G-11
// already covers this" instead of raising, and an approver is told the same
// instead of issuing, a second grant that changes nothing (operator report
// 2026-11-13: three grants for S-793 and two each for S-721 and S-794 on one
// machine, every later one covered by the first).

// Held is a grant in force, reduced to what coverage reads. The caller lists
// only grants that are in force right now for the same member (the server's
// in-force view, the node's honoured cache): a scheduled, ended or unverified
// grant covers nothing.
type Held struct {
	ID              int64
	Type            string
	Effect          string
	SubjectKind     string
	MachineIdentity string
	RuleID          string
	Lane            string
	CommandClass    string
	OperandHash     string
	ProjectRootHash string
	Target          string
	// ExpiresAtNs 0 is no expiry; MaxUses 0 is unlimited.
	ExpiresAtNs int64
	MaxUses     int64
}

// HeldFromWire is a node-cached (or server-built) grant as coverage reads it.
func HeldFromWire(g orgcontract.AccessGrantWire) Held {
	return Held{
		ID: g.ID, Type: g.Type, Effect: g.Effect, SubjectKind: g.SubjectKind, MachineIdentity: g.MachineIdentity,
		RuleID: g.RuleID, Lane: g.Lane, CommandClass: g.CommandClass, OperandHash: g.OperandHash,
		ProjectRootHash: g.ProjectRootHash, Target: g.Target, ExpiresAtNs: g.ExpiresAtNs, MaxUses: g.MaxUses,
	}
}

// Ask is what a new request or proposal would give.
type Ask struct {
	Type            string
	Effect          string
	SubjectKind     string
	MachineIdentity string
	RuleID          string
	Lane            string
	CommandClass    string
	OperandHash     string
	ProjectRootHash string
	Target          string
	// EndsAtNs is when the ask would end; 0 asks for no expiry.
	EndsAtNs int64
	// SupersedesID is the grant an extension replaces: it never covers its
	// own extension.
	SupersedesID int64
}

// AskFromRequest is a developer's request as coverage reads it: the scope its
// breadth names (D-092: rule-wide drops the command class and the operand,
// class-wide drops the operand) and the window it asks for, measured from now.
func AskFromRequest(n Normalized, now time.Time) Ask {
	p := n.Payload
	a := Ask{
		Type: n.Type, Effect: p.Effect, SubjectKind: n.SubjectKind, MachineIdentity: n.Machine,
		RuleID: p.RuleID, Lane: p.Lane, CommandClass: p.CommandClass, OperandHash: p.OperandHash,
		ProjectRootHash: p.ProjectRootHash, Target: p.Target, SupersedesID: p.SupersedesGrantID,
		EndsAtNs: now.Add(n.Duration).UnixNano(),
	}
	switch p.Breadth {
	case BreadthRule:
		a.CommandClass, a.OperandHash = "", ""
	case BreadthClass:
		a.OperandHash = ""
	}
	return a
}

// AskFromProposal is an approver's proposal as coverage reads it, with the
// window Decide resolved. supersedes is the grant an extension replaces.
func AskFromProposal(p Proposal, d Decision, supersedes int64) Ask {
	a := Ask{
		Type: p.Type, Effect: p.Effect, SubjectKind: p.SubjectKind, MachineIdentity: p.MachineIdentity,
		RuleID: p.RuleID, Lane: p.Lane, CommandClass: p.CommandClass, OperandHash: p.OperandHash,
		ProjectRootHash: p.ProjectRootHash, Target: p.Target, SupersedesID: supersedes,
	}
	if !d.ExpiresAt.IsZero() {
		a.EndsAtNs = d.ExpiresAt.UnixNano()
	}
	return a
}

// coverRule is one row of the coverage table. A held grant covers an ask only
// when EVERY row holds (AND); the first row that fails names why not.
type coverRule struct {
	name  string
	holds func(h Held, a Ask) bool
}

// anyLane reports a lane value that matches every lane.
func anyLane(v string) bool { return v == "" || v == LaneAll }

// narrowCovers is one narrowing field: a held grant that does not pin the
// field reaches every value; one that pins it reaches only that value, so it
// covers only an ask pinned to the same value.
func narrowCovers(held, ask string) bool { return held == "" || held == ask }

var coverRules = []coverRule{
	{"not the grant being extended", func(h Held, a Ask) bool { return a.SupersedesID == 0 || h.ID != a.SupersedesID }},
	{"same type, one that lands on the grant rail", func(h Held, a Ask) bool {
		// A budget increase is an amount, not an on/off exception: a second
		// one asks for MORE, so it is never "already granted".
		t, ok := TypeByID(a.Type)
		return ok && h.Type == a.Type && t.Landing == LandGrantRail
	}},
	{"same rule", func(h Held, a Ask) bool {
		t, _ := TypeByID(a.Type)
		return !t.Names(FieldRuleID) || (a.RuleID != "" && h.RuleID == a.RuleID)
	}},
	{"same target", func(h Held, a Ask) bool {
		t, _ := TypeByID(a.Type)
		return !t.Names(FieldTarget) || (a.Target != "" && h.Target == a.Target)
	}},
	{"reaches the same machines", func(h Held, a Ask) bool {
		if h.SubjectKind == orgcontract.AccessGrantSubjectMember {
			return true
		}
		return a.SubjectKind == orgcontract.AccessGrantSubjectMachine && a.MachineIdentity != "" && h.MachineIdentity == a.MachineIdentity
	}},
	{"at least as strong an effect", func(h Held, a Ask) bool {
		// Exempt gives everything soften gives. An ask that names no effect
		// leaves it to the approver, who may choose exempt, so only an
		// exempt grant covers it.
		if h.Type != TypeGuardExemption {
			return true
		}
		return h.Effect == orgcontract.AccessGrantEffectExempt ||
			(h.Effect == orgcontract.AccessGrantEffectSoften && a.Effect == orgcontract.AccessGrantEffectSoften)
	}},
	{"every lane the ask names", func(h Held, a Ask) bool {
		return anyLane(h.Lane) || (!anyLane(a.Lane) && h.Lane == a.Lane)
	}},
	{"every command the ask names", func(h Held, a Ask) bool {
		return narrowCovers(h.CommandClass, a.CommandClass) && narrowCovers(h.OperandHash, a.OperandHash)
	}},
	{"every project the ask names", func(h Held, a Ask) bool { return narrowCovers(h.ProjectRootHash, a.ProjectRootHash) }},
	{"not use-limited", func(h Held, _ Ask) bool { return h.MaxUses == 0 }},
	{"lasts at least as long", func(h Held, a Ask) bool {
		return h.ExpiresAtNs == 0 || (a.EndsAtNs != 0 && h.ExpiresAtNs >= a.EndsAtNs)
	}},
}

// covers reports whether h gives everything a would give.
func covers(h Held, a Ask) bool {
	for _, r := range coverRules {
		if !r.holds(h, a) {
			return false
		}
	}
	return true
}

// CoveredBy returns the grant in force that already gives everything the ask
// would give. Among several, a grant with no expiry wins, then the latest
// expiry, then the lowest id, so the answer is deterministic and names the
// grant that will be there longest.
func CoveredBy(a Ask, held []Held) (Held, bool) {
	var best Held
	found := false
	for _, h := range held {
		if !covers(h, a) {
			continue
		}
		if !found || coverBetter(h, best) {
			best, found = h, true
		}
	}
	return best, found
}

func coverBetter(a, b Held) bool {
	ae, be := expirySortKey(a.ExpiresAtNs), expirySortKey(b.ExpiresAtNs)
	if ae != be {
		return ae > be
	}
	return a.ID < b.ID
}

// CodeAlreadyGranted is the Problem code of an ask a grant in force already
// covers.
const CodeAlreadyGranted = "already_granted"

// AlreadyGrantedProblem is the refusal for an ask h already covers. approver
// selects the sentence: the developer is told nothing more is needed, the
// approver how to change the grant that exists.
func AlreadyGrantedProblem(h Held, approver bool) Problem {
	msg := fmt.Sprintf("%s already covers this%s, so a new request would change nothing. If it still stops you, the block text says why the grant did not apply; send that to your approver.", HeldLabel(h), heldWindowWords(h))
	if approver {
		msg = fmt.Sprintf("%s already covers this%s, so another grant would change nothing. Extend or revoke that grant instead, or decline this request.", HeldLabel(h), heldWindowWords(h))
	}
	return Problem{Field: "grant", Code: CodeAlreadyGranted, Message: msg}
}

// HeldLabel names a held grant the way every surface does ("G-11").
func HeldLabel(h Held) string { return fmt.Sprintf("G-%d", h.ID) }

func heldWindowWords(h Held) string {
	if h.ExpiresAtNs == 0 {
		return " (in force, no expiry)"
	}
	return " (in force until " + time.Unix(0, h.ExpiresAtNs).UTC().Format("2006-01-02 15:04 UTC") + ")"
}

// Redundant lists, for each held grant another held grant fully covers, the
// id of the grant that covers it (the Grants page and the node's exception
// list mark it, so an approver can revoke what no longer changes anything).
// Of two grants that cover each other, only the later one is redundant.
func Redundant(held []Held) map[int64]int64 {
	out := map[int64]int64{}
	for _, h := range held {
		var keep []Held
		for _, c := range held {
			if c.ID == h.ID || !covers(c, askOfHeld(h)) {
				continue
			}
			if covers(h, askOfHeld(c)) && h.ID < c.ID {
				continue
			}
			keep = append(keep, c)
		}
		if by, ok := CoveredBy(askOfHeld(h), keep); ok {
			out[h.ID] = by.ID
		}
	}
	return out
}

// askOfHeld restates a held grant as the ask it would be.
func askOfHeld(h Held) Ask {
	return Ask{
		Type: h.Type, Effect: h.Effect, SubjectKind: h.SubjectKind, MachineIdentity: h.MachineIdentity,
		RuleID: h.RuleID, Lane: h.Lane, CommandClass: h.CommandClass, OperandHash: h.OperandHash,
		ProjectRootHash: h.ProjectRootHash, Target: h.Target, EndsAtNs: h.ExpiresAtNs,
	}
}
