package accessgrant

import (
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Describe renders what a grant would do in one line ("R-171 for alice on
// laptop-7, exact command, soften, 8h, until 18:00 UTC"), the approver
// card's "what the grant would do" (§2.4). The org renders it from the
// proposal; nothing on the node parses it.
func Describe(p Proposal, d Decision, who string, now time.Time) string {
	return DescribeLabeled(p, d, who, now, Labels{})
}

// Labels are the human names the org resolves for the ids a grant carries, so
// the approver reads "monthly, $2,000, alice@acme.example" and "Alice's Linux
// computer" instead of a budget uuid and a 64-hex machine fingerprint. An
// empty field falls back to the id (what Describe has always printed).
type Labels struct {
	// Budget names the budget a budget-increase grant raises.
	Budget string
	// Machine names the machine a machine-scoped grant is pinned to.
	Machine string
}

// DescribeLabeled is Describe with resolved names for the budget and machine.
func DescribeLabeled(p Proposal, d Decision, who string, now time.Time, labels Labels) string {
	if who == "" {
		who = p.UserID
	}
	var parts []string
	t, _ := TypeByID(p.Type)
	switch p.Type {
	case TypeGuardExemption:
		parts = append(parts, p.RuleID)
	case TypeBudgetIncrease:
		parts = append(parts, budgetPhrase(p, d, labels.Budget))
	default:
		parts = append(parts, strings.ToLower(t.Label)+" "+p.Target)
	}
	subject := "for " + who
	if p.SubjectKind == orgcontract.AccessGrantSubjectMachine && p.MachineIdentity != "" {
		subject += " on " + firstLabel(labels.Machine, p.MachineIdentity)
	} else {
		subject += " on all of their machines"
	}
	parts[0] += " " + subject
	if p.Type == TypeGuardExemption {
		switch {
		case p.OperandHash != "":
			parts = append(parts, "exact command")
		case p.CommandClass != "":
			parts = append(parts, "command class "+p.CommandClass)
		default:
			parts = append(parts, "rule-wide")
		}
		if p.ProjectRootHash != "" {
			parts = append(parts, "this project")
		}
		if p.Lane != "" && p.Lane != LaneAll {
			parts = append(parts, p.Lane+" lane")
		}
		if p.Effect == orgcontract.AccessGrantEffectSoften {
			parts = append(parts, "soften (still confirm each call)")
		} else {
			parts = append(parts, "lift (recorded, not asked)")
		}
	}
	if p.MaxUses > 0 {
		parts = append(parts, fmt.Sprintf("%d use(s)", p.MaxUses))
	}
	if d.ExpiresAt.IsZero() {
		parts = append(parts, "perpetual")
	} else {
		start := d.StartsAt
		parts = append(parts, HumanDuration(d.ExpiresAt.Sub(start).Round(time.Minute)),
			"until "+d.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC"))
		if start.After(now.Add(time.Minute)) {
			parts = append(parts, "from "+start.UTC().Format("2006-01-02 15:04 UTC"))
		}
	}
	return strings.Join(parts, ", ")
}

func firstLabel(label, fallback string) string {
	if label != "" {
		return label
	}
	return fallback
}

func budgetPhrase(p Proposal, d Decision, label string) string {
	var b []string
	if p.DeltaTokens > 0 {
		b = append(b, fmt.Sprintf("+%d tokens (cap %d)", p.DeltaTokens, d.CapTokens))
	}
	if p.DeltaUSD > 0 {
		// no-bare-usd:allow (the org decision preview an admin approves; admins always see dollars)
		b = append(b, fmt.Sprintf("+$%.2f (cap $%.2f)", p.DeltaUSD, d.CapUSD))
	}
	return "budget " + firstLabel(label, p.BudgetID) + " " + strings.Join(b, " and ")
}

// Budget periods, restated from orgcontract so callers need one import.
const (
	PeriodRolling30d    = orgcontract.BudgetPolicyPeriodRolling30d
	PeriodCalendarDay   = orgcontract.BudgetPolicyPeriodCalendarDay
	PeriodCalendarMonth = orgcontract.BudgetPolicyPeriodCalendarMonth
)

// periodEnds maps a budget period onto the end of the window containing now
// (D-081: a budget increase lasts at most until the end of the current
// period). A rolling window has no boundary, so its "period" is its length.
var periodEnds = map[string]func(now time.Time, loc *time.Location) time.Time{
	PeriodRolling30d: func(now time.Time, _ *time.Location) time.Time { return now.Add(30 * 24 * time.Hour) },
	PeriodCalendarDay: func(now time.Time, loc *time.Location) time.Time {
		l := now.In(loc)
		return time.Date(l.Year(), l.Month(), l.Day()+1, 0, 0, 0, 0, loc)
	},
	PeriodCalendarMonth: func(now time.Time, loc *time.Location) time.Time {
		l := now.In(loc)
		return time.Date(l.Year(), l.Month()+1, 1, 0, 0, 0, 0, loc)
	},
}

// PeriodEnd returns the end of the current budget period (zero for an
// unknown period, which Decide bounds by MaxBudgetFallback). An unknown
// timezone reads as UTC.
func PeriodEnd(period, timezone string, now time.Time) time.Time {
	f, ok := periodEnds[period]
	if !ok {
		return time.Time{}
	}
	loc := time.UTC
	if timezone != "" {
		if l, err := time.LoadLocation(timezone); err == nil {
			loc = l
		}
	}
	return f(now, loc).UTC()
}
