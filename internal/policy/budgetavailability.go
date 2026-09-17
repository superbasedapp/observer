package policy

// BudgetUnavailableWindows identifies accounting windows whose usage cannot
// be determined. False means no accounting failure was stamped; hook events
// remain unstamped because they cannot perform the daemon's spend lookup.
type BudgetUnavailableWindows struct {
	Session bool
	Daily   bool
	Weekly  bool
	Monthly bool
}

// Budget WINDOW vocabulary. The four names are the node's own windows, shared
// by the $ rows, the token rows and the subject rows so a cap, a stamp and a
// rule row can all name the same window with the same string (bundle BUD-N).
const (
	BudgetWindowSession = "session"
	BudgetWindowDaily   = "daily"
	BudgetWindowWeekly  = "weekly"
	BudgetWindowMonthly = "monthly"
)

// BudgetWindowAmounts is one set of per-window amounts in BOTH units. It is
// deliberately one type used for three different things — the cross-machine org
// baseline, a tool's own spend, a model's own spend — because they are the same
// shape and a rule that compares them must never have to convert between three
// near-identical structs.
//
// 0 is unknown/unstamped in every field, the same sentinel every other budget
// stamp uses; it is never "free".
type BudgetWindowAmounts struct {
	SessionUSD float64
	DailyUSD   float64
	WeeklyUSD  float64
	MonthlyUSD float64

	SessionTokens int64
	DailyTokens   int64
	WeeklyTokens  int64
	MonthlyTokens int64
}

// USD returns the amount for one window name, and whether the name is one of
// the four. A table read, so a caller never writes the switch again.
func (a BudgetWindowAmounts) USD(window string) (float64, bool) {
	switch window {
	case BudgetWindowSession:
		return a.SessionUSD, true
	case BudgetWindowDaily:
		return a.DailyUSD, true
	case BudgetWindowWeekly:
		return a.WeeklyUSD, true
	case BudgetWindowMonthly:
		return a.MonthlyUSD, true
	}
	return 0, false
}

// Tokens is USD's integer sibling.
func (a BudgetWindowAmounts) Tokens(window string) (int64, bool) {
	switch window {
	case BudgetWindowSession:
		return a.SessionTokens, true
	case BudgetWindowDaily:
		return a.DailyTokens, true
	case BudgetWindowWeekly:
		return a.WeeklyTokens, true
	case BudgetWindowMonthly:
		return a.MonthlyTokens, true
	}
	return 0, false
}

// Unavailable returns the availability flag for one window name.
func (w BudgetUnavailableWindows) Unavailable(window string) bool {
	switch window {
	case BudgetWindowSession:
		return w.Session
	case BudgetWindowDaily:
		return w.Daily
	case BudgetWindowWeekly:
		return w.Weekly
	case BudgetWindowMonthly:
		return w.Monthly
	}
	return false
}

// Any reports whether ANY window is unavailable.
func (w BudgetUnavailableWindows) Any() bool {
	return w.Session || w.Daily || w.Weekly || w.Monthly
}

// BudgetSubjectCap is ONE organization cap narrowed to one tool or one model,
// for one window, already resolved at the composition boundary
// (internal/orgbudget) — the same discipline every other threshold on Config
// follows: this package receives numbers, never a body.
//
// Kind/ID arrive NORMALIZED (trimmed, ASCII-lowercased) and are compared
// against a likewise-normalized Event.Tool / Event.Model, because the two
// spellings come from different places: the org admin typed one and an adapter
// captured the other.
type BudgetSubjectCap struct {
	// Kind is "tool" or "model" (orgcontract.BudgetSubject* — re-spelled
	// here because this package imports nothing).
	Kind string
	// ID is the normalized subject identifier.
	ID string
	// Window is one of the BudgetWindow* names.
	Window string
	// CapUSD / CapTokens are the ceilings, 0 meaning unset in both — the
	// same sentinel as every window ceiling on Config.
	CapUSD    float64
	CapTokens int64
	// BaselineUSD / BaselineTokens are this subject's cross-machine baseline,
	// composed onto the local total before the comparison exactly as
	// Event.OrgBaseline is for the node-wide windows. Zero when the org
	// supplied none, or supplied one the node refused.
	BaselineUSD    float64
	BaselineTokens int64
	// BaselineFlagOnly says the baseline above may WARN and may not deny: the
	// org's measurement counted rows it could not attribute to a machine, so it
	// may overlap this node's own usage. A cap the org authored HARD therefore
	// compares local usage alone; a soft one still composes the two, because a
	// warning raised on a possibly-overlapping number costs nothing and a
	// stopped process does.
	BaselineFlagOnly bool
	// Hard says a breach of THIS cap denies in enforce mode. It is per cap
	// because the org authors enforcement per cap and a node that folded the
	// strictest mode across subjects would deny a cap the admin wrote as a
	// nudge — the same defect the per-window SoftWindows set exists to
	// prevent (MEDIUM-3).
	Hard bool
}
