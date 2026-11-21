package sandboxadopt

import "strings"

// CodePolicyChanged refuses a re-adoption or a restore whose kept plan is
// wider than the plan today's settings would build (audit F4): a setting,
// an organization floor or the backend list changed since the run started.
const CodePolicyChanged Code = "policy_changed"

// PolicyFacts compare what a kept run was launched under with what today's
// [terminal.sandbox] settings, the organization floors in force and the
// backend list allow. The caller reads both sides; every field is a fact.
type PolicyFacts struct {
	// Recorded: the run's launch settings were kept with its plan.
	Recorded bool
	// TodayRead: today's settings were read; TodayErr says why not.
	TodayRead bool
	TodayErr  string
	// Backend is the run's row; Listed: it is still among today's enabled
	// backends (the master switch on, no organization pin emptying them).
	Backend string
	Listed  bool
	// BelowMinIsolation names today's min_isolation the row is below.
	BelowMinIsolation string
	// FloorDropped is an organization floor's refusal of the row at the
	// run's kept tier ("" when none rules it out).
	FloorDropped string
	// KeptTier and TodayTier are the network tiers, with their strictness
	// (a higher value lets less out; -1 is unknown).
	KeptTier, TodayTier                     string
	KeptTierStrictness, TodayTierStrictness int
	// WidenedBinds are kept extra binds today's settings no longer allow
	// (a read-write bind now only read-only counts).
	WidenedBinds []string
	// WidenedCIDRs are kept egress allow-list entries today's list lacks.
	WidenedCIDRs []string
	// DroppedMasks are today's mask paths the kept plan did not hide.
	DroppedMasks []string
	// ToolConfigWritesWidened: the run may write the tool's config and
	// today's settings no longer allow it.
	ToolConfigWritesWidened bool
}

// policyRule is one row of the policy table: when match holds, the kept
// plan is refused with the rendered reason.
type policyRule struct {
	name   string
	match  func(PolicyFacts) bool
	reason func(PolicyFacts) string
}

// policyRules is walked top-down; the first row that matches refuses. A
// kept plan that passes every row is the same as today's or stricter.
var policyRules = []policyRule{
	{"recorded", func(f PolicyFacts) bool { return !f.Recorded }, func(PolicyFacts) string {
		return "the run's launch settings were not kept with its plan, so it cannot be checked against today's"
	}},
	{"today", func(f PolicyFacts) bool { return !f.TodayRead }, func(f PolicyFacts) string {
		return "today's sandbox settings could not be read: " + f.TodayErr
	}},
	{"listed", func(f PolicyFacts) bool { return !f.Listed }, func(f PolicyFacts) string {
		return f.Backend + " is no longer in the backend list of the Sandbox isolation settings card (Terminals > Settings; [terminal.sandbox].backends), or the sandbox is off, or your organization's pin left no backend"
	}},
	{"min_isolation", func(f PolicyFacts) bool { return f.BelowMinIsolation != "" }, func(f PolicyFacts) string {
		return f.Backend + " is below the Minimum isolation of the Sandbox isolation settings card (Terminals > Settings; [terminal.sandbox].min_isolation = " + f.BelowMinIsolation + ")"
	}},
	{"org_floor", func(f PolicyFacts) bool { return f.FloorDropped != "" }, func(f PolicyFacts) string {
		return "an organization floor in force now rules the run out: " + f.FloorDropped
	}},
	{"tier", func(f PolicyFacts) bool {
		return f.KeptTierStrictness < 0 || f.TodayTierStrictness < 0 || f.KeptTierStrictness < f.TodayTierStrictness
	}, func(f PolicyFacts) string {
		return "the run's network tier " + f.KeptTier + " is wider than today's " + f.TodayTier
	}},
	{"binds", func(f PolicyFacts) bool { return len(f.WidenedBinds) > 0 }, func(f PolicyFacts) string {
		return "the run binds what today's settings no longer allow: " + strings.Join(f.WidenedBinds, ", ")
	}},
	{"cidrs", func(f PolicyFacts) bool { return len(f.WidenedCIDRs) > 0 }, func(f PolicyFacts) string {
		return "the run may reach what today's egress allow-list no longer has: " + strings.Join(f.WidenedCIDRs, ", ")
	}},
	{"masks", func(f PolicyFacts) bool { return len(f.DroppedMasks) > 0 }, func(f PolicyFacts) string {
		return "the run does not hide what today's mask_paths hide: " + strings.Join(f.DroppedMasks, ", ")
	}},
	{"tool_config_writes", func(f PolicyFacts) bool { return f.ToolConfigWritesWidened }, func(PolicyFacts) string {
		return "the run may write the tool's config and allow_tool_config_writes is now off"
	}},
}

// CheckPolicy refuses (CodePolicyChanged) a kept plan wider than today's;
// nil when it is the same or stricter.
func CheckPolicy(f PolicyFacts) *Refusal {
	for _, r := range policyRules {
		if r.match(f) {
			return &Refusal{Code: CodePolicyChanged, Reason: r.reason(f)}
		}
	}
	return nil
}

// WidenedBinds lists the kept extra binds today's lists do not allow: a
// kept read-write bind must be in today's read-write list, a kept
// read-only bind in either.
func WidenedBinds(keptRW, keptRO, todayRW, todayRO []string) []string {
	rw, either := set(todayRW), set(todayRW, todayRO)
	var out []string
	for _, b := range keptRW {
		if !rw[strings.TrimSpace(b)] {
			out = append(out, b+" (read-write)")
		}
	}
	for _, b := range keptRO {
		if !either[strings.TrimSpace(b)] {
			out = append(out, b+" (read-only)")
		}
	}
	return out
}

// Missing lists the entries of want that have lacks.
func Missing(want, have []string) []string {
	h := set(have)
	var out []string
	for _, w := range want {
		if !h[strings.TrimSpace(w)] {
			out = append(out, w)
		}
	}
	return out
}

func set(lists ...[]string) map[string]bool {
	m := map[string]bool{}
	for _, l := range lists {
		for _, v := range l {
			m[strings.TrimSpace(v)] = true
		}
	}
	return m
}
