package policy

import "fmt"

// Mode is the guard's global posture (spec §4.1). The default is
// ModeObserve (operator decision D2): nothing blocks until the
// operator opts into enforcement.
type Mode string

// Mode values.
const (
	// ModeOff disables evaluation entirely (Evaluate returns the
	// allow verdict immediately).
	ModeOff Mode = "off"
	// ModeObserve records and alerts; rule verdicts use the
	// catalog's observe-mode decisions.
	ModeObserve Mode = "observe"
	// ModeEnforce uses the catalog's enforce-mode decisions.
	ModeEnforce Mode = "enforce"
)

// ParseMode converts a config string into a Mode. Unknown strings are
// an error so a typo'd [guard] mode is loud, never a silent
// fallback.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case ModeOff, ModeObserve, ModeEnforce:
		return Mode(s), nil
	default:
		return ModeObserve, fmt.Errorf("policy.ParseMode: unknown mode %q", s)
	}
}

// BudgetProtection identifies the exact effective budget rows authorized by a
// managed organization's hard cap. The zero value grants no native process
// intervention authority.
type BudgetProtection struct {
	SessionUSD bool
	DailyUSD   bool
	WeeklyUSD  bool
	MonthlyUSD bool

	SessionTokens bool
	DailyTokens   bool
	WeeklyTokens  bool
	MonthlyTokens bool
}

// ProtectsRule reports whether the managed organization authored the hard
// ceiling represented by ruleID. B-625 is controlled separately by
// Config.BudgetRequired because it represents a missing required document.
func (p BudgetProtection) ProtectsRule(ruleID string) bool {
	switch ruleID {
	case "B-601":
		return p.SessionUSD
	case "B-602":
		return p.DailyUSD
	case "B-603":
		return p.MonthlyUSD
	case "B-604":
		return p.WeeklyUSD
	case "B-621":
		return p.SessionTokens
	case "B-622":
		return p.DailyTokens
	case "B-623":
		return p.MonthlyTokens
	case "B-624":
		return p.WeeklyTokens
	default:
		return false
	}
}

func (p BudgetProtection) protectsUSD(scope string) bool {
	switch scope {
	case "session":
		return p.SessionUSD
	case "daily":
		return p.DailyUSD
	case "weekly":
		return p.WeeklyUSD
	case "monthly":
		return p.MonthlyUSD
	default:
		return false
	}
}

func (p BudgetProtection) protectsTokens(scope string) bool {
	switch scope {
	case "session":
		return p.SessionTokens
	case "daily":
		return p.DailyTokens
	case "weekly":
		return p.WeeklyTokens
	case "monthly":
		return p.MonthlyTokens
	default:
		return false
	}
}

// Config is everything the engine needs from the outside world,
// injected at construction (purity: this package never reads the
// environment or filesystem itself). Nil slice fields mean "use the
// defaults"; explicitly empty slices mean "none".
type Config struct {
	// Mode is the global posture; "" means ModeObserve (D2).
	Mode Mode
	// Home is the user's home directory in the CLIENT's path flavor
	// (the guard layer injects it; policy never calls
	// os.UserHomeDir). When empty, "~"-anchored patterns still
	// match literal unexpanded "~/..." targets — graceful
	// degradation, pinned by tests.
	Home string
	// AllowPaths are [guard.boundary].allow_paths glob patterns:
	// locations outside the project root that are routinely and
	// legitimately touched (temp dirs, toolchain caches). Nil means
	// DefaultAllowPaths.
	AllowPaths []string
	// ProtectedBranches are the branch glob patterns R-110/R-111
	// protect. Nil means DefaultProtectedBranches.
	ProtectedBranches []string
	// KnownProjectRoots are ALL project roots the daemon observes —
	// the cross-project-bleed rule R-151's reference set (unique to
	// observer: we know every project the user works in). Static
	// per engine; the guard layer rebuilds the engine when the set
	// changes (engines are cheap to construct).
	KnownProjectRoots []string
	// Disabled lists rule IDs turned off entirely
	// ([guard.rules].disable).
	Disabled []string
	// ExtraRules are additional rows compiled from the user/project
	// TOML policy layers (spec §4.4), appended AFTER the built-in
	// tables so built-ins keep tie-break priority. The guard layer
	// compiles matchers and applies the §4.6 layering before
	// construction; the engine validates and walks them like any
	// other row.
	ExtraRules []Rule
	// Overrides tune rule rows by ID (spec §4.4 [[override]]). The
	// guard layer has already applied the §4.6 one-way trust rules;
	// the engine applies these mechanically at construction. An
	// override naming an unknown rule ID is a construction error.
	Overrides []Override
	// BudgetSessionUSD / BudgetDailyUSD are the [guard.budget]
	// thresholds the B-601/B-602 rows compare against (spec §12.1).
	// 0 disables the row (and unstamped events carry 0 cost, so the
	// rows are doubly inert without the guard layer's budget lookup).
	BudgetSessionUSD float64
	BudgetDailyUSD   float64
	// BudgetWeeklyUSD / BudgetMonthlyUSD are the [guard.budget]
	// rolling-7-day and calendar-month $ thresholds the B-604 / B-603
	// rows compare against (spec §12.1). 0 disables the row.
	BudgetWeeklyUSD  float64
	BudgetMonthlyUSD float64
	// BudgetSessionTokens / BudgetDailyTokens / BudgetWeeklyTokens /
	// BudgetMonthlyTokens are the TOKEN-denominated ceilings the B-621..B-624
	// rows compare against (org-budget plan §3.3c), one for one with the four
	// $ fields above. 0 disables the row, exactly like the $ fields — 0 is
	// "unset", never a ceiling of zero.
	//
	// The value may be the node's own [guard.budget].*_tokens or an
	// ORGANIZATION cap already composed onto it at the boundary
	// (internal/orgbudget). This package cannot tell the two apart and must
	// not: it sees a configured number, exactly like every other threshold.
	BudgetSessionTokens int64
	BudgetDailyTokens   int64
	BudgetWeeklyTokens  int64
	BudgetMonthlyTokens int64
	// LimitUtil* are the [guard.budget.window] utilization thresholds
	// (0..1) the B-610..B-613 provider-usage-window rows compare
	// against. warn flags, deny blocks; 0 disables the threshold.
	// These are NOT touched by BudgetHard (a util window carries its
	// own explicit deny threshold — CategoryLimit, not CategoryBudget).
	LimitUtil5hWarn     float64
	LimitUtil5hDeny     float64
	LimitUtilWeeklyWarn float64
	LimitUtilWeeklyDeny float64
	// BudgetRequired is the FAIL-CLOSED budget posture (org-budget ruling
	// R2): this node may not run without the organization's budget, and none
	// has ever been verified here. It arms B-625, the one budget row that
	// compares no number — every other row in this file needs a stamped
	// value AND a configured ceiling, and "we have no ceiling" is precisely
	// the state that must block.
	//
	// Like every other field here it is a plain configured fact: this package
	// cannot tell whether it came from a grant, a tenancy or a test, and must
	// not (CLAUDE.md #3). The boundary (internal/orgbudget through the guard)
	// resolves it.
	BudgetRequired bool
	// BudgetProtection marks the exact effective ceilings that came from a
	// managed organization's hard budget. It is runtime provenance supplied by
	// the composition boundary, never a user-authored config key. A preserved
	// local ceiling remains unprotected even when another window or unit is
	// organization-authoritative.
	BudgetProtection BudgetProtection
	// BudgetHard is [guard.budget].hard: upgrade the B-601/B-602
	// ENFORCE-mode decision to deny (§12.1 "deny-on-proxy" — only the
	// proxy channel can actually block an api_request; watcher
	// surfaces degrade per §6.2). The observe-mode decision stays
	// flag — D2: nothing blocks until the operator flips enforce.
	BudgetHard bool
	// SecretDetect, when non-nil, is the typed secret detector the
	// R-172 shell-arg row runs over network-command arguments. It
	// returns the PATTERN-CERTAIN detector type names found in s
	// (entropy hits excluded by the provider — random-looking tokens
	// are routine in shell args). Injected by the guard layer from
	// internal/scrub (Module rule 1: dependencies arrive as funcs;
	// this package imports zero observer packages). Nil leaves the
	// R-172 shell row inert — the engine still constructs.
	SecretDetect func(s string) []string
}

// DefaultAllowPaths returns the default outside-project allowlist:
// temp directories and toolchain caches in both path flavors (spec
// §16 [guard.boundary].allow_paths defaults).
func DefaultAllowPaths() []string {
	return []string{
		"/tmp/**", "/var/tmp/**", "/private/tmp/**", "/dev/null",
		"~/.cache/**", "~/.npm/**", "~/go/pkg/**", "~/.cargo/registry/**",
		"~/appdata/local/temp/**",
		"?:/users/*/appdata/local/temp/**", "?:/windows/temp/**",
	}
}

// DefaultProtectedBranches returns the default protected branch
// patterns (spec §16 [guard.boundary].protected_branches).
func DefaultProtectedBranches() []string {
	return []string{"main", "master", "release/*"}
}

// Engine evaluates Events against the assembled rule tables. It is
// immutable after New and safe for concurrent use: Evaluate touches
// no shared mutable state.
type Engine struct {
	cfg   Config
	rules []Rule
}

// New constructs an Engine from cfg plus the built-in rule tables,
// applying defaults for unset fields, filtering disabled rules, and
// validating the tables (a malformed table is a construction error,
// never a silent runtime no-op).
func New(cfg Config) (*Engine, error) {
	if cfg.Mode == "" {
		cfg.Mode = ModeObserve
	}
	if cfg.Mode != ModeOff && cfg.Mode != ModeObserve && cfg.Mode != ModeEnforce {
		return nil, fmt.Errorf("policy.New: unknown mode %q", cfg.Mode)
	}
	if cfg.AllowPaths == nil {
		cfg.AllowPaths = DefaultAllowPaths()
	}
	if cfg.ProtectedBranches == nil {
		cfg.ProtectedBranches = DefaultProtectedBranches()
	}
	rules := builtinRules()
	// [guard.budget].hard (§12.1): the budget rows' enforce-mode
	// decision upgrades to deny. A config-driven decision-table
	// adjustment applied in ONE place, before extra layers so user
	// overrides can still tune the result; observe stays flag (D2).
	if cfg.BudgetHard {
		for i := range rules {
			if rules[i].Category == CategoryBudget {
				rules[i].Enforce = DecisionDeny
			}
		}
	}
	rules = append(rules, cfg.ExtraRules...)
	if len(cfg.Disabled) > 0 {
		off := setOf(cfg.Disabled...)
		kept := rules[:0]
		for _, r := range rules {
			if !off[r.ID] || protectedBudgetRuleID(cfg, r.ID) {
				kept = append(kept, r)
			}
		}
		rules = kept
	}
	// Overrides apply after disable-filtering (an override on a
	// disabled rule is the construction error it should be) and
	// before validation (so an override that broke a table invariant
	// would be caught — none can today, since Decision sets both mode
	// columns equal).
	for _, ov := range cfg.Overrides {
		matched := false
		for i := range rules {
			if rules[i].ID != ov.RuleID {
				continue
			}
			matched = true
			if ov.Decision != nil && ov.Source != SourceOrgBudget &&
				protectedBudgetRuleID(cfg, rules[i].ID) &&
				*ov.Decision < rules[i].Enforce {
				// A local/user/project override cannot weaken an
				// organization-authoritative hard budget. The internal
				// org-budget soft-window override is the one exception:
				// it carries the administrator-authored per-window mode.
				continue
			}
			if ov.Decision != nil {
				rules[i].Observe = *ov.Decision
				rules[i].Enforce = *ov.Decision
			}
			if ov.Enforced {
				rules[i].Enforced = true
			}
			if ov.Source != "" {
				rules[i].Source = ov.Source
			}
		}
		if !matched {
			return nil, fmt.Errorf("policy.New: override references unknown rule %q", ov.RuleID)
		}
	}
	if err := validateRules(rules); err != nil {
		return nil, fmt.Errorf("policy.New: %w", err)
	}
	return &Engine{cfg: cfg, rules: rules}, nil
}

// builtinRules assembles the built-in rule tables in catalog order
// (destructive §5.1, boundary §5.2, exfil §5.3, injection §8.4,
// posture §5.4, mcp §5.5, taint §5.6, budget+anomaly §5.7 last — a
// budget/anomaly hit must never out-rank a same-decision substantive
// rule on the same event). Order matters only as the final tie-break
// (earlier row wins among equal decision+severity hits); rules are
// otherwise independent.
func builtinRules() []Rule {
	rules := destructiveRules()
	rules = append(rules, boundaryRules()...)
	rules = append(rules, exfilRules()...)
	rules = append(rules, injectionRules()...)
	rules = append(rules, postureRules()...)
	rules = append(rules, mcpRules()...)
	rules = append(rules, taintRules()...)
	rules = append(rules, budgetRules()...)
	rules = append(rules, tokenBudgetRules()...)
	rules = append(rules, requiredBudgetRules()...)
	rules = append(rules, limitRules()...)
	return append(rules, anomalyRules()...)
}

// Mode returns the engine's active mode.
func (e *Engine) Mode() Mode { return e.cfg.Mode }

// RuleCount returns the number of active rule table rows (after
// Disabled filtering) — a cheap introspection hook for status
// surfaces.
func (e *Engine) RuleCount() int { return len(e.rules) }

// BudgetRuleProtected reports whether ruleID is a currently blocking budget
// row whose decision came from the managed organization budget boundary.
// B-625 is protected whenever armed. Soft organization windows finish at flag
// and therefore report false, preserving their advisory behavior.
func (e *Engine) BudgetRuleProtected(ruleID string) bool {
	if e == nil || !protectedBudgetRuleID(e.cfg, ruleID) {
		return false
	}
	for i := range e.rules {
		if e.rules[i].ID == ruleID && e.rules[i].Enforce >= DecisionDeny {
			return true
		}
	}
	return false
}

// SourceOrgBudget identifies the guard's internal per-window budget override.
// Policy files cannot author this source; their layer source is assigned by
// the guard parser.
const SourceOrgBudget = "org_budget"

func protectedBudgetRuleID(cfg Config, id string) bool {
	if id == "B-625" {
		return cfg.BudgetRequired
	}
	if !cfg.BudgetHard {
		return false
	}
	return cfg.BudgetProtection.ProtectsRule(id)
}

// Evaluate is THE evaluation seam (spec §17.2): one Event in, one
// Verdict out. It is deterministic and pure — no I/O, no recover()
// (the Q2 fail-open/fail-closed wrapper lives at the guard
// composition seam where [guard] strict is known). Multiple rule hits
// resolve to the strictest decision, tie-broken by higher severity,
// then by earlier table position. No hits (or ModeOff) yields the
// allow verdict.
func (e *Engine) Evaluate(ev Event) Verdict {
	return e.evaluate(ev, false, false)
}

// EvaluateBudget evaluates only the built-in budget and utilization admission
// rows. The proxy admission seam uses it so an unrelated, stricter custom
// api_request rule cannot win the shared decision ordering and hide a budget
// breach. Ordinary Evaluate continues to consider the full table.
func (e *Engine) EvaluateBudget(ev Event) Verdict {
	return e.evaluate(ev, true, false)
}

// EvaluateManagedBudget evaluates only organization-authorized hard budget
// rows. Filtering occurs before verdict ordering so a stricter local budget
// row cannot hide an applicable managed stop decision.
func (e *Engine) EvaluateManagedBudget(ev Event) Verdict {
	return e.evaluate(ev, true, true)
}

// EvaluateMissingManagedBudget evaluates only the built-in B-625 row with
// the missing-document posture armed. The guard uses it when the proxy
// engine's enrollment binding no longer matches the current local identity;
// it preserves the engine's off/observe/enforce behavior without mixing in
// stale numeric rows or duplicating B-625's reason text outside this package.
func (e *Engine) EvaluateMissingManagedBudget(ev Event) Verdict {
	allow := Verdict{Decision: DecisionAllow, Source: SourceBuiltin}
	if e == nil || e.cfg.Mode == ModeOff {
		return allow
	}
	clone := *e
	clone.cfg.BudgetRequired = true
	rule := requiredBudgetRules()[0]
	if !rule.appliesTo(ev.Kind) {
		return allow
	}
	hit, detail := applyRule(&rule, clone.buildContext(&ev))
	if !hit {
		return allow
	}
	return clone.verdictFor(&rule, detail)
}

func (e *Engine) evaluate(ev Event, budgetOnly, managedOnly bool) Verdict {
	allow := Verdict{Decision: DecisionAllow, Source: SourceBuiltin}
	if e.cfg.Mode == ModeOff {
		return allow
	}
	ctx := e.buildContext(&ev)
	best := allow
	for i := range e.rules {
		r := &e.rules[i]
		if budgetOnly && !budgetAdmissionRuleID(r.ID) {
			continue
		}
		if managedOnly && !protectedBudgetRuleID(e.cfg, r.ID) {
			continue
		}
		if !r.appliesTo(ev.Kind) {
			continue
		}
		hit, detail := applyRule(r, ctx)
		if !hit {
			continue
		}
		v := e.verdictFor(r, detail)
		if stricter(v, best) {
			best = v
		}
	}
	return best
}

// ManagedBudgetRequired reports whether this policy snapshot contains a
// protected budget row whose enforce decision can deny. Unlike the runtime
// admission cache predicate, it remains true in off/observe mode: disabling
// enforcement cannot make the organization's control requirement disappear.
func (e *Engine) ManagedBudgetRequired() bool {
	if e == nil {
		return false
	}
	// Ask the existing matchers which configured windows would refuse an
	// unverifiable request. Compiled rows with a zero limit are inactive, and
	// soft org overrides must not create a process-intervention requirement.
	unavailable := BudgetUnavailableWindows{Session: true, Daily: true, Weekly: true, Monthly: true}
	ev := Event{Kind: KindAPIRequest, USDUnavailable: unavailable, TokensUnavailable: unavailable}
	ctx := e.buildContext(&ev)
	for i := range e.rules {
		r := &e.rules[i]
		if protectedBudgetRuleID(e.cfg, r.ID) && r.Enforce >= DecisionDeny {
			if hit, _ := applyRule(r, ctx); hit {
				return true
			}
		}
	}
	return false
}

// BudgetAdmissionRequiresFresh reports whether an organization-protected
// budget row can currently deny. Managed blocking admission must read current
// accounting rather than the advisory TTL cache; local and soft-only engines
// retain the established cache behavior.
func (e *Engine) BudgetAdmissionRequiresFresh() bool {
	if e == nil || e.cfg.Mode == ModeOff {
		return false
	}
	for i := range e.rules {
		r := &e.rules[i]
		if !protectedBudgetRuleID(e.cfg, r.ID) {
			continue
		}
		d := r.Observe
		if e.cfg.Mode == ModeEnforce || r.Enforced {
			d = r.Enforce
		}
		if d >= DecisionDeny {
			return true
		}
	}
	return false
}

func budgetAdmissionRuleID(id string) bool {
	switch id {
	case "B-601", "B-602", "B-603", "B-604",
		"B-610", "B-611", "B-612", "B-613",
		"B-621", "B-622", "B-623", "B-624", "B-625":
		return true
	default:
		return false
	}
}

// buildContext does the per-event work exactly once (latency
// invariant §17.9): command parsing for shell events, path resolution
// for file events.
func (e *Engine) buildContext(ev *Event) *MatchContext {
	ctx := &MatchContext{Event: ev, Cfg: &e.cfg}
	switch ev.Kind {
	case KindShellExec:
		if len(ev.Args) > 0 {
			ctx.Cmds = ParseArgv(ev.Args, ev.Dialect)
		} else {
			ctx.Cmds = ParseCommand(ev.Target, ev.Dialect)
		}
	case KindFileAccess, KindConfigChange:
		ctx.Path = resolvePath(ev.Target, e.cfg.Home, ev.Cwd, ev.ProjectRoot)
	}
	return ctx
}

// applyRule runs one rule row against the context. The
// safe-pattern-first ordering is owned HERE, structurally (the dcg
// lesson, spec §4.3): for command-unit rules every unit is checked
// against the rule's safe patterns before its matcher, and a safe
// unit is exempt from THIS rule only — other units and other rules
// still evaluate. Event-scoped rules get one safe-pattern pass with a
// nil unit.
func applyRule(r *Rule, ctx *MatchContext) (bool, string) {
	if r.MatchCmd != nil {
		for i := range ctx.Cmds {
			cmd := &ctx.Cmds[i]
			if anySafe(r.SafePat, ctx, cmd) {
				continue
			}
			if hit, detail := r.MatchCmd(ctx, cmd); hit {
				return true, detail
			}
		}
		return false, ""
	}
	if anySafe(r.SafePat, ctx, nil) {
		return false, ""
	}
	return r.Match(ctx)
}

// anySafe reports whether any safe pattern exempts the candidate.
func anySafe(pats []SafeFn, ctx *MatchContext, cmd *Command) bool {
	for _, p := range pats {
		if p(ctx, cmd) {
			return true
		}
	}
	return false
}

// verdictFor builds the verdict for a rule hit, selecting the
// mode-appropriate decision (approved deviation 2: rules carry the §5
// catalog's observe→enforce decision pair). A per-rule-enforced rule
// (spec §4.1: `enforce = true` on a rule/override) uses its
// enforce-mode decision even while the engine mode is observe — the
// "enforce critical, observe rest" posture.
func (e *Engine) verdictFor(r *Rule, detail string) Verdict {
	d := r.Observe
	if e.cfg.Mode == ModeEnforce || r.Enforced {
		d = r.Enforce
	}
	reason := r.Doc
	if detail != "" {
		reason += ": " + detail
	}
	source := r.Source
	if source == "" {
		source = SourceBuiltin
	}
	return Verdict{
		Decision: d,
		RuleID:   r.ID,
		Severity: r.Severity,
		Reason:   reason,
		Advice:   r.Advice,
		Source:   source,
	}
}

// stricter reports whether verdict a should replace current winner b:
// stricter decision wins; equal decisions resolve to higher severity;
// full ties keep the earlier row (strict inequality).
func stricter(a, b Verdict) bool {
	if a.Decision != b.Decision {
		return a.Decision > b.Decision
	}
	return a.Severity > b.Severity
}
