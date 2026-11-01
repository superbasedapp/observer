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

	// ToolUSD / ToolTokens / ModelUSD / ModelTokens are the SUBJECT rows'
	// provenance (bundle BUD-N): true when a managed organization authored at
	// least one HARD cap of that kind and unit. They are per kind+unit rather
	// than per subject because they answer the question protection is asked —
	// "may a node-side process intervention act on this rule row?" — and a
	// rule row is per kind+unit. Which SUBJECT actually crossed is decided by
	// the matcher against Config.BudgetSubjectCaps, where each cap carries its
	// own Hard flag.
	ToolUSD     bool
	ToolTokens  bool
	ModelUSD    bool
	ModelTokens bool
}

// ProtectsRule reports whether the managed organization authored the hard
// ceiling represented by ruleID. B-625 is controlled separately by
// Config.BudgetRequired because it represents a missing required document.
func (p BudgetProtection) ProtectsRule(ruleID string) bool {
	switch ruleID {
	case "B-626":
		return p.ToolUSD
	case "B-627":
		return p.ToolTokens
	case "B-628":
		return p.ModelUSD
	case "B-629":
		return p.ModelTokens
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
	// ResolveLinks, when set, resolves the symlinks in the longest
	// EXISTING prefix of a normalized absolute path and returns the
	// result (forward slashes), or "" when the path is not on this
	// machine's path flavor or nothing resolves. It is I/O, injected by
	// the guard layer; nil keeps resolution purely lexical. R-101 uses it
	// so a delete that reaches the home directory or a filesystem root
	// THROUGH a symlink (`ln -s ~ out; rm -rf out/*`) is judged by where
	// it lands (Sol A2-04).
	ResolveLinks func(path string) string
	// KnownProjectRoots are ALL project roots the daemon observes —
	// the cross-project-bleed rule R-151's reference set (unique to
	// observer: we know every project the user works in). Static
	// per engine; the guard layer rebuilds the engine when the set
	// changes (engines are cheap to construct).
	KnownProjectRoots []string
	// HookSwitches are the vendor settings that turn a coding agent's
	// hooks off, Observer's guard hooks included: the R-162 rows refuse an
	// agent write that turns one on. The guard layer injects the table
	// from internal/hookdisable, its one owner; nil means none (the rows
	// are then inert), since this package never enumerates vendors.
	HookSwitches []HookSwitch
	// ReadFile reads the CURRENT content of a file an R-162 row judges, so
	// an Edit is replayed onto the whole file (an edit that changes only
	// `false` to `true` next to a hook switch carries no key in its own
	// text). It is I/O, injected by the guard layer like ResolveLinks, and
	// is only called for a path that names a hook-bearing settings file.
	// ok=false means unreadable or absent; nil keeps R-162 to the text of
	// the proposed edit alone.
	ReadFile func(path string) (content []byte, ok bool)
	// GitAliases returns the git aliases in force for a directory (alias
	// name, lowercased, to its expansion), so the R-112 to R-114 rows see
	// through `git ci` to the `commit --no-verify` it runs. The guard
	// layer injects it from the per-project alias table the daemon
	// precomputes; the hook never runs git. ok=false means no table covers
	// the directory; nil leaves the rows to aliases defined on the command
	// line itself.
	GitAliases func(dir string) (aliases map[string]string, ok bool)
	// ProtectedPathClasses are the R-166 path classes an agent may not
	// write ([guard.boundary].protected_path_classes; ProtectedPathClasses
	// lists the vocabulary). Empty, the default, leaves R-166 inert.
	ProtectedPathClasses []string
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
	// BudgetSubjectCaps are the organization's PER-TOOL and PER-MODEL caps,
	// already resolved per window at the composition boundary (bundle BUD-N).
	// The B-626..B-629 rows walk this table; an empty table leaves all four
	// rows inert, which is every node the org authored no subject cap for.
	//
	// It is a TABLE rather than four more scalar ceilings because the number
	// of subjects is the org's to choose, not this struct's — a fleet may cap
	// two tools or twenty, and the rule rows are the same either way
	// (CLAUDE.md #5).
	BudgetSubjectCaps []BudgetSubjectCap
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
	// readsBudgetStamps is ReadsBudgetStamps, resolved once at New.
	readsBudgetStamps bool
}

// budgetStampConsumers is the closed table of configured facts that make a
// row compare a guard-stamped spend, usage or utilization value. Any one true
// means the guard must stamp; all false means every budget, limit and subject
// row is inert (an unconfigured ceiling disables its row) and a stamp would
// be read by nothing. A new configured ceiling is one more row here.
var budgetStampConsumers = []func(*Config) bool{
	func(c *Config) bool { return c.BudgetSessionUSD > 0 },
	func(c *Config) bool { return c.BudgetDailyUSD > 0 },
	func(c *Config) bool { return c.BudgetWeeklyUSD > 0 },
	func(c *Config) bool { return c.BudgetMonthlyUSD > 0 },
	func(c *Config) bool { return c.BudgetSessionTokens > 0 },
	func(c *Config) bool { return c.BudgetDailyTokens > 0 },
	func(c *Config) bool { return c.BudgetWeeklyTokens > 0 },
	func(c *Config) bool { return c.BudgetMonthlyTokens > 0 },
	func(c *Config) bool { return len(c.BudgetSubjectCaps) > 0 },
	func(c *Config) bool { return c.LimitUtil5hWarn > 0 },
	func(c *Config) bool { return c.LimitUtil5hDeny > 0 },
	func(c *Config) bool { return c.LimitUtilWeeklyWarn > 0 },
	func(c *Config) bool { return c.LimitUtilWeeklyDeny > 0 },
	// B-625 compares no number, but a node whose organization requires a
	// budget is one the org budget rail governs; stamping keeps its admission
	// path exactly as it was.
	func(c *Config) bool { return c.BudgetRequired },
}

// resolveReadsBudgetStamps computes ReadsBudgetStamps for one built engine.
func resolveReadsBudgetStamps(cfg *Config, rules []Rule) bool {
	for _, consumes := range budgetStampConsumers {
		if consumes(cfg) {
			return true
		}
	}
	for i := range rules {
		if rules[i].ReadsBudgetStamps {
			return true
		}
	}
	return false
}

// ReadsBudgetStamps reports whether any row of this engine can read the
// guard-stamped spend / usage / utilization fields: a configured budget,
// limit or subject cap (local or composed from the organization's budget),
// the fail-closed org-budget posture, or a policy-file rule with a spend
// matcher. When false, the guard skips its budget accounting lookup
// entirely: nothing would read the numbers it returns (T-418).
//
// It is a CAPABILITY of the built engine, resolved once at New, so the hot
// path reads a bool rather than walking the configuration per event; a
// changed budget or policy rebuilds the engine and with it this answer.
func (e *Engine) ReadsBudgetStamps() bool {
	if e == nil {
		return false
	}
	return e.readsBudgetStamps
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
			// SUBJECT rows are exempt, and deliberately so (bundle BUD-N).
			// [guard.budget].hard is the node's posture about the node's OWN
			// window ceilings; a per-tool / per-model cap carries the
			// organization's own per-cap enforcement, and the pair of rows
			// each subject ID ships (a deny row that matches only hard caps
			// and a flag row that matches only soft ones — approved deviation
			// 3) already encodes it. Sweeping them up here would deny a
			// subject cap the admin authored as `soft`, which is exactly the
			// cross-period fold MEDIUM-3 removed for windows.
			if rules[i].Category == CategoryBudget && !subjectBudgetRuleID(rules[i].ID) {
				rules[i].Enforce = DecisionDeny
			}
		}
	}
	rules = append(rules, cfg.ExtraRules...)
	floor := orgFloorIDs(cfg)
	if len(cfg.Disabled) > 0 {
		off := setOf(cfg.Disabled...)
		kept := rules[:0]
		for i := range rules {
			// protectedIntegrityRule is a HARD BACKSTOP alongside
			// protectedBudgetRule: R-160/R-161 can never be disabled by
			// any layer below the org, and every disable (config/user/
			// trusted-project) funnels to cfg.Disabled, so keeping the row
			// here closes the whole class even if a merge path missed it.
			// The org floor is the third backstop (OSH-R-014): a rule the
			// organization's layer defined or tuned is a strictness floor
			// no below-org disable removes, the config-level
			// [guard.rules] disable included, which never passes the merge.
			if !off[rules[i].ID] || protectedBudgetRule(cfg, &rules[i]) || protectedIntegrityRule(&rules[i]) || floor[rules[i].ID] {
				kept = append(kept, rules[i])
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
			if floor[rules[i].ID] && overrideRelaxesOrgFloor(&rules[i], ov) {
				// A below-org override cannot weaken an org-floored row
				// (OSH-R-014): the guard merge already drops it with a
				// surfaced issue; this is the hard backstop.
				continue
			}
			applyOverride(cfg, &rules[i], ov)
		}
		if !matched {
			return nil, fmt.Errorf("policy.New: override references unknown rule %q", ov.RuleID)
		}
	}
	if err := validateRules(rules); err != nil {
		return nil, fmt.Errorf("policy.New: %w", err)
	}
	return &Engine{cfg: cfg, rules: rules, readsBudgetStamps: resolveReadsBudgetStamps(&cfg, rules)}, nil
}

// orgFloorIDs is the set of rule IDs the organization's policy layer
// defined (an ExtraRules row with Source == SourceOrg) or tuned (an Override
// with Source == SourceOrg). The org layer is escalate-only, so each is a
// strictness floor: no layer below the org may disable it or relax it
// (OSH-R-014). The org's internal budget override (SourceOrgBudget) carries
// the admin's own per-window mode and is not part of the floor.
func orgFloorIDs(cfg Config) map[string]bool {
	floor := map[string]bool{}
	for i := range cfg.ExtraRules {
		if cfg.ExtraRules[i].Source == SourceOrg {
			floor[cfg.ExtraRules[i].ID] = true
		}
	}
	for _, ov := range cfg.Overrides {
		if ov.Source == SourceOrg {
			floor[ov.RuleID] = true
		}
	}
	return floor
}

// overrideRelaxesOrgFloor reports whether ov, coming from below the org,
// would weaken row r: a strictly weaker decision than r's current enforce
// stance, or an explicit `enforce = false`. An org override (the floor's own
// author) and the org budget boundary are never refused here.
func overrideRelaxesOrgFloor(r *Rule, ov Override) bool {
	if ov.Source == SourceOrg || ov.Source == SourceOrgBudget {
		return false
	}
	return (ov.Decision != nil && *ov.Decision < r.Enforce) || ov.EnforceOff
}

// strongerPin keeps the most trusted layer that pinned a rule's
// decision: once the org layer pinned it, a later lower-trust override
// (which the guard merge only lets through when it escalates) does not
// take the org attribution away; otherwise the latest pin wins.
func strongerPin(current, next string) string {
	if current == SourceOrg {
		return current
	}
	return next
}

// applyOverride applies one override to one matching rule row.
func applyOverride(cfg Config, r *Rule, ov Override) {
	if ((ov.Decision != nil && *ov.Decision < r.Enforce) || ov.EnforceOff) &&
		overrideWeakensProtected(cfg, r, ov) {
		// A below-org override cannot WEAKEN a protected row: an
		// organization-authoritative hard budget, or one of the
		// guard's own integrity rules (R-160/R-161). An ESCALATION
		// still passes — a stricter decision is not < the current
		// enforce stance. An explicit `enforce = false` is a weakening
		// (Sol A2-06). This is a hard backstop; the guard merge layer
		// already drops these with a surfaced issue.
		return
	}
	pinBy := ov.Source
	if pinBy == "" {
		pinBy = SourceBuiltin
	}
	if ov.Decision != nil {
		r.Observe = *ov.Decision
		r.Enforce = *ov.Decision
		r.DecisionPinnedBy = strongerPin(r.DecisionPinnedBy, pinBy)
	}
	if ov.Enforced {
		r.Enforced = true
		r.EnforceCappedBy = ""
		r.DecisionPinnedBy = strongerPin(r.DecisionPinnedBy, pinBy)
	}
	if ov.EnforceOff {
		r.Enforced = false
		r.EnforceCappedBy = pinBy
		r.DecisionPinnedBy = ""
	}
	// Org-granted override (Track B): additive-only, "false
	// wins". A row only ever GAINS overridability, and only
	// from an org-layer override (guard/merge.go is the one
	// place that lets the key through).
	if ov.Overridable {
		r.Overridable = true
	}
	if ov.Source != "" {
		r.Source = ov.Source
	}
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
	rules = append(rules, subjectBudgetRules()...)
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
	if e == nil {
		return false
	}
	for i := range e.rules {
		if e.rules[i].ID != ruleID || e.rules[i].Enforce < DecisionDeny || e.rules[i].EnforceCappedBy != "" {
			continue
		}
		if protectedBudgetRule(e.cfg, &e.rules[i]) {
			return true
		}
	}
	return false
}

// SourceOrgBudget identifies the guard's internal per-window budget override.
// Policy files cannot author this source; their layer source is assigned by
// the guard parser.
const SourceOrgBudget = "org_budget"

// IsIntegrityRuleID reports whether id names one of the guard's own
// INTEGRITY rules: R-160, R-161, R-162 and R-165. It is a small, closed set:
//
//   - R-160 denies an agent modifying observer/guard/hook configuration,
//     which INCLUDES the ~/.observer trusted per-project policy dir. It is
//     the guard's own tamper-evidence, and the entire trusted-layer trust
//     model depends on it: the dashboard-authored trusted layer is a
//     weaken-allowed layer that is safe ONLY because it lives under
//     ~/.observer where R-160 keeps the agent out. Let R-160 be disabled or
//     relaxed for one project and an agent can write ~/.observer/** freely —
//     a global blast radius.
//   - R-161 flags an agent modifying the in-repo project guard file, the
//     escalate-only, agent-writable layer whose one-way trust the merge
//     model rests on.
//   - R-162 (T-910, widened deliberately) denies an agent turning a coding
//     agent's hooks off (disableAllHooks and its siblings). With a switch
//     on, the guard hooks themselves stop running, so a layer that relaxed
//     R-162 would let an agent remove every other rule at once.
//   - R-165 (D-761) denies an agent approving its own guard exception
//     (`observer guard approve`, the dashboard's approval routes, a direct
//     write into guard_approvals). A layer that relaxed it would let an
//     agent turn any block into a grant of its own, which removes every
//     other rule one call at a time. Its request row only flags and stays
//     a flag.
//
// None may be DISABLED or RELAXED by any layer BELOW the org (config,
// user, trusted-project); the org may still define or escalate them (the
// org layer is escalate-only anyway). Exported so the guard merge layer can
// enforce this floor at every below-org layer by ID without importing the
// rule rows. Widening this set is a deliberate edit, never an accident.
func IsIntegrityRuleID(id string) bool {
	return id == "R-160" || id == "R-161" || id == "R-162" || id == "R-165"
}

// protectedIntegrityRule reports whether THIS ROW is an integrity rule
// (R-160/R-161/R-162/R-165). It is the row-taking companion to IsIntegrityRuleID
// used by New's disable filter and override loop as a hard backstop: a
// below-org layer may never disable or weaken these, mirroring protectedBudgetRule
// but with no runtime provenance — the protection is intrinsic to the ID.
func protectedIntegrityRule(r *Rule) bool {
	return r != nil && IsIntegrityRuleID(r.ID)
}

// overrideWeakensProtected reports whether ov (which the caller has already
// checked carries a decision strictly weaker than r's enforce stance) targets
// a row no below-org layer may weaken: an organization-authoritative hard
// budget row (protectedBudgetRule — the internal org-budget soft-window
// override, SourceOrgBudget, is the one exception, as it carries the admin's
// own per-window mode) or one of the guard's own integrity rules
// (protectedIntegrityRule, R-160/R-161, which have no such exception because
// the org never weakens). Folding both weaken-backstops into one predicate
// keeps New's override loop a single branch.
func overrideWeakensProtected(cfg Config, r *Rule, ov Override) bool {
	if protectedIntegrityRule(r) {
		return true
	}
	return ov.Source != SourceOrgBudget && protectedBudgetRule(cfg, r)
}

// protectedBudgetRule reports whether THIS ROW is an organization-authorized
// blocking budget row: one a local [guard.rules].disable may not remove, a
// local override may not weaken, and the managed process-control pass may act
// on.
//
// IT TAKES A ROW, NOT AN ID (adversarial review of BUD-N, P2-5). Each subject
// ID ships TWO rows — a deny row that matches only caps the org authored HARD
// and a flag row that matches only SOFT ones — while BudgetProtection is per
// kind+unit. Asking by ID alone therefore protected the FLAG row of a soft cap
// as well, so an operator's `[guard.rules] disable = ["B-626"]` was silently
// ignored for a per-tool cap the admin had written as a nudge. Protection is
// the org's authority over a DENY, and a row that cannot deny carries none.
//
// HARDNESS IS READ OFF THE ROW'S OWN ENFORCE DECISION rather than a marker
// field, because that IS the distinction: subjectBudgetRules builds the hard
// half with Enforce=deny and the soft half with Enforce=flag, and no subject
// row is ever swept up by the [guard.budget].hard blanket upgrade (New exempts
// them for the same reason this function exists).
func protectedBudgetRule(cfg Config, r *Rule) bool {
	if r == nil {
		return false
	}
	if r.ID == "B-625" {
		return cfg.BudgetRequired
	}
	if subjectBudgetRuleID(r.ID) {
		// A SUBJECT row's hardness is the ORGANIZATION's, per cap — the same
		// reason it is exempt from the [guard.budget].hard blanket upgrade in
		// New. Gating its protection on the node's own hard flag would let a
		// developer un-protect a cap the org authored hard by clearing one
		// local key, which is exactly the shape B-625 already refuses.
		// BudgetProtection is set only for an ORG-AUTHORITATIVE hard cap
		// (internal/orgbudget.SubjectProtection), so a lowering-only node's own
		// tightening still authorizes nothing.
		if r.Enforce < DecisionDeny {
			return false
		}
		return cfg.BudgetProtection.ProtectsRule(r.ID)
	}
	if !cfg.BudgetHard {
		return false
	}
	return cfg.BudgetProtection.ProtectsRule(r.ID)
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

// EvaluateRule evaluates only the rows whose ID is ruleID, under the
// engine's mode, disables and overrides. The guard layer uses it for a
// signal that rides beside another verdict on the same action (A-613 after
// the deny it follows), which full evaluation would hide behind the
// stricter row.
func (e *Engine) EvaluateRule(ruleID string, ev Event) Verdict {
	allow := Verdict{Decision: DecisionAllow, Source: SourceBuiltin}
	if e == nil || e.cfg.Mode == ModeOff {
		return allow
	}
	ctx := e.buildContext(&ev)
	best := allow
	for i := range e.rules {
		r := &e.rules[i]
		if r.ID != ruleID || !r.appliesTo(ev.Kind) {
			continue
		}
		hit, detail, capped := applyRuleCeiling(r, ctx)
		if !hit {
			continue
		}
		if v := capUncalled(e.verdictFor(r, detail), capped); stricter(v, best) {
			best = v
		}
	}
	return best
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
		if managedOnly && !protectedBudgetRule(e.cfg, r) {
			continue
		}
		if !r.appliesTo(ev.Kind) {
			continue
		}
		hit, detail, capped := applyRuleCeiling(r, ctx)
		if !hit {
			continue
		}
		v := capUncalled(e.verdictFor(r, detail), capped)
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
		if protectedBudgetRule(e.cfg, r) && r.Enforce >= DecisionDeny {
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
		if !protectedBudgetRule(e.cfg, r) {
			continue
		}
		if e.ruleDecision(r) >= DecisionDeny {
			return true
		}
	}
	return false
}

func budgetAdmissionRuleID(id string) bool {
	switch id {
	case "B-601", "B-602", "B-603", "B-604",
		"B-610", "B-611", "B-612", "B-613",
		"B-621", "B-622", "B-623", "B-624", "B-625",
		// The per-tool / per-model subject caps (bundle BUD-N). They are
		// admission rows for the same reason their node-wide siblings are:
		// the proxy request path is the one channel that can refuse, and a
		// cap the org authored for one tool must bite there.
		"B-626", "B-627", "B-628", "B-629":
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
			if alt := ev.AltDialect; alt != "" && normDialect(alt) != normDialect(ev.Dialect) {
				// A second reading only ADDS units: every rule sees what
				// the command means under either shell.
				altCmds := ParseCommand(ev.Target, alt)
				for i := range altCmds {
					altCmds[i].altReading = true
				}
				ctx.Cmds = append(ctx.Cmds, altCmds...)
			}
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
	hit, detail, _ := applyRuleCeiling(r, ctx)
	return hit, detail
}

// applyRuleCeiling is applyRule that also reports whether the hit came
// only from units that run solely if a later command calls the function
// whose body holds them (Command.uncalledDef, T-525 / D-338): such a hit
// is capped at ASK by the caller. A hit on a unit that can run wins over
// a capped one, so the cap never hides a real hit later in the line.
//
// When the event carries a second reading (Event.AltDialect), its units
// are asked first, so the reason quotes the command as the alternate shell
// reads it. The boundary asks for a second reading only when the host's own
// shell may be the alternate one (a Windows working directory: PowerShell),
// whose lexer keeps a Windows path's backslashes; the POSIX reading of
// `C:\Users\dev` is `C:Usersdev` (WINNODE item 2). The order changes only
// which hit names the reason: a hit in any unit is a hit, and the cap applies
// only when no runnable unit hits, in either order.
func applyRuleCeiling(r *Rule, ctx *MatchContext) (hit bool, detail string, capped bool) {
	if r.MatchCmd != nil {
		capHit, capDetail := false, ""
		for _, alt := range [2]bool{true, false} {
			for i := range ctx.Cmds {
				cmd := &ctx.Cmds[i]
				if cmd.altReading != alt || anySafe(r.SafePat, ctx, cmd) {
					continue
				}
				ok, d := r.MatchCmd(ctx, cmd)
				if !ok {
					continue
				}
				if cmd.uncalledDef == "" {
					return true, d, false
				}
				if !capHit {
					capHit = true
					capDetail = d + " (inside function " + cmd.uncalledDef + ", which this command defines but does not call)"
				}
			}
		}
		return capHit, capDetail, capHit
	}
	if anySafe(r.SafePat, ctx, nil) {
		return false, "", false
	}
	hit, detail = r.Match(ctx)
	if !hit {
		return false, "", false
	}
	// An event-scoped rule reads every unit at once, so it is asked again
	// over the units that can run; only a hit that needs an uncalled body
	// is capped.
	runnable := make([]Command, 0, len(ctx.Cmds))
	for i := range ctx.Cmds {
		if ctx.Cmds[i].uncalledDef == "" {
			runnable = append(runnable, ctx.Cmds[i])
		}
	}
	if len(runnable) == len(ctx.Cmds) {
		return true, detail, false
	}
	sub := *ctx
	sub.Cmds = runnable
	if h, d := r.Match(&sub); h {
		return true, d, false
	}
	return true, detail + " (inside a function this command defines but does not call)", true
}

// capUncalled lowers a verdict drawn only from an uncalled function body
// to ASK (D-338); a lower decision is kept.
func capUncalled(v Verdict, capped bool) Verdict {
	if capped && v.Decision > DecisionAsk {
		v.Decision = DecisionAsk
	}
	return v
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
	d := e.ruleDecision(r)
	reason := r.Doc
	if detail != "" {
		reason += ": " + detail
	}
	source := r.Source
	if source == "" {
		source = SourceBuiltin
	}
	return Verdict{
		Decision:    d,
		RuleID:      r.ID,
		Severity:    r.Severity,
		Reason:      reason,
		Advice:      r.Advice,
		Source:      source,
		Overridable: r.Overridable,

		EnforceCappedBy:  r.EnforceCappedBy,
		DecisionPinnedBy: r.DecisionPinnedBy,
	}
}

// ruleDecision is the ONE mode-to-decision selection for a rule row: the
// observe decision, or the enforce decision in enforce mode or for a
// per-rule-enforced row, then capped at FLAG when an explicit
// `enforce = false` override capped the row (D-030, Sol A2-06).
func (e *Engine) ruleDecision(r *Rule) Decision {
	d := r.Observe
	if e.cfg.Mode == ModeEnforce || r.Enforced {
		d = r.Enforce
	}
	if r.EnforceCappedBy != "" && d > DecisionFlag {
		d = DecisionFlag
	}
	return d
}

// RuleStances returns, for every row carrying ruleID, the stance a match
// would take before any event-specific detail: the mode-selected decision,
// the overridable bit and the layer that pinned it. The guard's gate
// posture reads it so an org-pinned prompt-rule floor counts as enforcing
// even when the local [guard.prompt] mode alone would not (integration
// security review, 2026-10-15). Empty for an unknown rule or a nil engine.
func (e *Engine) RuleStances(ruleID string) []Verdict {
	if e == nil || ruleID == "" {
		return nil
	}
	var out []Verdict
	for i := range e.rules {
		r := &e.rules[i]
		if r.ID != ruleID {
			continue
		}
		out = append(out, Verdict{
			Decision: e.ruleDecision(r), RuleID: r.ID, Severity: r.Severity,
			Overridable: r.Overridable, EnforceCappedBy: r.EnforceCappedBy, DecisionPinnedBy: r.DecisionPinnedBy,
		})
	}
	return out
}

// RuleEnforceDenies reports whether some row carrying ruleID would deny in
// enforce mode (its enforce decision is deny and no `enforce = false`
// override caps it). The A-613 evasion tracker reads it so a flag in
// observe mode from a rule that enforce would deny counts as a refusal
// (plans decision log P-004). False for an unknown rule or a nil engine.
func (e *Engine) RuleEnforceDenies(ruleID string) bool {
	if e == nil || ruleID == "" {
		return false
	}
	for i := range e.rules {
		r := &e.rules[i]
		if r.ID == ruleID && r.Enforce == DecisionDeny && r.EnforceCappedBy == "" {
			return true
		}
	}
	return false
}

// RuleEnforceCapped reports whether every row with ruleID is capped at
// FLAG by an explicit `enforce = false` override (false when no row has
// the ID). Seams that decide from a rule ID without an evaluated verdict
// (the gate posture, the unscanned-prompt fallback) read it.
func (e *Engine) RuleEnforceCapped(ruleID string) bool {
	if e == nil || ruleID == "" {
		return false
	}
	found := false
	for i := range e.rules {
		if e.rules[i].ID != ruleID {
			continue
		}
		if e.rules[i].EnforceCappedBy == "" {
			return false
		}
		found = true
	}
	return found
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
