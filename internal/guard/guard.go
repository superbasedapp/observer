package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// GuardErrorRuleID is the synthetic rule ID stamped on verdicts (and
// audit rows) produced by the Q2 failure wrapper instead of a real
// evaluation — a recovered panic or a degraded policy layer. It is
// not a catalog rule; dashboards and the CLI treat it as a guard
// health signal.
const GuardErrorRuleID = "guard_error"

// maxProjectEngines bounds the per-project engine cache. Projects per
// daemon are typically O(10); the bound only guards against a
// pathological watcher feeding thousands of synthetic roots. On
// overflow new roots evaluate with the base engine (correct, minus
// any project-layer escalations for those roots).
const maxProjectEngines = 64

// Options configures Guard construction. All I/O inputs (home dir,
// known roots) are resolved by the caller — composition stays at the
// cmd layer.
type Options struct {
	// Config is the loaded [guard] section.
	Config config.GuardConfig
	// Home is the daemon user's home directory (native path flavor),
	// used for "~" expansion in policy paths and pattern matching.
	Home string
	// KnownProjectRoots is the daemon's observed-project root set —
	// R-151's cross-project-bleed reference. Snapshot at
	// construction; projects created later join on the next daemon
	// start (documented approximation; engines are cheap but the
	// set's churn doesn't justify a live feed in G3).
	KnownProjectRoots []string
	// ReadFile overrides policy-file reading in tests. Nil means
	// os.ReadFile.
	ReadFile func(path string) ([]byte, error)
	// OnPolicyState, when non-nil, is invoked once per successfully
	// loaded policy layer — including project layers that load
	// LAZILY on first event for their root, which a one-shot
	// PolicyStates() poll at startup would miss. The cmd composition
	// wires it to store.RecordGuardPolicyState (the §14.4
	// policy-change log); guard itself never touches the store.
	// Called outside guard locks; implementations may do I/O but
	// must not call back into the Guard.
	OnPolicyState func(PolicyState)
	// Notifier, when non-nil, receives desktop alerts for verdicts
	// meeting the [guard.alerts] threshold (MaybeAlert). The cmd
	// composition wires guard/notify.Desktop; nil disables alerting
	// (tests, alerts.desktop=false).
	Notifier Notifier
	// OrgKeyPinHash, when non-empty, is the sha256 hex of the org
	// policy public key pinned at enrolment
	// (orgcontract.PublicKeyPinHash; the guard_policy_state key-pin
	// row). The org bundle loader then requires the cached envelope's
	// embedded key to match the pin in addition to the self-contained
	// signature check. The daemon composition (guardwire) reads the
	// pin from the store and sets this; hook processes leave it empty
	// — they still verify the envelope's signature against its
	// embedded key (catching corruption and casual tampering) but
	// skip the pin comparison rather than pay a DB open before the
	// hook reply (§6.4). The wire seam (orgclient fetch) is where
	// untrusted bytes enter and ALWAYS pin-checks before writing the
	// cache, so a hook process only ever reads a file that already
	// passed the full check once.
	OrgKeyPinHash string
	// ManagedTenancy, when non-nil, reports whether this node runs
	// under Enterprise-Managed Tenancy (govern.Effective.Managed -
	// managed-class consent on the org's SIGNED enrolment grant). It
	// is the tenancy half of the org lock (override.go / engineSet.
	// orgLocksRule):
	//
	//   - true  - the organization is authoritative here, so every
	//     rule an applied org bundle does not mark `overridable` is
	//     org-locked, named by the bundle or not (the enterprise
	//     ruling).
	//   - false - an individual node. An org bundle is a FLOOR: it
	//     locks the rules it NAMES, and every other rule keeps the
	//     node's own §6.3 approvals (CLAUDE.md's lowering-only posture
	//     for the individual plane).
	//   - nil   - tenancy UNRESOLVED in this process. The lock stays
	//     as wide as it was before this seam existed (every rule under
	//     an applied bundle): a short-lived process that cannot afford
	//     the read must never be the one that WIDENS what a developer
	//     may approve. Wire it wherever the answer is cheap - the
	//     daemon composition (cmd/observer/guardwire.go) and the node
	//     dashboard both do.
	//
	// It is a func, not a bool, because tenancy is durable state that
	// can change under a long-lived daemon (an enrolment mid-run), so
	// implementations are expected to cache rather than to be cheap.
	// Called only on the rare blocking path and on read surfaces,
	// never on the allow path.
	ManagedTenancy func() bool
}

// Notifier is the alert channel seam (guard spec §3.1: notify owns
// all alerting). Implementations must be best-effort and non-blocking
// in spirit — MaybeAlert is called off hot paths (after replies /
// persists), but a notifier still must not hang its caller.
type Notifier interface {
	Notify(title, body string)
}

// PolicyState describes one loaded policy layer for the §14.4
// policy-change log. The caller (cmd composition) persists these via
// store.RecordGuardPolicyState — guard does not import store.
type PolicyState struct {
	// Layer is "user", "project" or "org".
	Layer string
	// Path is the source file location (the bundle cache path for the
	// org layer).
	Path string
	// Version is the org bundle version for the org layer; empty for
	// local file layers (they have no version concept beyond the
	// content hash).
	Version string
	// ContentHash is the sha256 hex of the policy source bytes — for
	// the org layer that is the bundle TOML itself, not the envelope,
	// so the hash lines up with the fetch-time row the org client
	// records.
	ContentHash string
	// Notes are non-fatal parse notes, e.g. org-bundle keys this
	// binary does not understand and ignored. The layer IS loaded and
	// in force — a note is not a LoadIssue. Empty for a clean layer.
	Notes []string
}

// Guard is the composition root: engines + taint tracker + failure
// wrapper. Safe for concurrent use (immutable engines; mutex-guarded
// caches and trackers).
type Guard struct {
	cfg      config.GuardConfig
	home     string
	roots    []string
	readFile func(string) ([]byte, error)

	// managedTenancy is Options.ManagedTenancy behind an
	// atomic.Pointer so SetManagedTenancy can wire (or re-wire) it
	// after construction without racing the hot paths that read it.
	// A nil pointer means "tenancy unresolved in this process" - see
	// Options.ManagedTenancy for what that deliberately implies.
	managedTenancy atomic.Pointer[func() bool]

	// projectRootForSession is the injected session-to-project
	// resolver (approvals.go: SessionProjectRootLookup). nil on every
	// lane that already carries a ProjectRoot on its events.
	projectRootForSession SessionProjectRootLookup

	// onPolicyState is Options.OnPolicyState (may be nil).
	onPolicyState func(PolicyState)

	// set holds the ENTIRE org-derived engine snapshot behind ONE
	// atomic.Pointer (P0-7 hot-reload): the base engine, the parsed
	// org + user layers, the builtin/org/user layer states + rule
	// categories, and the per-snapshot lazy project-engine cache.
	// Every hot-path read Loads it lock-free; ReloadOrgLayer builds a
	// FRESH engineSet against a re-verified org bundle and Stores it,
	// so an accepted org policy applies to the LIVE decision engine
	// in-process with no daemon restart. In-flight Evaluate calls keep
	// the snapshot they Loaded (a consistent view); the swapped-in set
	// starts with an empty project cache that rebuilds lazily against
	// the new org layer.
	set atomic.Pointer[engineSet]
	// effBudget holds the EFFECTIVE [guard.budget] numbers behind an
	// atomic.Pointer, exactly as `set` holds the engine snapshot. nil means
	// "the numbers this Guard was constructed with" (cfg.Budget), which is
	// byte-identical to a build that never had the org budget rail.
	//
	// It exists because the org's per-caller budget arrives LATER than
	// construction (on the push cycle) and may change without a restart, and
	// because buildEngine is the ONE funnel every engine rebuild goes through
	// — the project-layer build (engineset.go), the org-bundle reload
	// (ReloadOrgLayer) and New all call it. Reading the numbers HERE rather
	// than capturing them at construction is what keeps a rebuild from
	// silently reverting to the node's own looser ceilings.
	// See ApplyOrgBudget in orgbudget.go.
	effBudget atomic.Pointer[config.GuardBudgetConfig]
	// effBudgetSoft is the PER-WINDOW half of effBudget: the budget windows
	// whose breach must stay a flag even while effBudget.Hard is on, because
	// the org authored THAT period as soft/report (review fix round 2,
	// MEDIUM-3). nil / empty is one uniform posture, which is what every
	// purely local node and every single-period org budget composes to.
	// Published and read exactly like effBudget, and consumed in the same one
	// place — buildEngine, so a later rebuild cannot revert to the fold.
	// See budgetSoftOverrides in orgbudget.go.
	effBudgetSoft atomic.Pointer[[]string]
	// effBudgetRequired is the FAIL-CLOSED half of the composition (org-budget
	// ruling R2): this node is managed, its organization holds enforce.budget,
	// and no verified org budget body has ever been applied here, so every
	// proxied request must be refused.
	//
	// It rides beside effBudget rather than inside it because
	// config.GuardBudgetConfig is an operator-authored TOML block and this is
	// not a key an operator may author — the same reason effBudgetSoft is its
	// own field. Read in ONE place, buildEngine, so a later rebuild cannot
	// revert to running unbudgeted. See ApplyOrgBudget in orgbudget.go.
	effBudgetRequired atomic.Bool
	// effBudgetProtection carries authority provenance for each effective hard
	// budget unit and window. A preserved local ceiling remains false even when
	// another ceiling came from a managed organization's enforce.budget grant.
	// It is runtime state rather than a user-configurable [guard.budget] field.
	effBudgetProtection atomic.Pointer[policy.BudgetProtection]
	// effBudgetBinding identifies the exact enrollment epoch that published
	// effBudgetProtection. Native process intervention supplies a binding from
	// its fresh authority read and may use numeric caps only when it matches.
	effBudgetBinding   atomic.Pointer[string]
	effBudgetCalendars atomic.Pointer[BudgetCalendars]
	// effBudgetSubjects / effBudgetBaseline are the org's PER-TOOL and
	// PER-MODEL caps and the CROSS-MACHINE spend baseline (bundle BUD-N),
	// published by ApplyOrgBudgetSubjects and read in the same two places
	// everything else on this rail is: buildEngine (the caps, so a later
	// rebuild cannot revert them) and stampBudget (the baseline, so every
	// budget row compares against one consistent pair).
	//
	// They ride beside effBudget rather than inside it for the same reason
	// effBudgetSoft does: config.GuardBudgetConfig must stay exactly the
	// operator's own [guard.budget] block, and neither of these is a key an
	// operator may author.
	effBudgetSubjects atomic.Pointer[[]policy.BudgetSubjectCap]
	effBudgetBaseline atomic.Pointer[policy.BudgetWindowAmounts]
	// effBudgetBaselineFlagOnly says the published baseline may WARN and may
	// not deny (orgcontract.BudgetBaselineAppliedFlagOnly): the org counted
	// rows it could not attribute to a machine, so the number may overlap this
	// node's own spend. Its own field rather than a member of
	// policy.BudgetWindowAmounts because that type is ALSO the per-tool and
	// per-model usage shape, where the flag would mean nothing.
	effBudgetBaselineFlagOnly atomic.Bool
	// effBudgetSubjectUnmatched records that a published per-tool / per-model
	// cap's id did not appear in the accounting keys of the last full
	// accounting pass — the cap is in force and biting nothing on this node. It
	// is an OBSERVATION, written by the budget stamp and read only by the
	// posture boundary; nothing in the decision path consults it.
	effBudgetSubjectUnmatched atomic.Bool
	// budgetSubjectResolver folds a captured tool/model id onto the identity
	// the org's subject caps were composed onto. Installed ONCE at composition
	// (SetBudgetSubjectResolver), like budgetLookup; nil means the plain
	// trim+lowercase normalisation, which is what a hook process and a node
	// with no price table both get.
	budgetSubjectResolver func(kind, id string) string
	// reloadMu serializes ReloadOrgLayer construct+publish so a
	// concurrent reload can never publish an OLDER snapshot over a
	// newer one (the production caller is single-threaded — the mutex
	// is defensive and makes the concurrency test honest).
	reloadMu sync.Mutex
	// orgKeyPinHash + orgBundlePath are IMMUTABLE after New — the
	// re-verification inputs ReloadOrgLayer feeds back through the
	// SAME §14.2 acceptance path (signature + optional key pin) New
	// used, so a reload verifies identically to construction.
	orgKeyPinHash string
	orgBundlePath string

	// mu guards issues only — the engine snapshot (base, layers,
	// project cache, states, categories) lives behind g.set.
	mu     sync.Mutex
	issues []string

	taint *taintTracker

	// egressAllow are the compiled [guard.proxy].egress_allow value
	// patterns (proxyguard.go); invalid patterns degrade to LoadIssues.
	egressAllow []*regexp.Regexp
	// proxyMu guards proxySeen, the proxy seam's per-session
	// record-dedup state (proxyguard.go). Separate from mu: the proxy
	// hot path must never contend with engine-cache loads.
	proxyMu   sync.Mutex
	proxySeen map[string]*proxySeen

	// notifier + alertMin implement [guard.alerts] (MaybeAlert).
	notifier Notifier
	alertMin policy.Severity

	// approvals is the §6.3 grant lookup (SetApprovalLookup); nil =
	// no approvals, every blocking verdict enforces.
	approvals ApprovalLookup

	// promptAllow are the compiled [guard.prompt].allow value patterns
	// (promptguard.go), analogous to egressAllow but a distinct config
	// key — a finding an operator has allowlisted for the prompt-
	// submit channel is not necessarily allowlisted for proxy egress
	// and vice versa. Invalid patterns degrade to LoadIssues.
	promptAllow []*regexp.Regexp
	// promptReconsider is the reconsider-once persistence seam
	// (SetPromptReconsiderStore; promptguard.go) — guard never imports
	// store, mirroring ApprovalLookup. Zero value (all three funcs
	// nil) fails CLOSED: every ask-once/redact finding behaves as
	// block until the store seam is wired (prompt-submit-intervention
	// spec §5.4/§10 item 5 — never a silent allow).
	promptReconsider PromptReconsiderFuncs

	// mcpPins is the §9.2 pin-status lookup (SetMCPPinLookup); nil =
	// every MCP server marks mcp_unpinned taint (the G3 baseline).
	mcpPins MCPPinLookup
	// watches are the watched-config-path triggers — ONE mechanism
	// with two consumers (the §9.2 MCP re-scan and the §13.2 dialect
	// drift check), keyed by consumer tag. Registered once at
	// composition (SetMCPRescan / SetDialectRescan) before traffic;
	// read on the ingest path (mcp.go maybeConfigRescan).
	watches map[string]configWatch

	// Budget state (§12.1, budget.go): the injected spend lookup, its
	// TTL cache, and the once-per-session flag-record dedup.
	budgetLookup BudgetAccountingLookup
	// budgetBindingLookup resolves the current enrollment epoch for proxy
	// admission. Native intervention supplies the same fact explicitly after
	// its authority read; proxy requests need this local-store seam so an
	// external re-enrollment immediately invalidates the prior engine binding.
	budgetBindingLookup BudgetBindingLookup
	budgetMu            sync.Mutex
	budgetCache         map[string]budgetEntry
	budgetRecorded      map[string]map[string]bool
	// repeats is the A-610 consecutive-identical tracker (§12.2,
	// repeat.go) feeding Event.RepeatCount on the ingest path.
	repeats repeatTracker
}

// New constructs a Guard from the loaded configuration. Construction
// is deliberately tolerant of POLICY-FILE problems (a malformed user
// policy degrades to built-ins with the issue recorded — the daemon
// must never refuse to start over a policy typo; `observer guard
// lint` is the strict checker) but strict about CONFIG problems
// (unknown mode strings error: that's an operator typo in
// config.toml, the same class the config loader rejects).
func New(opts Options) (*Guard, error) {
	mode, err := policy.ParseMode(modeOrDefault(opts.Config.Mode))
	if err != nil {
		return nil, fmt.Errorf("guard.New: %w", err)
	}
	g := &Guard{
		cfg:           opts.Config,
		home:          opts.Home,
		roots:         opts.KnownProjectRoots,
		readFile:      opts.ReadFile,
		onPolicyState: opts.OnPolicyState,
		orgKeyPinHash: opts.OrgKeyPinHash,
		orgBundlePath: OrgBundlePath(opts.Config, opts.Home),
		taint:         newTaintTracker(opts.Config.Taint),
		watches:       make(map[string]configWatch),
	}
	if g.readFile == nil {
		g.readFile = os.ReadFile
	}
	if opts.ManagedTenancy != nil {
		g.SetManagedTenancy(opts.ManagedTenancy)
	}
	// [guard.alerts].min_severity: parse once; an empty/unknown value
	// falls back to the documented "high" default (the config loader
	// validates the field, so unknown only happens on hand-built
	// Options in tests).
	g.alertMin = policy.SeverityHigh
	if s, err := policy.ParseSeverity(opts.Config.Alerts.MinSeverity); err == nil {
		g.alertMin = s
	}
	if opts.Config.Alerts.Desktop {
		g.notifier = opts.Notifier
	}
	// [guard.proxy].egress_allow: compile once; bad patterns degrade
	// (skipped + recorded) per the policy-file failure posture.
	var allowIssues []string
	g.egressAllow, allowIssues = compileEgressAllow(opts.Config.Proxy.EgressAllow)
	g.issues = append(g.issues, allowIssues...)

	// [guard.prompt].allow: compile once, same degrade-on-bad-pattern
	// posture as egress_allow above.
	var promptAllowIssues []string
	g.promptAllow, promptAllowIssues = compilePromptAllow(opts.Config.Prompt.Allow)
	g.issues = append(g.issues, promptAllowIssues...)

	// Layers are accumulated into LOCALS (not g fields) and sealed
	// into the initial engineSet at the end — the snapshot is the one
	// owner of the engine state (P0-7).
	var orgLayer, userLayer *policyFile
	var states []PolicyState

	// Org layer (G13): read + verify + parse the locally cached,
	// signed policy bundle. Absence is normal (not enrolled, no
	// bundle published, or pre-G13 server); every failure degrades to
	// local-only policy with the issue recorded — the §14.2 compat
	// posture mirrors the user-layer failure posture below.
	if g.orgBundlePath != "" {
		pf, st, issue, loaded := g.parseOrgBundle(g.orgBundlePath, opts.OrgKeyPinHash)
		if issue != "" {
			g.issues = append(g.issues, issue)
		}
		if loaded {
			orgLayer = pf
			states = append(states, st)
		}
	}

	// User layer: read + parse the configured policy file. Absence
	// is normal (no user policy); a read/parse failure degrades to
	// built-ins with the issue recorded (doc.go failure posture).
	userPath := UserPolicyPath(opts.Config, opts.Home)
	if userPath != "" {
		raw, err := g.readFile(userPath)
		switch {
		case err == nil:
			pf, perr := parsePolicyFile(raw, layerUser)
			if perr != nil {
				g.issues = append(g.issues, fmt.Sprintf("user policy %s: %v", userPath, perr))
			} else {
				userLayer = pf
				states = append(states, PolicyState{Layer: layerUser, Path: userPath, ContentHash: sha256hex(raw)})
			}
		case os.IsNotExist(err):
			// no user policy — built-ins only
		default:
			g.issues = append(g.issues, fmt.Sprintf("user policy %s: %v", userPath, err))
		}
	}

	base, err := g.buildEngine(mode, orgLayer, userLayer, nil)
	if err != nil {
		// A layer that breaks ENGINE construction (e.g. an override
		// on an unknown rule) degrades the same way a parse failure
		// does: drop the offending layer, keep the innocent one.
		// Isolate the culprit by retrying without org, then without
		// user, then without both — the first combination that builds
		// wins, and every dropped layer records an issue (and its
		// state, so PolicyStates never reports a dropped layer).
		firstErr := err
		built := false
		if orgLayer != nil {
			if b, e := g.buildEngine(mode, nil, userLayer, nil); e == nil {
				g.issues = append(g.issues, fmt.Sprintf("org policy layer dropped: %v", firstErr))
				orgLayer, base, built = nil, b, true
				states = dropLayerState(states, layerOrg)
			}
		}
		if !built && userLayer != nil {
			if b, e := g.buildEngine(mode, orgLayer, nil, nil); e == nil {
				g.issues = append(g.issues, fmt.Sprintf("user policy layer dropped: %v", firstErr))
				userLayer, base, built = nil, b, true
				states = dropLayerState(states, layerUser)
			}
		}
		if !built {
			if orgLayer != nil || userLayer != nil {
				g.issues = append(g.issues, fmt.Sprintf("org+user policy layers dropped: %v", firstErr))
			}
			orgLayer, userLayer, states = nil, nil, nil
			b, e := g.buildEngine(mode, nil, nil, nil)
			if e != nil {
				return nil, fmt.Errorf("guard.New: built-in engine: %w", e)
			}
			base = b
		}
	}

	g.set.Store(newEngineSet(base, orgLayer, userLayer, states, buildRuleCategories(orgLayer, userLayer), g.budgetBinding(), g.budgetCalendars()))

	// Fire OnPolicyState for the SURVIVING layer states (a dropped
	// layer is never reported as loaded). Project layers load lazily
	// and fire from engineFor.
	if g.onPolicyState != nil {
		for i := range states {
			g.onPolicyState(states[i])
		}
	}
	return g, nil
}

// modeOrDefault maps an empty config mode to the D2 default.
func modeOrDefault(s string) string {
	if strings.TrimSpace(s) == "" {
		return string(policy.ModeObserve)
	}
	return s
}

// buildEngine assembles a policy.Engine from config + the passed org +
// user layers + an optional project layer, applying the §4.6 one-way
// layering merge (org floor on top). The layers are PARAMETERS (not g
// fields) so New, ReloadOrgLayer, and the per-snapshot project-engine
// build all funnel through this one seam against an explicit layer set
// (B3 — no hidden read of mutable guard state).
func (g *Guard) buildEngine(mode policy.Mode, org, user, project *policyFile) (*policy.Engine, error) {
	extra, overrides, mergeIssues := mergeLayers(org, user, project)
	g.recordIssues(mergeIssues)
	// The EFFECTIVE budget, not g.cfg.Budget: an org-composed ceiling applied
	// through ApplyOrgBudget must survive every later engine rebuild (project
	// layer, org-bundle reload). Falls back to the constructed config when
	// nothing has been applied.
	budget := g.budgetConfig()
	// The per-window half of that budget: BudgetHard below upgrades EVERY
	// CategoryBudget row to deny, so the windows the org authored as
	// soft/report are held back at flag by an override appended AFTER the
	// layer overrides (policy.New applies overrides in order, last wins).
	// Empty on every node with one uniform posture. See ApplyOrgBudget.
	budgetSoft := g.budgetSoftOverrides()
	// Boundary slices pass through as-is: nil (section absent) lets
	// the engine defaults apply; an explicitly-empty TOML list means
	// "none" — the decoder already produces exactly this distinction.
	return policy.New(policy.Config{
		Mode:              mode,
		Home:              g.home,
		AllowPaths:        g.cfg.Boundary.AllowPaths,
		ProtectedBranches: g.cfg.Boundary.ProtectedBranches,
		KnownProjectRoots: g.roots,
		Disabled:          g.cfg.Rules.Disable,
		ExtraRules:        extra,
		Overrides:         appendOverrides(overrides, budgetSoft),
		// [guard.budget] (§12.1): thresholds for the B-601..B-604 $ rows;
		// hard upgrades their enforce-mode decision to deny. The
		// [guard.budget.window] utilization thresholds feed the
		// B-610..B-613 limit rows (CategoryLimit — untouched by hard).
		BudgetSessionUSD: budget.SessionUSD,
		BudgetDailyUSD:   budget.DailyUSD,
		BudgetWeeklyUSD:  budget.WeeklyUSD,
		BudgetMonthlyUSD: budget.MonthlyUSD,
		// The TOKEN ceilings (B-621..B-624), the same four windows in the
		// other unit — an org budget is authored in tokens because a token
		// cap needs no rate card (org-budget plan R3).
		BudgetSessionTokens: budget.SessionTokens,
		BudgetDailyTokens:   budget.DailyTokens,
		BudgetWeeklyTokens:  budget.WeeklyTokens,
		BudgetMonthlyTokens: budget.MonthlyTokens,
		// The organization's per-tool / per-model caps (B-626..B-629). Read
		// here, in the one rebuild funnel, so a project layer loading lazily
		// cannot silently drop a cap the org authored.
		BudgetSubjectCaps: g.budgetSubjectCaps(),
		BudgetHard:        budget.Hard,
		BudgetProtection:  g.budgetProtection(),
		// The fail-closed row (B-625): armed only by an org-composed posture
		// that says this managed node may not run without the organization's
		// budget. Zero on every individual node.
		BudgetRequired:      g.effBudgetRequired.Load(),
		LimitUtil5hWarn:     budget.Window.Util5hWarn,
		LimitUtil5hDeny:     budget.Window.Util5hDeny,
		LimitUtilWeeklyWarn: budget.Window.UtilWeeklyWarn,
		LimitUtilWeeklyDeny: budget.Window.UtilWeeklyDeny,
		// R-172's shell-arg row runs the typed certain-only detector
		// (Module rule 1: scrub arrives as an injected func — policy
		// imports zero observer packages).
		SecretDetect: scrub.CertainSecretTypes,
	})
}

// recordIssues appends load-time issues under the Guard's lock.
func (g *Guard) recordIssues(issues []string) {
	if len(issues) == 0 {
		return
	}
	g.mu.Lock()
	g.issues = append(g.issues, issues...)
	g.mu.Unlock()
}

// LoadIssues returns the policy-load problems recorded so far (parse
// failures, dropped relaxation attempts). The caller logs them and
// emits a guard_error audit row per issue.
func (g *Guard) LoadIssues() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, len(g.issues))
	copy(out, g.issues)
	return out
}

// PolicyStates returns the loaded policy-layer descriptors for the
// §14.4 policy-change log (persisted by the caller through
// store.RecordGuardPolicyState). Read off the live snapshot: after a
// successful ReloadOrgLayer the org entry carries the just-accepted
// version + hash (the pair guardRunningFromGuard reads).
func (g *Guard) PolicyStates() []PolicyState {
	return g.set.Load().policyStates()
}

// Mode returns the active global mode.
func (g *Guard) Mode() policy.Mode { return g.set.Load().base.Mode() }

// RuleCount returns the base engine's active rule-row count (status
// surfaces).
func (g *Guard) RuleCount() int { return g.set.Load().base.RuleCount() }

// MaybeAlert fires a desktop notification for a verdict that meets
// the [guard.alerts] threshold (desktop enabled at construction +
// severity >= min_severity + an actual rule hit). Called by the
// persistence sites AFTER replies/persists — never on the latency-
// critical half of a hot path. Best-effort by the Notifier contract.
//
// Volume note: the default min_severity "high" keeps this to the
// rare verdicts worth interrupting a human for; if the P0 soak shows
// alert fatigue the threshold (not this mechanism) is the knob.
func (g *Guard) MaybeAlert(v ActionVerdict) {
	if g.notifier == nil || v.Verdict.RuleID == "" {
		return
	}
	// GuardError bypasses BOTH gates below — a genuine evaluation
	// failure is always worth surfacing regardless of severity or a
	// channel's own "already shown in-band" suppression (FIX-3).
	if !v.GuardError {
		if v.SuppressAlert {
			return
		}
		// Track B: an ENFORCED deny of an org-OVERRIDABLE rule always
		// interrupts, whatever its severity — the developer can take
		// this one, but only if they are told it happened and how. A
		// hard deny keeps today's severity gate.
		if !alertsRegardlessOfSeverity(v) && v.Verdict.Severity < g.alertMin {
			return
		}
	}
	title := "Observer Guard: " + v.Verdict.RuleID + " " + v.Verdict.Decision.String()
	body := v.Verdict.Reason
	if v.Input.Tool != "" {
		body = v.Input.Tool + ": " + body
	}
	if line := HumanBlockLine(v, v.Input.SessionID); line != "" {
		body = line
	}
	g.notifier.Notify(title, body)
}

// alertsRegardlessOfSeverity is the one-row exception table to the
// [guard.alerts].min_severity gate: an enforced deny of a rule the
// organization marked overridable. Every other verdict — including a
// hard org-locked deny and every verdict on an individual node —
// returns false and keeps the configured threshold.
func alertsRegardlessOfSeverity(v ActionVerdict) bool {
	return v.Enforced && v.Overridable && v.Verdict.Decision == policy.DecisionDeny
}

// EffectiveRules returns the BASE engine's effective rule rows
// (built-ins + user layer, with overrides applied) for `observer
// guard rules --effective`. Project layers are per-root and lazy;
// the CLI surfaces the base set plus the loaded project states.
func (g *Guard) EffectiveRules() []policy.RuleInfo {
	return g.set.Load().base.RuleInfos()
}

// CategoryFor returns the category of a rule ID for audit-row
// attribution ("" when unknown; GuardErrorRuleID reports "guard" so
// wrapper rows filter as guard-health signals). The CLI's unpaired
// call Loads its own snapshot; the in-package Evaluate+CategoryFor hot
// paths thread the SAME snapshot via categoryWith (the NIT
// same-evaluation-snapshot contract).
func (g *Guard) CategoryFor(ruleID string) string {
	return g.categoryWith(g.set.Load(), ruleID)
}

// Evaluate is the guard-level evaluation seam: it stamps nothing,
// reads nothing — it picks the project-appropriate engine and applies
// the Q2 failure wrapper around the pure evaluation. The returned
// guardErr is non-nil when the wrapper engaged (recovered panic); the
// verdict is then the fail-open allow (or fail-closed deny under
// [guard] strict) carrying GuardErrorRuleID, and the caller must
// surface it as an audit row.
//
// Callers that own cross-event state (the ingest seam, the hook
// handler) populate ev.Taint BEFORE calling — see EvaluateActions for
// the ingest path that does both. The public entry Loads one snapshot;
// in-package callers that also categorize should use evaluateWith +
// categoryWith with a single Loaded snapshot (the NIT contract).
func (g *Guard) Evaluate(ev policy.Event) (verdict policy.Verdict, guardErr error) {
	return g.evaluateWith(g.set.Load(), ev)
}

// evaluateWith evaluates ev against an ALREADY-LOADED snapshot so the
// caller can pair it with categoryWith on the same snapshot (the
// same-evaluation-snapshot contract). The Q2 failure wrapper is
// applied here.
func (g *Guard) evaluateWith(es *engineSet, ev policy.Event) (verdict policy.Verdict, guardErr error) {
	defer func() {
		if r := recover(); r != nil {
			guardErr = fmt.Errorf("guard.Evaluate: recovered: %v", r)
			verdict = g.failureVerdict(guardErr)
		}
	}()
	return es.engineFor(g, ev.ProjectRoot).Evaluate(ev), nil
}

// evaluateBudgetWith is evaluateWith's budget-only sibling for proxy
// admission. It keeps the same snapshot selection and Q2 failure wrapper while
// preventing unrelated api_request rules from masking the budget decision.
func (g *Guard) evaluateBudgetWith(es *engineSet, ev policy.Event) (verdict policy.Verdict, guardErr error) {
	defer func() {
		if r := recover(); r != nil {
			guardErr = fmt.Errorf("guard.EvaluateBudget: recovered: %v", r)
			verdict = g.failureVerdict(guardErr)
		}
	}()
	return es.engineFor(g, ev.ProjectRoot).EvaluateBudget(ev), nil
}

// evaluateManagedBudgetWith is the native-intervention sibling. It filters to
// the exact organization-authorized hard rows before verdict ordering, while
// retaining the same snapshot selection and Q2 failure wrapper.
func (g *Guard) evaluateManagedBudgetWith(es *engineSet, ev policy.Event) (verdict policy.Verdict, guardErr error) {
	defer func() {
		if r := recover(); r != nil {
			guardErr = fmt.Errorf("guard.EvaluateManagedBudget: recovered: %v", r)
			verdict = g.failureVerdict(guardErr)
		}
	}()
	return es.engineFor(g, ev.ProjectRoot).EvaluateManagedBudget(ev), nil
}

// categoryWith returns the category of ruleID off an ALREADY-LOADED
// snapshot — the in-package pair for evaluateWith so a hot path never
// does a second g.set.Load() between evaluating and categorizing.
func (g *Guard) categoryWith(es *engineSet, ruleID string) string {
	if ruleID == GuardErrorRuleID {
		return "guard"
	}
	return es.categoryFor(ruleID)
}

// failureVerdict builds the Q2 wrapper verdict: fail-open allow by
// default, fail-closed deny under [guard] strict. Severity is high
// either way — a guard internal error is always worth surfacing.
func (g *Guard) failureVerdict(err error) policy.Verdict {
	v := policy.Verdict{
		Decision: policy.DecisionAllow,
		RuleID:   GuardErrorRuleID,
		Severity: policy.SeverityHigh,
		Reason:   "guard internal error (fail-open): " + err.Error(),
		Advice:   "Run `observer guard lint` and check the daemon log; report a reproducer if the panic persists.",
		Source:   policy.SourceBuiltin,
	}
	if g.cfg.Strict {
		v.Decision = policy.DecisionDeny
		v.Reason = "guard internal error (fail-closed, [guard] strict=true): " + err.Error()
	}
	return v
}

// UserPolicyPath resolves the configured [guard.rules] user_policy
// location with ~ expanded against home — the exact resolution New
// applies when loading the layer. Exported so editing surfaces (the
// dashboard policy editor) target the same file the guard loads;
// empty when no user policy is configured.
func UserPolicyPath(cfg config.GuardConfig, home string) string {
	return expandUserPath(cfg.Rules.UserPolicy, home)
}

// ProjectPolicyPath resolves a project root's policy-file location
// ([guard.rules] project_policy, relative to the root) — the exact
// resolution loadProjectEngine applies. Empty when either part is
// unconfigured.
func ProjectPolicyPath(cfg config.GuardConfig, projectRoot string) string {
	if projectRoot == "" || cfg.Rules.ProjectPolicy == "" {
		return ""
	}
	return filepath.Join(projectRoot, filepath.FromSlash(cfg.Rules.ProjectPolicy))
}

// OrgBundlePath resolves the configured [guard.rules] org_bundle
// cache location with ~ expanded against home — the exact resolution
// New applies before loadOrgBundle. Empty when unconfigured.
func OrgBundlePath(cfg config.GuardConfig, home string) string {
	return expandUserPath(cfg.Rules.OrgBundle, home)
}

// expandUserPath expands a leading "~/" against home. Empty input
// stays empty (no user policy configured).
func expandUserPath(p, home string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home == "" {
			return ""
		}
		return filepath.Join(home, p[2:])
	}
	return p
}
