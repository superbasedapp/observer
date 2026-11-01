package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
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
	// PackRules are a module's rule pack composed in by the cmd layer
	// (the security pillar's S-7xx rows, Source policy.SourcePackSecurity;
	// security pillar plan section 4.7 item 1), already validated there.
	// They join every engine before the policy layers' rules and are
	// tuned like built-ins. Nil when no module is active, which is
	// byte-identical to the engine before the pillar.
	PackRules []policy.Rule
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
	// OrgBundleExpected reports that this node has accepted a verified org
	// bundle before (the daemon reads it from its store: an org row for the
	// fetched bundle). A missing bundle file is then a DELETION, not "never
	// published" (T-864 gap 1). Hook and CLI processes get the same fact
	// from the daemon's MAC'd org lock (config.GuardOrgLock), so they leave
	// this false.
	OrgBundleExpected bool
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
	// Layer is "user", "project", "trusted_project" or "org".
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
	// packRules are Options.PackRules, fixed for the Guard's lifetime.
	packRules []policy.Rule
	cfg       config.GuardConfig
	home      string
	roots     []string
	readFile  func(string) ([]byte, error)

	// budgetOrigins is the org-authored window label table (budgetorigin.go),
	// keyed by rule id. nil = every ceiling renders as a local one.
	budgetOrigins atomic.Pointer[map[string]BudgetOrigin]
	// costDisplay resolves the developer cost display (budgetorigin.go,
	// SetCostDisplay). nil = dollars.
	costDisplay atomic.Pointer[func() string]

	// managedTenancy is Options.ManagedTenancy behind an
	// atomic.Pointer so SetManagedTenancy can wire (or re-wire) it
	// after construction without racing the hot paths that read it.
	// A nil pointer means "tenancy unresolved in this process" - see
	// Options.ManagedTenancy for what that deliberately implies.
	managedTenancy atomic.Pointer[func() bool]

	// orgBundleRejected is set when a cached org bundle EXISTS but could
	// not be verified or parsed (signature, key pin, envelope or TOML),
	// at construction or at the last ReloadOrgLayer; cleared by a
	// successful reload. GateEnforcement reads it: on a managed node an
	// unverifiable bundle counts as enforcing (the org's floor is
	// unknown, not absent); on an individual node it counts as absent.
	orgBundleRejected atomic.Bool
	// orgBundleTampered records that the cached bundle FILE did not verify at
	// the last load, whether or not the last verified copy covered for it
	// (T-844). Status surfaces read it; decisions read orgBundleRejected.
	orgBundleTampered atomic.Bool
	// orgBundleCause is the orgBundleCause of the last tamper
	// orgBundleTampered recorded (T-889), so the status line says "missing"
	// for a deleted file rather than "does not verify". Status only.
	orgBundleCause atomic.Int32
	// orgLKGInUse records that the org layer in force is the daemon's last
	// verified copy from the MAC'd org lock, not the cached file (T-844).
	orgLKGInUse atomic.Bool
	// orgLastVerified is the last verified signed org bundle envelope the
	// daemon recorded in its MAC'd org lock (config.GuardConfig.Lock.Bundle),
	// immutable after New. nil when no valid lock carries one.
	orgLastVerified []byte
	// orgBundleExpected: this node accepted a verified org bundle before
	// (Options.OrgBundleExpected, or the org lock's BundleExpected /
	// OrgExpected), so a missing bundle file is a deletion (T-864 gap 1).
	// Immutable after New.
	orgBundleExpected bool

	// projectRootForSession is the injected session-to-project
	// resolver (approvals.go: SessionProjectRootLookup). nil on every
	// lane that already carries a ProjectRoot on its events.
	projectRootForSession SessionProjectRootLookup

	// onPolicyState is Options.OnPolicyState (may be nil).
	onPolicyState func(PolicyState)

	// mcpAccess is the Agent Access node MCP-access lookup
	// (mcpaccess.go: SetMCPAccessLookup), behind an atomic.Pointer because
	// the daemon binds it after construction, once the relay's table holder
	// exists. nil = no compiled table in this process → no R-306/R-307
	// finding is ever stamped.
	mcpAccess atomic.Pointer[MCPAccessLookup]
	// gitAliases is the injected per-project git alias table
	// (gitalias.go: SetGitAliasLookup), read by every engine through
	// gitAliasesFor, so wiring it after construction reaches engines that
	// already exist. nil = only aliases defined on the command line.
	gitAliases atomic.Pointer[GitAliasLookup]

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
	// orgGrants is the org access-grant claim (orggrant.go,
	// SetOrgGrantClaim); nil = no org grants.
	orgGrants OrgGrantClaim
	// requestBase is the node dashboard origin for the org-locked deny
	// line's request link (override.go, SetRequestAccessBase).
	requestBase string
	// hookBudget is the hook path's managed budget stop lookup
	// (hookbudget.go, SetHookBudgetLookup); nil = the hook path never stops
	// on a budget (the daemon, every test that does not wire it).
	hookBudget HookBudgetLookup

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
	// promptPreSend is the post-hoc prompt lane's dedupe lookup
	// (SetPromptPreSendLookup; posthocprompt.go): did a hook/proxy lane
	// already judge this session's prompt? nil = always record.
	promptPreSend PromptPreSendLookup
	// promptSessionStop is the stopped-conversation lookup
	// (SetPromptSessionStopLookup; promptsessionstop.go): did a pre-send
	// lane already stop a prompt in this conversation? nil = never.
	promptSessionStop PromptSessionStopLookup

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
	// It is TRI-STATE (REVIEW-4 P4-01, ruling D-521): a read that failed is
	// "unknown", never "not enrolled".
	budgetIdentityLookup BudgetIdentityLookup
	budgetMu             sync.Mutex
	budgetCache          map[string]budgetEntry
	budgetRecorded       map[string]map[string]bool
	// budgetClock is the clock the budget cache ages on (budgetNow).
	// Nil means wall-clock time; tests inject a fake one.
	budgetClock budgetClockFunc
	// repeats is the A-610 consecutive-identical tracker (§12.2,
	// repeat.go) feeding Event.RepeatCount on the ingest path.
	repeats repeatTracker
	// evasions is the A-613 tracker (evasion.go) feeding Event.EvasionOf
	// and Event.EvasionShapes on the ingest path, while
	// [guard.rules].evasion_window_seconds is set.
	evasions evasionTracker
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
		packRules:         append([]policy.Rule(nil), opts.PackRules...),
		cfg:               opts.Config,
		home:              opts.Home,
		roots:             opts.KnownProjectRoots,
		readFile:          opts.ReadFile,
		onPolicyState:     opts.OnPolicyState,
		orgKeyPinHash:     opts.OrgKeyPinHash,
		orgBundleExpected: opts.OrgBundleExpected,
		orgBundlePath:     OrgBundlePath(opts.Config, opts.Home),
		taint:             newTaintTracker(opts.Config.Taint),
		watches:           make(map[string]configWatch),
	}
	if g.readFile == nil {
		g.readFile = os.ReadFile
	}
	if opts.ManagedTenancy != nil {
		g.SetManagedTenancy(opts.ManagedTenancy)
	}
	g.applyOrgLock(opts)
	// A module's rule pack that does not build on its own is dropped with
	// an issue: a broken pack never takes guard down (the pack is validated
	// by the cmd layer first; this is the backstop).
	if len(g.packRules) > 0 {
		if _, err := policy.New(policy.Config{ExtraRules: g.packRules}); err != nil {
			g.issues = append(g.issues, fmt.Sprintf("rule pack dropped: %v", err))
			g.packRules = nil
		}
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

	// [guard.boundary].protected_path_classes (R-166): an unknown class
	// is dropped with a recorded issue, the policy-file failure posture
	// (policy owns the vocabulary, so the config loader cannot check it).
	var classIssues []string
	g.cfg.Boundary.ProtectedPathClasses, classIssues = knownProtectedPathClasses(opts.Config.Boundary.ProtectedPathClasses)
	g.issues = append(g.issues, classIssues...)

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
		pf, st, issue, cause, loaded, lkg := g.loadOrgLayer(g.orgBundlePath, g.orgKeyPinHash, g.orgLastVerified, g.missingBundleIsTamper(nil))
		if issue != "" {
			g.issues = append(g.issues, issue)
			// With the last verified layer in force the org's floor is
			// KNOWN, so the "unverifiable bundle counts as enforcing" and
			// "approvals refused for every rule" readings do not apply:
			// the layer itself decides, as it did before the tamper.
			g.orgBundleRejected.Store(!lkg)
			g.orgBundleTampered.Store(true)
			g.orgBundleCause.Store(int32(cause))
		}
		g.orgLKGInUse.Store(lkg)
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

	_, _, v3 := decodeOrgProjectEnvelope(orgLayer)
	var lazyNotes []string
	lazy := false
	if v3 {
		lazy, lazyNotes = g.layersBuild(orgLayer, userLayer)
	}
	if lazy {
		// The project audience is in force (lane sec-p2a, P-052 finding 5):
		// the base engine is built on first use, so a hook in a project root
		// whose org project sections load builds only the folded project
		// engine. The layers were checked to build; should the build fail
		// anyway, the same ladder runs then and records what it dropped.
		// The merge notes a base build records are recorded now, so a status
		// surface reading LoadIssues sees them without building the engine.
		g.issues = append(g.issues, lazyNotes...)
		g.set.Store(newLazyEngineSet(mode, func() (*policy.Engine, []string) {
			b, keptOrg, keptUser, issues, err := g.buildBaseLadder(mode, orgLayer, userLayer)
			g.recordIssues(issues)
			if err != nil {
				g.recordIssues([]string{fmt.Sprintf("built-in engine: %v", err)})
			}
			// The layers the ladder dropped, so no status surface reports
			// them loaded (P-058; the eager branch drops their states).
			var dropped []string
			if keptOrg == nil && orgLayer != nil {
				dropped = append(dropped, layerOrg)
			}
			if keptUser == nil && userLayer != nil {
				dropped = append(dropped, layerUser)
			}
			return b, dropped
		}, orgLayer, userLayer, states, buildRuleCategories(orgLayer, userLayer), g.budgetBinding(), g.budgetCalendars()))
	} else {
		base, keptOrg, keptUser, issues, err := g.buildBaseLadder(mode, orgLayer, userLayer)
		if err != nil {
			return nil, fmt.Errorf("guard.New: built-in engine: %w", err)
		}
		g.issues = append(g.issues, issues...)
		if keptOrg == nil && orgLayer != nil {
			states = dropLayerState(states, layerOrg)
		}
		if keptUser == nil && userLayer != nil {
			states = dropLayerState(states, layerUser)
		}
		orgLayer, userLayer = keptOrg, keptUser
		g.set.Store(newEngineSet(base, orgLayer, userLayer, states, buildRuleCategories(orgLayer, userLayer), g.budgetBinding(), g.budgetCalendars()))
	}

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

// buildBaseLadder builds the base engine from the org and user layers. A
// layer that breaks ENGINE construction (e.g. an override on an unknown rule)
// degrades the same way a parse failure does: drop the offending layer, keep
// the innocent one. It isolates the culprit by retrying without org, then
// without user, then without both: the first combination that builds wins,
// and every dropped layer is named in issues. The returned layers are the
// ones kept (nil when dropped). err is set only when the built-in engine
// itself does not build.
func (g *Guard) buildBaseLadder(mode policy.Mode, org, user *policyFile) (*policy.Engine, *policyFile, *policyFile, []string, error) {
	base, err := g.buildEngine(mode, org, user, nil, nil)
	if err == nil {
		return base, org, user, nil, nil
	}
	firstErr := err
	if org != nil {
		if b, e := g.buildEngine(mode, nil, user, nil, nil); e == nil {
			return b, nil, user, []string{fmt.Sprintf("org policy layer dropped: %v", firstErr)}, nil
		}
	}
	if user != nil {
		if b, e := g.buildEngine(mode, org, nil, nil, nil); e == nil {
			return b, org, nil, []string{fmt.Sprintf("user policy layer dropped: %v", firstErr)}, nil
		}
	}
	var issues []string
	if org != nil || user != nil {
		issues = append(issues, fmt.Sprintf("org+user policy layers dropped: %v", firstErr))
	}
	b, e := g.buildEngine(mode, nil, nil, nil, nil)
	if e != nil {
		return nil, nil, nil, issues, e
	}
	return b, nil, nil, issues, nil
}

// layersBuild reports, without building an engine, whether the org and user
// layers would build: every override they carry names a rule the engine will
// hold (a built-in, a rule pack row, or a rule a layer defines) and not one
// the config disables. It is the check that lets New defer the base engine
// build (newLazyEngineSet) and keep its build-failure ladder for the rare
// layer set that would not build. notes are the merge's load notes, the ones
// a base build would record.
func (g *Guard) layersBuild(org, user *policyFile) (ok bool, notes []string) {
	extra, overrides, _, notes := mergeLayersWithPack(g.packRules, org, user, nil, nil)
	known := map[string]bool{}
	for _, info := range policy.Catalog() {
		known[info.ID] = true
	}
	for i := range extra {
		known[extra[i].ID] = true
	}
	disabled := map[string]bool{}
	for _, id := range effectiveConfigDisable(org, g.cfg.Rules.Disable) {
		disabled[id] = true
	}
	for _, ov := range overrides {
		if !known[ov.RuleID] || disabled[ov.RuleID] {
			return false, nil
		}
	}
	return true, notes
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
func (g *Guard) buildEngine(mode policy.Mode, org, user, project, trusted *policyFile) (*policy.Engine, error) {
	return g.buildEngineWith(mode, org, user, project, trusted, g.publishedBudgetInputs())
}

// engineBudgetInputs is every budget-shaped input one engine build reads. It
// exists so the ONE build funnel can produce two engines from the same layers:
// the published (org-composed) one, and the node's own local-only one the
// proxy admission falls back to when the enrolment the composition belongs to
// is gone or replaced (REVIEW-4 P4-02).
type engineBudgetInputs struct {
	budget     config.GuardBudgetConfig
	soft       []policy.Override
	subjects   []policy.BudgetSubjectCap
	protection policy.BudgetProtection
	required   bool
}

// publishedBudgetInputs reads the EFFECTIVE budget, not g.cfg.Budget: an
// org-composed ceiling applied through ApplyOrgBudget must survive every later
// engine rebuild (project layer, org-bundle reload). Falls back to the
// constructed config when nothing has been applied.
func (g *Guard) publishedBudgetInputs() engineBudgetInputs {
	return engineBudgetInputs{
		budget: g.budgetConfig(),
		// The per-window half of that budget: BudgetHard upgrades EVERY
		// CategoryBudget row to deny, so the windows the org authored as
		// soft/report are held back at flag by an override appended AFTER the
		// layer overrides (policy.New applies overrides in order, last wins).
		// Empty on every node with one uniform posture. See ApplyOrgBudget.
		soft:       g.budgetSoftOverrides(),
		subjects:   g.budgetSubjectCaps(),
		protection: g.budgetProtection(),
		required:   g.effBudgetRequired.Load(),
	}
}

// localBudgetInputs is the node's OWN [guard.budget] block as this Guard was
// constructed with it, and nothing an organization composed: no per-subject
// caps, no authority provenance, no soft-window set and never the B-625
// requirement. It is what D-502 means by "fail open on its own numbers".
func (g *Guard) localBudgetInputs() engineBudgetInputs {
	return engineBudgetInputs{budget: g.cfg.Budget}
}

// engineBuilds counts engine builds in this process (one per buildEngineWith
// call). Tests read it to pin that a hook builds one engine per load
// (lane sec-p2a, P-052 finding 5); nothing else does.
var engineBuilds atomic.Int64

// buildEngineWith is buildEngine over an explicit set of budget inputs.
func (g *Guard) buildEngineWith(mode policy.Mode, org, user, project, trusted *policyFile, in engineBudgetInputs) (*policy.Engine, error) {
	engineBuilds.Add(1)
	extra, overrides, layerDisable, mergeIssues := mergeLayersWithPack(g.packRules, org, user, project, trusted)
	g.recordIssues(mergeIssues)
	g.recordIssues(configDisableOrgFloorIssues(org, g.cfg.Rules.Disable))
	budget := in.budget
	budgetSoft := in.soft
	// Boundary slices pass through as-is: nil (section absent) lets
	// the engine defaults apply; an explicitly-empty TOML list means
	// "none" — the decoder already produces exactly this distinction.
	return policy.New(policy.Config{
		Mode:              mode,
		Home:              g.home,
		AllowPaths:        g.cfg.Boundary.AllowPaths,
		ProtectedBranches: g.cfg.Boundary.ProtectedBranches,
		// R-166 (D-761): the opt-in protected path classes; empty keeps
		// the rows inert.
		ProtectedPathClasses: g.cfg.Boundary.ProtectedPathClasses,
		KnownProjectRoots:    g.roots,
		ResolveLinks:         resolveExistingLinks,
		// R-162 (T-910): the hook-switch table and the reader that lets
		// an edit be judged on the whole file it produces.
		HookSwitches: hookSwitchesForPolicy(),
		ReadFile:     readHookSwitchFile,
		// R-112 to R-114 (D-761): the daemon's per-project git alias
		// table, so an alias that expands to a hook bypass is judged as
		// what it runs.
		GitAliases: g.gitAliasesFor,
		// Config-level disables ([guard.rules] disable) unioned with the
		// trusted per-project layer's `disable` list (empty on New /
		// ReloadOrgLayer, where trusted is nil — byte-identical to the
		// pre-arc Disabled: g.cfg.Rules.Disable).
		// policy.New keeps every org-floored row whatever this lists
		// (OSH-R-014); configDisableOrgFloorIssues above says so.
		Disabled:   unionDisable(g.cfg.Rules.Disable, layerDisable),
		ExtraRules: extra,
		Overrides:  appendOverrides(overrides, budgetSoft),
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
		BudgetSubjectCaps: in.subjects,
		BudgetHard:        budget.Hard,
		BudgetProtection:  in.protection,
		// The fail-closed row (B-625): armed only by an org-composed posture
		// that says this managed node may not run without the organization's
		// budget. Zero on every individual node.
		BudgetRequired:      in.required,
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
func (g *Guard) Mode() policy.Mode { return g.set.Load().mode }

// RuleCount returns the base engine's active rule-row count (status
// surfaces).
func (g *Guard) RuleCount() int { return g.set.Load().base().RuleCount() }

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
	// The request form's link rides the notification, which only a human
	// reads; the in-band reason names the dashboard page instead (WINNODE2
	// 16d).
	if link := RequestAccessLink(v); link != "" {
		body += " Request: " + link
	}
	g.notifier.Notify(title, body)
}

// alertsRegardlessOfSeverity is the exception table to the
// [guard.alerts].min_severity gate: an enforced deny of a rule the
// organization marked overridable, and an enforced stop whose channel
// showed the developer no reason in band (ActionVerdict.SilentStop: the
// toast is the only signal they get). Every other verdict, including a
// hard org-locked deny and every other verdict on an individual node,
// returns false and keeps the configured threshold.
func alertsRegardlessOfSeverity(v ActionVerdict) bool {
	return v.Enforced && (v.SilentStop || (v.Overridable && v.Verdict.Decision == policy.DecisionDeny))
}

// EffectiveRules returns the BASE engine's effective rule rows
// (built-ins + user layer, with overrides applied) for `observer
// guard rules --effective`. Project layers are per-root and lazy;
// the CLI surfaces the base set plus the loaded project states.
func (g *Guard) EffectiveRules() []policy.RuleInfo {
	return g.set.Load().base().RuleInfos()
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
	// Agent Access (doc3 §12.6): stamp the node MCP-access finding on the
	// event copy before the engine runs — the ONE place every KindMCPCall
	// channel (hook, ingest, proxy inspection) passes through.
	g.stampMCPAccess(&ev)
	return g.displayVerdict(es.engineForEvent(g, projectLookupRoot(&ev), ev.Cwd).Evaluate(ev)), nil
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
//
// Superseded default for gate hooks under enforcement (2026-10-03,
// hook-parity audit section 5.7): `observer hook` sets Strict on the
// config it builds a gate hook's guard from whenever the node's posture
// says enforcement is in force (cmd/observer/hook.go buildHookGuard), so
// on that path this wrapper denies. Every other caller keeps the
// configured default.
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
// ([guard.rules] project_policy, relative to the root): the main
// checkout's copy, the file the dashboard editor shows. Empty when either
// part is unconfigured. The engine reads ProjectPolicyPaths.
func ProjectPolicyPath(cfg config.GuardConfig, projectRoot string) string {
	if projectRoot == "" || cfg.Rules.ProjectPolicy == "" {
		return ""
	}
	return filepath.Join(projectRoot, filepath.FromSlash(cfg.Rules.ProjectPolicy))
}

// maxWorktreePolicyFiles caps the linked worktrees whose in-repo policy
// file one project engine reads.
const maxWorktreePolicyFiles = 32

// ProjectPolicyPaths is every in-repo policy file the project engine for
// projectRoot reads: the main checkout's (ProjectPolicyPath) first, then
// the same file in each linked worktree of the project, found from git's
// back pointers by file reads only (git.LinkedWorktreeCheckouts, at most
// maxWorktreePolicyFiles). The in-repo file is a checkout file (the
// internal/git doc rule: identity reads Root, file reads the checkout),
// and the engine is one per project root, so a worktree's own file
// applies with the main checkout's; the layer is escalate-only, so the
// strictest wins in every checkout (lane shr-worktree2, PT-39). For a
// repository with no linked worktree it is exactly the one main path. The
// trusted per-project file stays keyed on Root (TrustedProjectPolicyPath).
func ProjectPolicyPaths(cfg config.GuardConfig, projectRoot string) []string {
	main := ProjectPolicyPath(cfg, projectRoot)
	if main == "" {
		return nil
	}
	out := []string{main}
	for _, checkout := range git.LinkedWorktreeCheckouts(projectRoot, maxWorktreePolicyFiles) {
		out = append(out, filepath.Join(checkout, filepath.FromSlash(cfg.Rules.ProjectPolicy)))
	}
	return out
}

// checkoutPolicyPaths is the in-repo policy files the engine of one
// checkout of projectRoot reads (lane LEFT-SHARED, SHR-8 residual): the main
// checkout's file, then the checkout's own when it is a linked worktree. A
// worktree's file therefore applies in that worktree only, never in the main
// checkout or a sibling worktree. checkout "" (not known) is every
// checkout's file (ProjectPolicyPaths), the strictest, so an event whose
// checkout cannot be told evaluates exactly as before.
func checkoutPolicyPaths(cfg config.GuardConfig, projectRoot, checkout string) []string {
	if checkout == "" {
		return ProjectPolicyPaths(cfg, projectRoot)
	}
	main := ProjectPolicyPath(cfg, projectRoot)
	if main == "" {
		return nil
	}
	out := []string{main}
	if !sameDir(checkout, projectRoot) {
		out = append(out, filepath.Join(checkout, filepath.FromSlash(cfg.Rules.ProjectPolicy)))
	}
	return out
}

// checkoutOf is the checkout of projectRoot that cwd sits in: projectRoot
// for the main checkout, a linked worktree's own top level for that
// worktree (git.Info.CheckoutRoot, P-041), and "" (not known) when cwd is
// empty, is not in a git checkout, or is in a checkout of another project.
// File reads only, no git process.
func checkoutOf(projectRoot, cwd string) string {
	if projectRoot == "" || cwd == "" || !filepath.IsAbs(cwd) {
		return ""
	}
	c, ok := git.FindCheckoutRoot(cwd)
	if !ok || c == "" {
		return ""
	}
	if sameDir(c, projectRoot) {
		return projectRoot
	}
	if target, ok := git.CheckoutRootTarget(c); ok && sameDir(target, projectRoot) {
		return c
	}
	return ""
}

// engineKey is the project engine cache key of one checkout of a root: the
// root alone for the every-checkout engine (checkout "").
func engineKey(projectRoot, checkout string) string {
	if checkout == "" {
		return projectRoot
	}
	return projectRoot + "\x00" + checkout
}

// sameDir reports whether a and b name the same directory (equal cleaned
// paths, or the same file on disk).
func sameDir(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	ia, err := os.Stat(a)
	if err != nil {
		return false
	}
	ib, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ia, ib)
}

// foldInRepoPolicyFiles folds the parsed in-repo policy files of a
// project's checkouts (ProjectPolicyPaths order) into the one in-repo
// layer the merge takes: every rule row and override, in order. Both are
// escalate-only (applyProject drops a relaxing override, and a later
// override below an earlier one's decision reads as relaxing), so the
// strictest stance wins.
func foldInRepoPolicyFiles(files []*policyFile) *policyFile {
	switch len(files) {
	case 0:
		return nil
	case 1:
		return files[0]
	}
	out := &policyFile{layer: files[0].layer}
	for _, f := range files {
		out.rules = append(out.rules, f.rules...)
		out.overrides = append(out.overrides, f.overrides...)
		out.notes = append(out.notes, f.notes...)
	}
	return out
}

// inRepoOverrideTargets returns the predicate an in-repo override's rule id
// must pass: some layer of the project engine carries a row for it (the
// built-in catalog, the module rule pack, or a [[rule]] of the org layer as
// composed with the org project sections, the user layer, the trusted
// layer or any in-repo file) and no disable removes that row. A disable
// counts from the config list and from the trusted layer's list, except on
// an integrity rule (never removable) and, for the trusted list, on an
// org-floored rule (the merge drops that disable). Pillar ids (S-7xx) pass,
// so dropUnloadedPackOverride keeps reporting an inactive module the way it
// words it. Conservative by construction: a row kept only by budget
// protection reads as disabled, which drops at most one in-repo escalation
// and never fails the build.
func inRepoOverrideTargets(pack []policy.Rule, cfgDisable []string, org, user, trusted *policyFile, inRepo []*policyFile) func(string) bool {
	rows := map[string]bool{}
	for _, info := range policy.Catalog() {
		rows[info.ID] = true
	}
	for i := range pack {
		rows[pack[i].ID] = true
	}
	layers := append([]*policyFile{org, user, trusted}, inRepo...)
	for _, f := range layers {
		if f == nil {
			continue
		}
		for i := range f.rules {
			rows[f.rules[i].ID] = true
		}
	}
	floored := map[string]bool{}
	if org != nil {
		for i := range org.rules {
			floored[org.rules[i].ID] = true
		}
		for _, ov := range org.overrides {
			floored[ov.RuleID] = true
		}
	}
	off := map[string]bool{}
	for _, id := range cfgDisable {
		off[id] = true
	}
	if trusted != nil {
		for _, id := range trusted.disable {
			if !floored[id] {
				off[id] = true
			}
		}
	}
	return func(id string) bool {
		if strings.HasPrefix(id, policy.SecurityRuleIDPrefix) {
			return true
		}
		if !rows[id] {
			return false
		}
		return !off[id] || policy.IsIntegrityRuleID(id)
	}
}

// dropUnloadedInRepoOverrides returns pf without the overrides whose rule id
// fails loaded, and one load issue per dropped override naming the file
// (path) and the rule, the dropUnloadedPackOverride pattern. pf is not
// modified; a file with nothing to drop is returned as is.
func dropUnloadedInRepoOverrides(pf *policyFile, path string, loaded func(string) bool) (*policyFile, []string) {
	if pf == nil {
		return nil, nil
	}
	var kept []rawOverride
	var issues []string
	for _, ov := range pf.overrides {
		if loaded(ov.RuleID) {
			kept = append(kept, ov)
			continue
		}
		issues = append(issues, fmt.Sprintf(
			"project policy %s: override on %s dropped: rule %s is not loaded (an in-repo file may only tune a loaded rule)",
			path, ov.RuleID, ov.RuleID,
		))
	}
	if len(issues) == 0 {
		return pf, nil
	}
	out := *pf
	out.overrides = kept
	return &out, issues
}

// TrustedProjectPolicyPath resolves the daemon-local trusted per-project
// policy file for a project root: <trusted_project_dir>/<sha256(canonical
// root)>.toml, with [guard.rules] trusted_project_dir's leading "~"
// expanded against home. The root is canonicalized (filepath.Clean +
// filepath.ToSlash) BEFORE hashing so a given LOGICAL root hashes
// identically across OSes — this is the ONE resolver both the loader
// (engineset.buildProjectEngine) and the dashboard writer call, so the
// load side and the write side always agree on the path. Empty when the
// root is empty or trusted_project_dir is unconfigured (the trusted layer
// disabled).
//
// The filename uses the FULL 64-hex-char digest, not a prefix: a truncated
// hash needlessly narrows the collision margin between distinct roots for
// no benefit. The feature is unreleased (no trusted files exist anywhere),
// so this needs no migration or back-compat shim.
func TrustedProjectPolicyPath(cfg config.GuardConfig, home, projectRoot string) string {
	if projectRoot == "" {
		return ""
	}
	dir := expandUserPath(cfg.Rules.TrustedProjectDir, home)
	if dir == "" {
		return ""
	}
	canonical := filepath.ToSlash(filepath.Clean(projectRoot))
	sum := sha256hex([]byte(canonical))
	return filepath.Join(dir, sum+".toml")
}

// unionDisable returns base ∪ extra (config-level disables unioned with a
// layer's `disable` list), order-preserving and deduplicated. When extra
// is empty it returns base unchanged (nil-safe), keeping every New /
// ReloadOrgLayer build byte-identical to the pre-arc single-source
// Config.Disabled.
func unionDisable(base, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]bool, len(base)+len(extra))
	out := make([]string, 0, len(base)+len(extra))
	for _, id := range base {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range extra {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
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

// knownProtectedPathClasses keeps the R-166 classes the policy vocabulary
// knows, in order, and reports each unknown one.
func knownProtectedPathClasses(classes []string) ([]string, []string) {
	known := policy.ProtectedPathClasses()
	var kept, issues []string
	for _, c := range classes {
		if slices.Contains(known, c) {
			kept = append(kept, c)
			continue
		}
		issues = append(issues, fmt.Sprintf("guard.boundary.protected_path_classes: unknown class %q dropped (known: %s)", c, strings.Join(known, ", ")))
	}
	return kept, issues
}
