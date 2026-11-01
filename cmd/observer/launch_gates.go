package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// launch_gates.go is the ONE ordered launch-gate table (joint roadmap F0-4,
// sandbox plan section 8.3, security plan section 5.1). Every gate that runs
// at a launch chokepoint before a coding agent starts is one row of
// launchGates, walked top-down by walkLaunchGates. A row names what it
// checks, what it can return and on which launch paths it runs. The table
// owns the ORDER; each row calls the decision it gates and never copies it
// (sandboxLaunchDecision stays the single owner of the sandbox selection).
//
// # The launch paths that reach a coding agent, and their gates today
//
// Two chokepoints walk the table. The gates in each list run in the order
// shown; "(table)" marks a row of launchGates, anything else runs outside
// the table, before or after it, and says why it stays there.
//
// 1. Dashboard New Terminal fresh launch (launchManagerAdapter.CreateFresh,
// path launchPathDashboardFresh), before the PTY is spawned:
//   - tool.disallow (table): node.features tools.disallow, peek only.
//   - repo.trust (table): the repository trust check; a refusal stops the
//     launch here, an ask is left to the inner launcher, which asks in the
//     PTY.
//   - hook.switch (table): T-910 project hook switches narrow the tool gate.
//   - sandbox.select (table): sandboxLaunchDecision (proceed, upgrade to a
//     sandbox, or the org_disallow refusal).
//   - state.load, budget.authority, budget.guard, budget.spend (table): the
//     managed hard budget, admitted daemon-side before the PTY spawns from
//     the daemon's own config and database (OSH-R-007); a plain shell is
//     exempt. budget.coverage stays on path 2, where the inner launcher has
//     the real route evidence.
//   - after the table, inside internal/termsvc.LaunchFresh: the
//     [terminal.launch] policy (fresh launches allowed, allowed tools,
//     allowed project roots) and, for a sandboxed launch, the Sandboxer seam
//     and its Prepare. Service-owned authorization, not a cmd-layer gate.
//   - the PTY then runs the inner `observer <tool>` launcher, which walks the
//     table again on path 2 (a launch the dashboard sandboxed carries the
//     sandbox marker, so its inner sandbox.select proceeds).
//
// 2. `observer <tool>` launchers (path launchPathCLI), at the shared launch
// admission chokepoint enforceBudgetControlledLaunch, called by every
// launcher right before the vendor process starts:
//   - route.maintenance (table): a maintenance verb is not an agent session;
//     the launch is allowed with no later row.
//   - state.load (table): config and database for the rows below. It never
//     creates the database (OSH-R-007): with no database file a launch in a
//     box, or one a daemon runs or spawned, refuses; a standalone launch on
//     a host that never ran Observer gets an in-memory one.
//   - terminals.feature (table): the org's node.features terminals decision
//     (terminals.enabled, sandbox_required; OSH-R-003), from the daemon's
//     live handle in the daemon and from the daemon's sidecar in a
//     standalone launcher; on a managed node a sidecar that cannot be read
//     refuses. The daemon's PTY entries (fresh, shell, handoff, resume,
//     attach, SSH) ask the same decision inside internal/termsvc before a
//     run is minted (Options.TerminalGate).
//   - repo.trust (table): the repository trust check, asking at the
//     terminal when stdin and stderr are terminals.
//   - hook.switch (table), sandbox.select (table): as on path 1, against the
//     launch's working directory, never upgrading (a CLI launch is never
//     sandboxed by Observer).
//   - budget.authority, budget.guard, budget.coverage, budget.spend (table):
//     the managed hard budget (docs/budgets.md).
//   - before the chokepoint, inside each launcher, in an order the launcher
//     owns: binary resolution and the host runtime preflight
//     (resolveToolBin), the conditional route gate (resolveGatedRoute, for
//     rows with a ProxyRoute.Gate), the capture-proxy-not-in-build fallback
//     (launch unrouted with a notice), and the org tool disallow
//     (refuseIfToolDisallowed and its variants, which also COUNT one use of
//     a covering org grant). These stay in the launchers: they decide the
//     route evidence the chokepoint reads, and moving the disallow check
//     into the chokepoint would reorder it against binary resolution and
//     newly refuse the GUI and benchmark callers, which never ran it. Agent
//     Arena runs it in its own admission seam before the walk
//     (arenaLaunchPolicyAdmission, OSH-R-004), with the [terminal.launch]
//     policy, because Arena starts the vendor binary itself.
//
// Every other way an agent starts reaches path 2:
//   - `observer <tool> --attach` peeks the tool disallow (no count), then
//     the daemon spawns the inner launcher in its PTY (path 2).
//   - Dashboard handoff (Create) and native resume (CreateResume) go through
//     internal/termsvc's launch policy, then the PTY runs the launcher (path
//     2); they do not walk path 1.
//   - Dashboard GUI launch (termsvc.LaunchGUI to guiLauncher.SpawnGUI) walks
//     path 2 with the registry's GUI surface class.
//   - Agent Arena and benchmark drivers walk path 2 with an unknown route as
//     their conservative outer check; a benchmark's harness launcher walks it
//     again with real evidence (Arena starts the vendor binary itself, so its
//     seam first applies the org tools.disallow and the node's own
//     [terminal.launch] policy, the gates a dashboard New Terminal launch
//     answers to; OSH-R-004).
//   - These three, and the sandbox capture relay's host-side gate for a
//     launch inside a box (sandboxGateWalk), are started by the daemon or a
//     runner, not from a developer's terminal, so they walk through
//     daemonLaunchGateRun
//     (enforceDaemonStartedLaunch): the launch directory is the run's own
//     (the project root, the worktree, the attempt workspace), never the
//     process's working directory; the trust row never asks (an ask refuses
//     and says where to accept); and the checked marker goes into the started
//     process's environment only, never into the daemon's.
//   - Shell-wrap shims exec `observer <tool>` (path 2).
//
// Not launch paths: dashboard Jump-in joins a run that already passed its
// gates (no process starts); setup PTYs (guided install, operator grants),
// outbound SSH terminals and `observer run` start no coding agent.
//
// # Repository trust (security Phase B)
//
// The repo.trust row (security section 5.1: the trust verdict goes to Guard
// as an agent_launch event; launch_trust.go) sits AFTER state.load and
// BEFORE hook.switch, on both paths: after the org tool disallow and the
// maintenance skip (a refused tool or a maintenance verb never reads the
// repository), after the state it needs (config, Guard), and before sandbox
// selection and every budget row, so a refusal for an untrusted repository
// is decided before a sandbox is chosen and before any spend is admitted
// (sandbox plan section 8.3 keeps sandboxLaunchDecision the owner of the
// selection the row precedes). TestLaunchGateOrder states the slot.

// launchPath is one way a launch reaches the gate table (a bit, so a row can
// name several).
type launchPath uint8

const (
	// launchPathDashboardFresh: the dashboard's New Terminal fresh launch,
	// before the PTY is spawned (launchManagerAdapter.CreateFresh).
	launchPathDashboardFresh launchPath = 1 << iota
	// launchPathCLI: the `observer <tool>` admission chokepoint
	// (enforceBudgetControlledLaunch), reached by every launcher.
	launchPathCLI
)

// launchPathsAll is every launch path.
const launchPathsAll = launchPathDashboardFresh | launchPathCLI

// launchGateOutcome is one thing a row can return (a bit, so a row declares
// the set it can return).
type launchGateOutcome uint8

const (
	// launchGateAllow: the launch goes on to the next row.
	launchGateAllow launchGateOutcome = 1 << iota
	// launchGateAllowNow: the launch is allowed and no later row runs.
	launchGateAllowNow
	// launchGateRefuse: the launch is refused with the row's error.
	launchGateRefuse
	// launchGateWarn: a warning is printed at the launch terminal and the
	// launch goes on.
	launchGateWarn
	// launchGateUpgrade: an unsandboxed request is turned into a sandboxed
	// one and the launch goes on.
	launchGateUpgrade
)

// launchGateStep is what one row returned for one launch.
type launchGateStep struct {
	// refuse, when non-nil, refuses the launch; no later row runs.
	refuse error
	// allowNow allows the launch; no later row runs.
	allowNow bool
	// warn is printed at the launch terminal; the launch goes on.
	warn string
	// upgraded reports that the row turned the request into a sandboxed one.
	upgraded bool
}

// outcomes is the set of outcomes this step is an instance of.
func (s launchGateStep) outcomes() launchGateOutcome {
	var o launchGateOutcome
	switch {
	case s.refuse != nil:
		o |= launchGateRefuse
	case s.allowNow:
		o |= launchGateAllowNow
	default:
		o |= launchGateAllow
	}
	if s.warn != "" {
		o |= launchGateWarn
	}
	if s.upgraded {
		o |= launchGateUpgrade
	}
	return o
}

// launchGate is one row of the table.
type launchGate struct {
	// id names the row in tests and docs.
	id string
	// checks says what the row checks, in one sentence.
	checks string
	// can is every outcome the row can return.
	can launchGateOutcome
	// paths is every launch path the row runs on.
	paths launchPath
	// run is the row itself.
	run func(r *launchGateRun) launchGateStep
}

// launchGateRun carries one launch through the table: the inputs its path
// injects (funcs, so a row never branches on the path) and the state rows
// fill for the rows below them.
type launchGateRun struct {
	ctx    context.Context
	path   launchPath
	tool   string
	stderr io.Writer

	// toolLaunchAllowed answers the node.features tools.disallow question
	// without counting a grant use (tool.disallow). Nil allows every tool.
	toolLaunchAllowed func(tool string) bool
	// configPath and evidence are the CLI launcher's --config value and its
	// route and process evidence (state.load and the budget rows).
	configPath string
	evidence   budgetLaunchEvidence
	// launchDir is the directory the tool starts in (hook.switch).
	launchDir func() (string, error)
	// baseToolGate reads the node's tool-gate hook state (hook.switch).
	baseToolGate func(tool string) nodeToolGateState
	// sandboxGateOn reports whether the sandbox selection consults the
	// Guard at all for this launch; evaluated once (sandboxOn).
	sandboxGateOn func(r *launchGateRun) bool
	// guardFor is the node's Guard for this launch (sandbox.select).
	guardFor func(r *launchGateRun) *guard.Guard
	// sandboxProbe reports whether a sandbox is available here; nil means
	// none (sandbox.select).
	sandboxProbe func() bool
	// sandboxRefusal renders the org_disallow refusal for this path.
	sandboxRefusal func(tool string) error
	// repoTrustFor returns the repository trust row's dependencies for this
	// launch, or nil when the security.trust component is inactive or the
	// guard is off (repo.trust; launch_trust.go). Nil leaves the row inert.
	repoTrustFor func(r *launchGateRun) *repoTrustDeps
	// markChecked records, once the repo.trust row let the launch go on, the
	// project-root hash it checked (repoTrustCheckedEnv) for the agent this
	// launch starts. A standalone `observer <tool>` launcher sets it in its
	// own environment, which the vendor process inherits; a launch the
	// daemon starts keeps it on the run (childEnv), so the daemon's own
	// environment never carries it. Nil records nothing.
	markChecked func(r *launchGateRun, rootHash string)
	// childEnv are the environment entries the rows want on the started
	// process (daemon-started launches only; see markChecked).
	childEnv []string
	// terminalGate is the org's node.features terminals decision for this
	// launch (terminals.feature; launch_terminals_gate.go). Nil allows.
	terminalGate func(r *launchGateRun) (bool, string)
	// inSandboxFn reports whether this launch already runs inside a
	// sandbox box (the CLI marker, or a box's host-side walk); nil is no.
	inSandboxFn func() bool
	// daemonRunsFn reports whether a daemon that holds the node database is
	// running this launch or spawned it (the daemon itself, or a launcher
	// with the daemon-child marker): state.load then never stands in for a
	// missing database (OSH-R-007). Nil is no.
	daemonRunsFn func() bool
	// budgetExempt marks a launch the budget rows do not judge (a dashboard
	// plain shell, which starts no agent, or a dashboard walk with no state
	// source): budget.authority allows it at once.
	budgetExempt bool
	// stateSource loads the config and database for state.load; nil is the
	// launcher's own loader (loadConfigAndDBNoCreate on configPath).
	stateSource func(ctx context.Context, configPath string) (config.Config, *sql.DB, func(), error)

	// sandboxed is the request on the way in and, after sandbox.select, the
	// launch's answer (an upgrade sets it).
	sandboxed bool

	// Filled by the rows, top-down.
	sandboxOnce *bool
	cfg         config.Config
	database    *sql.DB
	closers     []func()
	toolGate    func(tool string) nodeToolGateState
	budget      managedBudgetLaunchState
	budgetStore *store.Store
}

// inSandbox reports whether this launch runs inside a sandbox box.
func (r *launchGateRun) inSandbox() bool {
	return r.inSandboxFn != nil && r.inSandboxFn()
}

// sandboxOn is sandboxGateOn evaluated once per launch, so the two rows that
// read it agree.
func (r *launchGateRun) sandboxOn() bool {
	if r.sandboxOnce == nil {
		on := r.sandboxGateOn != nil && r.sandboxGateOn(r)
		r.sandboxOnce = &on
	}
	return *r.sandboxOnce
}

// close releases what the rows opened, last opened first.
func (r *launchGateRun) close() {
	for i := len(r.closers) - 1; i >= 0; i-- {
		r.closers[i]()
	}
	r.closers = nil
}

// launchGates is the table, in walking order. A new gate is one row here and
// one test in launch_gates_test.go; TestLaunchGateOrder pins the order.
var launchGates = []launchGate{
	{
		id:     "tool.disallow",
		checks: "the org's node.features tools.disallow list, peeked without counting a grant use (the inner launcher counts it)",
		can:    launchGateAllow | launchGateRefuse,
		paths:  launchPathDashboardFresh,
		run:    gateToolDisallow,
	},
	{
		id:     "route.maintenance",
		checks: "whether the launch is a maintenance verb rather than an agent session",
		can:    launchGateAllow | launchGateAllowNow,
		paths:  launchPathCLI,
		run:    gateRouteMaintenance,
	},
	{
		id:     "state.load",
		checks: "that the config and the database the rows below read can be loaded, never creating the database (OSH-R-007)",
		can:    launchGateAllow | launchGateRefuse,
		paths:  launchPathsAll,
		run:    gateStateLoad,
	},
	{
		id:     "terminals.feature",
		checks: "the org's node.features terminals decision (terminals.enabled, sandbox_required) for this launch, the one decision every daemon PTY entry also asks (OSH-R-003); on a managed node a policy that cannot be read refuses",
		can:    launchGateAllow | launchGateRefuse,
		paths:  launchPathCLI,
		run:    gateTerminalFeature,
	},
	{
		id:     "repo.trust",
		checks: "the repository trust check where the agent starts (security section 5.1), sent to Guard as an agent_launch event and decided by S-701 to S-705",
		can:    launchGateAllow | launchGateRefuse | launchGateWarn,
		paths:  launchPathsAll,
		run:    gateRepoTrust,
	},
	{
		id:     "hook.switch",
		checks: "project-scope hook switches where the tool starts, which make its blocking hook not current for this launch (T-910)",
		can:    launchGateAllow,
		paths:  launchPathsAll,
		run:    gateHookSwitch,
	},
	{
		id:     "project.match",
		checks: "the project audience match of the launch directory against the org-signed mapping (security section 7.11), recorded for the hook; never refuses",
		can:    launchGateAllow,
		paths:  launchPathCLI,
		run:    gateProjectMatch,
	},
	{
		id:     "sandbox.select",
		checks: "the sandbox selection for a tool the Guard enforces (sandboxLaunchDecision: proceed, upgrade, or the org_disallow refusal)",
		can:    launchGateAllow | launchGateRefuse | launchGateUpgrade,
		paths:  launchPathsAll,
		run:    gateSandboxSelect,
	},
	{
		id:     "budget.authority",
		checks: "whether a verified managed hard budget applies to this launch",
		can:    launchGateAllow | launchGateAllowNow | launchGateRefuse | launchGateWarn,
		paths:  launchPathsAll,
		run:    gateBudgetAuthority,
	},
	{
		id:     "budget.guard",
		checks: "that the Guard is ready to enforce the managed budget",
		can:    launchGateAllow | launchGateRefuse,
		paths:  launchPathsAll,
		run:    gateBudgetGuard,
	},
	{
		id:     "budget.coverage",
		checks: "that a proven proxy route, exact-process cutoff or unbindable surface covers this launch",
		can:    launchGateAllow | launchGateRefuse,
		paths:  launchPathCLI,
		run:    gateBudgetCoverage,
	},
	{
		id:     "budget.spend",
		checks: "that this tool's managed budget is not already spent",
		can:    launchGateAllow | launchGateRefuse,
		paths:  launchPathsAll,
		run:    gateBudgetSpend,
	},
}

// walkLaunchGates walks rows top-down for r's path: a refusal or an
// allow-now ends the walk, a warning is printed and the walk goes on. It
// releases what the rows opened before it returns.
func walkLaunchGates(r *launchGateRun, rows []launchGate) error {
	defer r.close()
	for _, g := range rows {
		if g.paths&r.path == 0 {
			continue
		}
		step := g.run(r)
		if step.warn != "" && r.stderr != nil {
			fmt.Fprintf(r.stderr, "observer %s: warning: %s\n", r.tool, step.warn)
		}
		if step.refuse != nil {
			return step.refuse
		}
		if step.allowNow {
			return nil
		}
	}
	return nil
}

// cliLaunchGateRun is the run of one `observer <tool>` launch at the
// admission chokepoint. Warnings go to the process's stderr, read now so a
// test that swaps it is honoured.
func cliLaunchGateRun(ctx context.Context, configPath, tool string, evidence budgetLaunchEvidence) *launchGateRun {
	return &launchGateRun{
		ctx:        ctx,
		path:       launchPathCLI,
		tool:       tool,
		stderr:     os.Stderr,
		configPath: configPath,
		evidence:   evidence,
		launchDir:  cliLaunchDir,
		baseToolGate: func(t string) nodeToolGateState {
			return cliLaunchToolGate(configPath, t)
		},
		// A guard that is disabled or off, or a launch already inside a
		// sandbox the dashboard built, costs nothing: no guard is built.
		sandboxGateOn: func(r *launchGateRun) bool {
			return r.cfg.Guard.Enabled && r.cfg.Guard.Mode != "off" && !cliSandboxedEnv()
		},
		guardFor: func(r *launchGateRun) *guard.Guard {
			return cliLaunchGuard(r.ctx, r.cfg, store.New(r.database))
		},
		// A CLI launch is never sandboxed by Observer, so "no sandbox here"
		// is the truth for it whatever the machine could do.
		sandboxProbe:   nil,
		sandboxRefusal: cliSandboxRefusal,
		repoTrustFor: func(r *launchGateRun) *repoTrustDeps {
			return cliRepoTrustDeps(r.cfg, componentSnapshotForConfig(r.cfg), store.New(r.database), r.stderr)
		},
		markChecked: func(_ *launchGateRun, rootHash string) {
			// A standalone launcher process: the agent it starts inherits
			// this process's environment, and the process ends with it.
			_ = os.Setenv(repoTrustCheckedEnv, rootHash)
		},
		terminalGate: launchTerminalGate,
		inSandboxFn:  cliSandboxedEnv,
		daemonRunsFn: runningAsDaemonChild,
	}
}

// daemonLaunch is what a launch the daemon starts itself (an Agent Arena
// candidate or judge, a benchmark attempt, a dashboard GUI launch) tells the
// gate table about where it runs. The daemon's own working directory and
// stdin belong to the daemon, never to the run, so neither is read.
type daemonLaunch struct {
	// dir is the directory the started process runs in; "" means it runs in
	// no repository of the run's own, and the rows that read the launch
	// directory (repo.trust, hook.switch) do not look at one.
	dir string
	// acceptDir, when set, is a source repository whose accepts the run
	// honours instead of its own (an Arena worktree made from it, a
	// benchmark task's local source repository).
	acceptDir string
	// notAgent marks a process that is not an agent launch (a benchmark
	// scorer): the repository trust row does not check it.
	notAgent bool
	// trustSkip, when set, says why the repository trust row does not check
	// this launch; the row says so as a warning when the component is
	// active (a benchmark attempt with no local source repository, whose
	// inner `observer <tool>` launcher checks again).
	trustSkip string
	// trustAdvice, when set, replaces the unattended trust refusal's "accept
	// them for <dir>" advice: a benchmark attempt from a remote task has no
	// directory an accept could cover (benchmarkTrustLaunch).
	trustAdvice string
	// boxed marks the host-side walk of a launch inside a sandbox box
	// (sandboxGateWalk): the terminals row judges it as sandboxed.
	boxed bool
}

// errNoDaemonLaunchDir is the launch directory of a daemon-started launch
// that names none.
var errNoDaemonLaunchDir = errors.New("the daemon-started launch names no directory")

// daemonLaunchGateRun is the CLI path's run for a launch the daemon starts:
// the same rows, but the launch directory is the run's own, the trust row
// never asks (nobody is at the daemon's stdin: an ask refuses and says
// where to accept), and the checked marker goes to the started process's
// environment (childEnv), never to the daemon's.
func daemonLaunchGateRun(ctx context.Context, configPath, tool string, evidence budgetLaunchEvidence, at daemonLaunch) *launchGateRun {
	r := cliLaunchGateRun(ctx, configPath, tool, evidence)
	r.launchDir = func() (string, error) {
		if strings.TrimSpace(at.dir) == "" {
			return "", errNoDaemonLaunchDir
		}
		return at.dir, nil
	}
	r.repoTrustFor = func(r *launchGateRun) *repoTrustDeps {
		if at.notAgent {
			return nil
		}
		return daemonRepoTrustDeps(r.cfg, componentSnapshotForConfig(r.cfg), store.New(r.database), at)
	}
	r.markChecked = func(r *launchGateRun, rootHash string) {
		r.childEnv = append(r.childEnv, repoTrustCheckedEnv+"="+rootHash)
	}
	// The daemon's own environment never says whether the started process
	// runs in a box; the launch says so.
	r.inSandboxFn = func() bool { return at.boxed }
	// The daemon holds the node database; one it cannot see is never
	// replaced by an empty stand-in (OSH-R-007).
	r.daemonRunsFn = func() bool { return true }
	return r
}

// enforceDaemonStartedLaunch is enforceBudgetControlledLaunch for a launch
// the daemon starts itself: it walks the same table through
// daemonLaunchGateRun and returns the environment entries the started
// process carries.
func enforceDaemonStartedLaunch(ctx context.Context, configPath, tool string, evidence budgetLaunchEvidence, at daemonLaunch) ([]string, error) {
	r := daemonLaunchGateRun(ctx, configPath, tool, evidence, at)
	if err := walkLaunchGates(r, launchGates); err != nil {
		return nil, err
	}
	return r.childEnv, nil
}

// gateToolDisallow refuses a tool on the org's disallow list. The wording
// names the request path.
func gateToolDisallow(r *launchGateRun) launchGateStep {
	if r.toolLaunchAllowed == nil || r.toolLaunchAllowed(r.tool) {
		return launchGateStep{}
	}
	return launchGateStep{refuse: fmt.Errorf("%w: your organization disallows %s; request access from the Requests page",
		dashapi.ErrLaunchToolNotAllowed, r.tool)}
}

// gateRouteMaintenance allows a maintenance verb with no later row: it starts
// no agent session, so no sandbox or budget question applies.
func gateRouteMaintenance(r *launchGateRun) launchGateStep {
	if r.evidence.Route == budgetLaunchRouteMaintenance {
		return launchGateStep{allowNow: true}
	}
	return launchGateStep{}
}

// gateStateLoad loads the config and database the rows below read; a load
// failure refuses with the safe-state error. It never creates the node
// database (OSH-R-007): a launcher that cannot see the host's database
// would otherwise answer from a fresh empty one, which reads as "not
// enrolled" and so admits a launch a managed hard budget refuses. With no
// database file, a launch in a sandbox box or run by (or for) a daemon,
// which always has one, refuses; a standalone launch on a host that has
// never run Observer gets an in-memory database, the same empty state a
// new file gave before, with nothing written to disk.
func gateStateLoad(r *launchGateRun) launchGateStep {
	load := r.stateSource
	if load == nil {
		load = loadConfigAndDBNoCreate
	}
	cfg, database, cleanup, err := load(r.ctx, r.configPath)
	if errors.Is(err, errNoNodeDatabase) {
		if r.inSandbox() || (r.daemonRunsFn != nil && r.daemonRunsFn()) {
			return launchGateStep{refuse: budgetLaunchStateFailure(r.tool, fmt.Errorf("%w: this launch cannot see the node database, so a managed budget cannot be checked", err))}
		}
		cfg, database, cleanup, err = openNodeDB(r.ctx, cfg, ":memory:")
		if err == nil {
			// Every connection to ":memory:" is its own empty database, so
			// the rows must share one that is never closed for idleness
			// (audit follow-up F3).
			database.SetMaxOpenConns(1)
			database.SetConnMaxIdleTime(0)
		}
	}
	if err != nil {
		return launchGateStep{refuse: budgetLaunchStateFailure(r.tool, err)}
	}
	r.cfg, r.database = cfg, database
	if cleanup != nil {
		r.closers = append(r.closers, cleanup)
	}
	return launchGateStep{}
}

// gateRepoTrust runs the repository trust check where the agent starts and
// lets Guard decide (repoTrustRun, launch_trust.go). It is inert when the
// path gives no dependencies (security.trust inactive, the guard off, or a
// build without the module, whose launch_trust_omit.go always gives none).
func gateRepoTrust(r *launchGateRun) launchGateStep {
	if r.repoTrustFor == nil || r.launchDir == nil {
		return launchGateStep{}
	}
	deps := r.repoTrustFor(r)
	if deps == nil {
		return launchGateStep{}
	}
	return repoTrustRun(r, deps)
}

// gateHookSwitch narrows the node's tool gate to this launch (T-910). It
// never refuses; sandbox.select reads what it leaves. It does nothing when
// the sandbox selection will not consult the Guard.
func gateHookSwitch(r *launchGateRun) launchGateStep {
	if !r.sandboxOn() {
		return launchGateStep{}
	}
	gate := r.baseToolGate
	if r.launchDir != nil {
		if dir, err := r.launchDir(); err == nil {
			gate = withProjectHookSwitches(gate, launchHookSwitchDirs(dir))
		}
	}
	r.toolGate = gate
	return launchGateStep{}
}

// gateSandboxSelect applies sandboxLaunchDecision, the single owner of the
// selection: an upgrade marks the launch sandboxed, a refusal renders this
// path's wording.
func gateSandboxSelect(r *launchGateRun) launchGateStep {
	var gd *guard.Guard
	if r.sandboxOn() && r.guardFor != nil {
		gd = r.guardFor(r)
	}
	switch sandboxLaunchDecision(gd, r.tool, r.sandboxed, r.sandboxProbe, r.toolGate) {
	case sandboxLaunchUpgrade:
		r.sandboxed = true
		return launchGateStep{upgraded: true}
	case sandboxLaunchRefuse:
		return launchGateStep{refuse: r.sandboxRefusal(r.tool)}
	default:
		return launchGateStep{}
	}
}

// gateBudgetAuthority resolves the managed budget posture from config, the
// verified budget cache and the managed grant. Not required: the launch is
// allowed now. An unverifiable grant without fail_closed warns (D-521).
func gateBudgetAuthority(r *launchGateRun) launchGateStep {
	if r.budgetExempt {
		return launchGateStep{allowNow: true}
	}
	state, err := resolveManagedBudgetLaunchState(r.ctx, r.cfg, r.database)
	if err != nil {
		return launchGateStep{refuse: budgetLaunchStateFailure(r.tool, err)}
	}
	r.budget = state
	return launchGateStep{warn: state.Warning, allowNow: !state.Required}
}

// gateBudgetGuard refuses when a required budget meets a Guard that cannot
// enforce it.
func gateBudgetGuard(r *launchGateRun) launchGateStep {
	if !r.budget.GuardReady {
		return launchGateStep{refuse: budgetLaunchRefusal(r.tool, budgetLaunchCauseGuardNotReady)}
	}
	return launchGateStep{}
}

// gateBudgetCoverage asks budgetLaunchCoverage whether anything can enforce
// the budget on this launch.
func gateBudgetCoverage(r *launchGateRun) launchGateStep {
	if err := budgetLaunchCoverage(r.ctx, r.cfg, r.budgetStoreFor(), r.tool, r.evidence); err != nil {
		return launchGateStep{refuse: err}
	}
	return launchGateStep{}
}

// gateBudgetSpend asks budgetLaunchSpendAdmission whether this tool's budget
// is already spent.
func gateBudgetSpend(r *launchGateRun) launchGateStep {
	if err := budgetLaunchSpendAdmission(r.ctx, r.cfg, r.configPath, r.budgetStoreFor(), r.tool, r.budget); err != nil {
		return launchGateStep{refuse: err}
	}
	return launchGateStep{}
}

// budgetStoreFor is the one store the coverage and spend rows share.
func (r *launchGateRun) budgetStoreFor() *store.Store {
	if r.budgetStore == nil {
		r.budgetStore = store.New(r.database)
	}
	return r.budgetStore
}
