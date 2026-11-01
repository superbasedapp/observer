package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgbudget"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// errBudgetLaunchUncontrolled is returned before an AI vendor process starts
// when a managed hard budget exists but this invocation cannot prove either a
// budget-enforcing proxy route or active exact-process cutoff coverage.
var errBudgetLaunchUncontrolled = errors.New("managed hard budget requires an Observer-controlled request or process-cutoff path")

// budgetLaunchRoute is the launcher's evidence about this invocation's final
// model-request path. The zero value is deliberately unknown: an unset or
// newly-added route cannot accidentally become budget-controlled.
type budgetLaunchRoute uint8

const (
	budgetLaunchRouteUnknown budgetLaunchRoute = iota
	budgetLaunchRouteObserverProxy
	budgetLaunchRouteDirect
	budgetLaunchRouteMaintenance
)

// budgetLaunchEvidence carries runtime route and process evidence. ProxyURL is
// meaningful only for budgetLaunchRouteObserverProxy. Executable and Arguments
// are checked against the live process controller's independently discovered
// installed surface and closed argv declaration; a caller-supplied path alone
// never establishes cutoff coverage.
type budgetLaunchEvidence struct {
	Route      budgetLaunchRoute
	ProxyURL   string
	Executable string
	Arguments  []string
	// SurfaceClass names the registry-declared process class of the surface
	// this invocation starts, when the caller starts something other than the
	// tool's own dedicated CLI (a GUI launch starts a shared IDE/desktop
	// host). Empty means the default: the tool's own launch surface, resolved
	// from the registry by integration.LaunchSurfaceClass.
	SurfaceClass integration.InterventionSurfaceClass
	// OrgRewrote names the base-URL keys a managed node's organization
	// rewrote over the developer's own preset value for this run (CLI-8,
	// D13), so the evidence says the route is the organization's. Empty on
	// an individual node, where the preset always stays.
	OrgRewrote []string
}

// managedBudgetLaunchState separates the organization's requirement from the
// node's readiness to satisfy it. A disabled/observing Guard must not erase a
// verified hard org cap: it makes the controlled launch unavailable instead.
type managedBudgetLaunchState struct {
	Required   bool
	GuardReady bool
	// Granted is the resolved managed enforce.budget authority. It is carried
	// so the spend admission can publish the org's numbers onto a cold guard
	// through the SAME composition boundary the daemon uses, instead of
	// resolving the capability a second time.
	Granted bool
	// Cached is the verified budget document this state was composed from,
	// and CacheErr the read failure that stood in for one. Both travel with
	// the state for the same reason as Granted: the spend admission must
	// publish exactly the document the requirement was decided on.
	Cached   store.OrgBudgetCache
	CacheErr error
	// Warning is set when the managed authority could not be verified for a
	// reason outside the request (an expired or unverifiable grant) and the
	// org did not opt into fail_closed: the launch proceeds on the node's own
	// caps and the launcher says so (REVIEW-4 P4-03, ruling D-521).
	Warning string
}

// resolveManagedBudgetLaunchState recomposes the cold-process budget posture
// from its three durable inputs: config, the verified budget cache, and the
// managed governance grant. It intentionally does not consult daemon atomics.
func resolveManagedBudgetLaunchState(ctx context.Context, cfg config.Config, database *sql.DB) (managedBudgetLaunchState, error) {
	if database == nil {
		return managedBudgetLaunchState{}, errors.New("budget launch state: no database")
	}
	st := store.New(database)
	granted, warning, err := resolveBudgetLaunchAuthority(ctx, st, cfg.Guard.Budget.FailClosed)
	if err != nil {
		return managedBudgetLaunchState{}, err
	}
	var (
		cached   store.OrgBudgetCache
		cacheErr error
	)
	if granted {
		cached, cacheErr = loadVerifiedOrgBudgetCache(ctx, cfg, st)
	} else {
		cached, cacheErr = st.LoadOrgBudget(ctx)
	}
	state := composeManagedBudgetLaunchState(cfg, cached, cacheErr, granted)
	state.Warning = warning
	return state, nil
}

// resolveBudgetLaunchAuthority answers "does the managed enforce.budget
// authority govern this launch?" over the durable enrolment and grant, walking
// budgetLaunchAuthorityRules (CLAUDE.md #5). A clean solo/individual node, a
// confirmed leave (the fenced, tombstoned generation a partly failed leave
// leaves behind) or an explicit non-enforce grant is known false. A store read
// failure is an error (the launch state is unknown).
//
// A managed grant that is missing, expired or not verifiable is a reason
// OUTSIDE the request (D-502). It follows the same switch as the proxy
// (REVIEW-4 P4-03, ruling D-521 "follow fail_closed"): refused only when the
// organization opted into [guard.budget].fail_closed, otherwise the tool
// starts on the node's own caps with a warning.
func resolveBudgetLaunchAuthority(ctx context.Context, st *store.Store, failClosed bool) (granted bool, warning string, err error) {
	if st == nil {
		return false, "", errors.New("budget launch authority: no store")
	}
	enrolment, err := st.LoadEnrolment(ctx)
	if err != nil {
		return false, "", fmt.Errorf("budget launch authority: %w", err)
	}
	if enrolment == nil {
		return false, "", nil
	}
	// The same identity read the proxy uses: a tombstoned generation is a
	// leave that already fenced, so nothing the enrolment conferred governs
	// this launch, exactly as the proxy admits it.
	if _, active, idErr := orgclient.CurrentBudgetIdentity(ctx, st); idErr != nil {
		return false, "", fmt.Errorf("budget launch authority: %w", idErr)
	} else if !active {
		return false, "", nil
	}
	grant, live, err := governanceIdentityLoader(st)(ctx)
	if err != nil {
		return false, "", fmt.Errorf("budget launch authority: %w", err)
	}
	// Managed by enrolment or by its org's switch to enterprise (P-204,
	// govern.GrantIsManaged over the verified grant the loader just read).
	in := budgetLaunchAuthorityInput{managed: enrolment.IsManaged() || govern.GrantIsManaged(grant), noGrant: grant == nil}
	var effective govern.Effective
	if grant != nil {
		effective = govern.Resolve(govern.Delivered{}, grant, live, time.Now().UTC())
		in.state = effective.State
	}
	for _, r := range budgetLaunchAuthorityRules {
		if !r.when(in) {
			continue
		}
		switch r.out {
		case budgetAuthorityUnverifiable:
			problem := r.problem(in)
			if failClosed {
				return false, "", errors.New("budget launch authority: " + problem)
			}
			return false, "the managed budget authority cannot be verified (" + problem +
				"); starting on this machine's own budget settings because the organization did not set guard.budget.fail_closed", nil
		case budgetAuthorityNone:
			return false, "", nil
		default:
			return effective.GrantsBudgetEnforcement(), "", nil
		}
	}
	return effective.GrantsBudgetEnforcement(), "", nil
}

// budgetLaunchAuthority is one outcome of budgetLaunchAuthorityRules.
type budgetLaunchAuthority uint8

const (
	// budgetAuthorityFromGrant: the verified grant decides.
	budgetAuthorityFromGrant budgetLaunchAuthority = iota
	// budgetAuthorityNone: no managed authority governs this launch.
	budgetAuthorityNone
	// budgetAuthorityUnverifiable: a managed grant exists in principle but
	// cannot be verified now; the fail_closed switch decides.
	budgetAuthorityUnverifiable
)

// budgetLaunchAuthorityInput is what the launcher knows about the grant.
type budgetLaunchAuthorityInput struct {
	managed bool
	noGrant bool
	state   govern.State
}

// budgetLaunchAuthorityRules is the ordered table resolveBudgetLaunchAuthority
// walks; one test case per row (TestBudgetLaunchAuthorityRules).
var budgetLaunchAuthorityRules = []struct {
	name    string
	when    func(budgetLaunchAuthorityInput) bool
	out     budgetLaunchAuthority
	problem func(budgetLaunchAuthorityInput) string
}{
	{
		name: "managed_no_grant", when: func(in budgetLaunchAuthorityInput) bool { return in.managed && in.noGrant },
		out: budgetAuthorityUnverifiable, problem: func(budgetLaunchAuthorityInput) string { return "managed enrolment has no readable grant" },
	},
	{name: "individual_no_grant", when: func(in budgetLaunchAuthorityInput) bool { return in.noGrant }, out: budgetAuthorityNone},
	{name: "managed_grant_expired", when: func(in budgetLaunchAuthorityInput) bool {
		return in.managed && in.state == govern.StateGrantExpired
	}, out: budgetAuthorityUnverifiable, problem: func(budgetLaunchAuthorityInput) string { return "managed enrolment grant is expired" }},
	{name: "managed_identity_unverifiable", when: func(in budgetLaunchAuthorityInput) bool {
		return in.managed && budgetLaunchUnverifiableState(in.state)
	}, out: budgetAuthorityUnverifiable, problem: func(in budgetLaunchAuthorityInput) string {
		return fmt.Sprintf("managed identity is not verifiable (%s)", in.state)
	}},
	{name: "individual_grant_unusable", when: func(in budgetLaunchAuthorityInput) bool {
		return in.state == govern.StateGrantExpired || budgetLaunchUnverifiableState(in.state)
	}, out: budgetAuthorityNone},
	{name: "verified_grant", when: func(budgetLaunchAuthorityInput) bool { return true }, out: budgetAuthorityFromGrant},
}

// budgetLaunchUnverifiableState names the governance states in which the
// grant's identity cannot be verified.
func budgetLaunchUnverifiableState(s govern.State) bool {
	switch s {
	case govern.StateIdentityChanged, govern.StateKeyPinMismatch, govern.StateGrantSignatureInvalid:
		return true
	default:
		return false
	}
}

// composeManagedBudgetLaunchState is the pure half of the cold resolver. The
// same orgbudget.Compose function used by the daemon owns all cap arithmetic.
// A cache read error is absence of verified evidence, which becomes the B-625
// blocking ceiling only when the managed grant requires the org budget.
func composeManagedBudgetLaunchState(cfg config.Config, cached store.OrgBudgetCache, cacheErr error, granted bool) managedBudgetLaunchState {
	guardMode := cfg.Guard.Mode
	if !cfg.Guard.Enabled {
		guardMode = "off"
	}
	caps := orgbudget.Capabilities{
		FromOrg:          cfg.Guard.Budget.FromOrg,
		OrgAuthoritative: granted,
		RequireOrgBudget: granted,
		FailClosed:       cfg.Guard.Budget.FailClosed,
		GuardMode:        guardMode,
	}
	switch {
	case cacheErr != nil:
		caps.FetchState = orgcontract.BudgetFetchUnverified
	case cached.Have:
		caps.HaveBody = true
		caps.FetchState = orgcontract.BudgetFetchUnreachable
	default:
		caps.FetchState = initialFetchState(cfg.Guard.Budget.FromOrg)
	}
	_, posture := orgbudget.Compose(thresholdsOf(cfg.Guard.Budget), cached.Body, caps)
	return managedBudgetLaunchState{
		Required: granted && posture.Hard && posture.Capped,
		GuardReady: cfg.Guard.Enabled &&
			strings.EqualFold(strings.TrimSpace(cfg.Guard.Mode), "enforce"),
		Granted:  granted,
		Cached:   cached,
		CacheErr: cacheErr,
	}
}

// enforceBudgetControlledLaunch refuses before process start when an active
// managed hard budget cannot govern the invocation, and — the point of the
// boundary — when the budget it CAN govern is already spent.
//
// The two questions are asked in order and they are different questions:
//
//  1. COVERAGE. Is there an enforcement point for this invocation at all: an
//     Observer proxy route the registry says is proven, live exact-process
//     cutoff over this launch, or a surface the registry says no process
//     cutoff could ever bind to (a shared IDE/desktop host), which is covered
//     by the org's existing proxy_only/partial posture rather than by a
//     refusal at $0.
//  2. SPEND. Would this invocation's own tool be denied right now? A launch
//     UNDER the cap runs; an exhausted cap, or accounting this tool's own
//     source cannot establish, refuses HERE rather than letting the vendor
//     process start and be killed a reconcile cycle later with nothing said
//     at the terminal.
//
// Config, database, and governance read failures return a safe-state error; an
// unreadable budget cache under verified managed authority composes the B-625
// blocking posture.
func enforceBudgetControlledLaunch(ctx context.Context, configPath, tool string, evidence budgetLaunchEvidence) error {
	return enforceBudgetControlledLaunchIn(ctx, configPath, tool, evidence, "")
}

// enforceBudgetControlledLaunchIn is enforceBudgetControlledLaunch for a
// launch that opens dir (`observer ide <app> <folder>`, FU-190): the gate
// rows that read the launch directory (repo trust, the hook switch) read the
// folder the app opens, not this process's working directory. An empty dir
// keeps the working directory (a launch that opens no folder).
func enforceBudgetControlledLaunchIn(ctx context.Context, configPath, tool string, evidence budgetLaunchEvidence, dir string) error {
	// The gates and their order are the launch-gate table (launch_gates.go):
	// the maintenance skip, the state load, the T-910 hook switch and the
	// org's "No sandbox available" choice (T-497, the same decision the
	// dashboard's fresh launch makes), then the two budget questions above.
	//
	// Inside a sandbox box (lane sbx-p2) the node database is not there:
	// the same walk runs host-side through the capture relay
	// (hook_relay.go boxLaunchGate, sandbox_relay.go runSandboxGate).
	if err, boxed := boxLaunchGate(tool, evidence); boxed {
		return err
	}
	r := cliLaunchGateRun(ctx, configPath, tool, evidence)
	if dir != "" {
		r.launchDir = func() (string, error) { return dir, nil }
	}
	return walkLaunchGates(r, launchGates)
}

// budgetLaunchCoverage answers question 1 above through the one cause
// classifier (budgetlaunch_remedy.go), which the New Terminal picker's
// preflight also asks, so the picker and the launcher never disagree.
func budgetLaunchCoverage(ctx context.Context, cfg config.Config, st *store.Store, tool string, evidence budgetLaunchEvidence) error {
	var why string
	cause := budgetLaunchCoverageCause(func() bool {
		var covered bool
		covered, why = nodeProcessCutoffCoverage(ctx, cfg, st, tool, evidence)
		return covered
	}, tool, evidence, resolveProxyURL(cfg.Proxy.Port, ""))
	if cause == budgetLaunchCovered {
		return nil
	}
	return budgetLaunchRefusalWith(tool, cause, why)
}

// budgetLaunchSurfaceUnbindable reports whether the registry declares that no
// process cutoff can bind to the surface this launch starts. An UNKNOWN tool
// is never unbindable: an undeclared row must keep the refusal, not inherit an
// exemption.
func budgetLaunchSurfaceUnbindable(tool string, evidence budgetLaunchEvidence) bool {
	class := evidence.SurfaceClass
	if class == "" {
		resolved, ok := integration.LaunchSurfaceClass(tool)
		if !ok {
			return false
		}
		class = resolved
	}
	switch class {
	case integration.SurfaceSharedHost, integration.SurfaceRemoteExecution:
		return true
	default:
		return false
	}
}

// budgetLaunchRefusal renders a coverage refusal: the cause's reason, then
// what the developer can do about it (T-685), so the refusal is never a dead
// end in the CLI or in a dashboard terminal, which shows the same text.
func budgetLaunchRefusal(tool string, cause budgetLaunchCause) error {
	return budgetLaunchRefusalWith(tool, cause, "")
}

// budgetLaunchRefusalWith is budgetLaunchRefusal carrying the live process-
// cutoff check that failed for this launch (empty when none was asked).
func budgetLaunchRefusalWith(tool string, cause budgetLaunchCause, why string) error {
	advice, ok := budgetLaunchAdviceFor(cause)
	if !ok {
		advice = budgetLaunchAdvice{reason: "no enforcement point covers this invocation"}
	}
	capability, _ := integration.For(tool)
	reason := advice.reason
	if advice.remedy != nil {
		reason += ". " + budgetLaunchRemedySentence(advice.remedy(capability, budgetLaunchCutoffGapClause(tool, why)))
	}
	err := fmt.Errorf("observer %s: %w; refusing to start the AI process because %s",
		tool, errBudgetLaunchUncontrolled, reason)
	return newVisibleLauncherError(err, err.Error())
}

func budgetLaunchStateFailure(tool string, cause error) error {
	err := fmt.Errorf("observer %s: cannot determine safe launch state: %w", tool, cause)
	return newVisibleLauncherError(err, fmt.Sprintf(
		"observer %s: cannot verify the managed-budget launch state; refusing to start the AI process",
		tool))
}

// envBudgetLaunchEvidence verifies the final environment route of a shared
// env launcher. Provider/config flags can make an otherwise-correct base URL
// irrelevant, so those invocations remain unknown. Config-file-only routes
// have no final env value to prove and also remain unknown.
func envBudgetLaunchEvidence(tool, proxyURL string, expected map[string]string, actualEnv, args []string) budgetLaunchEvidence {
	capability, _ := integration.For(tool)
	// The registry owns BOTH halves of the question: whether applying this
	// route proves the backend at all (RouteProven), and which product-
	// specific argv keys take that proof away (RouteSelectorArguments). No
	// tool name is compared here (CLAUDE.md #3).
	if !capability.RouteProven() || strings.TrimSpace(capability.Proxy.EnvVar) == "" ||
		ambiguousBudgetRoutingArgs(capability, args) {
		return budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
	}
	if !budgetLaunchEnvironmentMatches(capability.Proxy.EnvVar, proxyURL, expected, actualEnv) {
		return budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
	}
	return budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: proxyURL}
}

// fileRouteBudgetLaunchEvidence verifies a config-file route (T-208): a
// capability whose proven route is a provider entry the launcher wrote and
// selected, rather than an env var. The evidence is the entry's base URL read
// back from the file right before the process starts; it must be the proxy
// plus the route's own suffix. An operator selector in args (generic or the
// row's SelectorArguments) leaves the route unknown, exactly as for an env
// route. No tool name is compared here (CLAUDE.md #3).
func fileRouteBudgetLaunchEvidence(tool, proxyURL string, readBack func() (string, bool), args []string) budgetLaunchEvidence {
	capability, _ := integration.For(tool)
	if readBack == nil || !capability.RouteProven() || strings.TrimSpace(capability.Proxy.EnvVar) != "" ||
		ambiguousBudgetRoutingArgs(capability, args) {
		return budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
	}
	base, ok := readBack()
	want := strings.TrimRight(proxyURL, "/") + capability.Proxy.Suffix
	if !ok || strings.TrimRight(strings.TrimSpace(base), "/") != strings.TrimRight(want, "/") {
		return budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}
	}
	return budgetLaunchEvidence{Route: budgetLaunchRouteObserverProxy, ProxyURL: proxyURL}
}

// budgetLaunchEnvironmentMatches requires every non-secret routing value the
// launcher intended to set to survive into the child. Checking only the
// capability's primary base-URL variable is insufficient for multi-variable
// routes such as Copilot's provider type: an ambient non-OpenAI provider can
// otherwise make the injected base URL irrelevant.
func budgetLaunchEnvironmentMatches(proxyKey, proxyURL string, expected map[string]string, actualEnv []string) bool {
	want, ok := expected[proxyKey]
	if !ok || strings.TrimSpace(want) == "" {
		return false
	}
	for key, want := range expected {
		got, present := lookupEnvValue(actualEnv, key)
		if !present || strings.TrimSpace(got) == "" {
			return false
		}
		if key == proxyKey {
			if !urlRoutesToProxy(got, proxyURL) {
				return false
			}
			continue
		}
		if got != want {
			return false
		}
	}
	return true
}

// genericBudgetRoutingSelectors are the CROSS-VENDOR argv spellings that can
// outrank or bypass a launcher's environment route. They are owned here
// because they belong to no single product; a vendor's own selectors live on
// its registry row (ProxyRoute.SelectorArguments).
func genericBudgetRoutingSelectors() []string {
	return []string{
		"--provider", "--model-provider", "--model_provider",
		"--base-url", "--base_url", "--api-base", "--api_base",
		"--api-host", "--api_host", "--config", "--settings", "--profile",
	}
}

// ambiguousBudgetRoutingArgs recognizes the generic and registry-declared
// provider or config selectors that can outrank a launcher's applied route.
// The scan stops at a bare -- because later tokens are positional input for
// these launchers, and it compares the token before any '=' so a joined
// --flag=value form cannot slip past.
func ambiguousBudgetRoutingArgs(capability integration.Capability, args []string) bool {
	selectors := make(map[string]bool, 24)
	for _, key := range genericBudgetRoutingSelectors() {
		selectors[key] = true
	}
	for _, key := range capability.RouteSelectorArguments() {
		selectors[key] = true
	}
	for _, arg := range args {
		if arg == "--" {
			break
		}
		key := arg
		if i := strings.IndexByte(key, '='); i >= 0 {
			key = key[:i]
		}
		if selectors[key] {
			return true
		}
	}
	return false
}
