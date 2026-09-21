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
}

// resolveManagedBudgetLaunchState recomposes the cold-process budget posture
// from its three durable inputs: config, the verified budget cache, and the
// managed governance grant. It intentionally does not consult daemon atomics.
func resolveManagedBudgetLaunchState(ctx context.Context, cfg config.Config, database *sql.DB) (managedBudgetLaunchState, error) {
	if database == nil {
		return managedBudgetLaunchState{}, errors.New("budget launch state: no database")
	}
	st := store.New(database)
	granted, err := resolveBudgetLaunchAuthority(ctx, st)
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
	return composeManagedBudgetLaunchState(cfg, cached, cacheErr, granted), nil
}

// resolveBudgetLaunchAuthority returns a tri-state answer over the durable
// enrolment and grant. A clean solo/individual or explicit non-enforce grant
// is known false. An unreadable or incomplete managed identity is an error,
// because treating missing evidence as revoked authority would create a cold
// launch bypass. Enrolment grants are written only after verification.
func resolveBudgetLaunchAuthority(ctx context.Context, st *store.Store) (bool, error) {
	if st == nil {
		return false, errors.New("budget launch authority: no store")
	}
	enrolment, err := st.LoadEnrolment(ctx)
	if err != nil {
		return false, fmt.Errorf("budget launch authority: %w", err)
	}
	if enrolment == nil {
		return false, nil
	}
	grant, live, err := governanceIdentityLoader(st)(ctx)
	if err != nil {
		return false, fmt.Errorf("budget launch authority: %w", err)
	}
	if grant == nil {
		if enrolment.IsManaged() {
			return false, errors.New("budget launch authority: managed enrolment has no readable grant")
		}
		return false, nil
	}
	effective := govern.Resolve(govern.Delivered{}, grant, live, time.Now().UTC())
	switch effective.State {
	case govern.StateGrantExpired:
		if enrolment.IsManaged() {
			return false, errors.New("budget launch authority: managed enrolment grant is expired")
		}
		return false, nil
	case govern.StateIdentityChanged, govern.StateKeyPinMismatch, govern.StateGrantSignatureInvalid:
		if enrolment.IsManaged() {
			return false, fmt.Errorf("budget launch authority: managed identity is not verifiable (%s)", effective.State)
		}
		return false, nil
	default:
		return effective.GrantsBudgetEnforcement(), nil
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
	if evidence.Route == budgetLaunchRouteMaintenance {
		return nil
	}
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return budgetLaunchStateFailure(tool, err)
	}
	defer cleanup()

	state, err := resolveManagedBudgetLaunchState(ctx, cfg, database)
	if err != nil {
		return budgetLaunchStateFailure(tool, err)
	}
	if !state.Required {
		return nil
	}
	if !state.GuardReady {
		return budgetLaunchRefusal(tool,
			"the configured Guard is disabled or is not in enforce mode")
	}
	st := store.New(database)
	if err := budgetLaunchCoverage(ctx, cfg, st, tool, evidence); err != nil {
		return err
	}
	return budgetLaunchSpendAdmission(ctx, cfg, configPath, st, tool, state)
}

// budgetLaunchCoverage answers question 1 above. Every branch dispatches on a
// registry capability SHAPE — proven route, declared surface class — never on
// the tool's name.
func budgetLaunchCoverage(ctx context.Context, cfg config.Config, st *store.Store, tool string, evidence budgetLaunchEvidence) error {
	capability, _ := integration.For(tool)
	if capability.RouteProven() && evidence.Route == budgetLaunchRouteObserverProxy &&
		urlRoutesToProxy(evidence.ProxyURL, resolveProxyURL(cfg.Proxy.Port, "")) {
		return nil
	}
	if nodeProcessCutoffCoversLaunch(ctx, cfg, st, tool, evidence) {
		return nil
	}
	if budgetLaunchSurfaceUnbindable(tool, evidence) {
		// The registry says this surface has no process boundary a cutoff
		// could ever bind to. Refusing it at $0 would report a coverage gap
		// the org's posture already reports honestly (proxy_only / partial),
		// while blocking work that is under the cap. The spend gate below
		// still applies.
		return nil
	}
	if capability.BudgetAdmissionChannel() != integration.BudgetAdmissionObserverProxy {
		return budgetLaunchRefusal(tool,
			"this tool has no verified Observer budget-admission route")
	}
	return budgetLaunchRefusal(tool,
		"this invocation's final model route is direct or cannot be verified")
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

func budgetLaunchRefusal(tool, reason string) error {
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
