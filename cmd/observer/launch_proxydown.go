package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// launch_proxydown.go is the env launchers' one proxy-down seam (lane
// launcher-proxy-down, 2026-11-24). `observer claude` and `observer codex`
// already walk decideProxyFallback before they launch; the generic env
// launcher (gemini, hermes, pi, aider, ...) and `observer opencode` used to
// print "proxy not reachable ... NOT captured" and then inject the base URL
// anyway, so the tool's first request hit the dead port. This seam gives them
// the same three outcomes:
//
//   - proceed: the proxy answers; the launcher routes as before.
//   - neutralize: launch WITHOUT the route (no injected env, the operator's own
//     argv without the launcher's provider selection, no session-scoped
//     provider writes, no OTel "proxied" marker), with one notice saying so.
//   - fail closed: refuse with the fix, because something the launcher cannot
//     take away would still send the tool into the dead port, or because the
//     organization owns this managed machine's routes.
//
// What the launcher "cannot take away" is decided by the registry's RouteKind
// for the tool (envRouteCarriers), never by its name (CLAUDE.md #3): every
// kind can be pinned by a value the caller exported for a key the launcher
// injects (applyBaseURLEnv never clobbers one), and a persisted kind can also
// be pinned by a route the tool's own config file already holds. The dial and
// every read happen here at the boundary; decideEnvProxyFallback is pure.

// envRouteCarrier says, for one registry RouteKind, where a route the
// launcher did not apply in this run can live.
type envRouteCarrier struct {
	// file: the route is a provider entry in the tool's own config file,
	// which outlives this process. The launcher can drop its own selection of
	// that entry and skip its own session writes; it cannot undo a route the
	// file already held before this launch.
	file bool
}

// envRouteCarriers is keyed by RouteKind (CLAUDE.md #3/#5). A tool with no
// registry route, or a kind with no row, reads as the zero carrier: its only
// route is the environment the launcher injects for this one exec.
var envRouteCarriers = map[integration.RouteKind]envRouteCarrier{
	integration.RouteLauncher:     {},
	integration.RouteProviderJSON: {file: true},
	integration.RouteConfigFile:   {file: true},
	integration.RouteEnvSettings:  {file: true},
}

// envRouteKind is the registry RouteKind of tool's proxy route, "" when the
// tool has no registry row or no route.
func envRouteKind(tool string) integration.RouteKind {
	c, ok := integration.For(tool)
	if !ok || c.Proxy == nil {
		return ""
	}
	return c.Proxy.Kind
}

// envProxyDownFacts is everything decideEnvProxyFallback needs, resolved at
// the boundary as plain data.
type envProxyDownFacts struct {
	// kind is the tool's registry RouteKind ("" = no registry route).
	kind integration.RouteKind
	// proxyReachable reports whether a fresh dial of the proxy succeeded.
	proxyReachable bool
	// presetToProxy names the keys the launcher would inject that the caller
	// already set to a value pointing at the proxy's listener. The launcher
	// keeps a caller's value (applyBaseURLEnv), so dropping its own injection
	// does not take the tool off the proxy.
	presetToProxy []string
	// fileToProxy names the places in the tool's own config that already
	// route a launch to the proxy's listener before this launch touched it.
	// Counted only for a kind whose carrier is a file.
	fileToProxy []string
	// orgRequiresRoute reports a managed node whose organization owns the AI
	// tools' proxy routes (route posture maintain, launchOrgOwnsRoute).
	orgRequiresRoute bool
}

// pinned reports whether a route the launcher cannot take away would still
// send the tool to the proxy.
func (f envProxyDownFacts) pinned() bool {
	return len(f.presetToProxy) > 0 || (envRouteCarriers[f.kind].file && len(f.fileToProxy) > 0)
}

// decideEnvProxyFallback maps the facts onto the shared decideProxyFallback
// table. An env launcher has no --no-proxy-route flag and no override lever
// over a caller's environment or the tool's own config, so a pinned route is
// always a blocking one. Pure.
func decideEnvProxyFallback(f envProxyDownFacts) proxyFallbackDecision {
	return decideProxyFallback(proxyFallbackInputs{
		proxyReachable:          f.proxyReachable,
		persistentRoute:         f.pinned(),
		canNeutralizePersistent: false,
		orgRequiresRoute:        f.orgRequiresRoute,
	})
}

// proxyListenerURL reports whether raw is a URL that reaches the proxy's own
// listener at proxyURL: the same host and port, or both on loopback at the
// same port. The path is not compared: a lane (/up/<id>/...) or the client
// token form (/t/<token>/...) still hits the same port. Pure.
func proxyListenerURL(raw, proxyURL string) bool {
	got, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || got.Host == "" {
		return false
	}
	want, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil || want.Host == "" {
		return false
	}
	if strings.EqualFold(got.Host, want.Host) {
		return true
	}
	return isLoopbackHost(got.Hostname()) && isLoopbackHost(want.Hostname()) &&
		urlPort(got) != "" && urlPort(got) == urlPort(want)
}

// urlPort is u's port, defaulting from the scheme.
func urlPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}

// presetKeysToProxy returns, sorted, the keys of inject the caller already set
// in parent to a value that reaches the proxy's listener. Pure.
func presetKeysToProxy(parent []string, inject map[string]string, proxyURL string) []string {
	var out []string
	for k := range inject {
		if v, ok := lookupEnvValue(parent, k); ok && proxyListenerURL(v, proxyURL) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// envProxyGateRequest is one launch's proxy-down question.
type envProxyGateRequest struct {
	// label is the stderr label ("gemini").
	label string
	// tool is the integration-registry key ("gemini-cli"); "" = label.
	tool       string
	configPath string
	proxyURL   string
	// inject is the environment the launcher would add (nil for a route
	// carried by a file); parentEnv is what the child starts from.
	inject    map[string]string
	parentEnv []string
	// callerPins names caller-set variables whose value is not a plain URL
	// (a JSON config blob) that the launcher knows still route the tool to
	// the proxy. They count like presetToProxy. Nil = none.
	callerPins func() []string
	// fileRoutes, for a launcher whose route is a provider entry in the
	// tool's own config, names the places that config routes a launch to
	// proxyURL even WITHOUT the launcher's own provider selection (read when
	// the gate is asked, so before the launcher's writes when it asks first).
	// Nil = none.
	fileRoutes func() []string
	stderr     io.Writer
}

// envProxyGateOutcome is the seam's verdict for the caller.
type envProxyGateOutcome int

const (
	// envProxyGateProceed: the proxy answers; route as before.
	envProxyGateProceed envProxyGateOutcome = iota
	// envProxyGateNeutralize: the notice is printed; launch without the
	// route.
	envProxyGateNeutralize
)

// envLauncherProxyGate is the seam every env launcher calls before it applies
// a route: it asks launchProxyUp (which starts the daemon when it is down and
// auto-start applies, L-169) and, only when the proxy still does not answer,
// resolves the pinned-route and organization facts and walks
// decideEnvProxyFallback.
// On neutralize it prints the one notice and the caller launches unrouted; on
// fail closed it returns a visible error carrying the fix and nothing starts.
func envLauncherProxyGate(ctx context.Context, req envProxyGateRequest) (envProxyGateOutcome, error) {
	tool := req.tool
	if tool == "" {
		tool = req.label
	}
	// L-169: a daemon found down is started first and waited for
	// (launchProxyUp, launch_autostart.go); only one that cannot come up
	// reaches the pin and organization rows below.
	if launchProxyUp(ctx, launchAutostartRequest{
		label: req.label, configPath: req.configPath, proxyURL: req.proxyURL, wanted: true, stderr: req.stderr,
	}) {
		return envProxyGateProceed, nil
	}
	facts := envProxyDownFacts{
		kind:             envRouteKind(tool),
		presetToProxy:    presetKeysToProxy(req.parentEnv, req.inject, req.proxyURL),
		orgRequiresRoute: launchOrgOwnsRoute(ctx, req.configPath),
	}
	if req.callerPins != nil {
		facts.presetToProxy = uniqueSorted(append(facts.presetToProxy, req.callerPins()...))
	}
	if req.fileRoutes != nil {
		facts.fileToProxy = req.fileRoutes()
	}
	d := decideEnvProxyFallback(facts)
	daemonChild := runningAsDaemonChild()
	if d.action == proxyFailClosed {
		msg := envProxyFailClosedMsg(req.label, req.proxyURL, d.reason, facts, daemonChild)
		return envProxyGateProceed, newVisibleLauncherError(errors.New(msg), msg)
	}
	if req.stderr != nil {
		fmt.Fprintln(req.stderr, envProxyDownNotice(req.label, req.proxyURL, daemonChild))
	}
	return envProxyGateNeutralize, nil
}

// envProxyDownNotice is the one line a neutralized launch prints: what failed,
// what the launch does instead, and what is and is not captured. A build
// without capture.proxy keeps its own notice (D-514), which names the build.
// Pure apart from the build fact.
func envProxyDownNotice(label, proxyURL string, daemonChild bool) string {
	if notice, ok := proxyNotInBuildNotice(label); ok {
		return notice
	}
	return fmt.Sprintf(
		"observer %s: proxy not reachable at %s (%s) - launching %s without proxy routing: its transcript is still captured from its own files while the daemon runs, proxy-only token and cost detail for this run is not.",
		label, redactRouteURL(proxyURL), proxyDownAdvice(daemonChild), label)
}

// envProxyFailClosedMsg is the refusal for a proxy-down launch that cannot be
// taken off the proxy, naming what pins it and the fix. Pure apart from the
// build fact inside proxyDownAdvice.
func envProxyFailClosedMsg(label, proxyURL string, reason proxyFallbackReason, f envProxyDownFacts, daemonChild bool) string {
	at := redactRouteURL(proxyURL)
	fix := proxyDownAdvice(daemonChild)
	switch {
	case reason == reasonProxyDownOrgRoute:
		return fmt.Sprintf(
			"observer %s: refusing to launch - your organization routes AI tools through the Observer proxy on this managed machine, and the proxy at %s is not reachable, so this run would skip the organization's controls. Fix: %s, then re-run.",
			label, at, fix)
	case len(f.presetToProxy) > 0:
		keys := strings.Join(f.presetToProxy, ", ")
		return fmt.Sprintf(
			"observer %s: refusing to launch - %s in your environment points %s at the observer proxy at %s, which is not reachable, and the launcher never overrides a value you set, so every request would fail. Fix: %s; or unset %s to run %s directly. Then re-run.",
			label, keys, label, at, fix, keys, label)
	default:
		src := strings.Join(f.fileToProxy, ", ")
		return fmt.Sprintf(
			"observer %s: refusing to launch - %s already routes %s to the observer proxy at %s, which is not reachable; the launcher can drop its own provider selection but not a route your config holds, so every request would fail. Fix: %s; or point %s away from the proxy to run %s directly. Then re-run.",
			label, src, label, at, fix, src, label)
	}
}
