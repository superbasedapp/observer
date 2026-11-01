//go:build !sbo_omit_ingest_otlp

package main

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/otlpvendor"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
)

// otlp_proxyroute.go resolves, at the OTLP ingest boundary, whether a tool's
// proxy route is active on this node (T-536, operator ruling D-343 "proxy
// owns tokens"). The decision itself lives in otlpvendor's admission table;
// this file only turns configuration into the AdmitInput.ProxyRouted fact.
//
// Two sources, both capability-shaped (never a tool-name switch):
//   - the tool's PERSISTED route (proxyroute.InspectRoutes, the read-only
//     inspector table keyed by the registry's RouteKind) points at an
//     Observer proxy, and the node runs its proxy;
//   - per export: the run was started by an Observer launcher, which marks
//     the tool's OpenTelemetry resource (otlpvendor.RouteResourceAttr), read
//     by otlpvendor as Turn.ViaProxyRoute.
//
// The persisted-route answer is cached for otlpRouteTTL so turning a route
// on or off takes effect without a daemon restart and an export burst does
// not re-read config files per record.

// otlpRouteTTL is how long one inspection of the persisted routes is reused.
const otlpRouteTTL = 30 * time.Second

// proxyRouteResolver answers "does this tool's persisted proxy route point at
// this node's proxy". Safe for concurrent use.
type proxyRouteResolver struct {
	enabled bool
	inspect func() []proxyroute.RouteStatus
	now     func() time.Time

	mu     sync.Mutex
	at     time.Time
	routed map[string]bool
}

// newProxyRouteResolver builds the resolver for a node. proxyServing is
// proxyServingReason(...) == "": the build carries capture.proxy, the
// component is active and [proxy].enabled is on. A route pointing at a proxy
// this node does not run cannot have produced proxy rows, so it never owns
// tokens here (REVIEW-4 P4-18).
func newProxyRouteResolver(proxyServing bool, homeDir string) *proxyRouteResolver {
	return &proxyRouteResolver{
		enabled: proxyServing,
		// A route in the file whose tool talks to another provider does not
		// reach the proxy, so it owns no tokens (CLI-3).
		inspect: func() []proxyroute.RouteStatus {
			return proxyroute.ApplyActiveProvider(proxyroute.InspectRoutes(homeDir))
		},
		now: time.Now,
	}
}

// Routed reports whether tool's persisted route is active.
func (r *proxyRouteResolver) Routed(tool string) bool {
	if r == nil || !r.enabled {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.routed == nil || r.now().Sub(r.at) >= otlpRouteTTL {
		r.routed = routedTools(r.inspect())
		r.at = r.now()
	}
	return r.routed[tool]
}

// routedTools is the set of tools whose persisted route points at an
// Observer proxy.
func routedTools(statuses []proxyroute.RouteStatus) map[string]bool {
	out := make(map[string]bool, len(statuses))
	for _, s := range statuses {
		if s.State == proxyroute.RouteOurs {
			out[s.Tool] = true
		}
	}
	return out
}

// otlpTokenOwnerCheck is the doctor row that explains T-536: for every
// mapped tool whose persisted proxy route is active and whose export cannot
// merge into the proxy's rows, the proxy owns the token rows and the export
// adds only what the proxy cannot see. statuses is the persisted-route
// inspection (injected so the check is testable without real config files).
// proxyOff is proxyServingReason for this node: "" when it serves the proxy,
// else the one reason it does not, which the row states (REVIEW-4 P4-18).
func otlpTokenOwnerCheck(cfg config.Config, proxyOff string, statuses []proxyroute.RouteStatus) diag.Check {
	const name = "otlp.token_owner"
	if !cfg.Ingest.OTel.Enabled {
		return diag.Check{Name: name, Status: diag.StatusOK, Message: "OTLP ingest is off ([ingest.otel].enabled = false): no export can double a proxied call"}
	}
	details := []string{
		"a tool both proxied and exporting telemetry would report each call twice; the proxy owns the tokens (operator ruling D-343)",
		fmt.Sprintf("a run started with `observer <tool>` marks its telemetry with %s=%s, so its export is treated as proxied too", otlpvendor.RouteResourceAttr, otlpvendor.RouteProxy),
	}
	if proxyOff != "" {
		return diag.Check{Name: name, Status: diag.StatusOK, Message: proxyOff + ": OTLP exports keep their token rows", Details: details}
	}
	routed := routedTools(statuses)
	var owned []string
	for _, v := range otlpvendor.Vendors() {
		if v.Grain != otlpvendor.GrainUser || v.Owner.TokensMergeWithProxy || !routed[v.Tool] {
			continue
		}
		owned = append(owned, v.Tool)
	}
	sort.Strings(owned)
	if len(owned) == 0 {
		return diag.Check{Name: name, Status: diag.StatusOK, Message: "no exporting tool has a persisted proxy route: OTLP exports keep their token rows", Details: details}
	}
	for _, tool := range owned {
		details = append(details, fmt.Sprintf("%s: proxy route active, so its OTLP export's token rows are dropped; its tool calls and content still follow the transcript rule (they land while the tool's transcript capture is off)", tool))
	}
	return diag.Check{
		Name:    name,
		Status:  diag.StatusOK,
		Message: "the proxy owns token rows for: " + strings.Join(owned, ", "),
		Details: details,
	}
}
