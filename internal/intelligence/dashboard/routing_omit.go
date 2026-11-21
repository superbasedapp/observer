//go:build sbo_omit_proxy_routing

package dashboard

import (
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// routing_omit.go is the off side of routing.go and routingpolicy.go: in a
// `-tags sbo_omit_proxy_routing` build (component proxy.routing compiled
// out) the Routing page routes stay registered and answer 404
// component_not_installed, reason not_compiled, and this package does not
// import internal/routing or internal/routingconfig (lane MP-L1I, T-715).
// The [routing] section form still saves its plain keys; a rules fragment
// is refused, because nothing can lint it.

// handleRoutingStatus refuses: proxy.routing is not in this build.
func (s *Server) handleRoutingStatus(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "proxy.routing")
}

// handleRoutingDecisions refuses: proxy.routing is not in this build.
func (s *Server) handleRoutingDecisions(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "proxy.routing")
}

// handleRoutingSavings refuses: proxy.routing is not in this build.
func (s *Server) handleRoutingSavings(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "proxy.routing")
}

// handleRoutingTiers refuses: proxy.routing is not in this build.
func (s *Server) handleRoutingTiers(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "proxy.routing")
}

// handleRoutingHealth refuses: proxy.routing is not in this build.
func (s *Server) handleRoutingHealth(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "proxy.routing")
}

// handleRoutingShadow refuses: proxy.routing is not in this build.
func (s *Server) handleRoutingShadow(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "proxy.routing")
}

// handleRoutingSimulate refuses: proxy.routing is not in this build.
func (s *Server) handleRoutingSimulate(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "proxy.routing")
}

// handleRoutingPolicy refuses: proxy.routing is not in this build.
func (s *Server) handleRoutingPolicy(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "proxy.routing")
}

// handleRoutingPolicyLint refuses: proxy.routing is not in this build.
func (s *Server) handleRoutingPolicyLint(w http.ResponseWriter, _ *http.Request) {
	writeCompiledOut(w, "proxy.routing")
}

// routingPolicyTemplateNames is empty: the policy templates are not in
// this build, so the section form accepts only "custom".
func routingPolicyTemplateNames() []string { return nil }

// checkRoutingRulesTOML refuses every rules fragment: the compiler that
// lints it is not in this build.
func checkRoutingRulesTOML(config.RoutingConfig, string) ([]config.RoutingRuleConfig, []string) {
	return nil, []string{"model routing (proxy.routing) is not in this build, so a rules fragment cannot be checked"}
}

// newRoutingLintErrors finds nothing: the compiler is not in this build. A
// shape save still passes the dashboard's row checks and the loader's
// [routing] checks (routing_shapes.go); a daemon without routing only loads
// these shapes, it never compiles them.
func newRoutingLintErrors(config.RoutingConfig, config.RoutingConfig) []string { return nil }
