package cloudsession

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// worker.go is the pure planner behind `observer cloud-session worker`
// (lane CA-C4, the customer-compute proxy; plan of record
// docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md
// section 10, decision CA-D10).
//
// On compute the CUSTOMER runs (a Claude Code self-hosted environment, a
// GitHub Actions self-hosted runner driving the Copilot cloud agent, a Devin
// Outpost, a Warp self-hosted worker) the Observer API proxy can run inside
// the worker for the length of one run, and the agent's base URL can point
// at it, so accurate tokens, conversation compression and model routing work
// as they do on a laptop. On a VENDOR-hosted sandbox none of that is
// attempted (CA-D10): the worker table refuses.
//
// Every decision is a table walked top-down (CLAUDE.md module rules #3 and
// #5): the vendor-hosted refusal table (hostedRules), the worker environment
// table (workerEnvironments, each with its own customer-compute proof rows),
// the verdict table (workerVerdictRules) and the lifecycle step tables
// (workerLifecycles). How a harness is routed comes from its
// internal/integration registry row (ProxyRoute.EnvVar / Suffix / Lane /
// Gate), never from its tool name.

// WorkerAttestEnv is the variable a worker's administrator sets in the
// worker's own environment (the runner service, the worker image, the
// Outpost host; never a repository file) to the environment id, attesting
// that the machine is customer-run compute. It is the proof for the
// environments whose vendor documents no customer-compute marker. A
// vendor-hosted marker always wins over it (hostedRules run first).
const WorkerAttestEnv = "SBO_CUSTOMER_WORKER"

// RouteSink is how a worker hands the route (the base-URL variables) to the
// agent. Each sink is one row of the sink table.
type RouteSink string

// The route sinks.
const (
	// SinkChild sets the route on a child process `worker run` starts; the
	// route lives exactly as long as that child.
	SinkChild RouteSink = "child"
	// SinkGitHubEnv appends NAME=value lines to the file $GITHUB_ENV names,
	// the documented GitHub Actions way to hand a variable to later steps
	// of the same job. Route off appends the previous value (or an empty
	// one) back.
	SinkGitHubEnv RouteSink = "github-env"
	// SinkEnvFile writes a POSIX `export NAME=value` file in the worker's
	// state directory for the environment's own setup to source. Route off
	// deletes it.
	SinkEnvFile RouteSink = "env-file"
)

// sinkSpec is one row of the sink table.
type sinkSpec struct {
	sink RouteSink
	// background reports whether the sink works with `worker start` (the
	// proxy outlives the command); SinkChild needs `worker run`.
	background bool
	// needsEnv names a variable the sink requires (GITHUB_ENV).
	needsEnv string
}

// sinks is THE sink table.
var sinks = []sinkSpec{
	{sink: SinkChild},
	{sink: SinkGitHubEnv, background: true, needsEnv: "GITHUB_ENV"},
	{sink: SinkEnvFile, background: true},
}

// RouteSinks returns every sink name, in table order.
func RouteSinks() []string {
	out := make([]string, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, string(s.sink))
	}
	return out
}

func sinkFor(s RouteSink) (sinkSpec, bool) {
	for _, r := range sinks {
		if r.sink == s {
			return r, true
		}
	}
	return sinkSpec{}, false
}

// HostedRule is one row of the vendor-hosted refusal table: a marker that
// proves the process runs in a VENDOR-hosted sandbox.
type HostedRule struct {
	Marker Marker
	// What names the sandbox in the refusal.
	What string
	// Grounding records how the marker is known.
	Grounding string
}

// hostedRules is THE vendor-hosted refusal table, walked before any
// customer-compute proof for every environment: a vendor-hosted marker
// always refuses, whatever the worker attestation says.
var hostedRules = []HostedRule{
	{
		Marker:    Marker{Env: "CLAUDE_CODE_REMOTE", Equals: "true", AlsoEnv: "CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE", AlsoEquals: "cloud_default", Location: ExecutionVendorCloud},
		What:      "Claude Code on the web (an Anthropic-hosted cloud environment)",
		Grounding: "Live-grounded: CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE=cloud_default in Anthropic-hosted sessions (grounding/claude-code-cloud-2026-10-31.md, and again in the CA-C4 lane session 2026-11-01).",
	},
	{
		Marker:    Marker{Env: "GITHUB_ACTIONS", Equals: "true", AlsoEnv: "RUNNER_ENVIRONMENT", AlsoEquals: "github-hosted", Location: ExecutionVendorCloud},
		What:      "a GitHub-hosted Actions runner (the Copilot cloud agent's default sandbox)",
		Grounding: "GitHub documents RUNNER_ENVIRONMENT as github-hosted or self-hosted.",
	},
}

// HostedRules returns a copy of the vendor-hosted refusal table.
func HostedRules() []HostedRule {
	out := make([]HostedRule, len(hostedRules))
	copy(out, hostedRules)
	return out
}

// WorkerEnvironment is one row of the worker table: one kind of
// customer-run compute an agent can run on.
type WorkerEnvironment struct {
	// ID is the --env value.
	ID string
	// DisplayName is the vendor product shown in messages.
	DisplayName string
	// Proof are the customer-compute proof rows, walked top-down after the
	// vendor-hosted refusal table; the first match proves the machine is
	// customer-run (every row's Location is ExecutionCustomerWorker).
	Proof []Marker
	// ProofHint tells the operator how to satisfy Proof when nothing
	// matched.
	ProofHint string
	// Harnesses are the internal/integration registry tools whose MODEL
	// calls leave from the worker, so the proxy can carry them. The first is
	// the default. Empty when the vendor keeps inference off the worker.
	Harnesses []string
	// NoHarnessReason says why Harnesses is empty.
	NoHarnessReason string
	// Sinks are the route sinks this environment can use; the first
	// background sink is `worker start`'s default.
	Sinks []RouteSink
	// Grounding records what is verified and what is not.
	Grounding string
	// LiveCheck names the live check still owed on that environment.
	LiveCheck string
}

// workerEnvironments is THE worker table (CA-D10's four customer-run
// environments).
var workerEnvironments = []WorkerEnvironment{
	{
		ID:          "claude-code-self-hosted",
		DisplayName: "Claude Code self-hosted environment",
		Proof: []Marker{
			// CLAUDE_CODE_REMOTE=true marks every Claude Code cloud session;
			// the self-hosted value of CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE is
			// not grounded, so the administrator's attestation completes the
			// proof (the Anthropic-hosted value cloud_default is refused
			// first by hostedRules).
			{Env: "CLAUDE_CODE_REMOTE", Equals: "true", AlsoEnv: WorkerAttestEnv, AlsoEquals: "claude-code-self-hosted", Location: ExecutionCustomerWorker},
		},
		ProofHint: "set " + WorkerAttestEnv + "=claude-code-self-hosted in the self-hosted environment's own runtime (not in the repository)",
		Harnesses: []string{"claude-code"},
		Sinks:     []RouteSink{SinkChild, SinkEnvFile},
		Grounding: "The Anthropic-hosted marker is live-grounded; the self-hosted environment's variables are not.",
		LiveCheck: "On a Claude Code self-hosted environment: record CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE (to add a proof row without the attestation), whether the control plane supplies ANTHROPIC_BASE_URL (the worker then reports own_endpoint and stays unrouted), and that a routed turn lands an api_turns row.",
	},
	{
		ID:          "copilot-self-hosted-runner",
		DisplayName: "GitHub Copilot cloud agent on a self-hosted runner",
		Proof: []Marker{
			{Env: "GITHUB_ACTIONS", Equals: "true", AlsoEnv: "RUNNER_ENVIRONMENT", AlsoEquals: "self-hosted", Location: ExecutionCustomerWorker},
		},
		ProofHint: "run it in a job on a self-hosted runner (GitHub sets RUNNER_ENVIRONMENT=self-hosted there)",
		// The cloud agent's own model traffic is GitHub-hosted; only the
		// bring-your-own-key provider lane rides a base URL (the registry
		// row's RouteGate decides).
		Harnesses: []string{"copilot-cli"},
		Sinks:     []RouteSink{SinkGitHubEnv, SinkChild, SinkEnvFile},
		Grounding: "RUNNER_ENVIRONMENT is GitHub-documented; the route is the copilot-cli registry row's BYOK lane (live-verified for the CLI, not for the cloud agent).",
		LiveCheck: "On a self-hosted runner with a Copilot cloud agent task: that a variable written to $GITHUB_ENV in copilot-setup-steps reaches the agent's process, and whether the agent honours COPILOT_PROVIDER_BASE_URL with a BYOK key.",
	},
	{
		ID:          "devin-outpost",
		DisplayName: "Devin Outpost worker",
		Proof: []Marker{
			{Env: WorkerAttestEnv, Equals: "devin-outpost", Location: ExecutionCustomerWorker},
		},
		ProofHint:       "set " + WorkerAttestEnv + "=devin-outpost in the Outpost worker's service environment",
		NoHarnessReason: "Devin keeps the agent loop, and with it the model calls, in its own cloud; an Outpost worker runs tools only (reference chapter 05, DV18), so no model call leaves the worker for the proxy to carry",
		Sinks:           []RouteSink{SinkChild, SinkEnvFile},
		Grounding:       "From the reviewed vendor docs only; no Outpost was available.",
		LiveCheck:       "On a Devin Outpost: whether the Devin CLI worker makes any model call itself (then add its harness row) and which variable marks the worker.",
	},
	{
		ID:          "warp-self-hosted-worker",
		DisplayName: "Warp self-hosted worker (oz-agent-worker)",
		Proof: []Marker{
			{Env: WorkerAttestEnv, Equals: "warp-self-hosted-worker", Location: ExecutionCustomerWorker},
		},
		ProofHint: "set " + WorkerAttestEnv + "=warp-self-hosted-worker in the oz-agent-worker service environment",
		// Warp runs third-party harnesses (Claude Code, Codex) on the
		// worker; Warp's own agent keeps inference routing in Warp's cloud.
		Harnesses: []string{"claude-code", "codex"},
		Sinks:     []RouteSink{SinkChild, SinkEnvFile},
		Grounding: "From the reviewed vendor docs only (harness-usage covers the Claude Code and Codex harnesses); no worker was available.",
		LiveCheck: "On a Warp self-hosted worker: that a Claude Code harness run started by the worker inherits the route (`worker run` in unmanaged mode, or the env file sourced by the worker service), and which variable marks the worker.",
	},
}

// WorkerEnvironments returns a copy of the worker table, in table order.
func WorkerEnvironments() []WorkerEnvironment {
	out := make([]WorkerEnvironment, len(workerEnvironments))
	copy(out, workerEnvironments)
	return out
}

// WorkerEnvironmentIDs returns every environment id, sorted.
func WorkerEnvironmentIDs() []string {
	ids := make([]string, 0, len(workerEnvironments))
	for _, e := range workerEnvironments {
		ids = append(ids, e.ID)
	}
	sort.Strings(ids)
	return ids
}

// WorkerEnvironmentByID returns the worker table row for id.
func WorkerEnvironmentByID(id string) (WorkerEnvironment, error) {
	for _, e := range workerEnvironments {
		if e.ID == id {
			return e, nil
		}
	}
	return WorkerEnvironment{}, fmt.Errorf("cloudsession: unknown worker environment %q (known: %s)", id, strings.Join(WorkerEnvironmentIDs(), ", "))
}

// WorkerVerdict is what the planner decided for one worker request.
type WorkerVerdict string

// The worker verdicts.
const (
	// VerdictRoute: customer compute is proven and the harness can be
	// routed: start the proxy and point the base URL at it.
	VerdictRoute WorkerVerdict = "route"
	// VerdictRefused: a vendor-hosted sandbox, or customer compute is not
	// proven. Nothing is started.
	VerdictRefused WorkerVerdict = "refused"
	// VerdictUnrouted: customer compute is proven but nothing the proxy can
	// carry leaves the worker (no harness, a non-env route, a gated lane
	// without its credential, the agent's own endpoint). Nothing is
	// started; the reason says why.
	VerdictUnrouted WorkerVerdict = "unrouted"
)

// WorkerRequest is the input of PlanWorker.
type WorkerRequest struct {
	// Env is the worker environment id (--env).
	Env string
	// Harness overrides the environment's default harness; it must be one of
	// the environment's Harnesses.
	Harness string
	// Sink is the route sink; "" takes the mode's default.
	Sink RouteSink
	// Background reports `worker start` (the proxy outlives the command);
	// false is `worker run` or `worker check`.
	Background bool
	// ProxyHost and ProxyPort are where the worker's proxy listens.
	ProxyHost string
	ProxyPort int
	// ProxyURL, when set, is a proxy already known to be Observer's (the
	// route's own value never counts as the agent's own endpoint).
	ProxyURL string
	// Args are the agent's own arguments (`worker run -- <args>`), read only
	// for the route gate's model and provider selectors.
	Args []string
	// LookupEnv is the worker's environment (os.LookupEnv in production).
	LookupEnv LookupEnv
}

// RouteVar is one base-URL variable the route sets.
type RouteVar struct {
	Name  string
	Value string
	// Previous is the value the variable had before the route (restored by
	// route off where the sink can restore); HadPrevious reports it was
	// set.
	Previous    string
	HadPrevious bool
}

// WorkerPlan is the planner's answer.
type WorkerPlan struct {
	Environment WorkerEnvironment
	Verdict     WorkerVerdict
	// Reason explains a refused or unrouted verdict, and names the route of
	// a routed one.
	Reason string
	// Location is where sessions on this worker ran: ExecutionCustomerWorker
	// once the proof matched, "" when refused.
	Location ExecutionLocation
	// ProofEnv names the variable whose row proved customer compute (never
	// its value); HostedEnv names the variable of the refusing row.
	ProofEnv  string
	HostedEnv string
	// Harness is the routed registry tool.
	Harness string
	// Sink is the resolved route sink.
	Sink RouteSink
	// Route is the base-URL variables to set (VerdictRoute only).
	Route []RouteVar
	// GateOutcome is the registry route gate's outcome ("" when the route
	// has no gate).
	GateOutcome string
	// ProxyURL is the proxy base URL (scheme://host:port).
	ProxyURL string
}

// workerState is the mutable evaluation the verdict rows read.
type workerState struct {
	req    WorkerRequest
	env    WorkerEnvironment
	plan   *WorkerPlan
	route  *integration.ProxyRoute
	hosted *HostedRule
	proof  *Marker
}

// workerVerdictRule is one row of the verdict table: the first row whose
// match returns true decides; one test case per row.
type workerVerdictRule struct {
	name    string
	verdict WorkerVerdict
	match   func(s *workerState) (reason string, ok bool)
}

// workerVerdictRules is THE verdict table.
var workerVerdictRules = []workerVerdictRule{
	// 1. A vendor-hosted sandbox: never the proxy (CA-D10).
	{"vendor-hosted", VerdictRefused, func(s *workerState) (string, bool) {
		if s.hosted == nil {
			return "", false
		}
		return "this is " + s.hosted.What + ": the proxy runs only on customer-run compute (CA-D10)", true
	}},
	// 2. Customer compute not proven: unknown is never customer.
	{"not-proven", VerdictRefused, func(s *workerState) (string, bool) {
		if s.proof != nil {
			return "", false
		}
		return "customer-run compute is not proven for " + s.env.DisplayName + ": " + s.env.ProofHint, true
	}},
	// 3. Nothing leaves the worker for the proxy to carry.
	{"no-harness", VerdictUnrouted, func(s *workerState) (string, bool) {
		if len(s.env.Harnesses) > 0 {
			return "", false
		}
		return s.env.NoHarnessReason, true
	}},
	// 4. The harness has no proxy route at all.
	{"no-route", VerdictUnrouted, func(s *workerState) (string, bool) {
		if s.route != nil {
			return "", false
		}
		return s.plan.Harness + " has no proxy route in the integration registry", true
	}},
	// 5. The route is not a base-URL variable (a config-file route).
	{"not-env-route", VerdictUnrouted, func(s *workerState) (string, bool) {
		if s.route.EnvVar != "" {
			return "", false
		}
		why := s.plan.Harness + " is routed through a config file, and the worker sets base-URL variables only"
		if s.route.Note != "" {
			why += " (" + s.route.Note + ")"
		}
		return why, true
	}},
	// 6. The route needs a proxy lane, which the worker does not install.
	{"needs-lane", VerdictUnrouted, func(s *workerState) (string, bool) {
		if s.route.Lane == nil {
			return "", false
		}
		return s.plan.Harness + " needs a proxy upstream lane, which a worker run does not install", true
	}},
	// 7. The agent already points at an endpoint of its own: never
	// override it, never claim it.
	{"own-endpoint", VerdictUnrouted, func(s *workerState) (string, bool) {
		if !ownEndpoint(s) {
			return "", false
		}
		return gateReason(s, integration.RouteGateOwnEndpoint), true
	}},
	// 8. The registry route gate says the lane is not in use.
	{"gate", VerdictUnrouted, func(s *workerState) (string, bool) {
		outcome := integration.EvaluateRouteGate(s.route.Gate, gateInput(s))
		s.plan.GateOutcome = string(outcome)
		if s.route.Gate == nil && outcome == integration.RouteGateRouted {
			s.plan.GateOutcome = ""
		}
		switch outcome {
		case integration.RouteGateRouted, integration.RouteGateRoutedAuthPinned:
			return "", false
		}
		return gateReason(s, outcome), true
	}},
	// 9. Everything holds: route.
	{"route", VerdictRoute, func(s *workerState) (string, bool) {
		names := make([]string, 0, len(s.plan.Route))
		for _, v := range s.plan.Route {
			names = append(names, v.Name+"="+v.Value)
		}
		return s.plan.Harness + " routed through the worker's proxy: " + strings.Join(names, " "), true
	}},
}

// gateInput is the gate's boolean view of the worker's environment.
func gateInput(s *workerState) integration.RouteGateInput {
	look := func(n string) (string, bool) { return s.req.LookupEnv(n) }
	in := integration.RouteGateInput{OwnEndpoint: ownEndpoint(s)}
	if g := s.route.Gate; g != nil {
		in.CredentialPresent = g.CredentialPresent(look)
		in.ModelPresent = g.ModelPresent(look, s.req.Args, "")
		in.ForeignProvider = g.ProviderTypeForeign(look, s.req.Args)
	}
	return in
}

// ownEndpoint reports whether the route's variable is already set to an
// endpoint that is not this worker's proxy.
func ownEndpoint(s *workerState) bool {
	v, ok := s.req.LookupEnv(s.route.EnvVar)
	return ok && strings.TrimSpace(v) != "" && !s.isProxyURL(v)
}

// isProxyURL reports whether v is the worker's own proxy URL (a re-run of
// `worker start` sees its own route in the environment).
func (s *workerState) isProxyURL(v string) bool {
	v = strings.TrimRight(strings.TrimSpace(v), "/")
	want := strings.TrimRight(s.plan.ProxyURL+s.route.Suffix, "/")
	return v == want || v == strings.TrimRight(s.plan.ProxyURL, "/")
}

// gateReason words a non-routed gate outcome.
func gateReason(s *workerState, o integration.RouteGateOutcome) string {
	switch o {
	case integration.RouteGateOwnEndpoint:
		return s.route.EnvVar + " already points at an endpoint that is not this worker's proxy; the worker never overrides it"
	case integration.RouteGateNoCredential:
		why := "no provider credential is set"
		if s.route.Gate.UnroutedBecause != "" {
			why = s.route.Gate.UnroutedBecause
		}
		return why + ", so " + s.plan.Harness + "'s model traffic does not ride a base URL (set one of " + strings.Join(s.route.Gate.CredentialEnv, ", ") + " to route the bring-your-own-key lane)"
	case integration.RouteGateForeignProvider:
		return "the bring-your-own-key lane names a provider type the route cannot carry"
	case integration.RouteGateModelRequired:
		return "the bring-your-own-key lane needs an explicit model (" + strings.Join(append(append([]string{}, s.route.Gate.ModelEnv...), s.route.Gate.ModelArguments...), " or ") + ")"
	}
	return "route gate: " + string(o)
}

// PlanWorker walks the tables for one request. It returns an error only for
// a request it cannot evaluate (an unknown environment, harness or sink, a
// bad port); refusing a vendor-hosted sandbox is a VerdictRefused plan.
func PlanWorker(req WorkerRequest) (WorkerPlan, error) {
	env, err := WorkerEnvironmentByID(req.Env)
	if err != nil {
		return WorkerPlan{}, err
	}
	if req.LookupEnv == nil {
		req.LookupEnv = func(string) (string, bool) { return "", false }
	}
	plan := WorkerPlan{Environment: env}
	if err := resolveWorkerHarness(env, req, &plan); err != nil {
		return WorkerPlan{}, err
	}
	if err := resolveWorkerSink(env, req, &plan); err != nil {
		return WorkerPlan{}, err
	}
	if req.ProxyPort <= 0 || req.ProxyPort > 65535 {
		return WorkerPlan{}, fmt.Errorf("cloudsession: worker proxy port %d is out of range", req.ProxyPort)
	}
	host := req.ProxyHost
	if host == "" {
		host = "127.0.0.1"
	}
	plan.ProxyURL = "http://" + host + ":" + strconv.Itoa(req.ProxyPort)
	if req.ProxyURL != "" {
		plan.ProxyURL = strings.TrimRight(req.ProxyURL, "/")
	}

	s := &workerState{req: req, env: env, plan: &plan}
	for i := range hostedRules {
		if markerHolds(req.LookupEnv, hostedRules[i].Marker) {
			s.hosted = &hostedRules[i]
			plan.HostedEnv = hostedRules[i].Marker.Env
			break
		}
	}
	for i := range env.Proof {
		if markerHolds(req.LookupEnv, env.Proof[i]) {
			s.proof = &env.Proof[i]
			break
		}
	}
	if s.hosted == nil && s.proof != nil {
		plan.Location = s.proof.Location
		plan.ProofEnv = s.proof.Env
	}
	if plan.Harness != "" {
		if c, ok := integration.For(plan.Harness); ok && c.Proxy != nil {
			r := *c.Proxy
			s.route = &r
		}
	}
	if s.route != nil && s.route.EnvVar != "" {
		prev, had := req.LookupEnv(s.route.EnvVar)
		plan.Route = []RouteVar{{Name: s.route.EnvVar, Value: plan.ProxyURL + s.route.Suffix, Previous: prev, HadPrevious: had}}
	}
	for _, r := range workerVerdictRules {
		if reason, ok := r.match(s); ok {
			plan.Verdict, plan.Reason = r.verdict, reason
			break
		}
	}
	if plan.Verdict != VerdictRoute {
		plan.Route = nil
	}
	return plan, nil
}

// resolveWorkerHarness picks the harness: the request's, which must be one
// of the environment's, else the environment's first.
func resolveWorkerHarness(env WorkerEnvironment, req WorkerRequest, plan *WorkerPlan) error {
	if req.Harness == "" {
		if len(env.Harnesses) > 0 {
			plan.Harness = env.Harnesses[0]
		}
		return nil
	}
	for _, h := range env.Harnesses {
		if h == req.Harness {
			plan.Harness = h
			return nil
		}
	}
	if len(env.Harnesses) == 0 {
		return fmt.Errorf("cloudsession: %s has no routable harness: %s", env.DisplayName, env.NoHarnessReason)
	}
	return fmt.Errorf("cloudsession: --harness %q is not one of %s's harnesses (%s)", req.Harness, env.DisplayName, strings.Join(env.Harnesses, ", "))
}

// resolveWorkerSink picks the route sink: the request's, which must be one
// of the environment's and fit the mode, else the mode's default (child for
// `worker run`, the environment's first background sink for `worker start`).
func resolveWorkerSink(env WorkerEnvironment, req WorkerRequest, plan *WorkerPlan) error {
	if req.Sink == "" {
		for _, s := range env.Sinks {
			spec, _ := sinkFor(s)
			if spec.background == req.Background && sinkEnvReady(spec, req.LookupEnv) {
				plan.Sink = s
				return nil
			}
		}
		return fmt.Errorf("cloudsession: %s has no route sink for this mode", env.DisplayName)
	}
	spec, ok := sinkFor(req.Sink)
	if !ok {
		return fmt.Errorf("cloudsession: unknown route sink %q (known: %s)", req.Sink, strings.Join(RouteSinks(), ", "))
	}
	allowed := false
	for _, s := range env.Sinks {
		if s == req.Sink {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("cloudsession: route sink %q is not available for %s", req.Sink, env.DisplayName)
	}
	if spec.background != req.Background {
		if req.Background {
			return fmt.Errorf("cloudsession: route sink %q needs `worker run` (the route lives on the child it starts)", req.Sink)
		}
		return fmt.Errorf("cloudsession: route sink %q needs `worker start` (`worker run` hands the route to its child)", req.Sink)
	}
	if !sinkEnvReady(spec, req.LookupEnv) {
		return fmt.Errorf("cloudsession: route sink %q needs %s (it is set inside a GitHub Actions job)", req.Sink, spec.needsEnv)
	}
	plan.Sink = req.Sink
	return nil
}

// sinkEnvReady reports whether the variable a sink needs is set.
func sinkEnvReady(spec sinkSpec, env LookupEnv) bool {
	if spec.needsEnv == "" {
		return true
	}
	v, ok := env(spec.needsEnv)
	return ok && v != ""
}

// markerHolds reports whether every condition of m holds.
func markerHolds(env LookupEnv, m Marker) bool {
	if !envHolds(env, m.Env, m.Equals) {
		return false
	}
	return m.AlsoEnv == "" || envHolds(env, m.AlsoEnv, m.AlsoEquals)
}
