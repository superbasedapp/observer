package cloudsession

import (
	"fmt"
	"strings"
	"time"
)

// worker_lifecycle.go holds the step tables of a worker run (lane CA-C4).
// The command walks them in table order, so the proxy-safe order of
// docs/daemon-restart-runbook.md is data, pinned by a test, not a habit:
//
//	route ON only after the proxy answers;
//	route OFF before the proxy stops (never stop a proxy a live route points at).

// WorkerMode is one worker command shape.
type WorkerMode string

// The worker modes.
const (
	// ModeRun is `worker run -- <agent>`: proxy, child agent, teardown, in
	// one foreground command.
	ModeRun WorkerMode = "run"
	// ModeStart is `worker start`: start a background proxy and hand the
	// route to later steps.
	ModeStart WorkerMode = "start"
	// ModeStop is `worker stop`: take the route off, then stop the proxy.
	ModeStop WorkerMode = "stop"
)

// WorkerStep is one step of a worker lifecycle.
type WorkerStep string

// The worker steps.
const (
	// StepVerify walks the worker tables (PlanWorker); a refused or unrouted
	// plan stops the lifecycle before anything starts.
	StepVerify WorkerStep = "verify"
	// StepStartProxy starts the proxy (in process for run, a detached
	// process for start).
	StepStartProxy WorkerStep = "start-proxy"
	// StepAwaitReady waits until the proxy accepts connections.
	StepAwaitReady WorkerStep = "await-ready"
	// StepRouteOn hands the route (the base-URL variables) to the sink.
	StepRouteOn WorkerStep = "route-on"
	// StepRunAgent runs the agent as a child with the route (run only).
	StepRunAgent WorkerStep = "run-agent"
	// StepRouteOff takes the route back out of the sink.
	StepRouteOff WorkerStep = "route-off"
	// StepDrain waits for in-flight proxied requests to finish.
	StepDrain WorkerStep = "drain"
	// StepStopProxy stops the proxy.
	StepStopProxy WorkerStep = "stop-proxy"
	// StepScan runs the harness's adapter over its own store on the worker,
	// so the session rows the stamp needs exist (the proxy writes turns,
	// not session rows).
	StepScan WorkerStep = "scan"
	// StepStamp stamps the run's sessions execution_location=customer_worker.
	StepStamp WorkerStep = "stamp"
)

// workerLifecycles is THE lifecycle table: each mode's steps in order.
var workerLifecycles = map[WorkerMode][]WorkerStep{
	ModeRun:   {StepVerify, StepStartProxy, StepAwaitReady, StepRouteOn, StepRunAgent, StepRouteOff, StepDrain, StepStopProxy, StepScan, StepStamp},
	ModeStart: {StepVerify, StepStartProxy, StepAwaitReady, StepRouteOn},
	ModeStop:  {StepRouteOff, StepDrain, StepStopProxy, StepScan, StepStamp},
}

// teardownSteps are the steps that still run after an earlier step failed
// (each only when its counterpart ran), so a failure never leaves a route
// pointing at a stopped proxy or a proxy running after the command ends.
var teardownSteps = map[WorkerStep]bool{
	StepRouteOff:  true,
	StepDrain:     true,
	StepStopProxy: true,
	StepScan:      true,
	StepStamp:     true,
}

// workerRecovery is what a mode whose own table holds no teardown runs after
// a failed step (`worker start` failing half way must not leave a route or
// a background proxy behind). Each step still runs only when its
// counterpart ran.
var workerRecovery = map[WorkerMode][]WorkerStep{
	ModeStart: {StepRouteOff, StepDrain, StepStopProxy},
}

// WorkerRecoverySteps returns the steps mode runs after a failed step, in
// order (none for a mode whose table already ends in teardown).
func WorkerRecoverySteps(mode WorkerMode) []WorkerStep {
	return append([]WorkerStep(nil), workerRecovery[mode]...)
}

// IsTeardownStep reports whether s still runs after an earlier failure.
func IsTeardownStep(s WorkerStep) bool { return teardownSteps[s] }

// WorkerSteps returns mode's steps in order.
func WorkerSteps(mode WorkerMode) ([]WorkerStep, error) {
	steps, ok := workerLifecycles[mode]
	if !ok {
		return nil, fmt.Errorf("cloudsession: unknown worker mode %q", mode)
	}
	return append([]WorkerStep(nil), steps...), nil
}

// stepOrderRule is one row of the order table: within a lifecycle that
// holds both steps, Before must come before After.
type stepOrderRule struct {
	Before, After WorkerStep
	Why           string
}

// stepOrderRules is THE order table every lifecycle must satisfy.
var stepOrderRules = []stepOrderRule{
	{StepVerify, StepStartProxy, "nothing starts before the vendor-hosted refusal ran"},
	{StepAwaitReady, StepRouteOn, "never point an agent at a proxy that does not answer yet"},
	{StepRouteOn, StepRunAgent, "the agent starts with the route in place"},
	{StepRunAgent, StepRouteOff, "the route stays while the agent runs"},
	{StepRouteOff, StepStopProxy, "route off before stop: never stop a proxy a live route points at (docs/daemon-restart-runbook.md)"},
	{StepDrain, StepStopProxy, "in-flight requests finish before the proxy stops"},
	{StepStopProxy, StepScan, "the scan reads a database the proxy no longer writes"},
	{StepScan, StepStamp, "the stamp needs the session rows the scan writes"},
}

// CheckWorkerSteps checks steps against the order table. It returns the
// first violated rule.
func CheckWorkerSteps(steps []WorkerStep) error {
	pos := map[WorkerStep]int{}
	for i, s := range steps {
		if _, dup := pos[s]; dup {
			return fmt.Errorf("cloudsession: worker step %s appears twice", s)
		}
		pos[s] = i
	}
	for _, r := range stepOrderRules {
		b, okB := pos[r.Before]
		a, okA := pos[r.After]
		if okB && okA && b > a {
			return fmt.Errorf("cloudsession: worker step %s must come before %s: %s", r.Before, r.After, r.Why)
		}
	}
	return nil
}

// WorkerState is what `worker start` records for `worker stop` (a JSON file
// in the worker's state directory). It holds names and the proxy's process
// id, never a credential value.
type WorkerState struct {
	Env       string            `json:"env"`
	Harness   string            `json:"harness"`
	Sink      RouteSink         `json:"sink"`
	ProxyURL  string            `json:"proxy_url"`
	PID       int               `json:"pid"`
	StartedAt time.Time         `json:"started_at"`
	Location  ExecutionLocation `json:"execution_location"`
	Route     []RouteVar        `json:"route"`
	// RouteOn reports the route is handed out; stop clears it (and saves the
	// state) BEFORE it stops the proxy, so an interrupted stop never leaves
	// a route pointing at a stopped proxy without saying so.
	RouteOn bool `json:"route_on"`
	// EnvFile is the env-file sink's path; GitHubEnv the $GITHUB_ENV file
	// the github-env sink appended to.
	EnvFile   string `json:"env_file,omitempty"`
	GitHubEnv string `json:"github_env,omitempty"`
}

// RouteOnLines renders the sink content that hands the route out: POSIX
// export lines for SinkEnvFile, NAME=value lines for SinkGitHubEnv. A value
// is a proxy URL the planner built, never user text, but it is still checked.
func RouteOnLines(sink RouteSink, route []RouteVar) (string, error) {
	var b strings.Builder
	for _, v := range route {
		if err := checkRouteVar(v.Name, v.Value); err != nil {
			return "", err
		}
		switch sink {
		case SinkEnvFile:
			b.WriteString("export " + v.Name + "=" + shellQuote(v.Value) + "\n")
		case SinkGitHubEnv:
			b.WriteString(v.Name + "=" + v.Value + "\n")
		default:
			return "", fmt.Errorf("cloudsession: route sink %q writes no lines", sink)
		}
	}
	return b.String(), nil
}

// RouteOffLines renders what takes the route back out of a sink that cannot
// delete (SinkGitHubEnv: a later line wins, so the previous value, or an
// empty one, is appended).
func RouteOffLines(sink RouteSink, route []RouteVar) (string, error) {
	if sink != SinkGitHubEnv {
		return "", fmt.Errorf("cloudsession: route sink %q is turned off by deletion, not lines", sink)
	}
	var b strings.Builder
	for _, v := range route {
		restore := ""
		if v.HadPrevious {
			restore = v.Previous
		}
		if err := checkRouteVar(v.Name, restore); err != nil {
			return "", fmt.Errorf("cloudsession: cannot restore %s (%w); remove it by hand", v.Name, err)
		}
		b.WriteString(v.Name + "=" + restore + "\n")
	}
	return b.String(), nil
}

// checkRouteVar refuses a name or value that could break the sink's line
// format (a newline would inject a second variable).
func checkRouteVar(name, value string) error {
	if name == "" || strings.ContainsAny(name, "= \t\r\n") {
		return fmt.Errorf("cloudsession: bad route variable name %q", name)
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return fmt.Errorf("cloudsession: route variable %s value holds a line break", name)
	}
	return nil
}
