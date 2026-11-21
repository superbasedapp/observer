package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudsession_worker.go is `observer cloud-session worker` (cloud-agents
// lane CA-C4, the customer-compute proxy; docs/cloud-agents.md
// "Customer-run compute"). On compute the customer runs, it starts the
// Observer API proxy inside the worker for one run and points the agent's
// base URL at it; on a vendor-hosted sandbox it refuses (CA-D10). Every
// decision is internal/cloudsession's worker tables; this file executes the
// lifecycle step table (cloudsession.WorkerSteps) in order, so the
// route-off-before-stop rule of docs/daemon-restart-runbook.md is the
// table's, not this file's habit.

// Worker bounds.
const (
	// workerReadyTimeout bounds the wait for the proxy to accept
	// connections.
	workerReadyTimeout = 20 * time.Second
	// workerStopTimeout bounds the wait for the proxy to stop listening
	// (the proxy's own graceful shutdown is a few seconds).
	workerStopTimeout = 45 * time.Second
	// workerDefaultDrain is how long `worker stop` waits between route off
	// and stop, so a request started just before route off finishes.
	workerDefaultDrain = 2 * time.Second
	// workerPollEvery is the readiness / stop-file poll interval.
	workerPollEvery = 100 * time.Millisecond
)

// Worker state-directory file names.
const (
	workerStateFile = "state.json"
	workerStopFile  = "stop"
	workerRouteFile = "route.env"
)

// errWorkerNotRouted marks a plan that ended before anything started
// (refused or unrouted); the command prints the reason.
var errWorkerNotRouted = errors.New("worker not routed")

func newCloudSessionWorkerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "worker",
		Short: "Run the API proxy inside a customer-run worker for one agent run (customer compute only)",
		Long: "On compute you run yourself (a Claude Code self-hosted environment, a\n" +
			"GitHub Actions self-hosted runner, a Devin Outpost, a Warp self-hosted\n" +
			"worker) start the Observer API proxy inside the worker for the run and\n" +
			"point the agent's base URL at it, so accurate tokens, compression and\n" +
			"routing work as on a laptop under this worker's own config. Sessions\n" +
			"are stamped execution_location=customer_worker. Refused on a\n" +
			"vendor-hosted sandbox. See docs/cloud-agents.md \"Customer-run compute\".\n\n" +
			"  check  say what would happen here, change nothing\n" +
			"  run    proxy + the agent as a child + teardown, in one command\n" +
			"  start  start a background proxy and hand the route to later steps\n" +
			"  stop   take the route off, then stop the proxy, then stamp sessions",
	}
	cmd.AddCommand(newWorkerCheckCmd(), newWorkerRunCmd(), newWorkerStartCmd(), newWorkerStopCmd(), newWorkerServeCmd())
	return cmd
}

// workerFlags are the flags check, run and start share.
type workerFlags struct {
	env, harness, sink, configPath string
	port                           int
	jsonOut                        bool
}

func (f *workerFlags) bind(cmd *cobra.Command, withSink bool) {
	cmd.Flags().StringVar(&f.env, "env", "", "customer-run environment: "+strings.Join(cloudsession.WorkerEnvironmentIDs(), ", "))
	_ = cmd.MarkFlagRequired("env")
	cmd.Flags().StringVar(&f.harness, "harness", "", "the agent harness whose model calls the proxy carries (default: the environment's first)")
	cmd.Flags().IntVar(&f.port, "port", 0, "loopback port for the worker's proxy (default: a free port)")
	cmd.Flags().StringVar(&f.configPath, "config", "", "Path to observer config.toml (the worker's own config decides compression and routing)")
	cmd.Flags().BoolVar(&f.jsonOut, "json", false, "print the plan as JSON on stderr")
	if withSink {
		cmd.Flags().StringVar(&f.sink, "sink", "", "how the route reaches the agent: "+strings.Join(cloudsession.RouteSinks(), ", ")+" (default: the environment's first for this command)")
	}
}

// workerPlanJSON is the plan as printed by --json.
type workerPlanJSON struct {
	Env         string                  `json:"env"`
	Verdict     string                  `json:"verdict"`
	Reason      string                  `json:"reason"`
	Location    string                  `json:"execution_location,omitempty"`
	ProofEnv    string                  `json:"proof_env,omitempty"`
	HostedEnv   string                  `json:"hosted_env,omitempty"`
	Harness     string                  `json:"harness,omitempty"`
	Sink        string                  `json:"sink,omitempty"`
	GateOutcome string                  `json:"gate,omitempty"`
	ProxyURL    string                  `json:"proxy_url,omitempty"`
	Route       []cloudsession.RouteVar `json:"route,omitempty"`
	LiveCheck   string                  `json:"live_check,omitempty"`
}

// printWorkerPlan prints the plan (names and URLs only; a previous value of
// a route variable is never printed).
func printWorkerPlan(w io.Writer, p cloudsession.WorkerPlan, jsonOut bool) {
	if jsonOut {
		route := make([]cloudsession.RouteVar, 0, len(p.Route))
		for _, v := range p.Route {
			route = append(route, cloudsession.RouteVar{Name: v.Name, Value: v.Value, HadPrevious: v.HadPrevious})
		}
		_ = json.NewEncoder(w).Encode(workerPlanJSON{
			Env: p.Environment.ID, Verdict: string(p.Verdict), Reason: p.Reason, Location: string(p.Location),
			ProofEnv: p.ProofEnv, HostedEnv: p.HostedEnv, Harness: p.Harness, Sink: string(p.Sink),
			GateOutcome: p.GateOutcome, ProxyURL: p.ProxyURL, Route: route, LiveCheck: p.Environment.LiveCheck,
		})
		return
	}
	fmt.Fprintf(w, "cloud-session worker: %s: %s: %s\n", p.Environment.DisplayName, p.Verdict, p.Reason)
	switch {
	case p.HostedEnv != "":
		fmt.Fprintf(w, "cloud-session worker: vendor-hosted marker: %s\n", p.HostedEnv)
	case p.ProofEnv != "":
		fmt.Fprintf(w, "cloud-session worker: customer compute proven by %s; sessions are stamped execution_location=%s\n", p.ProofEnv, p.Location)
	}
	if p.Verdict == cloudsession.VerdictRoute {
		fmt.Fprintf(w, "cloud-session worker: route sink %s\n", p.Sink)
	}
	if p.Environment.LiveCheck != "" {
		fmt.Fprintf(w, "cloud-session worker: not yet live-checked here: %s\n", p.Environment.LiveCheck)
	}
}

// planWorker resolves the port and walks the worker tables.
func planWorker(f workerFlags, background bool, args []string, env cloudsession.LookupEnv) (cloudsession.WorkerPlan, error) {
	port := f.port
	if port == 0 {
		p, err := workerFreeLoopbackPort()
		if err != nil {
			return cloudsession.WorkerPlan{}, err
		}
		port = p
	}
	return cloudsession.PlanWorker(cloudsession.WorkerRequest{
		Env: f.env, Harness: f.harness, Sink: cloudsession.RouteSink(f.sink), Background: background,
		ProxyHost: "127.0.0.1", ProxyPort: port, Args: args, LookupEnv: env,
	})
}

// workerFreeLoopbackPort asks the kernel for a free loopback port.
func workerFreeLoopbackPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("pick a proxy port: %w", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func newWorkerCheckCmd() *cobra.Command {
	var f workerFlags
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Say whether this machine may run the worker proxy, and what it would route; change nothing",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The plan of `worker run` by default; a background sink asks
			// for the plan of `worker start`.
			background := f.sink != "" && cloudsession.RouteSink(f.sink) != cloudsession.SinkChild
			p, err := planWorker(f, background, nil, os.LookupEnv)
			if err != nil {
				return err
			}
			printWorkerPlan(cmd.OutOrStdout(), p, f.jsonOut)
			return nil
		},
	}
	f.bind(cmd, true)
	return cmd
}

func newWorkerRunCmd() *cobra.Command {
	var f workerFlags
	cmd := &cobra.Command{
		Use:   "run --env <id> -- <agent command> [args...]",
		Short: "Start the proxy, run the agent with its base URL at it, then tear down in the safe order",
		Long: "Starts the proxy on a loopback port, runs the agent as a child with its\n" +
			"base-URL variable pointing at it, and when the agent exits: the route\n" +
			"goes with the child, the proxy drains and stops, the harness's store is\n" +
			"scanned and the run's sessions are stamped customer_worker. Exits with\n" +
			"the agent's exit code. On a vendor-hosted sandbox it refuses; where\n" +
			"nothing can be routed it runs the agent unrouted and says why.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			errOut := cmd.ErrOrStderr()
			p, err := planWorker(f, false, args[1:], os.LookupEnv)
			if err != nil {
				return err
			}
			printWorkerPlan(errOut, p, f.jsonOut)
			switch p.Verdict {
			case cloudsession.VerdictRefused:
				return errors.New("refused: " + p.Reason)
			case cloudsession.VerdictUnrouted:
				// Customer compute, nothing to carry: run the agent as asked.
				return runWorkerChildPlain(ctx, args, errOut)
			}
			ops := newWorkerRunOps(f.configPath, p, args, cmd.InOrStdin(), cmd.OutOrStdout(), errOut)
			return walkWorkerSteps(ctx, cloudsession.ModeRun, p, ops, errOut)
		},
	}
	f.bind(cmd, false)
	return cmd
}

func newWorkerStartCmd() *cobra.Command {
	var f workerFlags
	cmd := &cobra.Command{
		Use:   "start --env <id>",
		Short: "Start a background proxy for this run and hand the route to later steps",
		Long: "For a worker where the vendor starts the agent (a self-hosted runner's\n" +
			"setup step, a self-hosted environment's setup): starts the proxy as a\n" +
			"background process and hands the route out through the sink\n" +
			"($GITHUB_ENV inside GitHub Actions, else an env file the environment\n" +
			"sources). Pair it with `worker stop` after the agent finishes.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			errOut := cmd.ErrOrStderr()
			stateDir, err := workerStateDir(f.configPath)
			if err != nil {
				return err
			}
			if st, ok := loadWorkerState(stateDir); ok {
				return fmt.Errorf("a worker proxy is already recorded for this run (%s, started %s); run `observer cloud-session worker stop` first", st.ProxyURL, st.StartedAt.Format(time.RFC3339))
			}
			p, err := planWorker(f, true, nil, os.LookupEnv)
			if err != nil {
				return err
			}
			printWorkerPlan(errOut, p, f.jsonOut)
			switch p.Verdict {
			case cloudsession.VerdictRefused:
				return errors.New("refused: " + p.Reason)
			case cloudsession.VerdictUnrouted:
				fmt.Fprintln(errOut, "cloud-session worker: nothing started")
				return nil
			}
			ops := newWorkerBackgroundOps(f.configPath, stateDir, p, os.LookupEnv, errOut)
			if err := walkWorkerSteps(ctx, cloudsession.ModeStart, p, ops, errOut); err != nil {
				// The recovery took the route off and stopped the proxy;
				// keep the state only when the proxy still answers, so
				// `worker stop` can finish the job.
				if awaitClosed(ops.proxyHostPort(), 0) == nil {
					_ = os.Remove(filepath.Join(stateDir, workerStateFile))
				}
				return err
			}
			if p.Sink == cloudsession.SinkEnvFile {
				fmt.Fprintf(errOut, "cloud-session worker: source %s in the agent's environment\n", ops.state.EnvFile)
			}
			return nil
		},
	}
	f.bind(cmd, true)
	return cmd
}

func newWorkerStopCmd() *cobra.Command {
	var (
		configPath string
		drain      time.Duration
	)
	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Take the route off, then stop the background proxy, then stamp the run's sessions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			errOut := cmd.ErrOrStderr()
			stateDir, err := workerStateDir(configPath)
			if err != nil {
				return err
			}
			st, ok := loadWorkerState(stateDir)
			if !ok {
				fmt.Fprintln(errOut, "cloud-session worker: no worker proxy recorded; nothing to stop")
				return nil
			}
			p := cloudsession.WorkerPlan{
				Verdict: cloudsession.VerdictRoute, Harness: st.Harness, Sink: st.Sink,
				Location: st.Location, Route: st.Route, ProxyURL: st.ProxyURL,
			}
			ops := &workerBackgroundOps{workerCommon: workerCommon{configPath: configPath, plan: p, startedAt: st.StartedAt, drain: drain, errOut: errOut}, stateDir: stateDir, state: st}
			if err := walkWorkerSteps(cmd.Context(), cloudsession.ModeStop, p, ops, errOut); err != nil {
				return err
			}
			_ = os.Remove(filepath.Join(stateDir, workerStateFile))
			_ = os.Remove(filepath.Join(stateDir, workerStopFile))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml")
	cmd.Flags().DurationVar(&drain, "drain", workerDefaultDrain, "wait between route off and stop for in-flight requests")
	return cmd
}

// newWorkerServeCmd is the background proxy `worker start` spawns. It is
// the ordinary proxy on a loopback port; it stops when `worker stop` drops
// the stop file in the state directory (no process signal, so a recycled
// pid can never be hit) or on SIGINT/SIGTERM.
func newWorkerServeCmd() *cobra.Command {
	var (
		configPath, stateDir string
		port                 int
	)
	cmd := &cobra.Command{
		Use:    "serve",
		Short:  "Background proxy of `worker start` (internal)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer cancel()
			if stateDir == "" || port <= 0 {
				return errors.New("serve needs --state-dir and --port")
			}
			stopPath := filepath.Join(stateDir, workerStopFile)
			_ = os.Remove(stopPath)
			go watchWorkerStopFile(ctx, stopPath, cancel)
			pw, err := buildProxy(ctx, configPath, "", port, "127.0.0.1", nil)
			if err != nil {
				return err
			}
			defer pw.Cleanup()
			if err := pw.Proxy.ListenAndServe(ctx, pw.Addr); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml")
	cmd.Flags().StringVar(&stateDir, "state-dir", "", "worker state directory")
	cmd.Flags().IntVar(&port, "port", 0, "loopback port")
	return cmd
}

// watchWorkerStopFile cancels when path appears.
func watchWorkerStopFile(ctx context.Context, path string, cancel func()) {
	t := time.NewTicker(workerPollEvery * 5)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := os.Stat(path); err == nil {
				cancel()
				return
			}
		}
	}
}

// workerOps is one implementation of every lifecycle step. walkWorkerSteps
// calls them in the order of cloudsession.WorkerSteps; tests substitute a
// recorder.
type workerOps interface {
	startProxy(ctx context.Context) error
	awaitReady(ctx context.Context) error
	routeOn(ctx context.Context) error
	runAgent(ctx context.Context) error
	routeOff(ctx context.Context) error
	drainProxy(ctx context.Context) error
	stopProxy(ctx context.Context) error
	scan(ctx context.Context) error
	stamp(ctx context.Context) error
}

// walkWorkerSteps executes mode's lifecycle in table order. After a failed
// step only teardown steps run, and only those whose counterpart ran (no
// route off without a route on, no stop without a start), so a failure never
// leaves a route pointing at a stopped proxy. The first error is returned
// (an agent's exit code included, after the teardown).
func walkWorkerSteps(ctx context.Context, mode cloudsession.WorkerMode, p cloudsession.WorkerPlan, ops workerOps, errOut io.Writer) error {
	steps, err := cloudsession.WorkerSteps(mode)
	if err != nil {
		return err
	}
	if err := cloudsession.CheckWorkerSteps(steps); err != nil {
		return err
	}
	// The stop lifecycle tears down what a start set up.
	started, routed := mode == cloudsession.ModeStop, mode == cloudsession.ModeStop
	// Teardown runs to the end even after an interrupt cancelled ctx.
	teardownCtx := context.WithoutCancel(ctx)
	var first error
	for i := 0; i < len(steps); i++ {
		s := steps[i]
		if first != nil && !cloudsession.IsTeardownStep(s) {
			continue
		}
		ctx := ctx
		if cloudsession.IsTeardownStep(s) {
			ctx = teardownCtx
		}
		var serr error
		switch s {
		case cloudsession.StepVerify:
			if p.Verdict != cloudsession.VerdictRoute {
				serr = fmt.Errorf("%w: %s", errWorkerNotRouted, p.Reason)
			}
		case cloudsession.StepStartProxy:
			serr = ops.startProxy(ctx)
			started = serr == nil
		case cloudsession.StepAwaitReady:
			serr = ops.awaitReady(ctx)
		case cloudsession.StepRouteOn:
			routed = true // a partial route on is still taken off
			serr = ops.routeOn(ctx)
		case cloudsession.StepRunAgent:
			serr = ops.runAgent(ctx)
		case cloudsession.StepRouteOff:
			if routed {
				serr = ops.routeOff(ctx)
			}
		case cloudsession.StepDrain:
			if started {
				serr = ops.drainProxy(ctx)
			}
		case cloudsession.StepStopProxy:
			if started {
				serr = ops.stopProxy(ctx)
			}
		case cloudsession.StepScan:
			if started {
				// A scan failure loses no proxy rows; the stamp still runs.
				if e := ops.scan(ctx); e != nil {
					fmt.Fprintf(errOut, "cloud-session worker: scan: %v\n", e)
				}
			}
		case cloudsession.StepStamp:
			if started {
				serr = ops.stamp(ctx)
			}
		}
		if serr != nil && first == nil {
			first = serr
			// A mode whose table holds no teardown appends its recovery.
			steps = append(steps, cloudsession.WorkerRecoverySteps(mode)...)
		}
		if serr != nil && cloudsession.IsTeardownStep(s) && !errors.As(serr, new(exitErr)) {
			fmt.Fprintf(errOut, "cloud-session worker: %s: %v\n", s, serr)
		}
	}
	return first
}

// workerCommon holds what every implementation shares: the scan and the
// stamp read the worker's own database after the proxy stopped.
type workerCommon struct {
	configPath string
	plan       cloudsession.WorkerPlan
	startedAt  time.Time
	drain      time.Duration
	errOut     io.Writer
}

// scan runs the harness's adapter over its own store on this worker, so the
// session rows the stamp needs exist.
func (c *workerCommon) scan(ctx context.Context) error {
	w, cleanup, err := buildWatcherWithOverride(ctx, c.configPath, c.plan.Harness)
	if err != nil {
		return err
	}
	defer cleanup()
	sr, err := w.Scan(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.errOut, "cloud-session worker: scanned %d %s file(s)\n", sr.FilesProcessed, c.plan.Harness)
	return nil
}

// stamp stamps every session the run touched execution_location =
// customer_worker through the one writer (first wins: a session another
// rail already stamped keeps its stamp).
func (c *workerCommon) stamp(ctx context.Context) error {
	_, database, cleanup, err := loadConfigAndDB(ctx, c.configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	st := store.New(database)
	ids, err := st.SessionIDsActiveSince(ctx, c.startedAt)
	if err != nil {
		return err
	}
	det := cloudsession.Detection{InCloud: true, Location: c.plan.Location}
	n, err := cloudsession.ApplyStamps(ctx, executionStamperFor(st), cloudsession.PlanStamps(det, ids))
	if err != nil {
		return err
	}
	fmt.Fprintf(c.errOut, "cloud-session worker: %d session(s) in this run, %d newly stamped execution_location=%s\n", len(ids), n, c.plan.Location)
	return nil
}

// proxyHostPort returns the host:port of the plan's proxy URL.
func (c *workerCommon) proxyHostPort() string {
	return strings.TrimPrefix(strings.TrimPrefix(c.plan.ProxyURL, "http://"), "https://")
}

// proxyPort returns the port of the plan's proxy URL.
func (c *workerCommon) proxyPort() (int, error) {
	_, port, err := net.SplitHostPort(c.proxyHostPort())
	if err != nil {
		return 0, fmt.Errorf("proxy address %q: %w", c.plan.ProxyURL, err)
	}
	return strconv.Atoi(port)
}

// awaitListening polls until something accepts on hostPort, or fails early
// when failed returns an error.
func awaitListening(ctx context.Context, hostPort string, failed func() error) error {
	deadline := time.Now().Add(workerReadyTimeout)
	for {
		if conn, err := net.DialTimeout("tcp", hostPort, time.Second); err == nil {
			_ = conn.Close()
			return nil
		}
		if failed != nil {
			if err := failed(); err != nil {
				return err
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the proxy did not answer on %s within %s", hostPort, workerReadyTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(workerPollEvery):
		}
	}
}

// awaitClosed polls until nothing accepts on hostPort.
func awaitClosed(hostPort string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", hostPort, time.Second)
		if err != nil {
			return nil
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			return fmt.Errorf("the proxy on %s is still listening after %s", hostPort, timeout)
		}
		time.Sleep(workerPollEvery)
	}
}

// workerRunOps is `worker run`: an in-process proxy and a child agent.
type workerRunOps struct {
	workerCommon
	args          []string
	stdin         io.Reader
	stdout        io.Writer
	childEnv      []string
	proxyCancel   context.CancelFunc
	proxyDone     chan error
	proxyCleanup  func()
	proxyFinished bool
}

func newWorkerRunOps(configPath string, p cloudsession.WorkerPlan, args []string, stdin io.Reader, stdout, errOut io.Writer) *workerRunOps {
	return &workerRunOps{workerCommon: workerCommon{configPath: configPath, plan: p, errOut: errOut}, args: args, stdin: stdin, stdout: stdout}
}

func (o *workerRunOps) startProxy(ctx context.Context) error {
	o.startedAt = time.Now()
	port, err := o.proxyPort()
	if err != nil {
		return err
	}
	pw, err := buildProxy(ctx, o.configPath, "", port, "127.0.0.1", nil)
	if err != nil {
		return err
	}
	pctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	o.proxyCancel, o.proxyCleanup, o.proxyDone = cancel, pw.Cleanup, make(chan error, 1)
	go func() { o.proxyDone <- pw.Proxy.ListenAndServe(pctx, pw.Addr) }()
	return nil
}

func (o *workerRunOps) awaitReady(ctx context.Context) error {
	return awaitListening(ctx, o.proxyHostPort(), func() error {
		select {
		case err := <-o.proxyDone:
			o.proxyFinished = true
			if err == nil {
				err = errors.New("the proxy stopped before it answered")
			}
			return err
		default:
			return nil
		}
	})
}

func (o *workerRunOps) routeOn(context.Context) error {
	o.childEnv = workerChildEnv(os.Environ(), o.plan.Route)
	fmt.Fprintf(o.errOut, "cloud-session worker: proxy on %s, route on for the agent\n", o.plan.ProxyURL)
	return nil
}

func (o *workerRunOps) runAgent(ctx context.Context) error {
	return runWorkerChild(ctx, o.args, o.childEnv, o.stdin, o.stdout, o.errOut)
}

// routeOff: the route lived only in the child's environment, and the child
// has exited, so nothing points at the proxy any more.
func (o *workerRunOps) routeOff(context.Context) error {
	o.childEnv = nil
	fmt.Fprintln(o.errOut, "cloud-session worker: route off (it lived on the agent process, which has exited)")
	return nil
}

// drainProxy: the only client was the child, which has exited; the
// proxy's own graceful shutdown (stopProxy) finishes anything left.
func (o *workerRunOps) drainProxy(context.Context) error { return nil }

func (o *workerRunOps) stopProxy(context.Context) error {
	defer o.proxyCleanup()
	o.proxyCancel()
	if o.proxyFinished {
		return nil
	}
	select {
	case err := <-o.proxyDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		fmt.Fprintln(o.errOut, "cloud-session worker: proxy stopped")
		return nil
	case <-time.After(workerStopTimeout):
		return fmt.Errorf("the proxy did not stop within %s", workerStopTimeout)
	}
}

// workerChildEnv returns base with every route variable set to its route
// value (replacing any earlier entry).
func workerChildEnv(base []string, route []cloudsession.RouteVar) []string {
	out := make([]string, 0, len(base)+len(route))
	set := map[string]bool{}
	for _, v := range route {
		set[v.Name] = true
	}
	for _, kv := range base {
		name, _, _ := strings.Cut(kv, "=")
		if !set[name] {
			out = append(out, kv)
		}
	}
	for _, v := range route {
		out = append(out, v.Name+"="+v.Value)
	}
	return out
}

// runWorkerChild runs the agent with env, forwarding its exit code. The
// child is not bound to ctx: an interactive agent handles its own Ctrl-C
// (the terminal sends it to the whole process group), and this process,
// which caught the signal, stays alive to tear down in order.
func runWorkerChild(_ context.Context, args, env []string, stdin io.Reader, stdout, stderr io.Writer) error {
	child := exec.Command(args[0], args[1:]...) // #nosec G204 -- the operator's own agent command line
	child.Env = env
	child.Stdin, child.Stdout, child.Stderr = stdin, stdout, stderr
	if err := child.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitErr(ee.ExitCode())
		}
		return fmt.Errorf("run %s: %w", args[0], err)
	}
	return nil
}

// runWorkerChildPlain runs the agent unrouted (customer compute where
// nothing can be routed).
func runWorkerChildPlain(ctx context.Context, args []string, errOut io.Writer) error {
	fmt.Fprintln(errOut, "cloud-session worker: running the agent unrouted")
	return runWorkerChild(ctx, args, nil, os.Stdin, os.Stdout, errOut)
}

// workerBackgroundOps is `worker start` / `worker stop`: a detached proxy
// process and a route handed out through a sink.
type workerBackgroundOps struct {
	workerCommon
	stateDir string
	lookup   cloudsession.LookupEnv
	state    cloudsession.WorkerState
	// spawn starts the background proxy (spawnDetached in production).
	spawn func(argv []string, dir string, env []string) (*os.Process, error)
}

func newWorkerBackgroundOps(configPath, stateDir string, p cloudsession.WorkerPlan, lookup cloudsession.LookupEnv, errOut io.Writer) *workerBackgroundOps {
	return &workerBackgroundOps{
		workerCommon: workerCommon{configPath: configPath, plan: p, errOut: errOut},
		stateDir:     stateDir, lookup: lookup, spawn: spawnDetached,
		state: cloudsession.WorkerState{
			Env: p.Environment.ID, Harness: p.Harness, Sink: p.Sink, ProxyURL: p.ProxyURL,
			Location: p.Location, Route: p.Route,
		},
	}
}

func (o *workerBackgroundOps) startProxy(context.Context) error {
	if err := os.MkdirAll(o.stateDir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	_ = os.Remove(filepath.Join(o.stateDir, workerStopFile))
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate observer: %w", err)
	}
	port, err := o.proxyPort()
	if err != nil {
		return err
	}
	argv := []string{exe, "cloud-session", "worker", "serve", "--state-dir", o.stateDir, "--port", strconv.Itoa(port)}
	if o.configPath != "" {
		argv = append(argv, "--config", o.configPath)
	}
	o.state.StartedAt = time.Now().UTC()
	proc, err := o.spawn(argv, o.stateDir, os.Environ())
	if err != nil {
		return err
	}
	o.state.PID = proc.Pid
	_ = proc.Release()
	return saveWorkerState(o.stateDir, o.state)
}

func (o *workerBackgroundOps) awaitReady(ctx context.Context) error {
	return awaitListening(ctx, o.proxyHostPort(), nil)
}

func (o *workerBackgroundOps) routeOn(context.Context) error {
	switch o.state.Sink {
	case cloudsession.SinkGitHubEnv:
		path, _ := o.lookup("GITHUB_ENV")
		lines, err := cloudsession.RouteOnLines(cloudsession.SinkGitHubEnv, o.state.Route)
		if err != nil {
			return err
		}
		if err := appendFile(path, lines); err != nil {
			return fmt.Errorf("write $GITHUB_ENV: %w", err)
		}
		o.state.GitHubEnv = path
	case cloudsession.SinkEnvFile:
		lines, err := cloudsession.RouteOnLines(cloudsession.SinkEnvFile, o.state.Route)
		if err != nil {
			return err
		}
		path := filepath.Join(o.stateDir, workerRouteFile)
		if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
			return fmt.Errorf("write route file: %w", err)
		}
		o.state.EnvFile = path
	default:
		return fmt.Errorf("route sink %q needs `worker run`", o.state.Sink)
	}
	o.state.RouteOn = true
	return saveWorkerState(o.stateDir, o.state)
}

func (o *workerBackgroundOps) runAgent(context.Context) error {
	return errors.New("worker start does not run the agent")
}

// routeOff takes the route back out and records that BEFORE the proxy
// stops, so an interrupted stop never leaves an unrecorded route.
func (o *workerBackgroundOps) routeOff(context.Context) error {
	switch o.state.Sink {
	case cloudsession.SinkGitHubEnv:
		lines, err := cloudsession.RouteOffLines(cloudsession.SinkGitHubEnv, o.state.Route)
		if err != nil {
			return err
		}
		if o.state.GitHubEnv != "" {
			if err := appendFile(o.state.GitHubEnv, lines); err != nil {
				return fmt.Errorf("write $GITHUB_ENV: %w", err)
			}
		}
	case cloudsession.SinkEnvFile:
		if o.state.EnvFile != "" {
			if err := os.Remove(o.state.EnvFile); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove route file: %w", err)
			}
		}
	}
	o.state.RouteOn = false
	fmt.Fprintln(o.errOut, "cloud-session worker: route off")
	return saveWorkerState(o.stateDir, o.state)
}

func (o *workerBackgroundOps) drainProxy(context.Context) error {
	if o.drain > 0 {
		time.Sleep(o.drain)
	}
	return nil
}

// stopProxy drops the stop file the serve process watches and waits for the
// port to close. No signal is sent to a recorded pid, which could have been
// recycled since `worker start`.
func (o *workerBackgroundOps) stopProxy(context.Context) error {
	if err := os.WriteFile(filepath.Join(o.stateDir, workerStopFile), nil, 0o600); err != nil {
		return fmt.Errorf("write stop file: %w", err)
	}
	if err := awaitClosed(o.proxyHostPort(), workerStopTimeout); err != nil {
		return fmt.Errorf("%w (background proxy pid %d; stop it by hand)", err, o.state.PID)
	}
	fmt.Fprintln(o.errOut, "cloud-session worker: proxy stopped")
	return nil
}

// appendFile appends s to path (created 0600 when absent).
func appendFile(path, s string) error {
	if path == "" {
		return errors.New("no file named")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: $GITHUB_ENV, the file the Actions runner names for exactly this
	if err != nil {
		return err
	}
	if _, err := f.WriteString(s); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// workerStateDir is the worker's state directory beside the database.
func workerStateDir(configPath string) (string, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}
	return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "cloud-session", "worker"), nil
}

func loadWorkerState(dir string) (cloudsession.WorkerState, bool) {
	var st cloudsession.WorkerState
	b, err := os.ReadFile(filepath.Join(dir, workerStateFile))
	if err != nil || json.Unmarshal(b, &st) != nil {
		return cloudsession.WorkerState{}, false
	}
	return st, true
}

func saveWorkerState(dir string, st cloudsession.WorkerState) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode worker state: %w", err)
	}
	tmp := filepath.Join(dir, workerStateFile+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write worker state: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, workerStateFile)); err != nil {
		return fmt.Errorf("write worker state: %w", err)
	}
	return nil
}
