// service_saferestart.go - `observer service restart`, the shipped safe
// restart (SR-12, lane sr-restart).
//
// The daemon IS the proxy, so stopping it while an AI tool routes through it
// gives that tool ConnectionRefused (CLAUDE.md, Don'ts). The safe order is
// route OFF, stop, relaunch, route ON, as one operation; until this verb it
// lived only in the source checkout's scripts/restart-daemon.sh. Now:
//
//   - internal/service.DecideRestart (a table) picks the mechanism: the
//     service manager that runs the daemon (systemd, launchd), or, when none
//     does, the daemon's own graceful shutdown and in-place re-exec (the
//     dashboard restart; same terminal, log, arguments and environment). It
//     refuses inside a session the daemon launched, on a managed node whose
//     organization maintains the routes, and where no mechanism exists.
//   - internal/proxyroute's route hold takes off exactly the routes that
//     reach this proxy (the per-tool route rows and their Leave removers),
//     journals them, and puts exactly those back once the new proxy serves:
//     the file as it was when nothing else wrote it, else the row's own
//     writer with the provenance record put back as it was.
//
// Review fixes (fixup/restart-hold): the daemon's config and proxy port are
// resolved first (the unit's or LaunchAgent's arguments, the running
// daemon's own report) and the environment is built for that config; a
// dashboard that answers while nothing answers on that proxy port, and an
// organization posture that cannot be read, are refusals, never an
// unprotected restart; each verb holds the route hold lock for its whole run;
// and the daemon puts back a hold for its own port once its proxy serves
// (routehold_putback.go), so a stop or a failed restart never leaves routes
// off for good.
//
// Every fact and action is a seam (safeRestartEnv), so the tests run with
// fakes and never touch systemd, launchd, a daemon or real AI tool configs.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/proxyroute"
	"github.com/marmutapp/superbased-observer/internal/service"
)

// safeRestartDefaultTimeout bounds the wait for the new daemon: its own stop
// is bounded at 20s and a cold start runs migrations before the proxy binds.
const safeRestartDefaultTimeout = 90 * time.Second

// safeRestartPollEvery is the readiness poll interval.
const safeRestartPollEvery = 250 * time.Millisecond

// safeRestartOptions is one `observer service restart` request.
type safeRestartOptions struct {
	scope      service.Scope
	configPath string
	keepRoutes bool
	dryRun     bool
	timeout    time.Duration
	liveRuns   cliLiveRunChoice
	out        io.Writer
}

// daemonStatus is what the running daemon's dashboard said about itself.
type daemonStatus struct {
	// Answers: a daemon serving this config's database answered.
	Answers bool
	// StartedAt is its process start (the new process has another one).
	StartedAt string
}

// safeRestartEnv is the I/O the restart needs, every piece a seam.
type safeRestartEnv struct {
	// manager is the host's service manager.
	manager func() service.RestartManager
	// unit reports Observer's unit (or LaunchAgent): installed, running,
	// and its main pid (0 when unknown).
	unit func(m service.RestartManager, scope service.Scope) (installed, active bool, pid int)
	// status asks the running daemon's dashboard who it is.
	status func(ctx context.Context) daemonStatus
	// proxyServing reports whether the proxy on port answers its probe.
	proxyServing func(ctx context.Context, port int) bool
	// inPlace reports whether this OS can re-exec the daemon in place.
	inPlace func() bool
	// daemonChild reports whether this process runs inside a session the
	// daemon launched (daemonPID, 0 when unknown).
	daemonChild func(daemonPID int) bool
	// daemonPID is the running daemon's pid from its start lock (0: none).
	daemonPID func() int
	// orgMaintainsRoutes reports a managed node whose organization
	// maintains the routes (route posture maintain); an error is a posture
	// that could not be read, and the verbs refuse on it.
	orgMaintainsRoutes func(ctx context.Context) (bool, error)
	// daemonProxyPort asks the running daemon's dashboard which port its
	// proxy listens on (GET /api/admin/restart proxy_port); ok is false when
	// no daemon serving this config's database answers.
	daemonProxyPort func(ctx context.Context) (port int, ok bool)
	// proxyExpected reports whether the daemon's config runs the API proxy
	// (capture.proxy active).
	proxyExpected func() bool
	// registrar builds the route registrar for the hold.
	registrar func(port int, dryRun bool) (*proxyroute.Registrar, error)
	// liveRuns asks the daemon about its live sandboxed runs.
	liveRuns daemonLiveRunsClient
	// restartUnit runs verb (restart, start, stop) on the unit; startOnly
	// turns a restart into a start.
	restartUnit func(m service.RestartManager, scope service.Scope, startOnly bool, verb string) error
	// restartInPlace asks the daemon to restart itself.
	restartInPlace func(ctx context.Context) error
	// guardSignals keeps Ctrl-C from ending the run between the route hold
	// and the put-back; the returned func releases the guard.
	guardSignals func(w io.Writer) func()
	sleep        func(time.Duration)
	now          func() time.Time
}

// newSafeRestartEnv is the production environment for the config at
// configPath ("" = the default lookup). A seam so tests swap it whole. The
// verbs build it for the daemon's resolved config (resolveSafeRestartTarget),
// never for the raw --config flag alone.
var newSafeRestartEnv = func(configPath string) safeRestartEnv {
	return safeRestartEnv{
		manager: func() service.RestartManager {
			switch {
			case launchdAvailable():
				return service.ManagerLaunchd
			case systemdAvailable():
				return service.ManagerSystemd
			default:
				return service.ManagerNone
			}
		},
		unit:         serviceUnitState,
		status:       func(ctx context.Context) daemonStatus { return daemonStatusFor(ctx, configPath) },
		proxyServing: proxyServing,
		inPlace:      reexecSupported,
		daemonChild: func(daemonPID int) bool {
			return runningAsDaemonChild() || (daemonPID > 0 && processDescendsFrom(os.Getpid(), daemonPID))
		},
		daemonPID: func() int {
			if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil {
				if l, ok := liveDaemonFor(cfg.Observer.DBPath); ok {
					return l.PID
				}
			}
			return 0
		},
		orgMaintainsRoutes: func(ctx context.Context) (bool, error) { return restartOrgMaintainsRoutes(ctx, configPath) },
		daemonProxyPort:    func(ctx context.Context) (int, bool) { return daemonProxyPortFor(ctx, configPath) },
		proxyExpected:      func() bool { return componentSnapshotFor(configPath).Active("capture.proxy") },
		registrar:          routeHoldRegistrar,
		liveRuns:           newDaemonLiveRunsClient(configPath),
		restartUnit:        restartServiceUnit,
		restartInPlace:     func(ctx context.Context) error { return postDaemonRestart(ctx, resolveDaemonHandoff(ctx, configPath)) },
		guardSignals:       guardRestartSignals,
		sleep:              time.Sleep,
		now:                time.Now,
	}
}

// serviceUnitState reports Observer's unit under manager m. A seam.
var serviceUnitState = func(m service.RestartManager, scope service.Scope) (installed, active bool, pid int) {
	home, _ := os.UserHomeDir()
	switch m {
	case service.ManagerSystemd:
		if _, err := os.Stat(service.UnitPath(scope, home)); err == nil {
			installed = true
		}
		a, p, err := systemctlShow(scope)
		if err != nil {
			return installed, false, 0
		}
		return installed, a, p
	case service.ManagerLaunchd:
		if _, err := os.Stat(service.LaunchAgentPath(home)); err == nil {
			installed = true
		}
		d, err := launchdDeps{}.resolve()
		if err != nil {
			return installed, false, 0
		}
		out, err := d.output(service.Launchctl("print", service.LaunchdTarget(d.uid)))
		if err != nil {
			return installed, false, 0
		}
		pid = service.ParseLaunchdPID(out)
		return installed, pid > 0, pid
	}
	return false, false, 0
}

// restartServiceUnit runs verb on the unit under manager m (a restart with
// startOnly is a start).
func restartServiceUnit(m service.RestartManager, scope service.Scope, startOnly bool, verb string) error {
	if verb == "restart" && startOnly {
		verb = "start"
	}
	switch m {
	case service.ManagerSystemd:
		return serviceSystemctl(service.Systemctl(scope, verb, service.UnitName))
	case service.ManagerLaunchd:
		return runLaunchdLifecycle(verb, scope == service.ScopeSystem, launchdDeps{})
	}
	return errNoSystemd
}

// daemonStatusFor asks the dashboard of the daemon serving configPath's
// database for its process start (GET /api/status started_at).
func daemonStatusFor(ctx context.Context, configPath string) daemonStatus {
	t := resolveDaemonHandoff(ctx, configPath)
	if !t.Use {
		return daemonStatus{}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Base+"/api/status", nil)
	if err != nil {
		return daemonStatus{}
	}
	t.setDBIdentity(req)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req) //nolint:gosec // G704: this node's own dashboard address from its config or listen record
	if err != nil {
		return daemonStatus{}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || isDBIdentityRefusal(resp, t.DBIdentity) {
		return daemonStatus{}
	}
	var body struct {
		StartedAt string `json:"started_at"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body)
	return daemonStatus{Answers: true, StartedAt: body.StartedAt}
}

// routeHoldRegistrar is the route registrar of a route hold: the safe
// restart, stop and start verbs and the daemon's own put-back
// (routehold_putback.go) all build it here, so they read and write the same
// journal under the same locks. A put-back never creates a missing vendor
// directory.
func routeHoldRegistrar(port int, dryRun bool) (*proxyroute.Registrar, error) {
	return proxyroute.NewRegistrar(proxyroute.RegisterOptions{
		ProxyPort: port, DryRun: dryRun,
		Lock: hook.LockSettingsFileIfPresent,
	})
}

// daemonProxyPortFor asks the dashboard of the daemon serving configPath's
// database which port its proxy listens on (GET /api/admin/restart, the
// restart dialog's own report, field proxy_port). ok is false when no such
// daemon answers or it names no port.
func daemonProxyPortFor(ctx context.Context, configPath string) (int, bool) {
	t := resolveDaemonHandoff(ctx, configPath)
	if !t.Use {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.Base+"/api/admin/restart", nil)
	if err != nil {
		return 0, false
	}
	t.setDBIdentity(req)
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req) //nolint:gosec // G704: this node's own dashboard address from its config or listen record
	if err != nil {
		return 0, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || isDBIdentityRefusal(resp, t.DBIdentity) {
		return 0, false
	}
	return daemonProxyPortFromBody(resp.Body)
}

// daemonProxyPortFromBody reads proxy_port from a GET /api/admin/restart
// body; ok is false when it names no valid port.
func daemonProxyPortFromBody(r io.Reader) (int, bool) {
	var body struct {
		ProxyPort int `json:"proxy_port"`
	}
	if json.NewDecoder(io.LimitReader(r, 1<<16)).Decode(&body) != nil || body.ProxyPort <= 0 || body.ProxyPort > 65535 {
		return 0, false
	}
	return body.ProxyPort, true
}

// restartOrgMaintainsRoutes reports whether this node's organization
// maintains the AI tools' proxy routes (route posture maintain), for the
// safe restart and stop. Unlike the launcher's answer (launchOrgOwnsRoute,
// which keeps a preset when unsure), anything it cannot read is an error,
// and the verbs refuse: on a node whose organization does maintain the
// routes, the new daemon would write a route the hold took off back as the
// organization's. The daemon's verified org lock answers for an individual
// node without opening the database; a managed node, a lock that is not
// there yet, and a lock that does not verify read the live governance state.
func restartOrgMaintainsRoutes(ctx context.Context, configPath string) (bool, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return false, fmt.Errorf("the config could not be read: %w", err)
	}
	lock := cfg.Guard.Lock
	switch {
	case lock.TenancyKnown && !lock.Managed:
		return false, nil
	case lock.State == "tampered" && !lock.TenancyKnown:
		return false, errors.New("the organization lock beside the config does not verify (" + lock.Detail + ")")
	}
	eff, err := governanceEffectiveFor(ctx, configPath)
	if err != nil {
		return false, fmt.Errorf("the organization's route posture could not be read: %w", err)
	}
	return eff.RoutePosture().Posture == govern.RoutePostureMaintain, nil
}

// postDaemonRestart asks the daemon at t for its in-place restart (POST
// /api/admin/restart, the dashboard's Restart now): a graceful shutdown and
// a re-exec of the same binary with the same arguments and environment.
func postDaemonRestart(ctx context.Context, t daemonTarget) error {
	if !t.Use {
		return fmt.Errorf("no daemon serving this database answered at %s: %s", strings.TrimPrefix(t.Base, "http://"), t.Reason)
	}
	ctx, cancel := context.WithTimeout(ctx, liveRunsDaemonTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Base+"/api/admin/restart", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	t.setDBIdentity(req)
	resp, err := (&http.Client{Timeout: liveRunsDaemonTimeout}).Do(req) //nolint:gosec // G704: this node's own dashboard address from its config or listen record
	if err != nil {
		return fmt.Errorf("the daemon did not answer the restart request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if isDBIdentityRefusal(resp, t.DBIdentity) {
		return fmt.Errorf("the daemon at %s serves another database; it was not restarted", req.URL.Host)
	}
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	var body struct {
		Error string `json:"error"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if json.Unmarshal(raw, &body) != nil || body.Error == "" {
		body.Error = strings.TrimSpace(string(raw))
	}
	return fmt.Errorf("the daemon refused the restart (%d): %s", resp.StatusCode, body.Error)
}

// processDescendsFrom reports whether pid's parent chain reaches ancestor.
// It reads /proc (Linux); elsewhere it answers false and the daemon's
// OBSERVER_DAEMON_CHILD marker is the signal.
func processDescendsFrom(pid, ancestor int) bool {
	if runtime.GOOS != "linux" || ancestor <= 1 {
		return false
	}
	cur := pid
	for i := 0; i < 64 && cur > 1; i++ {
		if cur == ancestor {
			return true
		}
		stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(cur), "stat")) //nolint:gosec // a /proc path built from a pid
		if err != nil {
			return false
		}
		s := string(stat)
		j := strings.LastIndex(s, ") ")
		if j < 0 {
			return false
		}
		f := strings.Fields(s[j+2:])
		if len(f) < 2 {
			return false
		}
		next, err := strconv.Atoi(f[1])
		if err != nil {
			return false
		}
		cur = next
	}
	return false
}

// guardRestartSignals catches Ctrl-C (and SIGTERM) while the routes are off,
// so the run still puts them back; it says so once.
func guardRestartSignals(w io.Writer) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	var once sync.Once
	go func() {
		for {
			select {
			case <-ch:
				once.Do(func() {
					fmt.Fprintln(w, "Finishing the restart first, so the proxy routes go back on.")
				})
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

// restartMechanismText describes the mechanism for the opening line.
func restartMechanismText(p service.RestartPlan) string {
	switch p.Mechanism {
	case service.RestartViaSystemd, service.RestartViaLaunchd, service.RestartInPlace:
		return p.Reason
	}
	return string(p.Mechanism)
}

// safeRestartEnvFor builds the environment for one config path (the
// production one is newSafeRestartEnv).
type safeRestartEnvFor func(configPath string) safeRestartEnv

// safeRestartTarget is the daemon a service verb acts on, resolved before
// anything else: the config it runs with, its proxy port, and the
// environment built for that config.
type safeRestartTarget struct {
	manager    service.RestartManager
	configPath string
	port       int
	env        safeRestartEnv
}

// resolveSafeRestartTarget resolves the config and proxy port of the daemon
// to act on: the --config given, else the one the installed unit (systemd)
// or LaunchAgent (launchd) passes the daemon, else the default lookup; the
// port is the one the running daemon reports for its proxy, else the unit's
// or agent's --port, else the config's [proxy] port, else 8820. The
// environment is built for the resolved config, so the dashboard, the start
// lock and the organization's posture are read for that daemon.
func resolveSafeRestartTarget(ctx context.Context, opts safeRestartOptions, envFor safeRestartEnvFor) safeRestartTarget {
	env := envFor(opts.configPath)
	m := env.manager()
	configPath, baked := opts.configPath, 0
	if configPath == "" {
		if args, ok := installedServiceArgs(m, opts.scope); ok {
			configPath, baked = serviceArgValue(args, "--config"), atoiOrZero(serviceArgValue(args, "--port"))
			if configPath != "" {
				env = envFor(configPath)
			}
		}
	}
	port := serviceProxyPort(configPath, baked)
	if p, ok := env.daemonProxyPort(ctx); ok {
		port = p
	}
	return safeRestartTarget{manager: m, configPath: configPath, port: port, env: env}
}

// installedServiceArgs reads the arguments the installed unit (systemd) or
// LaunchAgent (launchd) passes the daemon. A seam for tests.
var installedServiceArgs = func(m service.RestartManager, scope service.Scope) ([]string, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, false
	}
	switch m {
	case service.ManagerSystemd:
		raw, err := os.ReadFile(service.UnitPath(scope, home)) //nolint:gosec // the unit path is fixed by scope
		if err != nil {
			return nil, false
		}
		_, args, ok := service.SplitExecStart(service.ExecStartLine(string(raw)))
		return args, ok
	case service.ManagerLaunchd:
		raw, err := os.ReadFile(service.LaunchAgentPath(home)) //nolint:gosec // the agent path is fixed
		if err != nil {
			return nil, false
		}
		return service.LaunchAgentProgramArguments(string(raw))
	}
	return nil, false
}

// lockRouteHoldForVerb takes the route hold lock for a verb's whole run:
// another restart, stop or start (or a daemon putting routes back) running
// meanwhile is a refusal that changes nothing.
func lockRouteHoldForVerb(reg *proxyroute.Registrar) (func(), error) {
	release, ok, err := reg.LockRouteHold()
	if err != nil {
		return nil, fmt.Errorf("refused: the route hold lock beside %s could not be taken (%w); nothing was changed", reg.RouteHoldPath(), err)
	}
	if !ok {
		return nil, fmt.Errorf("refused: %w. Nothing was changed", proxyroute.ErrRouteHoldBusy)
	}
	return release, nil
}

// orgPosture fills the organization inputs of a plan: only a serving proxy
// whose routes would be taken off needs them.
func orgPosture(ctx context.Context, env safeRestartEnv, in *service.RestartInputs) error {
	if !in.ProxyServing || in.KeepRoutes {
		return nil
	}
	owns, err := env.orgMaintainsRoutes(ctx)
	in.OrgMaintainsRoutes, in.OrgUnknown = owns, err != nil
	return err
}

// refusal is a plan's refusal, with what could not be read when that is why.
func refusal(plan service.RestartPlan, orgErr error) error {
	if plan.Rule == "organization route posture unreadable" && orgErr != nil {
		return fmt.Errorf("refused: %s (%w). Nothing was changed", plan.Reason, orgErr)
	}
	return fmt.Errorf("refused: %s. Nothing was changed", plan.Reason)
}

// pendingHoldNote says what happens to routes an earlier run left off.
func pendingHoldNote(pending proxyroute.RouteHold) string {
	return fmt.Sprintf("%d proxy route(s) an earlier restart or stop took off (%s) stay off until a daemon's proxy on :%d answers; "+
		"the daemon puts them back itself then (`observer doctor` lists any still off)",
		len(pending.Routes), heldTools(pending.Routes), pending.Port)
}

// restartPendingHold reads the routes an earlier run left off and announces
// them. A hold for another proxy port is reported and set aside: routes held
// for another proxy are never put back onto this one.
func restartPendingHold(w io.Writer, reg *proxyroute.Registrar, port int) (proxyroute.RouteHold, error) {
	pending, err := reg.PendingRouteHold()
	if err != nil {
		return pending, fmt.Errorf("refused: the route hold journal %s could not be read (%w); nothing was changed", reg.RouteHoldPath(), err)
	}
	if !pending.Empty() && pending.Port != port {
		fmt.Fprintf(w, "%d proxy route(s) were taken off for a proxy on :%d, not :%d, so this restart leaves them off; `observer doctor` lists them.\n",
			len(pending.Routes), pending.Port, port)
		return proxyroute.RouteHold{}, nil
	}
	if !pending.Empty() {
		fmt.Fprintf(w, "An earlier restart was interrupted with %d proxy route(s) off (%s); they go back on once the daemon serves.\n",
			len(pending.Routes), heldTools(pending.Routes))
	}
	return pending, nil
}

// holdRoutesFor takes the routes to this proxy off and reports them. When
// the hold fails half way (a journal write), the routes already off go
// straight back onto the proxy that still serves, and the daemon is left as
// it is (verb names what was not done: "restarted", "stopped").
func holdRoutesFor(ctx context.Context, w io.Writer, env safeRestartEnv, reg *proxyroute.Registrar, port int, verb string) (proxyroute.RouteHold, error) {
	h, results, err := reg.HoldRoutes()
	if err != nil {
		if !h.Empty() && env.proxyServing(ctx, port) {
			reportRelease(w, reg.ReleaseRoutes(h))
			return proxyroute.RouteHold{}, fmt.Errorf("refused: the proxy routes could not be held (%w); the daemon was not %s", err, verb)
		}
		return proxyroute.RouteHold{}, fmt.Errorf("refused: the proxy routes could not be checked (%w); nothing was changed", err)
	}
	reportHold(w, port, results)
	return h, nil
}

// runSafeRestart is `observer service restart`.
func runSafeRestart(ctx context.Context, opts safeRestartOptions, envFor safeRestartEnvFor) error {
	w := opts.out
	tgt := resolveSafeRestartTarget(ctx, opts, envFor)
	env, port, m := tgt.env, tgt.port, tgt.manager
	opts.configPath = tgt.configPath
	if m == service.ManagerLaunchd && opts.scope == service.ScopeSystem {
		return errLaunchdSystemScope
	}
	reg, err := env.registrar(port, opts.dryRun)
	if err != nil {
		return fmt.Errorf("observer service restart: %w", err)
	}
	unlock, err := lockRouteHoldForVerb(reg)
	if err != nil {
		return err
	}
	defer unlock()

	installed, active, unitPID := env.unit(m, opts.scope)
	st := env.status(ctx)
	serving := env.proxyServing(ctx, port)
	daemonPID := env.daemonPID()
	if daemonPID == 0 {
		daemonPID = unitPID
	}
	in := service.RestartInputs{
		Manager: m, UnitInstalled: installed, UnitActive: active,
		DashboardAnswers: st.Answers, ProxyServing: serving, InPlaceSupported: env.inPlace(),
		DaemonChild: env.daemonChild(daemonPID), KeepRoutes: opts.keepRoutes,
		ProxyExpected: env.proxyExpected(),
	}
	orgErr := orgPosture(ctx, env, &in)
	plan := service.DecideRestart(in)

	pending, err := restartPendingHold(w, reg, port)
	if err != nil {
		return err
	}

	switch plan.Mechanism {
	case service.RestartRefuse:
		return refusal(plan, orgErr)
	case service.RestartNothing:
		if !pending.Empty() {
			return fmt.Errorf("%s. %s", plan.Reason, pendingHoldNote(pending))
		}
		return fmt.Errorf("%s", plan.Reason)
	}
	fmt.Fprintf(w, "Restarting the Observer daemon: %s.\n", restartMechanismText(plan))

	if opts.dryRun {
		return safeRestartDryRun(w, plan, reg, port, serving)
	}

	if in.Running() {
		if err := cliLiveRunCheck(ctx, w, liveRunTriggerServiceRestart, env.liveRuns, opts.liveRuns); err != nil {
			return err
		}
	}

	hold := pending
	if plan.HoldRoutes {
		if hold, err = holdRoutesFor(ctx, w, env, reg, port, "restarted"); err != nil {
			return err
		}
	} else {
		reportNoHold(w, plan, serving, opts.keepRoutes, port)
	}
	release := env.guardSignals(w)
	defer release()

	oldPID := unitPID
	if err := safeRestartRun(ctx, plan, m, opts.scope, env); err != nil {
		// The restart did not happen (or its outcome is unknown): put the
		// routes back only onto a proxy that serves.
		if env.proxyServing(ctx, port) {
			reportRelease(w, reg.ReleaseRoutes(hold))
		} else if !hold.Empty() {
			fmt.Fprintf(w, "The proxy on :%d is not answering, so the routes stay off; the daemon puts them back itself once its proxy answers again (`observer doctor` lists any still off).\n", port)
		}
		return fmt.Errorf("the restart failed: %w", err)
	}

	wantProxy := serving || !hold.Empty()
	if !safeRestartWait(ctx, env, opts, m, port, st, oldPID, wantProxy) {
		if hold.Empty() {
			return fmt.Errorf("the daemon did not answer within %s; check it with `observer service status` or its log", opts.timeout)
		}
		return fmt.Errorf("the daemon did not answer within %s, so the proxy routes stay off for now (your AI tools reach their providers directly); "+
			"the daemon puts them back itself once its proxy on :%d answers, and `observer doctor` lists any still off", opts.timeout, port)
	}
	switch {
	case serving || wantProxy:
		fmt.Fprintf(w, "Restarted. The proxy on :%d answers again.\n", port)
	case plan.StartOnly:
		fmt.Fprintln(w, "Started.")
	default:
		fmt.Fprintln(w, "Restarted.")
	}
	if !hold.Empty() {
		if failed := reportRelease(w, reg.ReleaseRoutes(hold)); failed > 0 {
			return fmt.Errorf("%d proxy route(s) could not be put back; they stay listed in %s for the next `observer service restart`", failed, reg.RouteHoldPath())
		}
	}
	return nil
}

// safeRestartRun performs the plan's restart.
func safeRestartRun(ctx context.Context, plan service.RestartPlan, m service.RestartManager, scope service.Scope, env safeRestartEnv) error {
	switch plan.Mechanism {
	case service.RestartViaSystemd, service.RestartViaLaunchd:
		return env.restartUnit(m, scope, plan.StartOnly, "restart")
	case service.RestartInPlace:
		return env.restartInPlace(ctx)
	}
	return fmt.Errorf("no restart mechanism (%s)", plan.Mechanism)
}

// safeRestartWait waits, bounded by opts.timeout, for the NEW daemon: its
// dashboard start time changed (or, without a dashboard, the unit's pid
// changed) and, when wantProxy, its proxy answers.
func safeRestartWait(ctx context.Context, env safeRestartEnv, opts safeRestartOptions, m service.RestartManager, port int, before daemonStatus, oldPID int, wantProxy bool) bool {
	deadline := env.now().Add(opts.timeout)
	for {
		fresh := true
		switch {
		case before.StartedAt != "":
			st := env.status(ctx)
			fresh = st.Answers && st.StartedAt != "" && st.StartedAt != before.StartedAt
		case oldPID > 0:
			_, _, pid := env.unit(m, opts.scope)
			fresh = pid > 0 && pid != oldPID
		}
		if fresh && (!wantProxy || env.proxyServing(ctx, port)) {
			return true
		}
		if !env.now().Before(deadline) || ctx.Err() != nil {
			return false
		}
		env.sleep(safeRestartPollEvery)
	}
}

// safeRestartDryRun prints what the restart would do to the routes.
func safeRestartDryRun(w io.Writer, plan service.RestartPlan, reg *proxyroute.Registrar, port int, serving bool) error {
	if !plan.HoldRoutes {
		reportNoHold(w, plan, serving, false, port)
		fmt.Fprintln(w, "Dry run: nothing was changed.")
		return nil
	}
	_, results, err := reg.HoldRoutes()
	if err != nil {
		return fmt.Errorf("the proxy routes could not be checked: %w", err)
	}
	reportHold(w, port, results)
	fmt.Fprintln(w, "Dry run: nothing was changed.")
	return nil
}

// reportNoHold says why no route is taken off.
func reportNoHold(w io.Writer, plan service.RestartPlan, serving, keepRoutes bool, port int) {
	switch {
	case keepRoutes && serving:
		fmt.Fprintf(w, "--keep-routes: the proxy routes to :%d stay on, so a request an AI tool sends during the restart fails; restart between AI turns.\n", port)
	case !serving && !plan.StartOnly:
		fmt.Fprintf(w, "Nothing answers on the proxy port :%d, so no AI tool is routed through this daemon and no route is taken off.\n", port)
	}
}

// reportHold prints the hold's results.
func reportHold(w io.Writer, port int, results []proxyroute.HoldResult) {
	if len(results) == 0 {
		fmt.Fprintf(w, "No proxy route reaches :%d, so none is taken off.\n", port)
		return
	}
	fmt.Fprintf(w, "Taking the proxy routes to :%d off first, so your AI tools reach their providers directly during the restart:\n", port)
	for _, r := range results {
		switch {
		case r.Err != nil:
			fmt.Fprintf(w, "  WARN %s (%s): could not take the route off (%v); it stays on.\n", r.Tool, r.ConfigPath, r.Err)
		case r.Action == proxyroute.HoldTakeOff && r.TakenOff:
			fmt.Fprintf(w, "  off   %s (%s)\n", r.Tool, r.ConfigPath)
		case r.Action == proxyroute.HoldTakeOff:
			fmt.Fprintf(w, "  would take off  %s (%s)\n", r.Tool, r.ConfigPath)
		default:
			fmt.Fprintf(w, "  kept  %s (%s): %s; a request it sends during the restart fails.\n", r.Tool, r.ConfigPath, proxyroute.HoldReasonText(r.Reason))
		}
	}
}

// releaseOutcomeText is the put-back line for each outcome.
var releaseOutcomeText = map[proxyroute.ReleaseOutcome]string{
	proxyroute.ReleaseRestored:         "back  %s (%s), exactly as it was",
	proxyroute.ReleaseRewritten:        "back  %s (%s), written again by Observer's route writer (the file changed during the restart)",
	proxyroute.ReleaseRewrittenDiffers: "WARN  %s (%s): written again, but the route now differs from the one taken off; check it",
	proxyroute.ReleaseSetMeanwhile:     "left  %s (%s): a route was set there during the restart, so it was left as it is",
	proxyroute.ReleaseChangedMeanwhile: "left  %s (%s): a setting the route lives beside changed during the restart, so Observer did not write over it and the route stays off; route it again with `observer init` (or Settings > Connected tools)",
	proxyroute.ReleaseConfigGone:       "gone  %s (%s): the file is gone, so nothing was put back",
	proxyroute.ReleaseFailed:           "WARN  %s (%s): could not put the route back",
}

// reportRelease prints the put-back and returns how many failed.
func reportRelease(w io.Writer, results []proxyroute.ReleaseResult) int {
	if len(results) == 0 {
		return 0
	}
	fmt.Fprintln(w, "Putting the proxy routes back:")
	failed := 0
	for _, r := range results {
		if r.Tool == "" {
			fmt.Fprintf(w, "  WARN the route hold journal could not be updated: %v\n", r.Err)
			continue
		}
		line := fmt.Sprintf("  "+releaseOutcomeText[r.Outcome], r.Tool, r.ConfigPath)
		if r.Err != nil {
			line += fmt.Sprintf(" (%v)", r.Err)
		}
		fmt.Fprintln(w, line)
		if r.Outcome == proxyroute.ReleaseFailed {
			failed++
		}
	}
	return failed
}

// heldTools lists the held routes' tools.
func heldTools(routes []proxyroute.HeldRoute) string {
	names := make([]string, 0, len(routes))
	for _, r := range routes {
		names = append(names, r.Tool)
	}
	return strings.Join(names, ", ")
}

// runSafeStop is `observer service stop`: the routes that reach this proxy
// come off first (journaled in the route hold), then the service manager
// stops the daemon, so no AI tool is left pointed at a proxy that is gone.
// `observer service start` puts them back. It refuses where the restart
// refuses for the same reasons (a session the daemon started, routes the
// organization maintains) unless --keep-routes.
func runSafeStop(ctx context.Context, opts safeRestartOptions, envFor safeRestartEnvFor) error {
	w := opts.out
	tgt := resolveSafeRestartTarget(ctx, opts, envFor)
	env, port, m := tgt.env, tgt.port, tgt.manager
	opts.configPath = tgt.configPath
	if m == service.ManagerNone {
		return errNoSystemd
	}
	reg, err := env.registrar(port, false)
	if err != nil {
		return fmt.Errorf("observer service stop: %w", err)
	}
	unlock, err := lockRouteHoldForVerb(reg)
	if err != nil {
		return err
	}
	defer unlock()
	_, active, unitPID := env.unit(m, opts.scope)
	serving := active && env.proxyServing(ctx, port)
	daemonPID := env.daemonPID()
	if daemonPID == 0 {
		daemonPID = unitPID
	}
	in := service.RestartInputs{
		Manager: m, UnitActive: active, ProxyServing: serving, DaemonChild: env.daemonChild(daemonPID), KeepRoutes: opts.keepRoutes,
		DashboardAnswers: active && env.status(ctx).Answers, ProxyExpected: env.proxyExpected(),
	}
	orgErr := orgPosture(ctx, env, &in)
	if plan := service.DecideRestart(in); plan.Mechanism == service.RestartRefuse {
		err := refusal(plan, orgErr)
		return errors.New(strings.ReplaceAll(err.Error(), "service restart --keep-routes", "service stop --keep-routes"))
	}
	var hold proxyroute.RouteHold
	if serving && !opts.keepRoutes {
		if hold, err = holdRoutesFor(ctx, w, env, reg, port, "stopped"); err != nil {
			return err
		}
	}
	if err := env.restartUnit(m, opts.scope, false, "stop"); err != nil {
		if !hold.Empty() && env.proxyServing(ctx, port) {
			reportRelease(w, reg.ReleaseRoutes(hold))
		}
		return err
	}
	if !hold.Empty() {
		fmt.Fprintf(w, "Stopped. %d proxy route(s) stay off, so your AI tools reach their providers directly; they go back on once the daemon's proxy answers again (`observer service start`).\n", len(hold.Routes))
	}
	return nil
}

// runSafeStart is `observer service start`: the service manager starts the
// daemon and, when a stop (or an interrupted restart) left proxy routes off,
// they go back on once the new proxy answers. With no service manager it
// cannot start a daemon, but it still puts back the routes a hold left off
// when a daemon's proxy on that port already answers.
func runSafeStart(ctx context.Context, opts safeRestartOptions, envFor safeRestartEnvFor) error {
	w := opts.out
	tgt := resolveSafeRestartTarget(ctx, opts, envFor)
	env, port, m := tgt.env, tgt.port, tgt.manager
	opts.configPath = tgt.configPath
	reg, err := env.registrar(port, false)
	if err != nil {
		return fmt.Errorf("observer service start: %w", err)
	}
	unlock, err := lockRouteHoldForVerb(reg)
	if err != nil {
		return err
	}
	defer unlock()
	pending, perr := reg.PendingRouteHold()
	if perr != nil && m != service.ManagerNone {
		// Start the daemon anyway; the routes stay as they are.
		if err := env.restartUnit(m, opts.scope, true, "start"); err != nil {
			return err
		}
		return fmt.Errorf("the route hold journal %s could not be read (%w); no route was put back", reg.RouteHoldPath(), perr)
	}
	if perr != nil {
		return fmt.Errorf("the route hold journal %s could not be read (%w); no route was put back", reg.RouteHoldPath(), perr)
	}
	if !pending.Empty() && pending.Port != port {
		fmt.Fprintf(w, "%d proxy route(s) were taken off for a proxy on :%d, not :%d, so they stay off; `observer doctor` lists them.\n",
			len(pending.Routes), pending.Port, port)
		pending = proxyroute.RouteHold{}
	}
	if m == service.ManagerNone {
		if pending.Empty() || !env.proxyServing(ctx, port) {
			if !pending.Empty() {
				return fmt.Errorf("%w\n  %s; start the daemon with `observer start`", errNoSystemd, pendingHoldNote(pending))
			}
			return errNoSystemd
		}
		// A daemon already serves the port: put its routes back.
	} else if err := env.restartUnit(m, opts.scope, true, "start"); err != nil {
		if !pending.Empty() {
			return fmt.Errorf("%w; %s", err, pendingHoldNote(pending))
		}
		return err
	}
	if pending.Empty() {
		return nil
	}
	deadline := env.now().Add(opts.timeout)
	for !env.proxyServing(ctx, port) {
		if !env.now().Before(deadline) || ctx.Err() != nil {
			return fmt.Errorf("the proxy on :%d did not answer within %s, so %d proxy route(s) stay off for now; the daemon puts them back itself once its proxy answers (`observer doctor` lists any still off)",
				port, opts.timeout, len(pending.Routes))
		}
		env.sleep(safeRestartPollEvery)
	}
	if failed := reportRelease(w, reg.ReleaseRoutes(pending)); failed > 0 {
		return fmt.Errorf("%d proxy route(s) could not be put back; they stay listed in %s", failed, reg.RouteHoldPath())
	}
	return nil
}

// errSafeRestartFlags is a contradictory flag pair.
var errSafeRestartFlags = errors.New("--when-idle and --end-sandboxed-runs are two different answers; pass one")
