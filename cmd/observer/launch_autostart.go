package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/daemonstart"
	"github.com/marmutapp/superbased-observer/internal/dblease"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/service"
)

// launch_autostart.go is the one seam every `observer <tool>` launcher walks
// before its proxy-down fallback (operator ruling L-169, 2026-11-24): a
// developer who runs a launcher while the daemon is down expects Observer to
// come up, so the launcher starts the daemon this install owns, waits for its
// proxy (bounded, [launch].start_daemon_wait_seconds, default 30 s) and then
// launches routed exactly as when the daemon was up. Only a daemon that cannot
// come up leaves the launch to the proxy-down fallback rows
// (decideProxyFallback: direct with a notice on an individual node, a refusal
// where the organization owns the routes or a route the launcher cannot take
// away is pinned).
//
// The decision is internal/daemonstart's table; this file gathers its facts,
// takes the launcher start lock and performs the start and the wait. Every
// piece of I/O is a field of launchAutostartEnv, so the tests run a stand-in
// starter against a loopback port and never start a real daemon. The daemon
// puts back the routes a stop took off itself once its proxy serves
// (routehold_putback.go); the launcher never touches them.
//
// Callers: envLauncherProxyGate (every env launcher and opencode, so cline-cli,
// pi, hermes, prime-agent, gemini, ...), `observer claude` and `observer
// codex` before decideProxyFallback, and the attach gate's reachability probe
// (launcherAttach), so an interactive launch attaches to the daemon it just
// started, as it would have to a running one.

// launchAutostartRequest is one launch's question: does the daemon answer,
// and if not, can this launcher bring it up?
type launchAutostartRequest struct {
	// label is the stderr label ("claude").
	label string
	// configPath is the launcher's --config ("" = the default lookup); the
	// daemon it starts runs with the same one.
	configPath string
	// proxyURL is the proxy URL the launcher resolved.
	proxyURL string
	// wanted: the launch needs the daemon (a routed launch, or an attach).
	wanted bool
	stderr io.Writer
}

// launchAutostartResult is the seam's answer.
type launchAutostartResult struct {
	// up: the Observer proxy answers at the launcher's URL; launch routed.
	up bool
	// started: this call started a daemon or waited for one that was
	// starting, and it came up.
	started bool
}

// launchAutostartEnv is the I/O the seam needs, every piece a seam.
type launchAutostartEnv struct {
	// testBinary: a test binary that installed no stand-in. It reads as
	// auto-start off, so no test ever starts a real daemon.
	testBinary bool
	// probe reports the proxy's state at proxyURL; own is whether that is
	// this node's own listener (only then is a foreign answer classified).
	probe func(ctx context.Context, proxyURL string, own bool) daemonstart.ProxyState
	// loadConfig loads the launcher's config.
	loadConfig func(configPath string) (config.Config, error)
	// notServed is "" when the daemon this config starts serves the proxy.
	notServed   func(cfg config.Config) string
	daemonChild func() bool
	inSandbox   func() bool
	// otherContext names the OS context this machine's daemon belongs to
	// when it is not this one.
	otherContext func(cfg config.Config) daemonstart.OtherContext
	// daemonRunning reports a live daemon start lock for dbPath.
	daemonRunning func(dbPath string) bool
	// startLock takes the launcher start lock in dir without waiting;
	// ok=false when another launcher holds it.
	startLock func(dir string) (release func(), ok bool)
	// portHeld reports whether the proxy's address cannot be bound.
	portHeld func(proxyURL string) bool
	// stopped reports that a stop took this port's routes off (a pending
	// route hold); only the copy reads it.
	stopped func(port int) bool
	// mechanism resolves how to start the daemon this install owns.
	mechanism func(configPath string) launchStartPlan
	// start performs the plan; exited, when not nil, receives the daemon's
	// exit status if it ends before the wait does.
	start func(ctx context.Context, plan launchStartPlan) (exited <-chan string, err error)
	now   func() time.Time
	sleep func(time.Duration)
}

// launchStartPlan is how this launch starts the daemon.
type launchStartPlan struct {
	mechanism daemonstart.Mechanism
	// argv is the background start's `observer start` invocation (sign-in
	// and detached only).
	argv []string
	// log is where the daemon's output goes, named in the line.
	log string
	// dir is the background start's working directory.
	dir string
}

// launchAutostartState is the one owner of this process's auto-start
// state: the --no-start flag the launcher's argv carried, and whether a
// start or wait already ran (a launcher process launches once, so the
// attach gate and the proxy-down path share one attempt, never two).
type launchAutostartState struct {
	mu        sync.Mutex
	noStart   bool
	attempted bool
	lastUp    bool
}

var launchAutostart = &launchAutostartState{}

// setNoStart records the launcher's --no-start flag.
func (s *launchAutostartState) setNoStart(v bool) {
	s.mu.Lock()
	s.noStart = v
	s.mu.Unlock()
}

// launchAutostartEnvFor is the production environment; a seam so tests swap
// it whole (stubLaunchAutostart).
var launchAutostartEnvFor = defaultLaunchAutostartEnv

// launchAutostartPoll is the readiness poll interval.
const launchAutostartPoll = 250 * time.Millisecond

// launchProxyUp is the seam every launcher calls where it used to dial the
// proxy: it answers whether the Observer proxy is up, starting the daemon
// first when the daemon is down and auto-start applies. It prints at most
// one line of its own (the start or wait line, or a refusal); the caller's
// proxy-down fallback prints the rest when it answers false.
func launchProxyUp(ctx context.Context, req launchAutostartRequest) bool {
	return ensureLaunchDaemon(ctx, req).up
}

// launchRoutedProxyUp is launchProxyUp for a launcher with a
// --no-proxy-route intent (claude, codex): such a launch needs no proxy, so
// it answers false without asking.
func launchRoutedProxyUp(ctx context.Context, label, configPath, proxyURL string, noProxyRoute bool, stderr io.Writer) bool {
	if noProxyRoute {
		return false
	}
	return launchProxyUp(ctx, launchAutostartRequest{label: label, configPath: configPath, proxyURL: proxyURL, wanted: true, stderr: stderr})
}

// launchDownOrgOwned is the managed-node input of decideProxyFallback for
// claude and codex (L-169 settles LPD-2): a routed launch whose proxy is still
// down after launchProxyUp, on a machine whose organization owns the routes.
// Asked only then, so the governance read is paid only on that path.
func launchDownOrgOwned(ctx context.Context, configPath string, noProxyRoute, proxyUp bool) bool {
	if noProxyRoute || proxyUp {
		return false
	}
	return launchOrgOwnsRoute(ctx, configPath)
}

// ensureLaunchDaemon is launchProxyUp with the full result.
func ensureLaunchDaemon(ctx context.Context, req launchAutostartRequest) launchAutostartResult {
	if !req.wanted {
		return launchAutostartResult{}
	}
	if req.stderr == nil {
		req.stderr = io.Discard
	}
	return launchAutostart.ensure(ctx, launchAutostartEnvFor(), req)
}

// ensure walks the decision for one request against env.
func (st *launchAutostartState) ensure(ctx context.Context, env launchAutostartEnv, req launchAutostartRequest) launchAutostartResult {
	st.mu.Lock()
	defer st.mu.Unlock()
	cfg, cfgErr := env.loadConfig(req.configPath)
	own := cfgErr == nil && launchOwnListener(req.proxyURL, cfg.Proxy.Port)
	state := env.probe(ctx, req.proxyURL, own)
	if state == daemonstart.ProxyServing {
		return launchAutostartResult{up: true}
	}
	if st.attempted && !st.lastUp {
		// One attempt per process: the attach gate already started (or
		// waited for) the daemon and it did not come up.
		return launchAutostartResult{}
	}
	facts := daemonstart.Facts{
		Wanted:      req.wanted,
		Proxy:       state,
		OwnListener: own,
		DaemonChild: env.daemonChild(),
		InSandbox:   env.inSandbox(),
		OptOut:      launchOptOut(env, st.noStart, cfg, cfgErr),
	}
	if cfgErr == nil {
		facts.NotServed = env.notServed(cfg)
	}
	d := daemonstart.Decide(facts)
	// The facts that cost a crossmount scan, a lock glob or the start lock
	// are resolved only once the cheap rows have let the launch through.
	if d.Action == daemonstart.ActionStart {
		facts.Other = env.otherContext(cfg)
		facts.DaemonRunning = env.daemonRunning(cfg.Observer.DBPath)
		d = daemonstart.Decide(facts)
	}
	if d.Action == daemonstart.ActionStart {
		rel, ok := env.startLock(filepath.Dir(cfg.Observer.DBPath))
		if !ok {
			facts.StartBusy = true
		} else {
			defer rel()
			// Under the lock, look again: a launcher that held it may have
			// just brought the daemon up, or left one starting. Only then is
			// the port's bind probe safe (no daemon of ours is binding it).
			facts.Proxy = env.probe(ctx, req.proxyURL, own)
			facts.DaemonRunning = env.daemonRunning(cfg.Observer.DBPath)
			facts.PortHeld = func() bool { return env.portHeld(req.proxyURL) }
		}
		d = daemonstart.Decide(facts)
		if d.Action == daemonstart.ActionProceed {
			return launchAutostartResult{up: true}
		}
	}
	port := urlPortOr(req.proxyURL, cfg.Proxy.Port)
	switch d.Action {
	case daemonstart.ActionRefuse:
		fmt.Fprintln(req.stderr, daemonstart.RefuseLine(req.label, d.Rule, port, facts.Other))
		return launchAutostartResult{}
	case daemonstart.ActionWait:
		st.attempted = true
		fmt.Fprint(req.stderr, daemonstart.WaitLine(req.label))
		st.lastUp = waitLaunchProxy(ctx, env, req, nil, launchWaitBound(cfg), "")
		return launchAutostartResult{up: st.lastUp, started: st.lastUp}
	case daemonstart.ActionStart:
		st.attempted = true
		plan := env.mechanism(req.configPath)
		portN, _ := strconv.Atoi(port)
		fmt.Fprint(req.stderr, daemonstart.StartLine(req.label, plan.mechanism, env.stopped(portN)))
		exited, err := env.start(ctx, plan)
		if err != nil {
			fmt.Fprintln(req.stderr, daemonstart.Failed(err, plan.log))
			return launchAutostartResult{}
		}
		st.lastUp = waitLaunchProxy(ctx, env, req, exited, launchWaitBound(cfg), plan.log)
		return launchAutostartResult{up: st.lastUp, started: st.lastUp}
	}
	return launchAutostartResult{}
}

// waitLaunchProxy polls the proxy until it serves, the bound passes, the
// started daemon exits, or ctx ends; it prints a dot a second and closes the
// line. log names the daemon's output ("" for a daemon this launcher did not
// start).
func waitLaunchProxy(ctx context.Context, env launchAutostartEnv, req launchAutostartRequest, exited <-chan string, bound time.Duration, log string) bool {
	start := env.now()
	deadline := start.Add(bound)
	nextDot := start.Add(time.Second)
	for {
		if env.probe(ctx, req.proxyURL, true) == daemonstart.ProxyServing {
			fmt.Fprintln(req.stderr, daemonstart.Ready(env.now().Sub(start)))
			return true
		}
		select {
		case status := <-exited:
			fmt.Fprintln(req.stderr, daemonstart.Exited(status, log))
			return false
		default:
		}
		now := env.now()
		if !now.Before(deadline) || ctx.Err() != nil {
			fmt.Fprintln(req.stderr, daemonstart.NotReady(bound, log))
			return false
		}
		if !now.Before(nextDot) {
			fmt.Fprint(req.stderr, ".")
			nextDot = nextDot.Add(time.Second)
		}
		env.sleep(launchAutostartPoll)
	}
}

// launchOptOut is why auto-start is off for this launch.
func launchOptOut(env launchAutostartEnv, noStart bool, cfg config.Config, cfgErr error) daemonstart.OptOut {
	switch {
	case noStart:
		return daemonstart.OptOutFlag
	case env.testBinary:
		return daemonstart.OptOutTestBinary
	case cfgErr != nil:
		// A config that does not load would give the started daemon the
		// same trouble; the launcher's own error path names it.
		return daemonstart.OptOutConfig
	case !cfg.Launch.StartDaemon:
		return daemonstart.OptOutConfig
	}
	return daemonstart.OptOutNone
}

// launchWaitBound is [launch].start_daemon_wait_seconds, default 30 s.
func launchWaitBound(cfg config.Config) time.Duration {
	s := cfg.Launch.StartDaemonWaitSeconds
	if s <= 0 {
		s = config.DefaultStartDaemonWaitSeconds
	}
	return time.Duration(s) * time.Second
}

// launchOwnListener reports whether proxyURL is this node's own proxy
// listener: loopback, at the configured port. Pure.
func launchOwnListener(proxyURL string, cfgPort int) bool {
	host, _, ok := splitHostPortFromURL(proxyURL)
	return ok && isLoopbackHost(host) && proxyListenerURL(proxyURL, resolveProxyURL(cfgPort, ""))
}

// urlPortOr is proxyURL's port, else the configured one.
func urlPortOr(proxyURL string, cfgPort int) string {
	if _, p, ok := splitHostPortFromURL(proxyURL); ok {
		return p
	}
	if cfgPort <= 0 {
		cfgPort = 8820
	}
	return strconv.Itoa(cfgPort)
}

// probeLaunchProxy is the production probe: a TCP dial (the check every
// launcher made before L-169), then, on this node's own listener, the
// proxy's liveness endpoint. A listener that answers HTTP with anything but
// the Observer proxy's liveness answer is foreign; one that accepts the
// connection without answering HTTP proves nothing either way and keeps the
// TCP reading.
func probeLaunchProxy(ctx context.Context, proxyURL string, own bool) daemonstart.ProxyState {
	if !proxyReachable(proxyURL, 250*time.Millisecond) {
		return daemonstart.ProxyDown
	}
	if !own {
		return daemonstart.ProxyServing
	}
	host, port, _ := splitHostPortFromURL(proxyURL)
	pctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+proxyHealthzPath, nil)
	if err != nil {
		return daemonstart.ProxyServing
	}
	resp, err := (&http.Client{Timeout: time.Second}).Do(req) //nolint:gosec // G704: this node's own loopback proxy liveness probe
	if err != nil {
		return daemonstart.ProxyServing
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode == http.StatusOK && strings.TrimSpace(string(body)) == `{"status":"ok"}` {
		return daemonstart.ProxyServing
	}
	return daemonstart.ProxyForeign
}

// launchPortHeld reports whether the proxy's address cannot be bound. It
// binds and closes at once; it runs only on the start row, after the start
// lock is held and no daemon start lock is live, so it never races a daemon
// this launcher or another one started.
func launchPortHeld(proxyURL string) bool {
	host, port, ok := splitHostPortFromURL(proxyURL)
	if !ok {
		return false
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, port)) //nolint:gosec // G102: a loopback bind check of this node's own proxy port, closed at once
	if err != nil {
		return true
	}
	_ = ln.Close()
	return false
}

// launchOtherContext is the production cross-OS fact: the crossmount scan
// of other OS contexts' homes for an observer.db (diag.DetectCrossEnvSiblingDBs,
// the same scan `observer start` warns from).
func launchOtherContext(cfg config.Config) daemonstart.OtherContext {
	dbPath := cfg.Observer.DBPath
	if dbPath == "" {
		return daemonstart.OtherContext{}
	}
	var sibs []daemonstart.Sibling
	for _, s := range diag.DetectCrossEnvSiblingDBs(dbPath, crossmount.AllHomes()) {
		sibs = append(sibs, daemonstart.Sibling{Origin: s.Origin, OS: s.OS})
	}
	_, statErr := os.Stat(dbPath)
	return daemonstart.OtherContextFor(daemonstart.ContextFacts{
		OnWindows:      runtime.GOOS == "windows",
		NativeDBExists: statErr == nil,
		Siblings:       sibs,
	})
}

// launchStartLockName is the launcher start lock beside the database: two
// launchers that find the daemon down at once start it once; the other
// waits for the port.
const launchStartLockName = "daemon-autostart"

// launchStartLock takes the launcher start lock without waiting. A lock that
// cannot be taken for any other reason (the directory cannot be created)
// reads as held, so the launcher waits instead of risking a second daemon.
func launchStartLock(dir string) (func(), bool) {
	release, ok, err := dblease.TryAcquire(dir, launchStartLockName)
	if err != nil || !ok {
		return nil, false
	}
	return release, true
}

// launchRoutesStopped reports a pending route hold for port: a stop took
// the routes off, and the daemon this launch starts puts them back.
func launchRoutesStopped(port int) bool {
	reg, err := routeHoldRegistrar(port, true)
	if err != nil {
		return false
	}
	h, err := reg.PendingRouteHold()
	return err == nil && !h.Empty() && h.Port == port
}

// launchStartPlanFor resolves how to start the daemon this install owns
// for configPath.
func launchStartPlanFor(configPath string) launchStartPlan {
	home, _ := os.UserHomeDir()
	facts := daemonstart.MechanismFacts{}
	m := service.ManagerNone
	switch {
	case launchdAvailable():
		m = service.ManagerLaunchd
		_, err := os.Stat(service.LaunchAgentPath(home))
		facts.LaunchAgent = err == nil
	case systemdAvailable():
		m = service.ManagerSystemd
		_, err := os.Stat(service.UnitPath(service.ScopeUser, home))
		facts.SystemdUnit = err == nil
	}
	if facts.LaunchAgent || facts.SystemdUnit {
		if args, ok := installedServiceArgs(m, service.ScopeUser); ok {
			facts.ServiceRunsThisConfig = sameConfigPath(serviceArgValue(args, "--config"), configPath)
		}
	}
	signInBin := launchSignInBinary()
	facts.SignInBinary = signInBin != ""
	logPath := launchDaemonLog(configPath)
	switch mech := daemonstart.ChooseMechanism(facts); mech {
	case daemonstart.MechanismSystemd:
		return launchStartPlan{mechanism: mech, log: "`journalctl --user -u " + service.UnitName + "`"}
	case daemonstart.MechanismLaunchd:
		return launchStartPlan{mechanism: mech, log: service.LaunchdLogPath(home)}
	case daemonstart.MechanismSignIn:
		return launchStartPlan{mechanism: mech, argv: launchStartArgv(signInBin, configPath), log: logPath, dir: home}
	default:
		self, err := absoluteBinaryPath()
		if err != nil {
			self = os.Args[0]
		}
		return launchStartPlan{mechanism: mech, argv: launchStartArgv(self, configPath), log: logPath, dir: home}
	}
}

// launchStartArgv is the background start: `<bin> start --no-open`, with
// the launcher's --config when it named one. Pure.
func launchStartArgv(bin, configPath string) []string {
	argv := []string{bin, "start", "--no-open"}
	if configPath != "" {
		argv = append(argv, "--config", configPath)
	}
	return argv
}

// sameConfigPath reports whether two --config values name the same file
// ("" = the default lookup).
func sameConfigPath(a, b string) bool {
	ra, errA := config.ResolveGlobalPath(a)
	rb, errB := config.ResolveGlobalPath(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return filepath.Clean(ra) == filepath.Clean(rb)
}

// launchDaemonLog is daemon.log beside the config's database (the file
// `observer setup launch` writes too).
func launchDaemonLog(configPath string) string {
	if cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath}); err == nil && cfg.Observer.DBPath != "" {
		return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "daemon.log")
	}
	return daemonLogPath()
}

// launchSignInBinary is the observer binary the Windows sign-in entry
// starts (the install `observer setup autostart on` registered), "" when
// there is none or it is gone.
func launchSignInBinary() string {
	sys := defaultSetupOS()
	if sys.readRun == nil {
		return ""
	}
	v, err := sys.readRun()
	if err != nil {
		return ""
	}
	return signInBinaryFromRunValue(v, binaryName("observer"), func(p string) bool {
		fi, err := os.Stat(p) //nolint:gosec // G703: false positive; the binary path this user's own sign-in Run entry names (written by `observer setup autostart on`), only stat'd to check it is a file
		return err == nil && !fi.IsDir()
	})
}

// signInBinaryFromRunValue extracts the launcher path a Run value quotes
// (setup.RunValue: `"<dir>\observerw.exe" setup launch`) and returns the
// observer binary beside it when exists says it is there. Pure apart from
// exists.
func signInBinaryFromRunValue(v, observerName string, exists func(string) bool) string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, `"`) {
		return ""
	}
	end := strings.Index(v[1:], `"`)
	if end < 0 {
		return ""
	}
	launcher := v[1 : 1+end]
	bin := filepath.Join(filepath.Dir(launcher), observerName)
	if !exists(bin) {
		return ""
	}
	return bin
}

// startLaunchDaemon is the production start.
func startLaunchDaemon(_ context.Context, plan launchStartPlan) (<-chan string, error) {
	switch plan.mechanism {
	case daemonstart.MechanismSystemd, daemonstart.MechanismLaunchd:
		m := service.ManagerSystemd
		if plan.mechanism == daemonstart.MechanismLaunchd {
			m = service.ManagerLaunchd
		}
		return nil, restartServiceUnit(m, service.ScopeUser, true, "start")
	}
	if err := os.MkdirAll(filepath.Dir(plan.log), 0o700); err != nil {
		return nil, fmt.Errorf("create %s: %w", filepath.Dir(plan.log), err)
	}
	p, err := startDaemonDetached(plan.argv, plan.log, plan.dir, "an `observer` launcher (auto-start)")
	if err != nil {
		return nil, err
	}
	exited := make(chan string, 1)
	go func() {
		// Reap the daemon if it ends while this launcher runs, and say so
		// while the launcher still waits for it.
		ps, err := p.Wait()
		switch {
		case err != nil:
			exited <- err.Error()
		default:
			exited <- ps.String()
		}
	}()
	return exited, nil
}

// errStartInTestBinary guards the real start in a test binary (belt and
// braces beside the test-binary opt-out).
var errStartInTestBinary = errors.New("a test binary never starts a real daemon")

// defaultLaunchAutostartEnv is the production environment.
func defaultLaunchAutostartEnv() launchAutostartEnv {
	inTest := testing.Testing()
	return launchAutostartEnv{
		testBinary: inTest,
		probe:      probeLaunchProxy,
		loadConfig: func(p string) (config.Config, error) { return config.Load(config.LoadOptions{GlobalPath: p}) },
		notServed: func(cfg config.Config) string {
			return proxyServingReason(cfg, componentSnapshotForConfig(cfg).Active("capture.proxy"))
		},
		daemonChild:  runningAsDaemonChild,
		inSandbox:    func() bool { return os.Getenv(sandboxEnvMarker) == "1" },
		otherContext: launchOtherContext,
		daemonRunning: func(dbPath string) bool {
			_, ok := liveDaemonFor(dbPath)
			return ok
		},
		startLock: launchStartLock,
		portHeld:  launchPortHeld,
		stopped:   launchRoutesStopped,
		mechanism: launchStartPlanFor,
		start: func(ctx context.Context, plan launchStartPlan) (<-chan string, error) {
			if inTest {
				return nil, errStartInTestBinary
			}
			return startLaunchDaemon(ctx, plan)
		},
		now:   time.Now,
		sleep: time.Sleep,
	}
}

// noStartFlag is the launchers' opt-out of auto-start for one launch.
const noStartFlag = "no-start"

// withNoStartFlag registers --no-start on a launcher verb. Every launcher
// row of launchers.go gets it in one place (newRootCmdWith), so no launcher
// can miss it; launcherArgsOrDone records its value.
func withNoStartFlag(cmd *cobra.Command) *cobra.Command {
	if cmd.Flags().Lookup(noStartFlag) == nil {
		cmd.Flags().Bool(noStartFlag, false,
			"Do not start the observer daemon when it is not running (default: the launcher starts it, waits for its proxy, then launches routed; [launch].start_daemon = false turns that off for every launch). Without a daemon the launch goes direct with a notice, or refuses where the proxy route cannot be taken away.")
	}
	return cmd
}

// recordNoStartFlag records the parsed --no-start value of a launcher verb
// (false when the verb has no such flag, e.g. built outside the root).
func recordNoStartFlag(cmd *cobra.Command) {
	if cmd.Flags().Lookup(noStartFlag) == nil {
		return
	}
	v, err := cmd.Flags().GetBool(noStartFlag)
	launchAutostart.setNoStart(err == nil && v)
}

// attachSocketWait bounds the wait for the attach socket after the launcher
// started the daemon and its proxy answered (the terminals service listens
// beside it). A var for tests.
var attachSocketWait = 5 * time.Second

// attachReachableOrStart is the attach gate's reachability probe with L-169
// folded in: the daemon's attach socket answers, or the daemon was down and
// this launcher started it (or waited for one starting) and its socket then
// answers. The attach gate asks it only on the rows that want the daemon
// (default-on attach on an interactive launch, or --attach), so a scripted
// launch never starts anything here; its proxy-down path decides.
func attachReachableOrStart(ctx context.Context, spec launcherAttachSpec, dbPath, proxyURL string) bool {
	if attachSocketReachable(dbPath) {
		return true
	}
	r := ensureLaunchDaemon(ctx, launchAutostartRequest{
		label:      launcherLabel(spec.tool),
		configPath: spec.configPath,
		proxyURL:   proxyURL,
		wanted:     true,
		stderr:     spec.stderr,
	})
	if !r.started {
		return false
	}
	deadline := time.Now().Add(attachSocketWait)
	for !attachSocketReachable(dbPath) {
		if !time.Now().Before(deadline) || ctx.Err() != nil {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
	return true
}

// launcherLabel is the verb a launcher prints its lines under: the
// registry's launch subcommand for tool ("claude" for claude-code), else the
// tool key.
func launcherLabel(tool string) string {
	if c, ok := integration.For(tool); ok && c.Handoff.Launch != nil && c.Handoff.Launch.Subcommand != "" {
		return c.Handoff.Launch.Subcommand
	}
	return tool
}
