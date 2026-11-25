package main

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/service"
)

// launch_autostart_test.go: L-169, a launcher that finds the daemon down
// starts it, waits for its proxy and continues routed. No test here starts a
// real daemon: the start is a stand-in (standInDaemon) that brings up an HTTP
// liveness endpoint on a loopback port after a delay, the way a daemon's
// proxy comes up.

// autostartFreeAddr returns a loopback address nothing listens on (taken and
// released).
func autostartFreeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// serveHealthz serves the Observer proxy's liveness answer on addr until the
// test ends.
func serveHealthz(t *testing.T, addr string, status int, body string) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Errorf("stand-in daemon: listen %s: %v", addr, err)
		return
	}
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == proxyHealthzPath {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
			return
		}
		http.NotFound(w, r)
	})}
	// Registered before Serve: nothing can answer (and let the test end)
	// before the cleanup is in place.
	t.Cleanup(func() { _ = srv.Close() })
	go func() { _ = srv.Serve(ln) }()
}

// standInDaemon stands in for the actual process start.
type standInDaemon struct {
	t     *testing.T
	addr  string
	delay time.Duration
	// fail makes the start itself fail; exit makes the "daemon" exit before
	// its proxy answers; neverUp starts nothing.
	fail    error
	exit    string
	neverUp bool

	mu     sync.Mutex
	starts int
	plans  []launchStartPlan
}

func (f *standInDaemon) start(_ context.Context, plan launchStartPlan) (<-chan string, error) {
	f.mu.Lock()
	f.starts++
	f.plans = append(f.plans, plan)
	f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	exited := make(chan string, 1)
	switch {
	case f.exit != "":
		exited <- f.exit
	case f.neverUp:
	default:
		go func() {
			time.Sleep(f.delay)
			serveHealthz(f.t, f.addr, http.StatusOK, `{"status":"ok"}`)
		}()
	}
	return exited, nil
}

func (f *standInDaemon) startCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts
}

// testAutostartEnv is the production environment with every fact that
// would read the host pinned: the config names addr's port and a database
// in a throwaway dir, nothing is a daemon child or a sandbox, no other OS
// context, no daemon running; the probe, the start lock and the bind probe
// are the real ones; the start is fd.
func testAutostartEnv(t *testing.T, addr string, fd *standInDaemon) (launchAutostartEnv, *config.Config) {
	t.Helper()
	_, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)
	dbDir := t.TempDir()
	cfg := config.Default()
	cfg.Proxy.Port = port
	cfg.Observer.DBPath = filepath.Join(dbDir, "observer.db")
	cfg.Launch.StartDaemonWaitSeconds = 10
	env := launchAutostartEnv{
		probe: probeLaunchProxy,
		// cfg is read at call time, so a test that edits *cfg (the pointer
		// returned below) changes what the seam reads.
		loadConfig:    func(string) (config.Config, error) { return cfg, nil },
		notServed:     func(config.Config) string { return "" },
		daemonChild:   func() bool { return false },
		inSandbox:     func() bool { return false },
		otherContext:  func(config.Config) daemonstart.OtherContext { return daemonstart.OtherContext{} },
		daemonRunning: func(string) bool { return false },
		startLock:     launchStartLock,
		portHeld:      launchPortHeld,
		stopped:       func(int) bool { return false },
		mechanism: func(configPath string) launchStartPlan {
			return launchStartPlan{
				mechanism: daemonstart.MechanismDetached,
				argv:      launchStartArgv("observer", configPath),
				log:       filepath.Join(dbDir, "daemon.log"),
			}
		},
		start: fd.start,
		now:   time.Now,
		sleep: time.Sleep,
	}
	return env, &cfg
}

// stubLaunchAutostart installs env as the seam's environment and a fresh
// per-process state, restored when the test ends.
func stubLaunchAutostart(t *testing.T, env launchAutostartEnv) {
	t.Helper()
	prevEnv, prevState := launchAutostartEnvFor, launchAutostart
	launchAutostartEnvFor = func() launchAutostartEnv { return env }
	launchAutostart = &launchAutostartState{}
	t.Cleanup(func() { launchAutostartEnvFor, launchAutostart = prevEnv, prevState })
}

func autostartReq(addr string, stderr io.Writer) launchAutostartRequest {
	return launchAutostartRequest{label: "gemini", proxyURL: "http://" + addr, wanted: true, stderr: stderr}
}

// TestLaunchAutostartStartsTheDaemonThenRoutes: the daemon is down, the
// stand-in start brings the proxy up after a delay, and the launch is
// told the proxy is up (it then routes exactly as when it was up).
func TestLaunchAutostartStartsTheDaemonThenRoutes(t *testing.T) {
	addr := autostartFreeAddr(t)
	fd := &standInDaemon{t: t, addr: addr, delay: 1200 * time.Millisecond}
	env, _ := testAutostartEnv(t, addr, fd)
	stubLaunchAutostart(t, env)
	var stderr bytes.Buffer
	if !launchProxyUp(context.Background(), autostartReq(addr, &stderr)) {
		t.Fatalf("the proxy did not come up:\n%s", stderr.String())
	}
	if fd.startCount() != 1 {
		t.Fatalf("starts = %d, want 1", fd.startCount())
	}
	got := stderr.String()
	if !strings.HasPrefix(got, "observer gemini: the observer daemon was not running; starting it in the background ...") ||
		!strings.Contains(got, " ready in ") || strings.Count(got, "\n") != 1 {
		t.Fatalf("want one start line ending ready, got:\n%q", got)
	}
	if !strings.Contains(got, ".") {
		t.Fatalf("no progress dot during a wait over a second:\n%q", got)
	}
	// The same process asks again (the attach gate and then the proxy-down
	// path): it is up, nothing starts twice.
	stderr.Reset()
	if !launchProxyUp(context.Background(), autostartReq(addr, &stderr)) || fd.startCount() != 1 || stderr.Len() != 0 {
		t.Fatalf("second ask: starts=%d stderr=%q", fd.startCount(), stderr.String())
	}
	if argv := fd.plans[0].argv; len(argv) < 3 || argv[1] != "start" || argv[2] != "--no-open" {
		t.Fatalf("background start argv = %v", argv)
	}
}

// TestLaunchAutostartRows walks the seam over the rows that change what it
// does, each against a real closed loopback port.
func TestLaunchAutostartRows(t *testing.T) {
	cases := []struct {
		name      string
		edit      func(env *launchAutostartEnv, cfg *config.Config, fd *standInDaemon, st *launchAutostartState)
		wantUp    bool
		wantStart int
		want      string // "" = nothing printed
	}{
		{
			name: "a dashboard terminal the daemon spawned never starts one",
			edit: func(env *launchAutostartEnv, _ *config.Config, _ *standInDaemon, _ *launchAutostartState) {
				env.daemonChild = func() bool { return true }
			},
		},
		{
			name: "a build without capture.proxy has nothing to start (D-514)",
			edit: func(env *launchAutostartEnv, _ *config.Config, _ *standInDaemon, _ *launchAutostartState) {
				env.notServed = func(config.Config) string { return "capture.proxy is not in this build" }
			},
		},
		{
			name: "inside a sandbox",
			edit: func(env *launchAutostartEnv, _ *config.Config, _ *standInDaemon, _ *launchAutostartState) {
				env.inSandbox = func() bool { return true }
			},
		},
		{
			name: "--no-start",
			edit: func(_ *launchAutostartEnv, _ *config.Config, _ *standInDaemon, st *launchAutostartState) {
				st.setNoStart(true)
			},
		},
		{
			name: "[launch].start_daemon = false",
			edit: func(_ *launchAutostartEnv, cfg *config.Config, _ *standInDaemon, _ *launchAutostartState) {
				cfg.Launch.StartDaemon = false
			},
		},
		{
			name: "a test binary with no stand-in",
			edit: func(env *launchAutostartEnv, _ *config.Config, _ *standInDaemon, _ *launchAutostartState) {
				env.testBinary = true
			},
		},
		{
			name: "a --proxy override to another port is not this node's to start",
			edit: func(_ *launchAutostartEnv, cfg *config.Config, _ *standInDaemon, _ *launchAutostartState) {
				cfg.Proxy.Port++
			},
		},
		{
			name: "the daemon lives in another OS context",
			edit: func(env *launchAutostartEnv, _ *config.Config, _ *standInDaemon, _ *launchAutostartState) {
				env.otherContext = func(config.Config) daemonstart.OtherContext {
					return daemonstart.OtherContext{Where: "WSL (Ubuntu)", Hint: "open a WSL (Ubuntu) terminal and run `observer start`"}
				}
			},
			want: "this machine's daemon runs in WSL (Ubuntu); not starting a second one here",
		},
		{
			name: "the port is held although nothing answers",
			edit: func(env *launchAutostartEnv, _ *config.Config, _ *standInDaemon, _ *launchAutostartState) {
				env.portHeld = func(string) bool { return true }
			},
			want: "the port cannot be bound",
		},
		{
			name: "a daemon already starting is waited for, not started again",
			edit: func(env *launchAutostartEnv, _ *config.Config, fd *standInDaemon, _ *launchAutostartState) {
				env.daemonRunning = func(string) bool { return true }
				go func() {
					time.Sleep(300 * time.Millisecond)
					serveHealthz(fd.t, fd.addr, http.StatusOK, `{"status":"ok"}`)
				}()
			},
			wantUp: true,
			want:   "the observer daemon is starting; waiting for its proxy ...",
		},
		{
			name: "after a deliberate `observer service stop` the launch starts it again",
			edit: func(env *launchAutostartEnv, _ *config.Config, _ *standInDaemon, _ *launchAutostartState) {
				env.stopped = func(int) bool { return true }
			},
			wantUp: true, wantStart: 1,
			want: "the observer daemon was stopped; starting it again in the background ...",
		},
		{
			name: "the start fails",
			edit: func(_ *launchAutostartEnv, _ *config.Config, fd *standInDaemon, _ *launchAutostartState) {
				fd.fail = errors.New("exec: observer: not found")
			},
			wantStart: 1,
			want:      " failed: exec: observer: not found; log: ",
		},
		{
			name: "the daemon exits during its start",
			edit: func(_ *launchAutostartEnv, _ *config.Config, fd *standInDaemon, _ *launchAutostartState) {
				fd.exit = "exit status 1"
			},
			wantStart: 1,
			want:      " it exited before its proxy answered (exit status 1); log: ",
		},
		{
			name: "the daemon does not answer within the bound",
			edit: func(_ *launchAutostartEnv, cfg *config.Config, fd *standInDaemon, _ *launchAutostartState) {
				fd.neverUp = true
				cfg.Launch.StartDaemonWaitSeconds = 1
			},
			wantStart: 1,
			want:      " no answer after 1 s; log: ",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			addr := autostartFreeAddr(t)
			fd := &standInDaemon{t: t, addr: addr, delay: 200 * time.Millisecond}
			env, cfg := testAutostartEnv(t, addr, fd)
			stubLaunchAutostart(t, env)
			c.edit(&env, cfg, fd, launchAutostart)
			launchAutostartEnvFor = func() launchAutostartEnv { return env }
			var stderr bytes.Buffer
			up := launchProxyUp(context.Background(), autostartReq(addr, &stderr))
			if up != c.wantUp || fd.startCount() != c.wantStart {
				t.Fatalf("up=%v starts=%d, want up=%v starts=%d\n%s", up, fd.startCount(), c.wantUp, c.wantStart, stderr.String())
			}
			if c.want == "" && stderr.Len() != 0 {
				t.Fatalf("this row prints nothing of its own, got %q", stderr.String())
			}
			if c.want != "" && !strings.Contains(stderr.String(), c.want) {
				t.Fatalf("stderr lacks %q:\n%s", c.want, stderr.String())
			}
		})
	}
}

// TestLaunchAutostartOneAttemptPerProcess: once a start in this process did
// not come up, the next ask (the proxy-down path after the attach gate)
// neither starts nor waits again.
func TestLaunchAutostartOneAttemptPerProcess(t *testing.T) {
	addr := autostartFreeAddr(t)
	fd := &standInDaemon{t: t, addr: addr, fail: errors.New("boom")}
	env, _ := testAutostartEnv(t, addr, fd)
	stubLaunchAutostart(t, env)
	var stderr bytes.Buffer
	for i := 0; i < 2; i++ {
		if launchProxyUp(context.Background(), autostartReq(addr, &stderr)) {
			t.Fatal("a failed start reads as down")
		}
	}
	if fd.startCount() != 1 || strings.Count(stderr.String(), "starting it") != 1 {
		t.Fatalf("starts=%d, stderr:\n%s", fd.startCount(), stderr.String())
	}
}

// TestLaunchAutostartForeignListener: something that is not Observer answers
// HTTP on this node's proxy port. The launch is not told the proxy is up
// (routing into it would send the tool's requests there), no daemon is
// started (it could not bind), and the line says so.
func TestLaunchAutostartForeignListener(t *testing.T) {
	addr := autostartFreeAddr(t)
	serveHealthz(t, addr, http.StatusNotFound, "<html>dev server</html>")
	fd := &standInDaemon{t: t, addr: addr}
	env, _ := testAutostartEnv(t, addr, fd)
	stubLaunchAutostart(t, env)
	var stderr bytes.Buffer
	if launchProxyUp(context.Background(), autostartReq(addr, &stderr)) || fd.startCount() != 0 {
		t.Fatalf("starts=%d stderr=%s", fd.startCount(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "answers, but not as the Observer proxy") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// TestLaunchAutostartProbe pins the probe's three readings: the liveness
// answer is the proxy; a listener that accepts without answering HTTP keeps
// the TCP reading every launcher made before (no false "foreign"); a
// --proxy override elsewhere is never asked for HTTP.
func TestLaunchAutostartProbe(t *testing.T) {
	ctx := context.Background()
	up := autostartFreeAddr(t)
	serveHealthz(t, up, http.StatusOK, `{"status":"ok"}`)
	if got := probeLaunchProxy(ctx, "http://"+up, true); got != daemonstart.ProxyServing {
		t.Errorf("liveness answer: %s", got)
	}
	acceptOnly := openLoopbackURL(t)
	if got := probeLaunchProxy(ctx, acceptOnly, true); got != daemonstart.ProxyServing {
		t.Errorf("accept-only listener: %s, want the TCP reading kept", got)
	}
	foreign := autostartFreeAddr(t)
	serveHealthz(t, foreign, http.StatusOK, `{"hello":"world"}`)
	if got := probeLaunchProxy(ctx, "http://"+foreign, true); got != daemonstart.ProxyForeign {
		t.Errorf("another HTTP server: %s", got)
	}
	if got := probeLaunchProxy(ctx, "http://"+foreign, false); got != daemonstart.ProxyServing {
		t.Errorf("not this node's listener: %s, want the TCP reading", got)
	}
	if got := probeLaunchProxy(ctx, "http://"+autostartFreeAddr(t), true); got != daemonstart.ProxyDown {
		t.Errorf("closed port: %s", got)
	}
}

// TestLaunchAutostartRaceStartsOnce: two launchers find the daemon down at
// the same moment. The launcher start lock (a real OS file lock beside the
// database) lets exactly one start it; the other waits for the port.
func TestLaunchAutostartRaceStartsOnce(t *testing.T) {
	addr := autostartFreeAddr(t)
	fd := &standInDaemon{t: t, addr: addr, delay: 800 * time.Millisecond}
	env, _ := testAutostartEnv(t, addr, fd)
	// Two launcher processes: two states, one database directory, one lock.
	a, b := &launchAutostartState{}, &launchAutostartState{}
	var wg sync.WaitGroup
	var outA, outB bytes.Buffer
	var upA, upB bool
	ready := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-ready
		upA = a.ensure(context.Background(), env, autostartReq(addr, &outA)).up
	}()
	go func() {
		defer wg.Done()
		<-ready
		upB = b.ensure(context.Background(), env, autostartReq(addr, &outB)).up
	}()
	close(ready)
	wg.Wait()
	if !upA || !upB {
		t.Fatalf("both launchers must find the proxy up: a=%v b=%v\n%s\n%s", upA, upB, outA.String(), outB.String())
	}
	if fd.startCount() != 1 {
		t.Fatalf("starts = %d, want exactly 1\n%s\n%s", fd.startCount(), outA.String(), outB.String())
	}
	both := outA.String() + outB.String()
	if strings.Count(both, "starting it") != 1 {
		t.Fatalf("one launcher starts, the other waits:\n%s", both)
	}
}

// TestLaunchOtherContextCrossOS runs the production cross-OS fact over a
// staged foreign layout (a Windows user home as WSL sees it under
// /mnt/c/Users): a launcher in a context that never ran a daemon, beside a
// Windows home that holds the machine's observer.db, does not start a second
// daemon; once this context has its own database it does. The Windows side
// of the same rule (a WSL daemon seen from observer.exe) is the pure table's
// (internal/daemonstart TestOtherContextForRows).
func TestLaunchOtherContextCrossOS(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the staged layout is the WSL view of /mnt/c/Users")
	}
	root := t.TempDir()
	user := filepath.Join(root, "dev")
	for _, p := range []string{filepath.Join(user, "NTUSER.DAT"), filepath.Join(user, ".observer", "observer.db")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	crossmount.StageForeignLayoutForTest(t, crossmount.ForeignLayoutForTest{Root: root, Discover: true})
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	got := launchOtherContext(cfg)
	if got.Where != "Windows" || !strings.Contains(got.Hint, "observer start") {
		t.Fatalf("no database here, the Windows home has one: %+v", got)
	}
	if err := os.WriteFile(cfg.Observer.DBPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := launchOtherContext(cfg); got.Where != "" {
		t.Fatalf("this context runs its own daemon (the operator's WSL box), want none, got %+v", got)
	}
	// The seam with that fact refuses to start and says where.
	addr := autostartFreeAddr(t)
	fd := &standInDaemon{t: t, addr: addr}
	env, _ := testAutostartEnv(t, addr, fd)
	env.otherContext = func(config.Config) daemonstart.OtherContext {
		return daemonstart.OtherContextFor(daemonstart.ContextFacts{OnWindows: true, Siblings: []daemonstart.Sibling{{Origin: "wslhost:Ubuntu/dev", OS: "linux"}}})
	}
	stubLaunchAutostart(t, env)
	var stderr bytes.Buffer
	if launchProxyUp(context.Background(), autostartReq(addr, &stderr)) || fd.startCount() != 0 {
		t.Fatalf("a Windows launcher must not start a daemon beside the WSL one: starts=%d", fd.startCount())
	}
	if !strings.Contains(stderr.String(), "runs in WSL (Ubuntu)") || !strings.Contains(stderr.String(), "WSL (Ubuntu) terminal") {
		t.Fatalf("the line must say where to start it: %q", stderr.String())
	}
}

// TestRunEnvLauncherAutostartsTheDaemon walks a whole env launch (aider,
// RouteKind launcher) with the daemon down: the stand-in start brings the
// proxy up and the child gets the routed environment, as when the daemon was
// up. On a managed node whose organization owns the routes the same launch
// starts the daemon too, and refuses only when it cannot come up (LPD-2).
func TestRunEnvLauncherAutostartsTheDaemon(t *testing.T) {
	skipWithoutProxyInBuild(t)
	t.Setenv(envDaemonChild, "")
	t.Setenv("OPENAI_API_BASE", "")
	os.Unsetenv("OPENAI_API_BASE") //nolint:errcheck // t.Setenv restores it

	t.Run("individual node: started, then routed", func(t *testing.T) {
		stubOrgOwnsRoute(t, false)
		addr := autostartFreeAddr(t)
		fd := &standInDaemon{t: t, addr: addr, delay: 300 * time.Millisecond}
		env, _ := testAutostartEnv(t, addr, fd)
		stubLaunchAutostart(t, env)
		down := "http://" + addr
		rec := runRecordedEnvLaunch(t, envLauncherSpec{
			tool: "aider", args: []string{"--yes"}, proxyURL: down,
			env: map[string]string{"OPENAI_API_BASE": down + "/v1"},
		})
		if rec.err != nil || !rec.started {
			t.Fatalf("launch failed: %v\n%s", rec.err, rec.stderr)
		}
		if v, _ := readRecordedEnvValue(t, rec.envPath, "OPENAI_API_BASE"); v != down+"/v1" {
			t.Errorf("child not routed: OPENAI_API_BASE=%q\n%s", v, rec.stderr)
		}
		if !strings.Contains(rec.stderr, "starting it in the background") || strings.Contains(rec.stderr, "without proxy routing") {
			t.Errorf("stderr:\n%s", rec.stderr)
		}
	})

	t.Run("organization owns the routes: started, then routed", func(t *testing.T) {
		stubOrgOwnsRoute(t, true)
		addr := autostartFreeAddr(t)
		fd := &standInDaemon{t: t, addr: addr, delay: 300 * time.Millisecond}
		env, _ := testAutostartEnv(t, addr, fd)
		stubLaunchAutostart(t, env)
		down := "http://" + addr
		rec := runRecordedEnvLaunch(t, envLauncherSpec{
			tool: "grok", proxyURL: down,
			env: map[string]string{"GROK_CLI_CHAT_PROXY_BASE_URL": down + "/up/grok/v1"},
		})
		if rec.err != nil || !rec.started || fd.startCount() != 1 {
			t.Fatalf("started=%v starts=%d err=%v\n%s", rec.started, fd.startCount(), rec.err, rec.stderr)
		}
	})

	t.Run("organization owns the routes: the daemon cannot come up, refused", func(t *testing.T) {
		stubOrgOwnsRoute(t, true)
		addr := autostartFreeAddr(t)
		fd := &standInDaemon{t: t, addr: addr, fail: errors.New("no observer binary")}
		env, _ := testAutostartEnv(t, addr, fd)
		stubLaunchAutostart(t, env)
		down := "http://" + addr
		rec := runRecordedEnvLaunch(t, envLauncherSpec{
			tool: "grok", proxyURL: down,
			env: map[string]string{"GROK_CLI_CHAT_PROXY_BASE_URL": down + "/up/grok/v1"},
		})
		if rec.started || rec.err == nil {
			t.Fatalf("started=%v err=%v; want a refusal", rec.started, rec.err)
		}
		if !strings.Contains(rec.stderr, "failed: no observer binary") {
			t.Errorf("the start line must say why the start failed:\n%s", rec.stderr)
		}
	})

	t.Run("individual node: the daemon cannot come up, direct with the notice", func(t *testing.T) {
		stubOrgOwnsRoute(t, false)
		addr := autostartFreeAddr(t)
		fd := &standInDaemon{t: t, addr: addr, fail: errors.New("no observer binary")}
		env, _ := testAutostartEnv(t, addr, fd)
		stubLaunchAutostart(t, env)
		down := "http://" + addr
		rec := runRecordedEnvLaunch(t, envLauncherSpec{
			tool: "aider", args: []string{"--yes"}, proxyURL: down,
			env: map[string]string{"OPENAI_API_BASE": down + "/v1"},
		})
		if rec.err != nil || !rec.started {
			t.Fatalf("launch failed: %v\n%s", rec.err, rec.stderr)
		}
		if v, ok := readRecordedEnvValue(t, rec.envPath, "OPENAI_API_BASE"); ok {
			t.Errorf("child still points at the dead port: %s", v)
		}
		if !strings.Contains(rec.stderr, "failed: no observer binary") || !strings.Contains(rec.stderr, "without proxy routing") {
			t.Errorf("stderr:\n%s", rec.stderr)
		}
	})
}

// TestClaudeLauncherAutostart: `observer claude` walks the same seam. With
// the daemon down it is started and claude launches routed; on a managed
// node whose organization owns the routes and a daemon that cannot come up,
// claude now refuses like every other launcher (L-169 settles LPD-2) instead
// of bypassing the organization's route with its --settings override.
func TestClaudeLauncherAutostart(t *testing.T) {
	skipWithoutProxyInBuild(t)
	t.Setenv(envDaemonChild, "")
	run := func(t *testing.T, fd *standInDaemon, addr string) (bool, string, string, error) {
		t.Helper()
		pinToolHomes(t)
		t.Setenv("ANTHROPIC_BASE_URL", "")
		os.Unsetenv("ANTHROPIC_BASE_URL") //nolint:errcheck // t.Setenv restores it
		env, _ := testAutostartEnv(t, addr, fd)
		stubLaunchAutostart(t, env)
		dir := t.TempDir()
		argvPath, envPath := filepath.Join(dir, "argv.out"), filepath.Join(dir, "env.out")
		stub := writeArgvEnvRecorderStub(t, dir, argvPath, envPath)
		cfgPath := writeCopilotCLITestConfig(t, dir)
		var stderr bytes.Buffer
		err := runClaudeLauncher(context.Background(), claudeLauncherOptions{
			configPath: cfgPath, proxyURL: "http://" + addr, claudePath: stub, noAttach: true, stderr: &stderr,
		})
		_, statErr := os.Stat(argvPath)
		base := ""
		if statErr == nil {
			base, _ = readRecordedEnvValue(t, envPath, "ANTHROPIC_BASE_URL")
		}
		return statErr == nil, base, stderr.String(), err
	}

	t.Run("started, then routed", func(t *testing.T) {
		stubOrgOwnsRoute(t, false)
		addr := autostartFreeAddr(t)
		fd := &standInDaemon{t: t, addr: addr, delay: 300 * time.Millisecond}
		started, base, stderr, err := run(t, fd, addr)
		if err != nil || !started || fd.startCount() != 1 {
			t.Fatalf("started=%v starts=%d err=%v\n%s", started, fd.startCount(), err, stderr)
		}
		if !strings.HasPrefix(base, "http://"+addr) {
			t.Errorf("claude not routed: ANTHROPIC_BASE_URL=%q\n%s", base, stderr)
		}
		if !strings.Contains(stderr, "observer claude: the observer daemon was not running; starting it") {
			t.Errorf("stderr:\n%s", stderr)
		}
	})

	t.Run("organization owns the routes and the daemon cannot come up: refused", func(t *testing.T) {
		stubOrgOwnsRoute(t, true)
		addr := autostartFreeAddr(t)
		fd := &standInDaemon{t: t, addr: addr, fail: errors.New("no observer binary")}
		started, _, stderr, err := run(t, fd, addr)
		if started || err == nil {
			t.Fatalf("started=%v err=%v; want a refusal\n%s", started, err, stderr)
		}
		if !strings.Contains(stderr, "your organization routes AI tools through the Observer proxy") {
			t.Errorf("stderr:\n%s", stderr)
		}
	})

	t.Run("individual node and the daemon cannot come up: direct, as before", func(t *testing.T) {
		stubOrgOwnsRoute(t, false)
		addr := autostartFreeAddr(t)
		fd := &standInDaemon{t: t, addr: addr, fail: errors.New("no observer binary")}
		started, base, stderr, err := run(t, fd, addr)
		if err != nil || !started {
			t.Fatalf("started=%v err=%v\n%s", started, err, stderr)
		}
		if strings.HasPrefix(base, "http://"+addr) {
			t.Errorf("claude routed into the dead port:\n%s", stderr)
		}
	})
}

// TestNoStartFlagOnEveryLauncher: every launcher verb the root registers
// carries --no-start, the flag is the launcher's own (never passed to the
// tool), and its value reaches the seam.
func TestNoStartFlagOnEveryLauncher(t *testing.T) {
	root := newRootCmd()
	for _, mk := range launcherCommands {
		name := mk().Name()
		var cmd *cobra.Command
		for _, c := range root.Commands() {
			if c.Name() == name {
				cmd = c
			}
		}
		if cmd == nil {
			continue // compiled out of this build
		}
		if cmd.Flags().Lookup(noStartFlag) == nil {
			t.Errorf("observer %s has no --%s", name, noStartFlag)
		}
	}
	prev := launchAutostart
	launchAutostart = &launchAutostartState{}
	t.Cleanup(func() { launchAutostart = prev })
	cmd := withNoStartFlag(&cobra.Command{Use: "gemini", DisableFlagParsing: true})
	args, done, err := launcherArgsOrDone(cmd, []string{"--no-start", "--yolo"})
	if err != nil || done || len(args) != 1 || args[0] != "--yolo" {
		t.Fatalf("args=%v done=%v err=%v", args, done, err)
	}
	if !launchAutostart.noStart {
		t.Fatal("--no-start did not reach the seam")
	}
}

// TestLaunchStartPlanFor: the daemon this install owns is started through
// its own service unit when one runs this config, else in the background
// with the launcher's config.
func TestLaunchStartPlanFor(t *testing.T) {
	home := pinToolHomes(t)
	prevSystemd, prevLaunchd, prevArgs := systemdAvailable, launchdAvailable, installedServiceArgs
	t.Cleanup(func() { systemdAvailable, launchdAvailable, installedServiceArgs = prevSystemd, prevLaunchd, prevArgs })
	launchdAvailable = func() bool { return false }
	systemdAvailable = func() bool { return true }

	cfgPath := filepath.Join(home, "custom.toml")
	if p := launchStartPlanFor(cfgPath); p.mechanism != daemonstart.MechanismDetached ||
		!equalArgs(p.argv[1:], []string{"start", "--no-open", "--config", cfgPath}) {
		t.Fatalf("no unit installed: %+v", p)
	}
	unit := service.UnitPath(service.ScopeUser, home)
	if err := os.MkdirAll(filepath.Dir(unit), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("[Service]\nExecStart=/usr/bin/observer start --config "+cfgPath+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := launchStartPlanFor(cfgPath); p.mechanism != daemonstart.MechanismSystemd || !strings.Contains(p.log, "journalctl --user") {
		t.Fatalf("a unit for this config: %+v", p)
	}
	if p := launchStartPlanFor(filepath.Join(home, "other.toml")); p.mechanism != daemonstart.MechanismDetached {
		t.Fatalf("a unit for another config starts in the background: %+v", p)
	}
}

// TestSignInBinaryFromRunValue pins the Windows sign-in entry parse.
func TestSignInBinaryFromRunValue(t *testing.T) {
	exists := func(p string) bool { return strings.HasSuffix(p, "observer.exe") }
	dir := filepath.Join("C:", "Users", "dev", "AppData", "Local", "SuperBased")
	v := `"` + filepath.Join(dir, "observerw.exe") + `" setup launch`
	if got := signInBinaryFromRunValue(v, "observer.exe", exists); got != filepath.Join(dir, "observer.exe") {
		t.Fatalf("got %q", got)
	}
	for _, bad := range []string{"", "observerw.exe setup launch", `"unterminated`} {
		if got := signInBinaryFromRunValue(bad, "observer.exe", exists); got != "" {
			t.Errorf("%q: got %q", bad, got)
		}
	}
	if got := signInBinaryFromRunValue(v, "observer.exe", func(string) bool { return false }); got != "" {
		t.Errorf("a removed install: got %q", got)
	}
}

// TestLaunchOwnListener pins which proxy URLs are this node's to start.
func TestLaunchOwnListener(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://127.0.0.1:8820":      true,
		"http://localhost:8820/t/x":  true,
		"http://[::1]:8820":          true,
		"http://127.0.0.1:9999":      false,
		"https://gateway.corp:8820":  false,
		"http://192.168.1.4:8820/v1": false,
	} {
		if got := launchOwnListener(raw, 8820); got != want {
			t.Errorf("%s: own=%v, want %v", raw, got, want)
		}
	}
}

// skipWithoutProxyInBuild skips a whole-launch test in a build without
// capture.proxy: there the seam has nothing to start (D-514, the
// RuleNotServed row of TestLaunchAutostartRows).
func skipWithoutProxyInBuild(t *testing.T) {
	t.Helper()
	if proxyNotInBuild() {
		t.Skip("capture.proxy is not in this build")
	}
}

// TestLaunchAutostartWaitsWhileAnotherLauncherHoldsTheLock is the race's
// deterministic half: another launcher holds the start lock (taken here
// first, as that launcher's process would), so this one starts nothing and
// waits for the port that launcher's daemon opens.
func TestLaunchAutostartWaitsWhileAnotherLauncherHoldsTheLock(t *testing.T) {
	addr := autostartFreeAddr(t)
	fd := &standInDaemon{t: t, addr: addr}
	env, cfg := testAutostartEnv(t, addr, fd)
	release, ok := launchStartLock(filepath.Dir(cfg.Observer.DBPath))
	if !ok {
		t.Fatal("could not take the start lock")
	}
	defer release()
	stubLaunchAutostart(t, env)
	go func() { time.Sleep(400 * time.Millisecond); serveHealthz(t, addr, http.StatusOK, `{"status":"ok"}`) }()
	var stderr bytes.Buffer
	if !launchProxyUp(context.Background(), autostartReq(addr, &stderr)) {
		t.Fatalf("not up:\n%s", stderr.String())
	}
	if fd.startCount() != 0 || !strings.Contains(stderr.String(), "is starting; waiting for its proxy ...") {
		t.Fatalf("starts=%d stderr=%q", fd.startCount(), stderr.String())
	}
}
