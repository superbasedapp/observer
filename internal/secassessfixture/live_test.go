package secassessfixture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The live tests start the deliberately vulnerable application (testdata/
// secassess/app) on a loopback port and replay truth/probes.json against it
// with a small net/http client. They run ONLY when OBSERVER_SECASSESS_FIXTURE=1
// is set (the repository's precedent for a test that needs an external engine
// is an opt-in variable, internal/secrulepack/fixtures_test.go
// OBSERVER_OPENGREP_BIN), and only when a real Python 3 answers --version.
//
// Each server runs in a temporary copy of app/ (nothing is written under
// testdata), is bound to 127.0.0.1 by the application itself, ends by itself
// after --max-seconds and is killed after hardLimit by the test.

const (
	optInVar  = "OBSERVER_SECASSESS_FIXTURE"
	hardLimit = 20 * time.Second
)

func requireOptIn(t *testing.T) {
	t.Helper()
	if os.Getenv(optInVar) != "1" {
		t.Skip("set " + optInVar + "=1 to start the deliberately vulnerable fixture on a loopback port")
	}
}

type interpreter struct {
	path string
	args []string
}

var rePython3 = regexp.MustCompile(`^Python 3\.[0-9]+`)

// isStoreAlias reports whether path is under the Windows Store app-execution
// aliases. Its python3.exe is a stub that opens the Store when it is not
// installed, so it is never run.
func isStoreAlias(path string) bool {
	return strings.Contains(strings.ToLower(filepath.ToSlash(path)), "/microsoft/windowsapps/")
}

// findPython returns a Python 3.8 or newer that really runs, or skips. A name
// on PATH is not enough: each candidate must answer --version with "Python 3"
// and run a one-line program.
func findPython(t *testing.T) interpreter {
	t.Helper()
	candidates := []interpreter{{path: "python3"}, {path: "python"}}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, interpreter{path: "py", args: []string{"-3"}})
	}
	for _, c := range candidates {
		p, err := exec.LookPath(c.path)
		if err != nil {
			continue
		}
		if isStoreAlias(p) {
			t.Logf("not using %s: a Microsoft Store alias", p)
			continue
		}
		run := func(args ...string) ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, p, append(append([]string{}, c.args...), args...)...).CombinedOutput()
		}
		out, err := run("--version")
		if err != nil || !rePython3.Match(bytes.TrimSpace(out)) {
			continue
		}
		if _, err := run("-c", "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"); err != nil {
			continue
		}
		return interpreter{path: p, args: c.args}
	}
	t.Skip("no working Python 3.8 or newer found (python3, python, py -3)")
	return interpreter{}
}

// copyApp copies the application into a fresh temporary directory.
func copyApp(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "notesapp")
	if err := os.CopyFS(dst, os.DirFS(filepath.Join(fixtureRoot, "app"))); err != nil {
		t.Fatalf("copy the application: %v", err)
	}
	return dst
}

// childEnv is the process environment of a started application: the test's
// own, with the opt-in variable decided by the caller.
func childEnv(optIn bool) []string {
	var env []string
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if strings.EqualFold(name, optInVar) {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "PYTHONDONTWRITEBYTECODE=1", "PYTHONNOUSERSITE=1")
	if optIn {
		env = append(env, optInVar+"=1")
	}
	return env
}

// freePortPair finds p such that p and p+1 are free on the loopback now.
func freePortPair() (int, bool) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, false
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	if p < 1024 || p > 65534 {
		return 0, false
	}
	l2, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p+1))
	if err != nil {
		return 0, false
	}
	_ = l2.Close()
	return p, true
}

type app struct {
	port, console int
	base          string
	done          chan struct{}
	stderr        *bytes.Buffer
}

// runApp runs the application to its end with the given environment and
// arguments (after the script name) and returns its exit code and stderr.
func runApp(t *testing.T, py interpreter, dir string, optIn bool, args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), hardLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, py.path, append(append(append([]string{}, py.args...), "-B", "server.py"), args...)...)
	cmd.Dir = dir
	cmd.Env = childEnv(optIn)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, stderr.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), stderr.String()
	default:
		t.Fatalf("run the application: %v", err)
		return -1, ""
	}
}

// startApp starts the application with the opt-in variable set and waits for
// its health route.
func startApp(t *testing.T, py interpreter, dir string) *app {
	t.Helper()
	for attempt := 0; attempt < 5; attempt++ {
		port, ok := freePortPair()
		if !ok {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), hardLimit)
		cmd := exec.CommandContext(ctx, py.path, append(append([]string{}, py.args...), "-B", "server.py", "--port", strconv.Itoa(port), "--max-seconds", "30")...)
		cmd.Dir = dir
		cmd.Env = childEnv(true)
		a := &app{port: port, console: port + 1, base: "http://127.0.0.1:" + strconv.Itoa(port), done: make(chan struct{}), stderr: &bytes.Buffer{}}
		cmd.Stderr = a.stderr
		if err := cmd.Start(); err != nil {
			cancel()
			t.Fatalf("start the application: %v", err)
		}
		go func() {
			_ = cmd.Wait()
			close(a.done)
		}()
		stop := func() {
			cancel()
			<-a.done
		}
		deadline := time.Now().Add(8 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			select {
			case <-a.done:
			default:
				resp, err := http.Get(a.base + "/api/health")
				if err == nil {
					_ = resp.Body.Close()
					ready = resp.StatusCode == http.StatusOK
				}
			}
			if ready {
				break
			}
			select {
			case <-a.done:
				deadline = time.Now()
			case <-time.After(100 * time.Millisecond):
			}
		}
		if ready {
			t.Cleanup(stop)
			return a
		}
		stop()
		t.Logf("attempt %d: the application did not become ready on %d: %s", attempt+1, port, strings.TrimSpace(a.stderr.String()))
	}
	t.Fatal("the application did not start")
	return nil
}

// client is one cookie jar (or none) talking to one application.
func newClient(withJar bool) *http.Client {
	c := &http.Client{
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	if withJar {
		c.Jar, _ = cookiejar.New(nil)
	}
	return c
}

type session struct {
	a     *app
	plain *http.Client
	jars  map[string]*http.Client
}

func newSession(a *app) *session {
	return &session{a: a, plain: newClient(false), jars: map[string]*http.Client{}}
}

func (s *session) client(jar string) *http.Client {
	if jar == "" {
		return s.plain
	}
	if c, ok := s.jars[jar]; ok {
		return c
	}
	c := newClient(true)
	s.jars[jar] = c
	return c
}

// send sends the request (Times times; Repeat times keeping every response)
// and returns the responses kept.
func (s *session) send(r Request) ([]Response, error) {
	n, keep := 1, 1
	if r.Times > 0 {
		n = r.Times
	}
	if r.Repeat > 0 {
		n, keep = r.Repeat, r.Repeat
	}
	var out []Response
	for i := 0; i < n; i++ {
		var body io.Reader
		if r.JSON != nil {
			body = strings.NewReader(ExpandPlaceholders(string(r.JSON), s.a.port, s.a.console))
		} else if r.Method == "POST" {
			body = strings.NewReader("{}")
		}
		req, err := http.NewRequest(r.Method, s.a.base+ExpandPlaceholders(r.Path, s.a.port, s.a.console), body)
		if err != nil {
			return nil, err
		}
		if r.Method == "POST" {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range r.Headers {
			req.Header.Set(k, v)
		}
		resp, err := s.client(r.Jar).Do(req)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, Response{Status: resp.StatusCode, Header: resp.Header, Body: string(data)})
		if len(out) > keep {
			out = out[len(out)-keep:]
		}
	}
	return out, nil
}

func (s *session) mustSend(t *testing.T, where string, r Request) []Response {
	t.Helper()
	resp, err := s.send(r)
	if err != nil {
		t.Fatalf("%s: %s %s: %v", where, r.Method, r.Path, err)
	}
	return resp
}

func (s *session) setup(t *testing.T, where string, reqs []Request) {
	t.Helper()
	for _, r := range reqs {
		resp := s.mustSend(t, where+" setup", r)
		if last := resp[len(resp)-1]; last.Status >= 500 {
			t.Fatalf("%s setup: %s %s answered %d: %.200s", where, r.Method, r.Path, last.Status, last.Body)
		}
	}
}

func last(r []Response) Response { return r[len(r)-1] }

func TestFixtureFlawsAreReal(t *testing.T) {
	requireOptIn(t)
	py := findPython(t)
	m, p := loadManifest(t), loadProbes(t)
	dir := copyApp(t)
	byID := map[string]FlawProbe{}
	for _, fp := range p.Flaws {
		byID[fp.ID] = fp
	}
	for _, f := range m.Flaws {
		for _, c := range byID[f.ID].Confirmations {
			t.Run(f.ID+"/"+c.Name, func(t *testing.T) {
				s := newSession(startApp(t, py, dir))
				s.setup(t, f.ID, c.Setup)
				ctrl := s.mustSend(t, f.ID+" control", c.Control)
				atk := s.mustSend(t, f.ID+" attack", c.Attack)
				if ok, why := c.Indicator.Holds(atk); !ok {
					t.Errorf("the attack does not show %s: %s (status %d, body %.300q)", f.ID, why, last(atk).Status, last(atk).Body)
				}
				if ok, _ := c.Indicator.Holds(ctrl); ok {
					t.Errorf("the control request satisfies the indicator too, so it proves nothing (status %d, body %.300q)", last(ctrl).Status, last(ctrl).Body)
				}
			})
		}
	}
}

func TestFixtureDecoysAreSafe(t *testing.T) {
	requireOptIn(t)
	py := findPython(t)
	m, p := loadManifest(t), loadProbes(t)
	dir := copyApp(t)
	byID := map[string]DecoyProbe{}
	for _, dp := range p.Decoys {
		byID[dp.ID] = dp
	}
	for _, d := range m.Decoys {
		dp := byID[d.ID]
		t.Run(d.ID, func(t *testing.T) {
			s := newSession(startApp(t, py, dir))
			s.setup(t, d.ID, dp.Setup)
			atk := s.mustSend(t, d.ID+" attack", dp.Attack)
			if ok, _ := dp.FlawIndicator.Holds(atk); ok {
				t.Errorf("the near miss %s behaves like its flaw (status %d, body %.300q)", d.ID, last(atk).Status, last(atk).Body)
			}
			works := s.mustSend(t, d.ID+" works", dp.Works.Request)
			if ok, why := dp.Works.Indicator.Holds(works); !ok {
				t.Errorf("the feature behind %s does not work: %s (status %d, body %.300q)", d.ID, why, last(works).Status, last(works).Body)
			}
		})
	}
}

func TestFixtureContainment(t *testing.T) {
	requireOptIn(t)
	py := findPython(t)
	p := loadProbes(t)
	dir := copyApp(t)

	t.Run("refuses without the opt-in variable", func(t *testing.T) {
		code, stderr := runApp(t, py, dir, false, "--port", "39500")
		if code != 2 || !strings.Contains(stderr, "refusing to start") {
			t.Fatalf("exit %d, stderr %q: the application started without %s", code, stderr, optInVar)
		}
	})
	for _, host := range []string{"0.0.0.0", "::", "::1", "localhost", "192.0.2.1", "10.0.0.1", ""} {
		t.Run("refuses host "+host, func(t *testing.T) {
			code, stderr := runApp(t, py, dir, true, "--host", host, "--port", "39510")
			if code != 2 || !strings.Contains(stderr, "refusing to start") {
				t.Fatalf("--host %q: exit %d, stderr %q", host, code, stderr)
			}
		})
	}
	for _, port := range []string{"80", "1023", "65535", "70000"} {
		t.Run("refuses port "+port, func(t *testing.T) {
			code, _ := runApp(t, py, dir, true, "--port", port)
			if code == 0 {
				t.Fatalf("--port %s: the application started", port)
			}
		})
	}
	t.Run("ends by itself", func(t *testing.T) {
		start := time.Now()
		port, ok := freePortPair()
		if !ok {
			t.Skip("no free port pair")
		}
		code, stderr := runApp(t, py, dir, true, "--port", strconv.Itoa(port), "--max-seconds", "2")
		if code != 0 || time.Since(start) > 12*time.Second {
			t.Fatalf("exit %d after %s, stderr %q: --max-seconds did not end the process", code, time.Since(start), stderr)
		}
	})
	t.Run("listens on the loopback only", func(t *testing.T) {
		a := startApp(t, py, dir)
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			t.Skip("no interface list")
		}
		tried := 0
		for _, ad := range addrs {
			ipn, ok := ad.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
				continue
			}
			tried++
			for _, port := range []int{a.port, a.console} {
				c, err := net.DialTimeout("tcp", net.JoinHostPort(ipn.IP.String(), strconv.Itoa(port)), 800*time.Millisecond)
				if err == nil {
					_ = c.Close()
					t.Errorf("%s:%d accepts a connection: the application is not loopback-only", ipn.IP, port)
				}
			}
		}
		t.Logf("checked %d non-loopback IPv4 address(es)", tried)
	})
	for _, cp := range p.Containment {
		t.Run(cp.ID+" "+cp.Name, func(t *testing.T) {
			s := newSession(startApp(t, py, dir))
			s.setup(t, cp.ID, cp.Setup)
			for _, ch := range cp.Checks {
				resp := s.mustSend(t, cp.ID, ch.Request)
				if ok, why := ch.Expect.Holds(resp); !ok {
					t.Errorf("%s %s: %s (status %d, body %.300q)", ch.Request.Method, ch.Request.Path, why, last(resp).Status, last(resp).Body)
				}
			}
		})
	}
	t.Run("a header value cannot be split", func(t *testing.T) {
		s := newSession(startApp(t, py, dir))
		resp := s.mustSend(t, "split", Request{Method: "GET", Path: "/go?next=%2Fa%0d%0aX-Injected%3A%201"})
		if got := http.Header(last(resp).Header).Get("X-Injected"); got != "" {
			t.Fatalf("a CR LF in a redirect target started a new header: %q", got)
		}
	})
	t.Run("writes no files", func(t *testing.T) {
		before := listTree(t, dir)
		s := newSession(startApp(t, py, dir))
		for _, fp := range p.Flaws {
			for _, c := range fp.Confirmations {
				for _, r := range append(append([]Request{}, c.Setup...), c.Control, c.Attack) {
					if _, err := s.send(r); err != nil {
						t.Fatalf("%s: %v", fp.ID, err)
					}
				}
			}
		}
		if after := listTree(t, dir); strings.Join(before, "\n") != strings.Join(after, "\n") {
			t.Fatalf("the application changed its directory:\nbefore %v\nafter  %v", before, after)
		}
	})
}

// listTree lists every path under dir with its size.
func listTree(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, fmt.Sprintf("%s %d", filepath.ToSlash(rel), info.Size()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}
