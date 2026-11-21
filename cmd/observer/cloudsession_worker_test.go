package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// recordOps records the lifecycle calls walkWorkerSteps makes; fail makes
// one step fail.
type recordOps struct {
	calls []string
	fail  map[string]error
}

func (r *recordOps) do(name string) error {
	r.calls = append(r.calls, name)
	return r.fail[name]
}

func (r *recordOps) startProxy(context.Context) error { return r.do("start-proxy") }
func (r *recordOps) awaitReady(context.Context) error { return r.do("await-ready") }
func (r *recordOps) routeOn(context.Context) error    { return r.do("route-on") }
func (r *recordOps) runAgent(context.Context) error   { return r.do("run-agent") }
func (r *recordOps) routeOff(context.Context) error   { return r.do("route-off") }
func (r *recordOps) drainProxy(context.Context) error { return r.do("drain") }
func (r *recordOps) stopProxy(context.Context) error  { return r.do("stop-proxy") }
func (r *recordOps) scan(context.Context) error       { return r.do("scan") }
func (r *recordOps) stamp(context.Context) error      { return r.do("stamp") }

var routedPlan = cloudsession.WorkerPlan{Verdict: cloudsession.VerdictRoute}

// TestWalkWorkerSteps: the lifecycle runs in table order, the route goes off
// before the proxy stops, and a failure tears down only what was set up.
func TestWalkWorkerSteps(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name    string
		mode    cloudsession.WorkerMode
		plan    cloudsession.WorkerPlan
		fail    map[string]error
		want    []string
		wantErr error
	}{
		{
			name: "run, agent succeeds",
			mode: cloudsession.ModeRun, plan: routedPlan,
			want: []string{"start-proxy", "await-ready", "route-on", "run-agent", "route-off", "drain", "stop-proxy", "scan", "stamp"},
		},
		{
			name: "run, agent exits 3: full teardown, exit code kept",
			mode: cloudsession.ModeRun, plan: routedPlan, fail: map[string]error{"run-agent": exitErr(3)},
			want:    []string{"start-proxy", "await-ready", "route-on", "run-agent", "route-off", "drain", "stop-proxy", "scan", "stamp"},
			wantErr: exitErr(3),
		},
		{
			name: "proxy never starts: nothing to take down",
			mode: cloudsession.ModeRun, plan: routedPlan, fail: map[string]error{"start-proxy": boom},
			want: []string{"start-proxy"}, wantErr: boom,
		},
		{
			name: "proxy never answers: no route was on, the proxy is stopped",
			mode: cloudsession.ModeRun, plan: routedPlan, fail: map[string]error{"await-ready": boom},
			want: []string{"start-proxy", "await-ready", "drain", "stop-proxy", "scan", "stamp"}, wantErr: boom,
		},
		{
			name: "start: route on fails half way, it is still taken off before the stop",
			mode: cloudsession.ModeStart, plan: routedPlan, fail: map[string]error{"route-on": boom},
			want: []string{"start-proxy", "await-ready", "route-on", "route-off", "drain", "stop-proxy"}, wantErr: boom,
		},
		{
			name: "start: proxy never answers, it is stopped and no route goes off",
			mode: cloudsession.ModeStart, plan: routedPlan, fail: map[string]error{"await-ready": boom},
			want: []string{"start-proxy", "await-ready", "drain", "stop-proxy"}, wantErr: boom,
		},
		{
			name: "start leaves the proxy running with the route on",
			mode: cloudsession.ModeStart, plan: routedPlan,
			want: []string{"start-proxy", "await-ready", "route-on"},
		},
		{
			name: "stop: route off first",
			mode: cloudsession.ModeStop, plan: routedPlan,
			want: []string{"route-off", "drain", "stop-proxy", "scan", "stamp"},
		},
		{
			name: "refused plan: nothing starts",
			mode: cloudsession.ModeRun, plan: cloudsession.WorkerPlan{Verdict: cloudsession.VerdictRefused, Reason: "vendor-hosted"},
			want: nil, wantErr: errWorkerNotRouted,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := &recordOps{fail: tc.fail}
			err := walkWorkerSteps(context.Background(), tc.mode, tc.plan, ops, &bytes.Buffer{})
			if !reflect.DeepEqual(ops.calls, tc.want) {
				t.Fatalf("calls %v\nwant  %v", ops.calls, tc.want)
			}
			if tc.wantErr == nil && err != nil {
				t.Fatalf("err %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("err %v, want %v", err, tc.wantErr)
			}
			off, stop := indexOf(ops.calls, "route-off"), indexOf(ops.calls, "stop-proxy")
			if off >= 0 && stop >= 0 && off > stop {
				t.Fatalf("route off after stop: %v", ops.calls)
			}
		})
	}
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// TestWorkerRefusesVendorHostedSandbox: the commands refuse on a
// vendor-hosted sandbox (the live-grounded Anthropic-hosted markers), even
// with the administrator attestation set, and start nothing: the agent does
// not run and no state is written.
func TestWorkerRefusesVendorHostedSandbox(t *testing.T) {
	cfg := cloudSessionFixture(t)
	t.Setenv("CLAUDE_CODE_REMOTE", "true")
	t.Setenv("CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE", "cloud_default")
	t.Setenv(cloudsession.WorkerAttestEnv, "claude-code-self-hosted")
	ran := filepath.Join(t.TempDir(), "ran")

	for _, args := range [][]string{
		{"run", "--env", "claude-code-self-hosted", "--config", cfg, "--", "touch", ran},
		{"start", "--env", "claude-code-self-hosted", "--config", cfg},
	} {
		cmd := newCloudSessionWorkerCmd()
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		cmd.SetArgs(args)
		err := cmd.Execute()
		if err == nil || !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "CA-D10") {
			t.Fatalf("%s: err %v, want a CA-D10 refusal\n%s", args[0], err, errOut.String())
		}
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("the agent ran on a vendor-hosted sandbox")
	}
	dir, err := workerStateDir(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, workerStateFile)); err == nil {
		t.Fatal("a refused start wrote worker state")
	}
}

// TestWorkerRunEndToEnd starts the real proxy inside the command, runs a
// child that records its base URL and reaches the proxy, and checks that
// the proxy is gone after the command returns with the child's exit code.
func TestWorkerRunEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the child is a POSIX sh script")
	}
	if proxyNotInBuild() {
		t.Skip("capture.proxy is not in this build")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	cfg := cloudSessionFixture(t)
	for _, v := range []string{"CLAUDE_CODE_REMOTE", "CLAUDE_CODE_REMOTE_ENVIRONMENT_TYPE", "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "ANTHROPIC_BASE_URL"} {
		t.Setenv(v, "")
		_ = os.Unsetenv(v)
	}
	t.Setenv(cloudsession.WorkerAttestEnv, "warp-self-hosted-worker")
	seen := filepath.Join(t.TempDir(), "seen")
	port, err := workerFreeLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	// The child records its route and whether the proxy answers on it.
	script := `printf '%s\n' "$ANTHROPIC_BASE_URL" > "$1"; ` +
		`if command -v curl >/dev/null 2>&1; then curl -s -o /dev/null -w '%{http_code}\n' "$ANTHROPIC_BASE_URL/" >> "$1" || echo curl-failed >> "$1"; fi; exit 7`
	cmd := newCloudSessionWorkerCmd()
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{"run", "--env", "warp-self-hosted-worker", "--config", cfg, "--port", strconv.Itoa(port), "--", "sh", "-c", script, "sh", seen})
	err = cmd.Execute()
	var code exitErr
	if !errors.As(err, &code) || int(code) != 7 {
		t.Fatalf("err %v, want the child's exit code 7\n%s", err, errOut.String())
	}
	b, rerr := os.ReadFile(seen)
	if rerr != nil {
		t.Fatalf("child did not run: %v\n%s", rerr, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if want := "http://127.0.0.1:" + strconv.Itoa(port); lines[0] != want {
		t.Fatalf("child saw ANTHROPIC_BASE_URL=%q, want %q", lines[0], want)
	}
	if len(lines) > 1 && (lines[1] == "000" || lines[1] == "curl-failed") {
		t.Fatalf("the proxy did not answer the child: %v\n%s", lines, errOut.String())
	}
	if conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port)); err == nil {
		_ = conn.Close()
		t.Fatal("the proxy is still listening after the run")
	}
	log := errOut.String()
	for _, want := range []string{"route on", "route off", "proxy stopped", "execution_location=customer_worker"} {
		if !strings.Contains(log, want) {
			t.Fatalf("stderr lacks %q:\n%s", want, log)
		}
	}
	if strings.Index(log, "route off") > strings.Index(log, "proxy stopped") {
		t.Fatalf("route off was reported after the proxy stopped:\n%s", log)
	}
}

// TestWorkerBackgroundSinks: route on and route off through the env-file
// and github-env sinks, without a proxy.
func TestWorkerBackgroundSinks(t *testing.T) {
	route := []cloudsession.RouteVar{{Name: "ANTHROPIC_BASE_URL", Value: "http://127.0.0.1:18820"}}
	t.Run("env-file", func(t *testing.T) {
		dir := t.TempDir()
		ops := &workerBackgroundOps{
			workerCommon: workerCommon{errOut: &bytes.Buffer{}}, stateDir: dir,
			state: cloudsession.WorkerState{Sink: cloudsession.SinkEnvFile, Route: route},
		}
		if err := ops.routeOn(context.Background()); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, workerRouteFile))
		if err != nil || string(b) != "export ANTHROPIC_BASE_URL=http://127.0.0.1:18820\n" {
			t.Fatalf("route file %q %v", b, err)
		}
		if st, ok := loadWorkerState(dir); !ok || !st.RouteOn {
			t.Fatalf("state after route on: %+v", st)
		}
		if err := ops.routeOff(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, workerRouteFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("route file still there: %v", err)
		}
		if st, ok := loadWorkerState(dir); !ok || st.RouteOn {
			t.Fatalf("state after route off: %+v", st)
		}
	})
	t.Run("github-env", func(t *testing.T) {
		dir := t.TempDir()
		ghEnv := filepath.Join(dir, "github_env")
		if err := os.WriteFile(ghEnv, []byte("OTHER=1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		lookup := func(n string) (string, bool) {
			if n == "GITHUB_ENV" {
				return ghEnv, true
			}
			return "", false
		}
		ops := &workerBackgroundOps{
			workerCommon: workerCommon{errOut: &bytes.Buffer{}}, stateDir: dir, lookup: lookup,
			state: cloudsession.WorkerState{Sink: cloudsession.SinkGitHubEnv, Route: route},
		}
		if err := ops.routeOn(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := ops.routeOff(context.Background()); err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(ghEnv)
		if want := "OTHER=1\nANTHROPIC_BASE_URL=http://127.0.0.1:18820\nANTHROPIC_BASE_URL=\n"; string(b) != want {
			t.Fatalf("$GITHUB_ENV:\n%s\nwant:\n%s", b, want)
		}
	})
}

// TestWorkerChildEnv: the route replaces any earlier value of its variable.
func TestWorkerChildEnv(t *testing.T) {
	got := workerChildEnv([]string{"A=1", "ANTHROPIC_BASE_URL=old", "B=2"}, []cloudsession.RouteVar{{Name: "ANTHROPIC_BASE_URL", Value: "http://127.0.0.1:1"}})
	want := []string{"A=1", "B=2", "ANTHROPIC_BASE_URL=http://127.0.0.1:1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// TestWorkerStampLandsCustomerWorker: the stamp step marks a session the run
// started execution_location=customer_worker and leaves an older, unproxied
// session alone.
func TestWorkerStampLandsCustomerWorker(t *testing.T) {
	cfg := cloudSessionFixture(t)
	ctx := context.Background()
	_, database, cleanup, err := loadConfigAndDB(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	runStart := time.Now().UTC()
	pid, err := st.UpsertProject(ctx, "/tmp/worker-run", "")
	if err != nil {
		t.Fatal(err)
	}
	for id, at := range map[string]time.Time{"in-run": runStart.Add(time.Second), "older": runStart.Add(-time.Hour)} {
		if err := st.UpsertSession(ctx, models.Session{ID: id, ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	cleanup()

	var errOut bytes.Buffer
	c := &workerCommon{
		configPath: cfg, startedAt: runStart, errOut: &errOut,
		plan: cloudsession.WorkerPlan{Location: cloudsession.ExecutionCustomerWorker},
	}
	if err := c.stamp(ctx); err != nil {
		t.Fatal(err)
	}
	_, database, cleanup, err = loadConfigAndDB(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	st = store.New(database)
	for id, want := range map[string]string{"in-run": models.ExecutionCustomerWorker, "older": ""} {
		ex, err := st.LoadSessionExecution(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if ex.ExecutionLocation != want {
			t.Fatalf("%s: execution_location %q, want %q", id, ex.ExecutionLocation, want)
		}
	}
	if !strings.Contains(errOut.String(), "1 session(s) in this run, 1 newly stamped") {
		t.Fatalf("stderr: %s", errOut.String())
	}
}
