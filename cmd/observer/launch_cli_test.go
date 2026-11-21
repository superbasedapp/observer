//go:build !sbo_omit_terminals && !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/localipc"
)

// serveFakeDaemon serves the attach endpoint with an attach host whose
// controller runs over the fake terminal service, and points the verbs'
// controlCall at it. It is the round trip of the CLI, the socket, the
// control ops and the launch control, with only the terminal service fake.
func serveFakeDaemon(t *testing.T, f *fakeTermsvc) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := localipc.Endpoint(filepath.Join(dir, "observer.db"))
	if err != nil {
		t.Skipf("no attach endpoint here: %v", err)
	}
	ln, err := localipc.ListenSocket(endpoint)
	if err != nil {
		t.Skipf("cannot listen on the attach endpoint: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	host := newAttachHost(nil, nil, nil).withControl(f.control(true))
	go func() {
		defer close(done)
		_ = attachsock.Serve(ctx, ln, host, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	}()
	old := controlCall
	controlCall = func(ctx context.Context, _ string, req attachsock.ControlRequest) (attachsock.ControlResult, error) {
		return attachsock.ControlCall(ctx, endpoint, req)
	}
	t.Cleanup(func() {
		controlCall = old
		cancel()
		_ = ln.Close()
		<-done
	})
}

// runVerb runs a root command line and returns stdout, stderr and the exit
// code main would use.
func runVerb(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	root := newRootCmd()
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err := root.Execute()
	code := 0
	var ec exitErr
	switch {
	case errors.As(err, &ec):
		code = int(ec)
	case err != nil:
		code = 1
	}
	return out.String(), errb.String(), code
}

// terminalsComponent is the component that owns the launch and terminals
// verbs.
const terminalsComponent = "terminals"

// requireTerminalsActive skips a test that runs the launch or terminals
// verbs through the root command where an unconfigured node of this build
// leaves terminals inactive (the managed edition, selected locally or by
// policy): there the component gate refuses the verb with exit 3 before
// the behaviour the test pins, as it should.
func requireTerminalsActive(t *testing.T) {
	t.Helper()
	requireComponents(t, terminalsComponent)
}

// TestLaunchCLIDetachJSON: `observer launch --detach --json` prints the run
// and the daemon's terminal service saw the spec.
func TestLaunchCLIDetachJSON(t *testing.T) {
	requireTerminalsActive(t)
	f := newFakeTermsvc()
	f.probe = liveProbe()
	serveFakeDaemon(t, f)
	out, errb, code := runVerb(t, "launch", "claude", "--project", "/home/dev/repo", "--sandbox", "auto", "--workspace", "clone-local", "--detach", "--json")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q, stdout %q", code, errb, out)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out)
	}
	if got["run_id"] != "run-new-0001" || got["handle"] != "h-new" || got["tool"] != "claude-code" || got["sandboxed"] != true || got["state"] != "running" {
		t.Fatalf("json = %v", got)
	}
	if len(f.specs) != 1 || f.specs[0].WorkspaceSource != "clone-local" || !f.specs[0].Sandbox || f.specs[0].Backend != "" {
		t.Fatalf("spec = %+v", f.specs)
	}
}

// TestLaunchCLIRefusals: exit codes and the --json error shape; a sandbox
// that cannot be built never launches.
func TestLaunchCLIRefusals(t *testing.T) {
	requireTerminalsActive(t)
	cases := []struct {
		name string
		args []string
		code int
		err  string
	}{
		{"usage before dialing", []string{"launch", "claude", "--project", "/r", "--branch", "main", "--json"}, launchExitUsage, "invalid_request"},
		{"bad --wait", []string{"launch", "claude", "--project", "/r", "--detach", "--wait", "soon", "--json"}, launchExitUsage, "invalid_request"},
		{"unknown backend", []string{"launch", "claude", "--project", "/r", "--sandbox", "e2b", "--detach", "--json"}, launchExitUnavailable, "sandbox_unavailable"},
		{"auto on a beta-only host", []string{"launch", "claude", "--project", "/r", "--sandbox", "auto", "--detach", "--json"}, launchExitUnavailable, "sandbox_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeTermsvc()
			f.probe = liveProbe()
			f.probe.Backends[0].Available = false // only the beta row left
			serveFakeDaemon(t, f)
			out, _, code := runVerb(t, tc.args...)
			if code != tc.code {
				t.Fatalf("exit = %d, want %d (%s)", code, tc.code, out)
			}
			var e launchErrorJSON
			if err := json.Unmarshal([]byte(out), &e); err != nil || e.Error.Code != tc.err || e.Error.Message == "" {
				t.Fatalf("error json = %q (%v), want code %s", out, err, tc.err)
			}
			if len(f.specs) != 0 {
				t.Fatalf("a refused launch reached the terminal service: %+v", f.specs)
			}
		})
	}
}

// TestLaunchCLIPolicyRefusal: a launch policy refusal exits 3 in text mode
// with one line on stderr.
func TestLaunchCLIPolicyRefusal(t *testing.T) {
	requireTerminalsActive(t)
	f := newFakeTermsvc()
	f.err = dashapi.ErrLaunchToolNotAllowed
	serveFakeDaemon(t, f)
	out, errb, code := runVerb(t, "launch", "claude", "--project", "/r", "--detach")
	if code != launchExitUnavailable || out != "" || !strings.Contains(errb, "allow-list") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errb)
	}
}

// TestTerminalsCLI covers ls / show / stop / wait over the socket.
func TestTerminalsCLI(t *testing.T) {
	requireTerminalsActive(t)
	f := newFakeTermsvc()
	f.snap = []dashapi.LaunchInfo{
		{ID: "h-1", RunID: "run-aaaa-0001", Tool: "codex", Kind: "fresh", CreatedAt: f.now},
	}
	f.sessions["run-aaaa-0001"] = "sess-9"
	serveFakeDaemon(t, f)

	out, _, code := runVerb(t, "terminals", "ls", "--json")
	var list struct {
		Runs []attachsock.RunInfo `json:"runs"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &list) != nil || len(list.Runs) != 1 || list.Runs[0].SessionID != "sess-9" {
		t.Fatalf("ls = %d %q", code, out)
	}
	out, _, code = runVerb(t, "terminals", "ls")
	if code != 0 || !strings.Contains(out, "RUN") || !strings.Contains(out, "run-aaaa-0001") {
		t.Fatalf("ls text = %d %q", code, out)
	}
	out, _, code = runVerb(t, "terminals", "show", "run-aaaa", "--json")
	if code != 0 || !strings.Contains(out, `"session_id": "sess-9"`) {
		t.Fatalf("show = %d %q", code, out)
	}
	out, _, code = runVerb(t, "terminals", "wait", "h-1", "--for", "session", "--json")
	if code != 0 || !strings.Contains(out, `"session_id": "sess-9"`) {
		t.Fatalf("wait session = %d %q", code, out)
	}
	out, _, code = runVerb(t, "terminals", "wait", "h-1", "--timeout", "50ms", "--json")
	if code != launchExitTimeout || !strings.Contains(out, `"timed_out": true`) {
		t.Fatalf("wait timeout = %d %q", code, out)
	}
	out, _, code = runVerb(t, "terminals", "stop", "run-aaaa-0001", "--json")
	if code != 0 || !strings.Contains(out, `"end_reason": "cli_stop"`) || f.stopped["h-1"] != "cli_stop" {
		t.Fatalf("stop = %d %q %v", code, out, f.stopped)
	}
	out, errb, code := runVerb(t, "terminals", "show", "missing-run")
	if code != launchExitUnavailable || out != "" || !strings.Contains(errb, "no such run") {
		t.Fatalf("show missing = %d %q %q", code, out, errb)
	}
}

// TestLaunchCLIDaemonDown: no daemon answers with exit 3 and the hint.
func TestLaunchCLIDaemonDown(t *testing.T) {
	requireTerminalsActive(t)
	old := controlCall
	defer func() { controlCall = old }()
	controlCall = func(ctx context.Context, _ string, req attachsock.ControlRequest) (attachsock.ControlResult, error) {
		return attachsock.ControlCall(ctx, filepath.Join(t.TempDir(), "absent.sock"), req)
	}
	out, _, code := runVerb(t, "terminals", "ls", "--json")
	if code != launchExitUnavailable || !strings.Contains(out, codeDaemonUnreachable) {
		t.Fatalf("exit %d %q", code, out)
	}
}

// TestLaunchCLIForegroundExitCodes: without --detach the tool's own exit
// code is reported in the output and never becomes the process's status,
// so a tool exiting 2, 3 or 4 cannot be read as a usage error, a refusal
// or a timeout.
func TestLaunchCLIForegroundExitCodes(t *testing.T) {
	requireTerminalsActive(t)
	for _, tc := range []struct{ tool, want int }{{0, 0}, {2, launchExitRunFailed}, {3, launchExitRunFailed}, {4, launchExitRunFailed}, {1, launchExitRunFailed}} {
		f := newFakeTermsvc()
		code := tc.tool
		f.exitCode = &code
		serveFakeDaemon(t, f)
		out, errb, got := runVerb(t, "launch", "claude", "--project", "/r", "--json")
		if got != tc.want {
			t.Fatalf("tool exit %d: CLI exit %d, want %d (%s %s)", tc.tool, got, tc.want, out, errb)
		}
		var run map[string]any
		if err := json.Unmarshal([]byte(out), &run); err != nil || run["exit_code"] != float64(tc.tool) {
			t.Fatalf("tool exit %d: output %q", tc.tool, out)
		}
	}
}
