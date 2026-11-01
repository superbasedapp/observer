//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/localipc"
	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandbox_windows_run3_fix_test.go pins the fixes of the Windows 11 Pro run
// 3 of 2026-10-22 (mxc-process, MXC 1.0.1): the relay judged a box's working
// directory in the POSIX syntax only, so the host helper refused every
// Windows box's launch check and closed its stream (the box saw EOF); every
// hop now names itself, the helper and the daemon log every refusal, the
// routing line masks the run token, and the box records its attach decision.

// run3Cwd is the box's working directory on the operator's machine.
const run3Cwd = `C:\Users\winagent\AppData\Local\Temp\sbo-p6-iso\work`

// run3DaemonHint is the advice only a failed helper to daemon connect gives.
const run3DaemonHint = "check that the Observer daemon is running"

// run3Opts shape one in-process relay chain.
type run3Opts struct {
	// helperPaths is the path syntax the host helper judges requests in
	// (the daemon always judges in the Windows syntax here).
	helperPaths sandboxrelay.PathSyntax
	// noDaemon: no daemon listens on the relay endpoint.
	noDaemon bool
	// daemonForgets: the daemon has no record of the run.
	daemonForgets bool
	// execErr: the daemon's executor fails.
	execErr error
}

// run3Relay is one run's relay chain in process, over the same seams a
// Windows run uses: the daemon's relay endpoint (sandboxrelayd.Daemon over
// localipc's Transport, the portable abstraction whose Windows transport is
// the named pipe) with a fake executor, the host helper's Forwarder behind
// its loopback port (mxcPort), and the box directory holding the launch and
// loopback records.
type run3Relay struct {
	obs, box string
	rec      sandboxrelayd.RunRecord
	port     int
	token    string

	mu        sync.Mutex
	reqs      []sandboxrelay.HookRequest
	daemonLog []string
	hostLog   []string
}

func newRun3Relay(t *testing.T, o run3Opts) *run3Relay {
	t.Helper()
	if !localipc.Supported() {
		t.Skip("no local IPC transport")
	}
	r := &run3Relay{obs: shortTempDir(t), box: shortTempDir(t)}
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "run3-relay", Tool: "claude-code", WorkspaceDir: r.obs, Roots: []string{r.obs}})
	if err != nil {
		t.Fatal(err)
	}
	r.rec = rec
	if !o.daemonForgets {
		if err := sandboxrelayd.WriteRun(r.obs, rec); err != nil {
			t.Fatal(err)
		}
	}
	ep, err := sandboxRelayEndpoint(r.obs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(ep), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if !o.noDaemon {
		dln, err := localipc.DefaultTransport().Listen(ep)
		if err != nil {
			t.Fatal(err)
		}
		rules := relayRules
		rules.Paths = sandboxrelay.WindowsPaths
		d := &sandboxrelayd.Daemon{
			ObserverDir: r.obs, Rules: rules, Peer: sandboxrelayd.PeerSameUser,
			Exec: func(_ context.Context, _ sandboxrelayd.RunRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
				r.mu.Lock()
				r.reqs = append(r.reqs, req)
				r.mu.Unlock()
				if o.execErr != nil {
					return sandboxrelay.HookResponse{}, o.execErr
				}
				return sandboxrelay.HookResponse{}, nil
			},
			Log: func(runID, reason string) {
				r.mu.Lock()
				r.daemonLog = append(r.daemonLog, runID+": "+reason)
				r.mu.Unlock()
			},
		}
		go func() { _ = d.Serve(ctx, dln) }()
	}
	rules := relayRules
	rules.Paths = o.helperPaths
	fw := &sandboxrelayd.Forwarder{Run: rec, DialDaemon: dialSandboxRelay(r.obs), Rules: rules, DaemonAddr: sandboxRelayAddr(r.obs)}
	r.token, _ = sandboxmxc.EncodeToken([]byte(strings.Repeat("3", 32)))
	r.port = startMXCPort(t, &mxcPort{Token: r.token, Tier: vocab.TierNone, Relay: fw.ServeConn, Log: func(line string) {
		r.mu.Lock()
		r.hostLog = append(r.hostLog, line)
		r.mu.Unlock()
	}})
	if err := sandboxrelayd.WriteBoxRecord(r.box, rec); err != nil {
		t.Fatal(err)
	}
	if err := writeMXCLoopback(r.box, mxcLoopback{V: 1, Port: r.port, Token: r.token}); err != nil {
		t.Fatal(err)
	}
	return r
}

// launchCheck runs the in-box launcher's launch check (boxLaunchGate) as a
// process in the box whose working directory is cwd.
func (r *run3Relay) launchCheck(t *testing.T, cwd string) error {
	t.Helper()
	oldRec, oldTrip, oldWd := boxRecordPath, boxRoundTrip, boxGetwd
	t.Cleanup(func() { boxRecordPath, boxRoundTrip, boxGetwd = oldRec, oldTrip, oldWd })
	boxRecordPath = filepath.Join(r.box, sandboxrelayd.BoxRecordName)
	boxRoundTrip = func(ctx context.Context, rec sandboxrelayd.BoxRecord, req sandboxrelay.HookRequest) (sandboxrelay.HookResponse, error) {
		return mxcBoxRoundTrip(ctx, r.box, rec, req)
	}
	boxGetwd = func() (string, error) { return cwd, nil }
	err, boxed := boxLaunchGate("claude-code", budgetLaunchEvidence{})
	if !boxed {
		t.Fatal("the launch check did not run as a box's")
	}
	return err
}

// logs waits briefly for the host log to say something (the helper writes
// its line once the box's stream is closed) and returns both logs.
func (r *run3Relay) logs(wantHost bool) (host, daemon string) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		host, daemon = strings.Join(r.hostLog, "\n"), strings.Join(r.daemonLog, "\n")
		r.mu.Unlock()
		if !wantHost || host != "" || time.Now().After(deadline) {
			return host, daemon
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMXCLaunchCheckReachesTheDaemon is the run 3 acceptance in process: a
// Windows box's launch check (its working directory a drive path) crosses
// the helper's port and the daemon's relay endpoint and is answered, and
// neither side logs a refusal.
func TestMXCLaunchCheckReachesTheDaemon(t *testing.T) {
	r := newRun3Relay(t, run3Opts{helperPaths: sandboxrelay.WindowsPaths})
	if err := r.launchCheck(t, run3Cwd); err != nil {
		t.Fatalf("the launch check was refused: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.reqs) != 1 || r.reqs[0].Kind != sandboxrelay.KindLaunchGate || r.reqs[0].Cwd != run3Cwd {
		t.Fatalf("the daemon ran %+v", r.reqs)
	}
	if len(r.hostLog) != 0 || len(r.daemonLog) != 0 {
		t.Fatalf("a served launch check logged a refusal: host %q daemon %q", r.hostLog, r.daemonLog)
	}
}

// TestMXCRelayHopsAreNamed (items 1 to 3): every way the relay chain can fail
// is refused naming its hop and address, the helper logs why it closed the
// box's stream, the daemon logs its refusals with the run id, and only a
// failed helper to daemon connect asks to check the daemon. The first row is
// run 3 itself, judged in the POSIX syntax the helper used to know only.
func TestMXCRelayHopsAreNamed(t *testing.T) {
	for name, c := range map[string]struct {
		opts      run3Opts
		refusal   string
		hostSays  string
		daemonSay string
		hint      bool
	}{
		"run 3: the helper judged a windows path in the posix syntax": {
			opts:     run3Opts{helperPaths: sandboxrelay.PosixPaths},
			refusal:  "the run's host helper at 127.0.0.1:%d refused the request",
			hostSays: "helper_refused_request",
		},
		"the daemon is not running": {
			opts:     run3Opts{helperPaths: sandboxrelay.WindowsPaths, noDaemon: true},
			refusal:  "could not connect to Observer's capture relay at %s",
			hostSays: "daemon_unreachable",
			hint:     true,
		},
		"the daemon does not know the run": {
			opts:      run3Opts{helperPaths: sandboxrelay.WindowsPaths, daemonForgets: true},
			refusal:   "Observer's capture relay at %s refused the run's host helper",
			hostSays:  "daemon_refused_link",
			daemonSay: "run3-relay: closed a helper's link whose handshake failed",
		},
		"the daemon ends the request without an answer": {
			opts:      run3Opts{helperPaths: sandboxrelay.WindowsPaths, execErr: errors.New("the relay child did not start")},
			refusal:   "Observer's capture relay at %s ended the request without an answer",
			hostSays:  "daemon_no_answer",
			daemonSay: "run3-relay: closed the link without an answer: sandboxrelayd.ServeConn: exec: the relay child did not start",
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRun3Relay(t, c.opts)
			err := r.launchCheck(t, run3Cwd)
			if err == nil {
				t.Fatal("the launch check passed")
			}
			want := c.refusal
			if strings.Contains(want, "%d") {
				want = strings.ReplaceAll(want, "%d", strconv.Itoa(r.port))
			} else {
				want = strings.ReplaceAll(want, "%s", sandboxRelayAddr(r.obs))
			}
			msg := err.Error()
			if !strings.Contains(msg, want) || strings.Contains(msg, run3DaemonHint) != c.hint {
				t.Fatalf("the refusal %q\nwant %q (daemon hint %v)", msg, want, c.hint)
			}
			host, daemon := r.logs(true)
			if !strings.Contains(host, "relay: closed the box's relay stream") || !strings.Contains(host, c.hostSays) {
				t.Errorf("the helper logged %q", host)
			}
			if c.daemonSay != "" && !strings.Contains(daemon, c.daemonSay) {
				t.Errorf("the daemon logged %q", daemon)
			}
			if strings.Contains(host+daemon+msg, r.token) {
				t.Fatal("the run token reached a log or the refusal")
			}
		})
	}
}

// TestMXCBoxToHelperHops: the box's own hop, to the helper's port, names the
// port; a refused stream is logged by the helper without the token.
func TestMXCBoxToHelperHops(t *testing.T) {
	r := newRun3Relay(t, run3Opts{helperPaths: sandboxrelay.WindowsPaths})
	// A port nobody listens on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	other, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("o", 32)))
	for name, c := range map[string]struct {
		lb   mxcLoopback
		hop  sandboxrelay.Hop
		says string
	}{
		"the box cannot connect":        {mxcLoopback{V: 1, Port: dead, Token: r.token}, sandboxrelay.HopBoxConnect, "the box could not connect to the run's host helper at 127.0.0.1:" + strconv.Itoa(dead)},
		"the helper refuses the stream": {mxcLoopback{V: 1, Port: r.port, Token: other}, sandboxrelay.HopBoxStream, "the run's host helper at 127.0.0.1:" + strconv.Itoa(r.port) + " refused the relay stream"},
	} {
		box := shortTempDir(t)
		if err := sandboxrelayd.WriteBoxRecord(box, r.rec); err != nil {
			t.Fatal(err)
		}
		if err := writeMXCLoopback(box, c.lb); err != nil {
			t.Fatal(err)
		}
		br, _, _ := sandboxrelayd.ReadBoxRecord(filepath.Join(box, sandboxrelayd.BoxRecordName))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := mxcBoxRoundTrip(ctx, box, br, sandboxrelay.HookRequest{Kind: sandboxrelay.KindLaunchGate, Args: []string{"claude-code"}, Cwd: run3Cwd})
		cancel()
		var hop *sandboxrelay.HopError
		if !errors.As(err, &hop) || hop.Hop != c.hop {
			t.Fatalf("%s: %v", name, err)
		}
		msg := boxGateUnreachableRefusal(err).Error()
		if !strings.Contains(msg, c.says) || strings.Contains(msg, run3DaemonHint) || strings.Contains(msg, other) {
			t.Errorf("%s: %q", name, msg)
		}
	}
	host, _ := r.logs(true)
	if !strings.Contains(host, "port: refused GET /relay/... with 403") || strings.Contains(host, other) || strings.Contains(host, r.token) {
		t.Fatalf("the helper logged %q", host)
	}
}

// TestBoxGateHopRefusals (item 3): the hop table names every hop and its
// address; only the failed helper to daemon connect asks to check the
// daemon, and a failure that names no hop does not either.
func TestBoxGateHopRefusals(t *testing.T) {
	hops := []sandboxrelay.Hop{
		sandboxrelay.HopBoxConnect, sandboxrelay.HopBoxStream, sandboxrelay.HopBoxClosed,
		sandboxrelay.HopHelperRequest, sandboxrelay.HopDaemonConnect, sandboxrelay.HopDaemonLink, sandboxrelay.HopDaemonAnswer,
	}
	if len(boxGateHops) != len(hops) {
		t.Fatalf("%d rows for %d hops", len(boxGateHops), len(hops))
	}
	for _, h := range hops {
		msg := boxGateUnreachableRefusal(&sandboxrelay.HopError{Hop: h, Addr: "ADDR", Detail: "DETAIL"}).Error()
		if !strings.Contains(msg, "at ADDR") || !strings.HasSuffix(msg, "(DETAIL)") {
			t.Errorf("%s: %q", h, msg)
		}
		if strings.Contains(msg, run3DaemonHint) != (h == sandboxrelay.HopDaemonConnect) {
			t.Errorf("%s: the daemon hint: %q", h, msg)
		}
		wantHop := "box to helper hop"
		switch h {
		case sandboxrelay.HopHelperRequest:
			wantHop = "host helper at ADDR refused"
		case sandboxrelay.HopDaemonConnect, sandboxrelay.HopDaemonLink, sandboxrelay.HopDaemonAnswer:
			wantHop = "helper to daemon relay hop"
		}
		if !strings.Contains(msg, wantHop) {
			t.Errorf("%s names no hop: %q", h, msg)
		}
	}
	plain := boxGateUnreachableRefusal(errors.New("EOF")).Error()
	if !strings.Contains(plain, relayLaunchGateRefusal) || strings.Contains(plain, run3DaemonHint) {
		t.Fatalf("a failure with no hop: %q", plain)
	}
}

// TestRedactRouteURL (item 4): the routing line masks a run token on every
// OS and leaves every other URL as it is.
func TestRedactRouteURL(t *testing.T) {
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("k", 32)))
	for in, want := range map[string]string{
		sandboxmxc.BaseURL(64830, tok):                         "http://127.0.0.1:64830/t/<redacted>",
		sandboxmxc.BaseURL(64830, tok) + "/v1/messages?beta=1": "http://127.0.0.1:64830/t/<redacted>/v1/messages?beta=1",
		"http://127.0.0.1:8820":                                "http://127.0.0.1:8820",
		"http://127.0.0.1:8820/up/hermes":                      "http://127.0.0.1:8820/up/hermes",
		"http://t/foo":                                         "http://t/foo",
		"http://127.0.0.1:1/t/":                                "http://127.0.0.1:1/t/",
		"not a url":                                            "not a url",
	} {
		if got := redactRouteURL(in); got != want {
			t.Errorf("redactRouteURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestMXCHostLog (item 2): the helper's host lines land in the log it
// created, prefixed host: and without the run's token, beside the box's own
// lines; a file the box put at the path afterwards gets nothing.
func TestMXCHostLog(t *testing.T) {
	dir := t.TempDir()
	l, err := openMXCHostLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.close()
	tok, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("h", 32)))
	registerBoxSecret(tok)
	l.line("relay: closed the box's relay stream for /relay/" + tok)
	t.Setenv(sandboxInnerLogEnv, mxcInnerLogPath(dir))
	appendBoxInnerLog("box detection: recognised run run3")
	b, err := os.ReadFile(mxcInnerLogPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], " host: relay: closed the box's relay stream for /relay/[REDACTED]") ||
		!strings.Contains(lines[1], "box detection: recognised run run3") || strings.Contains(string(b), tok) {
		t.Fatalf("the inner log:\n%s", b)
	}
	if _, err := openMXCHostLog(dir); err == nil {
		t.Fatal("the helper opened a log that already existed")
	}
	// The box replaces the log with a link to a host file: the helper's
	// line goes to the file it created, never through the link.
	host := filepath.Join(t.TempDir(), "host-file")
	if err := os.WriteFile(host, []byte("host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(mxcInnerLogPath(dir)); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		// Windows: the helper holds the log open without delete sharing,
		// so the box cannot replace it at all (the property this checks).
		t.Logf("the open log cannot be replaced here: %v", err)
	} else {
		if err := testSymlink(t, host, mxcInnerLogPath(dir)); err != nil {
			t.Skipf("no symlink here: %v", err)
		}
		l.line("after the swap")
		if b, _ := os.ReadFile(host); string(b) != "host\n" {
			t.Fatalf("the helper wrote through the box's link: %q", b)
		}
	}
	var nilLog *mxcHostLog
	nilLog.line("nothing")
	nilLog.close()
}

// TestAttachDecisionNote (item 5): the box records which attach row it took
// and the terminal facts it read.
func TestAttachDecisionNote(t *testing.T) {
	base := attachDecisionInputs{enabled: true, defaultOn: true, grounded: true, inSandbox: true, reachable: func() bool { return false }}
	for name, c := range map[string]struct {
		tty  bool
		want string
	}{
		"a terminal":          {true, "attach: launches without attach, notice printed (row: attach is not available inside the sandbox; stdin is a terminal: true, stdout is a terminal: true)"},
		"no terminal (run 3)": {false, "attach: launches without attach, no notice (row: stdin or stdout is not a terminal; stdin is a terminal: false, stdout is a terminal: false)"},
	} {
		in := base
		in.stdinTTY, in.stdoutTTY = c.tty, c.tty
		if got := attachDecisionNote(in, decideAttach(in)); got != c.want {
			t.Errorf("%s: %q", name, got)
		}
	}
	in := base
	in.stdinTTY, in.stdoutTTY, in.reachable = true, true, func() bool { return true }
	if got := attachDecisionNote(in, decideAttach(in)); !strings.HasPrefix(got, "attach: attaches") {
		t.Fatalf("attach: %q", got)
	}
}
