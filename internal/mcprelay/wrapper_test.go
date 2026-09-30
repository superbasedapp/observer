package mcprelay_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcprelay"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
)

// TestMain re-execs this test binary as the ORIGINAL stdio MCP server when
// MCPRELAY_HELPER is set (the wrapper's child).
func TestMain(m *testing.M) {
	if os.Getenv("MCPRELAY_HELPER") == "1" {
		helperServer()
		return
	}
	os.Exit(m.Run())
}

// helperServer is a minimal stdio MCP server: every line is logged to
// MCPRELAY_HELPER_LOG; tools/call echoes the raw request line, its cwd and a
// marker env var; tools/list returns three tools; SIGUSR1 emits a
// notification; the "exit" tool ends the process.
func helperServer() {
	logf, _ := os.OpenFile(os.Getenv("MCPRELAY_HELPER_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	out := bufio.NewWriter(os.Stdout)
	var mu sync.Mutex
	emit := func(b []byte) {
		mu.Lock()
		_, _ = out.Write(append(b, '\n'))
		_ = out.Flush()
		mu.Unlock()
	}
	if runtime.GOOS != "windows" {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGUSR1)
		go func() {
			for range sigs {
				emit([]byte(`{"jsonrpc":"2.0","method":"notifications/signal","params":{"sig":"USR1"}}`))
			}
		}()
		// MCPRELAY_HELPER_TERM_EXIT=<code>: on SIGTERM emit a notification
		// and exit with <code> (the client's own shutdown behaviour).
		// MCPRELAY_HELPER_IGNORE_TERM=1: ignore SIGTERM (a server that
		// hangs on shutdown) so the wrapper's grace -> kill ladder runs.
		if os.Getenv("MCPRELAY_HELPER_IGNORE_TERM") == "1" {
			signal.Ignore(syscall.SIGTERM)
		} else if code := os.Getenv("MCPRELAY_HELPER_TERM_EXIT"); code != "" {
			term := make(chan os.Signal, 1)
			signal.Notify(term, syscall.SIGTERM)
			go func() {
				<-term
				emit([]byte(`{"jsonrpc":"2.0","method":"notifications/signal","params":{"sig":"TERM"}}`))
				n := 0
				for _, ch := range code {
					n = n*10 + int(ch-'0')
				}
				os.Exit(n)
			}()
		}
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		_, _ = fmt.Fprintf(logf, "%s\n", line)
		var m mcprelay.Message
		if json.Unmarshal(line, &m) != nil || !m.HasID() {
			continue
		}
		var p struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(m.Params, &p)
		switch m.Method {
		case "tools/call":
			if p.Name == "exit" {
				return
			}
			cwd, _ := os.Getwd()
			res, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": m.ID,
				"result": map[string]any{"echo": string(line), "cwd": cwd, "env": os.Getenv("WRAP_TEST_ENV")},
			})
			emit(res)
		case "tools/list":
			emit([]byte(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"tools":[{"name":"a"},{"name":"secret"},{"name":"b"}]}}`))
		default:
			emit([]byte(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{}}`))
		}
	}
}

// localPDP is the fake node PDP: denies tool "secret", lists a+b.
type localPDP struct {
	mu   sync.Mutex
	reqs []localpdp.Request
}

func (p *localPDP) CheckRequest(_ context.Context, req localpdp.Request) localpdp.Decision {
	p.mu.Lock()
	p.reqs = append(p.reqs, req)
	p.mu.Unlock()
	d := localpdp.Decision{
		Verdict: localpdp.VerdictPass, Effect: "allow", DecisionClass: localpdp.ClassGoverned, Reason: "allow",
		Attestation: req.Principal.Access().ClientAttestation, PolicyGen: 3,
	}
	if req.Method == "tools/list" {
		d.DecisionClass, d.Visible = localpdp.ClassCatalogue, []string{"a", "b"}
	}
	if req.Tool == "secret" {
		d = localpdp.Decision{
			Verdict: localpdp.VerdictDeny, Effect: "deny", DecisionClass: localpdp.ClassGoverned, Reason: "no secret",
			Error: &localpdp.RPCError{Code: localpdp.CodeForbidden, Message: "Unknown tool: secret"},
		}
	}
	if req.Method == "tasks/get" {
		d = localpdp.Decision{Verdict: localpdp.VerdictError, Stripped: true, Error: &localpdp.RPCError{Code: localpdp.CodeMethodNotFound, Message: "Method not found: tasks/get"}}
	}
	return d
}

func (p *localPDP) requests() []localpdp.Request {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]localpdp.Request(nil), p.reqs...)
}

// wrapperEnv runs the wrapper with the helper child and a framed client.
type wrapperEnv struct {
	t        *testing.T
	store    *memStore
	pdp      *localPDP
	logPath  string
	cwd      string
	clientW  *io.PipeWriter
	clientR  *mcprelay.FrameReader
	done     chan error
	signals  chan os.Signal
	attestor mcprelay.Attestor
	relay    *mcprelay.Relay
}

type staticAttestor struct{ id mcprelay.ParentIdentity }

func (s staticAttestor) Attest(mcprelay.ClientRegistry) mcprelay.ParentIdentity { return s.id }

// wrapperEnvOpts tunes newWrapperEnvOpts: extra helper env, the forwarded-
// signal grace, and the Signals channel handed to the wrapper (nil -> the
// env's own injected channel).
type wrapperEnvOpts struct {
	extraEnv []string
	grace    time.Duration
	signals  chan os.Signal
	// projects / projectDir: the relay's resolver and the wrapper's own
	// spawn directory (P11 fold PF2).
	projects   *mcprelay.ProjectResolver
	projectDir string
}

func newWrapperEnv(t *testing.T, attestor mcprelay.Attestor) *wrapperEnv {
	t.Helper()
	return newWrapperEnvOpts(t, attestor, wrapperEnvOpts{})
}

func newWrapperEnvOpts(t *testing.T, attestor mcprelay.Attestor, opts wrapperEnvOpts) *wrapperEnv {
	t.Helper()
	e := &wrapperEnv{t: t, store: newMemStore(), pdp: &localPDP{}, attestor: attestor, done: make(chan error, 1), signals: make(chan os.Signal, 4)}
	if opts.signals != nil {
		e.signals = opts.signals
	}
	e.cwd = t.TempDir()
	e.logPath = filepath.Join(t.TempDir(), "child.log")
	r, err := mcprelay.New(mcprelay.Options{
		Records: e.store, SidecarPath: filepath.Join(t.TempDir(), mcprelay.SidecarName), CaptureLevel: "L2", Local: e.pdp, Projects: opts.projects,
		LocalPrincipal: func(vserver string, tr localpdp.Transport) (localpdp.Principal, bool) {
			if vserver != "local-gh" {
				return localpdp.Principal{}, false
			}
			return localpdp.Principal{Issuer: "i", Org: "o", Audience: []string{"a"}, Subject: "usr", MemberID: "usr", MachineFP: "fp", Transport: tr}, true
		},
	})
	mustNoErr(t, err)
	e.relay = r
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	e.clientW, e.clientR = inW, mcprelay.NewFrameReader(outR, 0)
	env := append(os.Environ(), "MCPRELAY_HELPER=1", "MCPRELAY_HELPER_LOG="+e.logPath, "WRAP_TEST_ENV=preserved-value")
	env = append(env, opts.extraEnv...)
	spec := mcprelay.LaunchSpec{ServerID: "srv_local", VServer: "local-gh", Command: os.Args[0], Args: []string{"-test.run=XXX_NONE"}, Cwd: e.cwd, Env: env}
	go func() {
		err := r.ServeStdioWrapper(context.Background(), mcprelay.WrapperOptions{
			Spec: spec, Stdin: inR, Stdout: outW, Stderr: io.Discard,
			Attestor: attestor, Signals: e.signals, Corr: mcprelay.Correlation{CodingSessionID: "sess_w"}, ExitGrace: 3 * time.Second, Grace: opts.grace,
			ProjectDir: opts.projectDir,
		})
		_ = outW.Close()
		e.done <- err
	}()
	return e
}

func (e *wrapperEnv) send(frame []byte) { mustNoErr(e.t, mcprelay.WriteFrame(e.clientW, frame)) }

// sendFragmented writes a frame one byte at a time (stdio fragmentation).
func (e *wrapperEnv) sendFragmented(frame []byte) {
	for _, b := range append(append([]byte(nil), frame...), '\n') {
		_, err := e.clientW.Write([]byte{b})
		mustNoErr(e.t, err)
	}
}

func (e *wrapperEnv) recv() *mcprelay.Message {
	e.t.Helper()
	ch := make(chan []byte, 1)
	errc := make(chan error, 1)
	go func() {
		f, err := e.clientR.Next()
		if err != nil {
			errc <- err
			return
		}
		ch <- f
	}()
	select {
	case f := <-ch:
		m, err := mcprelay.ParseMessage(f)
		mustNoErr(e.t, err)
		return m
	case err := <-errc:
		e.t.Fatalf("read: %v", err)
	case <-time.After(10 * time.Second):
		e.t.Fatal("no frame from the wrapper")
	}
	return nil
}

func (e *wrapperEnv) childLog() []string {
	b, _ := os.ReadFile(e.logPath)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (e *wrapperEnv) finish() error {
	_ = e.clientW.Close()
	select {
	case err := <-e.done:
		return err
	case <-time.After(15 * time.Second):
		e.t.Fatal("wrapper did not exit")
	}
	return nil
}

func TestStdioWrapperMediatesPreservesAndAttests(t *testing.T) {
	attested := staticAttestor{id: mcprelay.ParentIdentity{Attestation: "process_attested", Agent: "agent:claude-code", Product: "claude-code"}}
	e := newWrapperEnv(t, attested)

	// Byte-exact framing under fragmentation: the child echoes the raw line.
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":{"text":"tab\t ✓ \"q\""}}}`)
	e.sendFragmented(raw)
	m := e.recv()
	var res struct {
		Echo, Cwd, Env string
	}
	mustNoErr(t, json.Unmarshal(m.Result, &res))
	if res.Echo != string(raw) {
		t.Fatalf("child did not receive the exact bytes:\n%q\n%q", res.Echo, raw)
	}
	// cwd + env preserved from the launch spec.
	wantCwd, _ := filepath.EvalSymlinks(e.cwd)
	gotCwd, _ := filepath.EvalSymlinks(res.Cwd)
	if gotCwd != wantCwd || res.Env != "preserved-value" {
		t.Fatalf("cwd %q env %q", res.Cwd, res.Env)
	}

	// A raw stdio call to a denied tool is mediated: the child NEVER sees it.
	e.send(toolCall(2, "secret"))
	m = e.recv()
	if m.Error == nil || m.Error.Code != localpdp.CodeForbidden || string(m.ID) != "2" {
		t.Fatalf("deny %+v", m)
	}
	// Tasks are stripped (R8.27.b): refused, never forwarded.
	e.send(rpc(3, "tasks/get", map[string]any{"taskId": "t"}))
	m = e.recv()
	if m.Error == nil || m.Error.Code != localpdp.CodeMethodNotFound {
		t.Fatalf("tasks %+v", m)
	}
	// Catalogue filter: the child lists a/secret/b, the client sees a/b.
	e.send(rpc(4, "tools/list", nil))
	m = e.recv()
	if !strings.Contains(string(m.Result), `"a"`) || strings.Contains(string(m.Result), `"secret"`) || !strings.Contains(string(m.Result), `"b"`) {
		t.Fatalf("filtered list %s", m.Result)
	}
	// Signals reach the child.
	if runtime.GOOS != "windows" {
		e.signals <- syscall.SIGUSR1
		m = e.recv()
		if m.Method != "notifications/signal" {
			t.Fatalf("signal notification %+v", m)
		}
	}
	// Notifications from the client reach the child unmediated by effect.
	e.send([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
	e.send(toolCall(5, "b"))
	m = e.recv()
	if string(m.ID) != "5" {
		t.Fatalf("after notification %+v", m)
	}
	mustNoErr(t, e.finish())

	logLines := e.childLog()
	joined := strings.Join(logLines, "\n")
	if strings.Contains(joined, `"secret"`) || strings.Contains(joined, "tasks/get") {
		t.Fatalf("child received a mediated-out call:\n%s", joined)
	}
	if !strings.Contains(joined, "notifications/initialized") || !strings.Contains(joined, "tools/list") {
		t.Fatalf("child log missing forwarded frames:\n%s", joined)
	}
	// Attestation: process_attested flowed into the PDP principal and the
	// decision rows; the product client id was applied.
	reqs := e.pdp.requests()
	if reqs[0].Principal.ClientAttestation != "process_attested" || reqs[0].Principal.Transport != localpdp.TransportStdioWrapper || reqs[0].Principal.ClientID != "agent:claude-code" {
		t.Fatalf("pdp principal %+v", reqs[0].Principal)
	}
	rows := e.store.snapshot()
	var decisions, completions, denies int
	for _, r := range rows {
		switch r.Kind {
		case record.KindDecision:
			decisions++
			if r.ClientAttestation != record.AttestProcess || r.CodingSessionID != "sess_w" || r.Server != "srv_local" {
				t.Fatalf("decision row %+v", r)
			}
			if r.Decision == record.DecisionDeny {
				denies++
			}
		case record.KindCompletion:
			completions++
		}
	}
	// 1 call + deny + list + notification + call = 5 decisions (tasks/get
	// is refused before any record: stripped, not a policy verdict); every
	// decision has its completion (a notification's is its hand-off).
	if decisions != 5 || denies != 1 || completions != 5 {
		t.Fatalf("decisions=%d denies=%d completions=%d kinds=%v", decisions, denies, completions, e.store.kinds())
	}
}

func TestStdioWrapperDowngradesUnverifiedParent(t *testing.T) {
	// The default attestor cannot verify this test process's parent as a
	// registered client -> configured, node-wide principal.
	e := newWrapperEnv(t, nil)
	e.send(toolCall(1, "a"))
	m := e.recv()
	if m.Result == nil {
		t.Fatalf("%+v", m)
	}
	mustNoErr(t, e.finish())
	if got := e.pdp.requests()[0].Principal.ClientAttestation; got != "configured" {
		t.Fatalf("unverified parent must be configured, got %q", got)
	}
	if rows := e.store.snapshot(); rows[0].ClientAttestation != record.AttestConfigured {
		t.Fatalf("row attestation %q", rows[0].ClientAttestation)
	}
}

func TestStdioWrapperClaimCannotRaiseAboveTransport(t *testing.T) {
	// An attestor claiming process_attested over a LOOPBACK transport
	// cannot happen (the wrapper is always TransportStdioWrapper), but a
	// "configured" claim on the wrapper stays configured: never raised.
	e := newWrapperEnv(t, staticAttestor{id: mcprelay.ParentIdentity{Attestation: "configured", Reason: "test"}})
	e.send(toolCall(1, "a"))
	_ = e.recv()
	mustNoErr(t, e.finish())
	if got := e.pdp.requests()[0].Principal.ClientAttestation; got != "configured" {
		t.Fatalf("got %q", got)
	}
}

func TestStdioWrapperNoLocalPolicyBlocks(t *testing.T) {
	store := newMemStore()
	r, err := mcprelay.New(mcprelay.Options{Records: store, SidecarPath: filepath.Join(t.TempDir(), mcprelay.SidecarName)})
	mustNoErr(t, err)
	v := r.Decide(context.Background(), mcprelay.Call{Target: mcprelay.Target{VServer: "x", Local: true}, Raw: toolCall(1, "a"), Transport: localpdp.TransportStdioWrapper})
	if v.Forward {
		t.Fatal("a local call with no policy loaded must be blocked, never passed")
	}
}

// TestStdioWrapperForwardsTermSignalThenPropagatesExit exercises the
// PRODUCTION signal path (Sol P3+P4 finding 6): the wrapper's Signals
// channel is a real signal.Notify subscription in this process, a real
// SIGTERM is delivered to the process, the CHILD receives it first (it
// emits a notification and exits 3 on its own), and the wrapper returns
// the child's exit code - it never killed the child under a cancelled
// context.
func TestStdioWrapperForwardsTermSignalThenPropagatesExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals")
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM)
	defer signal.Stop(sigs)
	e := newWrapperEnvOpts(t, staticAttestor{id: mcprelay.ParentIdentity{Attestation: "configured"}},
		wrapperEnvOpts{extraEnv: []string{"MCPRELAY_HELPER_TERM_EXIT=3"}, grace: 5 * time.Second, signals: sigs})
	// A call first, so the child is up and mediated.
	e.send(toolCall(1, "a"))
	if m := e.recv(); m.Result == nil {
		t.Fatalf("%+v", m)
	}
	start := time.Now()
	mustNoErr(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))
	// The child saw the signal FIRST: its notification arrives before it exits.
	if m := e.recv(); m.Method != "notifications/signal" || !strings.Contains(string(m.Params), "TERM") {
		t.Fatalf("child did not receive the forwarded SIGTERM: %+v", m)
	}
	select {
	case err := <-e.done:
		var ce *mcprelay.ChildExitError
		if !errors.As(err, &ce) || ce.Code != 3 || !errors.Is(err, mcprelay.ErrChildFailed) {
			t.Fatalf("child exit not propagated: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("wrapper did not exit after the child did")
	}
	if el := time.Since(start); el > 4*time.Second {
		t.Fatalf("wrapper waited for the grace (%v) although the child exited on its own", el)
	}
	_ = e.clientW.Close()
}

// TestStdioWrapperEscalatesAfterGrace: a child that ignores SIGTERM is
// given exactly the configured grace, then killed; the wrapper reports the
// kill, never hangs.
func TestStdioWrapperEscalatesAfterGrace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals")
	}
	const grace = 700 * time.Millisecond
	e := newWrapperEnvOpts(t, staticAttestor{id: mcprelay.ParentIdentity{Attestation: "configured"}},
		wrapperEnvOpts{extraEnv: []string{"MCPRELAY_HELPER_IGNORE_TERM=1"}, grace: grace})
	e.send(toolCall(1, "a"))
	if m := e.recv(); m.Result == nil {
		t.Fatalf("%+v", m)
	}
	start := time.Now()
	e.signals <- syscall.SIGTERM
	select {
	case err := <-e.done:
		el := time.Since(start)
		var ce *mcprelay.ChildExitError
		if !errors.As(err, &ce) || ce.Signal != "killed" {
			t.Fatalf("want a kill after the grace, got %v", err)
		}
		if el < grace || el > grace+5*time.Second {
			t.Fatalf("escalation after %v, want >= %v", el, grace)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("wrapper hung on a child that ignores SIGTERM")
	}
	_ = e.clientW.Close()
}

// TestStdioWrapperNonTerminatingSignalNeverEscalates: a forwarded SIGUSR1
// is delivered and the child keeps running past any grace.
func TestStdioWrapperNonTerminatingSignalNeverEscalates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signals")
	}
	e := newWrapperEnvOpts(t, staticAttestor{id: mcprelay.ParentIdentity{Attestation: "configured"}}, wrapperEnvOpts{grace: 200 * time.Millisecond})
	// A call first: the child registers its SIGUSR1 handler before it reads
	// stdin, so a reply proves the handler is installed.
	e.send(toolCall(1, "a"))
	if m := e.recv(); m.Result == nil {
		t.Fatalf("%+v", m)
	}
	e.signals <- syscall.SIGUSR1
	if m := e.recv(); m.Method != "notifications/signal" {
		t.Fatalf("%+v", m)
	}
	time.Sleep(500 * time.Millisecond)
	e.send(toolCall(7, "a"))
	if m := e.recv(); string(m.ID) != "7" {
		t.Fatalf("child gone after a non-terminating signal: %+v", m)
	}
	mustNoErr(t, e.finish())
}
