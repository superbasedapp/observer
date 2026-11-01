//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// hostedSyncBuf is a goroutine-safe buffer for the terminal's output.
type hostedSyncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *hostedSyncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *hostedSyncBuf) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// hostedHarness drives a hostedRun against the in-memory vendor.
type hostedHarness struct {
	t       *testing.T
	run     *hostedRun
	client  *fakeBoxClient
	termIn  *io.PipeWriter
	out     *hostedSyncBuf
	resized chan struct{}
	stopped chan string
	ingests int
	mu      sync.Mutex
	ptys    []*pipeProcess
	guests  int
	// sizes are the resizes the guest PTY end received (Modal, Vercel).
	sizes []relaymux.Size
	// tools is what the box's tool probe answers.
	tools string
	// diff is the box's staged diff (answered only in the workspace);
	// diffCwd is the working directory the staged-diff call ran in.
	diff, diffCwd string
	// readyDelay delays each relay guest's ready; noReady withholds it.
	readyDelay time.Duration
	noReady    bool
	// readyAt is when the first relay guest said ready, agentAt when the
	// agent was started.
	readyAt, agentAt time.Time
	// relays are the relay guests, in order.
	relays []*relaymux.Guest
	// corrupt makes the box's join of the binary's parts differ.
	corrupt bool
	// sent is the joined upload of the binary as the box received it, and
	// mode the assemble mode it was told.
	sent []byte
	mode string
	// specs are every exec the box received, in order.
	specs []sandboxremote.ExecSpec
	// stageCode and stageOut answer the staging of the changes; diffCode
	// and diffOut, when diffCode is set, fail the staged diff.
	stageCode, diffCode int
	stageOut, diffOut   string
}

func newHostedHarness(t *testing.T, vendor string) *hostedHarness {
	t.Helper()
	obs := t.TempDir()
	sock := t.TempDir()
	if err := os.WriteFile(filepath.Join(sock, sandboxrelayd.BoxRecordName), []byte(`{"v":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "observer-box")
	_ = os.WriteFile(bin, []byte("binary"), 0o755)
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, ".env"), []byte("SECRET=1\n"), 0o600)
	old := hostedListWorkspace
	hostedListWorkspace = func(context.Context, string) ([]sandboxremote.Candidate, bool, error) {
		return []sandboxremote.Candidate{{Path: "main.go", Kind: sandboxremote.KindRegular, Size: 13}, {Path: ".env", Kind: sandboxremote.KindRegular, Size: 9}}, true, nil
	}
	t.Cleanup(func() { hostedListWorkspace = old })
	m, err := sandboxremote.PlanManifest(sandboxremote.ManifestInput{Root: root, Home: "/nonexistent-home", Repository: true, Candidates: []sandboxremote.Candidate{{Path: "main.go", Kind: sandboxremote.KindRegular, Size: 13}}})
	if err != nil {
		t.Fatal(err)
	}
	keys := hostedTestEnv(t, map[string]string{"E2B_API_KEY": "e2b_FAKEKEY_harness", "MODAL_TOKEN_ID": "id", "MODAL_TOKEN_SECRET": "s", "VERCEL_TOKEN": "t", "VERCEL_TEAM_ID": "team", "VERCEL_PROJECT_ID": "prj"})
	_ = keys
	v, _ := sandboxremote.VendorFor(vendor)
	inR, inW := io.Pipe()
	hh := &hostedHarness{t: t, client: newFakeBoxClient(), termIn: inW, out: &hostedSyncBuf{}, resized: make(chan struct{}, 1), stopped: make(chan string, 1), tools: "gzip\nsha256sum\n"}
	oldReg, hadReg := hostedVendorRegs[vendor]
	hostedVendorRegs[vendor] = hostedVendorReg{vendor: vendor, component: "x", newClient: func(sandboxremote.Credential, string) (sandboxremote.Client, error) { return hh.client, nil }}
	t.Cleanup(func() {
		if hadReg {
			hostedVendorRegs[vendor] = oldReg
		} else {
			delete(hostedVendorRegs, vendor)
		}
	})
	hh.client.execs = hh.exec
	hh.run = &hostedRun{
		plan: hostedPlanFile{
			Version: hostedPlanVersion, RunID: "run-h1", Provider: vendor, Endpoint: v.DefaultEndpoint, Region: v.Regions.Default,
			Tier: "proxy_only", Custody: "in_box_api_key", TimeoutMinutes: 30, Root: root, ScopeKey: m.ScopeKey,
			BoxBinary: bin, ToolStateRel: []string{".claude"}, CheckpointMinutes: 5, DailyBoxMinutes: 240, ObserverDir: obs, Tool: "claude-code",
		},
		h: sandbox.HostArgs{SockDir: sock, ProxyAddr: "127.0.0.1:8820", Command: []string{"/usr/local/bin/observer", "claude"}},
		t: hostedTerm{
			in: inR, out: hh.out, resized: hh.resized, stopped: hh.stopped,
			size: func() (uint16, uint16) { return 30, 100 }, raw: func() func() { return func() {} },
		},
		now: time.Now,
		ingest: func(context.Context) (hostedIngester, func(), error) {
			return func(context.Context, string, string, []string) (int, error) { hh.ingests++; return 1, nil }, func() {}, nil
		},
	}
	return hh
}

// hostedProbeOnTree runs args against the real command tree, as the in-box
// observer would, and returns what it printed.
func hostedProbeOnTree(args []string) string {
	root := newRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	_ = root.Execute()
	return buf.String()
}

// assemble plays the box's join of the binary's parts: in order, gunzipped
// when the mode is gz, checked against the digest, then installed.
func (hh *hostedHarness) assemble(b *fakeBox, out, want, mode string, parts []string) sandboxremote.Process {
	hh.client.mu.Lock()
	defer hh.client.mu.Unlock()
	var data []byte
	for _, p := range parts {
		data = append(data, b.files[p]...)
		delete(b.files, p)
	}
	hh.sent, hh.mode = append([]byte(nil), data...), mode
	if mode == "gz" {
		zr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return newFakeProcess("gzip: not in gzip format\n", 1)
		}
		if data, err = io.ReadAll(zr); err != nil {
			return newFakeProcess("gzip: corrupt\n", 1)
		}
	}
	if hh.corrupt {
		data = append(data, 'x')
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != want {
		return newFakeProcess("observer upload: digest mismatch\n", 3)
	}
	b.files[out] = data
	return newFakeProcess("", 0)
}

// exec plays the box: the tool probe, the binary's join and its
// self-check, the staged diff, the relay-stdio guest, and the agent's PTY
// (an echo that exits on "exit").
func (hh *hostedHarness) exec(b *fakeBox, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	argv := strings.Join(spec.Argv, " ")
	hh.mu.Lock()
	hh.specs = append(hh.specs, spec)
	hh.mu.Unlock()
	switch {
	case len(spec.Argv) >= 3 && spec.Argv[0] == "sh" && spec.Argv[2] == hostedBoxToolsProbe:
		return newFakeProcess(hh.tools, 0), nil
	case len(spec.Argv) >= 3 && spec.Argv[0] == "sh" && spec.Argv[2] == hostedBoxOwnerProbe:
		return newFakeProcess("1000:1000\n", 0), nil
	case len(spec.Argv) >= 3 && spec.Argv[0] == "sh" && spec.Argv[2] == hostedStageScript:
		return newFakeProcess(hh.stageOut, hh.stageCode), nil
	case len(spec.Argv) >= 8 && spec.Argv[0] == "sh" && spec.Argv[2] == hostedAssembleScript:
		return hh.assemble(b, spec.Argv[4], spec.Argv[5], spec.Argv[6], spec.Argv[7:]), nil
	case len(spec.Argv) > 1 && slices.Equal(spec.Argv[1:], hostedBoxProbeArgs):
		// The in-box observer answers its self-check from the real command
		// tree, so a probe the tree does not know gets no version back.
		return newFakeProcess(hostedProbeOnTree(spec.Argv[1:]), 0), nil
	case strings.Contains(argv, " "+sandbox.GuestStagedDiff+" "):
		hh.mu.Lock()
		hh.diffCwd = spec.Cwd
		hh.mu.Unlock()
		if spec.Cwd != hh.run.plan.Root {
			return newFakeProcess("fatal: not a git repository\n", 125), nil
		}
		if hh.diffCode != 0 {
			return newFakeProcess(hh.diffOut, hh.diffCode), nil
		}
		return newFakeProcess(hh.diff, 0), nil
	case strings.Contains(argv, relayStdioFlag) && !strings.Contains(argv, "--pty"):
		a, c := net.Pipe()
		secretPath := spec.Argv[len(spec.Argv)-1]
		hh.client.mu.Lock()
		secret := append([]byte(nil), b.files[secretPath]...)
		hh.client.mu.Unlock()
		p := &pipeProcess{c: a, done: make(chan int, 1), pid: "7"}
		go func() {
			g, err := relaymux.DialGuest(context.Background(), relayTestStack(c), relaymux.Options{RunID: "run-h1", Secret: secret})
			if err != nil {
				p.done <- 1
				return
			}
			hh.mu.Lock()
			hh.guests++
			hh.relays = append(hh.relays, g)
			delay, withhold := hh.readyDelay, hh.noReady
			hh.mu.Unlock()
			if !withhold {
				time.Sleep(delay)
				hh.mu.Lock()
				if hh.readyAt.IsZero() {
					hh.readyAt = time.Now()
				}
				hh.mu.Unlock()
				_ = g.Ready()
			}
			<-g.Done()
			p.done <- 0
		}()
		return p, nil
	case strings.Contains(argv, relayStdioFlag) && strings.Contains(argv, "--pty"):
		// The guest helper's PTY (Modal, Vercel): the terminal and its sizes
		// cross the mux; the agent is an echo that exits on "exit".
		a, c := net.Pipe()
		var secretPath string
		for i, s := range spec.Argv {
			if s == "--secret-file" && i+1 < len(spec.Argv) {
				secretPath = spec.Argv[i+1]
			}
		}
		hh.client.mu.Lock()
		secret := append([]byte(nil), b.files[secretPath]...)
		hh.client.mu.Unlock()
		p := &pipeProcess{c: a, done: make(chan int, 1)}
		hh.mu.Lock()
		hh.ptys = append(hh.ptys, p)
		if hh.agentAt.IsZero() {
			hh.agentAt = time.Now()
		}
		hh.mu.Unlock()
		go func() {
			g, err := relaymux.DialGuest(context.Background(), relayTestStack(c), relaymux.Options{RunID: "run-h1", Secret: secret})
			if err != nil {
				p.done <- 1
				return
			}
			go func() {
				for sz := range g.Resizes() {
					hh.mu.Lock()
					hh.sizes = append(hh.sizes, sz)
					hh.mu.Unlock()
				}
			}()
			pty := g.PTY()
			buf := make([]byte, 64)
			for {
				n, err := pty.Read(buf)
				if err != nil {
					p.done <- 1
					return
				}
				if strings.Contains(string(buf[:n]), "exit") {
					p.done <- 5
					g.Close()
					return
				}
				_, _ = pty.Write(buf[:n])
			}
		}()
		return p, nil
	case spec.PTY:
		a, c := net.Pipe()
		p := &pipeProcess{c: a, done: make(chan int, 1), pid: "42"}
		hh.mu.Lock()
		hh.ptys = append(hh.ptys, p)
		if hh.agentAt.IsZero() {
			hh.agentAt = time.Now()
		}
		hh.mu.Unlock()
		go func() {
			buf := make([]byte, 64)
			for {
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				if strings.Contains(string(buf[:n]), "exit") {
					_ = c.Close()
					p.done <- 5
					return
				}
				_, _ = c.Write(buf[:n])
			}
		}()
		return p, nil
	}
	return newFakeProcess("", 0), nil
}

// TestHostedHostLifecycle drives a whole E2B-shaped run: the intent is
// recorded before the create, the box gets its timeout and label, the
// consented files (never the credential-shaped one) and the in-box observer
// are uploaded, the relay comes up, the agent runs, and teardown pulls,
// deletes, confirms and removes the record and the per-box secret.
func TestHostedHostLifecycle(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { return strings.Contains(hh.out.String(), "box box1") })
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return hh.guests > 0 && len(hh.ptys) > 0 })
	_, _ = hh.termIn.Write([]byte("hello"))
	waitFor(t, func() bool { return strings.Contains(hh.out.String(), "hello") })
	_, _ = hh.termIn.Write([]byte("exit"))
	select {
	case c := <-code:
		if c != 5 {
			t.Errorf("exit %d, output %s", c, hh.out.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the run did not end")
	}
	calls := strings.Join(hh.client.calls, "|")
	if !strings.HasPrefix(calls, "create|") || !strings.Contains(calls, "delete|get") {
		t.Errorf("calls %s", calls)
	}
	b := hh.client.boxes["box1"]
	if b.spec.TimeoutSeconds != 30*60 || b.spec.Labels[sandboxremote.LabelKey] != "run-h1" {
		t.Errorf("box spec %+v", b.spec)
	}
	if _, ok := b.files[filepath.Join(hh.run.plan.Root, "main.go")]; !ok {
		t.Error("the consented file was not uploaded")
	}
	if _, ok := b.files[filepath.Join(hh.run.plan.Root, ".env")]; ok {
		t.Error("a credential-shaped file was uploaded")
	}
	if !b.deleted {
		t.Error("the box was not deleted")
	}
	if recs := hostedLoadRecords(hh.run.plan.ObserverDir); len(recs) != 0 {
		t.Errorf("records left %+v", recs)
	}
	if !strings.Contains(hh.out.String(), "deleted (confirmed") {
		t.Errorf("output %s", hh.out.String())
	}
}

// TestHostedHostCutTransportReattaches (A6 shape on E2B): the PTY stream is
// cut, the run re-attaches by pid and goes on.
func TestHostedHostCutTransportReattaches(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	reattached := make(chan struct{}, 1)
	hh.client.reattach = func(id, pid string) (sandboxremote.Process, error) {
		if pid != "42" {
			t.Errorf("reattach pid %s", pid)
		}
		reattached <- struct{}{}
		return hh.exec(hh.client.boxes[id], sandboxremote.ExecSpec{PTY: true})
	}
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.ptys) > 0 })
	hh.mu.Lock()
	first := hh.ptys[0]
	hh.mu.Unlock()
	first.mu.Lock()
	first.failWait = errors.New("stream cut")
	first.mu.Unlock()
	_ = first.c.Close()
	first.done <- -1
	select {
	case <-reattached:
	case <-time.After(10 * time.Second):
		t.Fatal("no reattach after the cut")
	}
	waitFor(t, func() bool { return strings.Contains(hh.out.String(), "re-attached") })
	_, _ = hh.termIn.Write([]byte("exit"))
	select {
	case c := <-code:
		if c != 5 {
			t.Errorf("exit %d", c)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the run did not end")
	}
}

// TestHostedHostStopTearsDown (the SBX-P7 merge's audit finding 2): a SIGHUP
// or SIGTERM during an E2B run (the vendor's own PTY) acts at once while the
// agent's stream is still open: the agent is killed, the run ends and the box
// is deleted, instead of the helper waiting for the stream and leaving the
// box to its timeout.
func TestHostedHostStopTearsDown(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.ptys) > 0 })
	hh.stopped <- "hangup"
	select {
	case c := <-code:
		if c == 0 {
			t.Error("a stopped run exited 0")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the stop did not end the run while the agent's stream was open")
	}
	hh.client.mu.Lock()
	deleted := hh.client.boxes["box1"].deleted
	hh.client.mu.Unlock()
	if !deleted {
		t.Error("the box outlived the stop")
	}
	if !strings.Contains(hh.out.String(), "deleted (confirmed") {
		t.Errorf("output %s", hh.out.String())
	}
}

// TestHostedHostNoReattachEndsHonestly (A7 on a row without reattach):
// Modal's cut transport ends the run and says to resume natively.
func TestHostedHostNoReattachEndsHonestly(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	v.Reattach = false
	hh.run.vendor = v
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.ptys) > 0 })
	hh.mu.Lock()
	first := hh.ptys[0]
	hh.mu.Unlock()
	first.mu.Lock()
	first.failWait = errors.New("stream cut")
	first.mu.Unlock()
	_ = first.c.Close()
	first.done <- -1
	select {
	case <-code:
	case <-time.After(20 * time.Second):
		t.Fatal("the run did not end")
	}
	if !hh.client.boxes["box1"].deleted {
		t.Error("the box outlived its run")
	}
}

// TestHostedHostLostCreate: a lost create answer is resolved by the label
// and nothing is left (and the launch refuses).
func TestHostedHostLostCreate(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	hh.client.loseCreate = true
	if code := hh.run.drive(context.Background()); code == 0 {
		t.Fatal("a lost create ran")
	}
	for _, b := range hh.client.boxes {
		if !b.deleted {
			t.Errorf("box %s left running", b.id)
		}
	}
	if recs := hostedLoadRecords(hh.run.plan.ObserverDir); len(recs) != 0 {
		t.Errorf("records %+v", recs)
	}
	// A lost create may have made a box that ran: it keeps its charge
	// (finding F13's other half).
	if used := hostedLedgerUsed(hh.run.plan.ObserverDir, sandboxremote.VendorE2B, time.Now(), 240); used == 0 {
		t.Error("a lost create was charged nothing")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestHostedHostGuestPTY drives a Modal- and a Vercel-shaped run: no vendor
// PTY is asked for (neither documents a resize), the guest helper's PTY
// carries the terminal over the relay exec stream, a resize reaches the
// guest end (the S11b resize decision for the guest-helper rows), and the
// run ends with the agent's own exit code and a confirmed delete.
func TestHostedHostGuestPTY(t *testing.T) {
	for _, vendor := range []string{sandboxremote.VendorModal, sandboxremote.VendorVercel} {
		t.Run(vendor, func(t *testing.T) { testHostedHostGuestPTY(t, vendor) })
	}
}

func testHostedHostGuestPTY(t *testing.T, vendor string) {
	hh := newHostedHarness(t, vendor)
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return hh.guests > 0 && len(hh.ptys) > 0 })
	_, _ = hh.termIn.Write([]byte("hello"))
	waitFor(t, func() bool { return strings.Contains(hh.out.String(), "hello") })
	hh.resized <- struct{}{}
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.sizes) > 0 })
	_, _ = hh.termIn.Write([]byte("exit"))
	select {
	case c := <-code:
		if c != 5 {
			t.Errorf("exit %d, output %s", c, hh.out.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the run did not end")
	}
	hh.mu.Lock()
	if sz := hh.sizes[len(hh.sizes)-1]; sz.Rows != 30 || sz.Cols != 100 {
		t.Errorf("resize %+v", sz)
	}
	hh.mu.Unlock()
	if !hh.client.boxes["box1"].deleted {
		t.Error("the box was not deleted")
	}
	for _, c := range hh.client.calls {
		if c == "reattach" {
			t.Error("a reattach was tried on a row without one")
		}
	}
}

// hostedEndRun ends a harness run by typing exit and returns its code.
func hostedEndRun(t *testing.T, hh *hostedHarness, code <-chan int) int {
	t.Helper()
	_, _ = hh.termIn.Write([]byte("exit"))
	select {
	case c := <-code:
		return c
	case <-time.After(20 * time.Second):
		t.Fatal("the run did not end")
	}
	return -1
}

// TestHostedBoxProbeArgvRunsOnTheRealTree (live run 2026-10-23, finding F1:
// the probe was `observer version`, a command that does not exist, so every
// hosted launch was refused): the in-box observer's self-check runs against
// the real command tree, reaches it (no pre-cobra helper takes it) and
// prints this version.
func TestHostedBoxProbeArgvRunsOnTheRealTree(t *testing.T) {
	if _, ok := sandboxHelperDispatch(append([]string{"/box/observer"}, hostedBoxProbeArgs...)); ok {
		t.Fatal("a pre-cobra helper took the probe")
	}
	out := hostedProbeOnTree(hostedBoxProbeArgs)
	if !strings.Contains(out, version) {
		t.Fatalf("the probe %v printed %q, not the version %s", hostedBoxProbeArgs, out, version)
	}
	if strings.Contains(strings.ToLower(out), "unknown") {
		t.Errorf("the tree refused the probe: %q", out)
	}
}

// TestHostedHostAgentWaitsForTheRelayRecord (finding F2: the agent started
// before the relay wrote its box record, so the in-box gate refused): the
// agent starts only after the relay's ready, however late it comes.
func TestHostedHostAgentWaitsForTheRelayRecord(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	hh.readyDelay = 700 * time.Millisecond
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.ptys) > 0 })
	hh.mu.Lock()
	readyAt, agentAt := hh.readyAt, hh.agentAt
	hh.mu.Unlock()
	if readyAt.IsZero() || !agentAt.After(readyAt) {
		t.Errorf("the agent started at %v, the relay was ready at %v", agentAt, readyAt)
	}
	if c := hostedEndRun(t, hh, code); c != 5 {
		t.Errorf("exit %d", c)
	}
}

// TestHostedHostRelayNeverReadyRefuses: a relay that never says ready ends
// the run, bounded, with the agent never started and the box deleted.
func TestHostedHostRelayNeverReadyRefuses(t *testing.T) {
	oldWait, oldRetry := hostedRelayReadyWait, hostedRelayRetryWait
	hostedRelayReadyWait = 400 * time.Millisecond
	hostedRelayRetryWait = func(int) time.Duration { return 50 * time.Millisecond }
	t.Cleanup(func() { hostedRelayReadyWait, hostedRelayRetryWait = oldWait, oldRetry })
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	hh.noReady = true
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	select {
	case c := <-code:
		if c == 0 {
			t.Error("a run with no ready relay exited 0")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the run did not end")
	}
	hh.mu.Lock()
	started := len(hh.ptys)
	hh.mu.Unlock()
	if started != 0 {
		t.Error("the agent was started with no ready relay")
	}
	if !hh.client.boxes["box1"].deleted {
		t.Error("the box outlived the refused run")
	}
}

// TestHostedHostKeepsHelperPID (finding F3: the create answer replaced the
// record's map, so a live run was listed as a leftover): the record keeps
// the helper's pid beside the vendor's keys while the run lives.
func TestHostedHostKeepsHelperPID(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	self := strconv.Itoa(os.Getpid())
	old := hostedHelperAlive
	hostedHelperAlive = func(pid string) bool { return pid == self }
	t.Cleanup(func() { hostedHelperAlive = old })
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	var rec sandboxremote.Record
	waitFor(t, func() bool {
		recs := hostedLoadRecords(hh.run.plan.ObserverDir)
		if len(recs) != 1 || recs[0].Extra["pty_pid"] == "" {
			return false
		}
		rec = recs[0]
		return true
	})
	if rec.Extra[hostedHelperPIDKey] != self || rec.Extra["vendor_key"] != "v1" {
		t.Errorf("record extra %v", rec.Extra)
	}
	recs := hostedLoadRecords(hh.run.plan.ObserverDir)
	if list := sandboxremote.Leftovers(recs, hostedLiveRuns(recs), time.Now()); len(list) != 0 {
		t.Errorf("a live run is listed as a leftover: %+v", list)
	}
	if c := hostedEndRun(t, hh, code); c != 5 {
		t.Errorf("exit %d", c)
	}
}

// TestHostedHostSavesStagedDiffFromWorkspace (finding F4: the staged diff
// ran with no working directory and was never saved): the diff is taken in
// the run's workspace and lands home, owner-only.
func TestHostedHostSavesStagedDiffFromWorkspace(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	hh.diff = "diff --git a/main.go b/main.go\n+// changed in the box\n"
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.ptys) > 0 })
	if c := hostedEndRun(t, hh, code); c != 5 {
		t.Errorf("exit %d", c)
	}
	hh.mu.Lock()
	cwd := hh.diffCwd
	hh.mu.Unlock()
	if cwd != hh.run.plan.Root {
		t.Errorf("the staged diff ran in %q, not the workspace %q", cwd, hh.run.plan.Root)
	}
	p := filepath.Join(hostedStateDir(hh.run.plan.ObserverDir), "returns", "run-h1.diff")
	b, err := os.ReadFile(p)
	if err != nil || string(b) != hh.diff {
		t.Fatalf("saved diff %q %v", b, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("diff mode %v", fi.Mode().Perm())
	}
}

// TestHostedInnerArgvCarriesProxyPort (finding F5: with a non-default proxy
// port the in-box launcher looked at 8820): the inner launcher is told the
// port the guest forwarder serves; none carries no proxy; a launch that
// names its own proxy keeps it.
func TestHostedInnerArgvCarriesProxyPort(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	hh.run.layout = v.Layout(hh.run.plan.Root)
	hh.run.h.ProxyAddr = "127.0.0.1:18920"
	hh.run.h.Command = []string{"/usr/local/bin/observer", "claude", "-p", "hi"}
	argv, err := hh.run.innerArgv()
	if err != nil {
		t.Fatal(err)
	}
	i := slices.Index(argv, "claude")
	if i < 1 || i+2 >= len(argv) || argv[i+1] != "--proxy" || argv[i+2] != "http://127.0.0.1:18920" || argv[i-1] != hh.run.layout.Binary {
		t.Fatalf("inner argv %v", argv)
	}
	hh.run.h.Command = []string{"/usr/local/bin/observer", "claude", "--proxy", "http://127.0.0.1:9999"}
	if argv, _ = hh.run.innerArgv(); strings.Count(" "+strings.Join(argv, " ")+" ", " --proxy ") != 1 || !slices.Contains(argv, "http://127.0.0.1:9999") {
		t.Errorf("a named proxy was replaced: %v", argv)
	}
	hh.run.plan.Tier = "none"
	hh.run.h.Command = []string{"/usr/local/bin/observer", "claude"}
	if argv, _ = hh.run.innerArgv(); slices.Contains(argv, "--proxy") {
		t.Errorf("the none tier carried a proxy: %v", argv)
	}
}

// TestHostedHostRefusedCreateChargesNothing (finding F13: a create the
// vendor refused was charged a box-minute; finding F6: Vercel's 404 for an
// image the team does not own): a refused create is charged 0, and one
// refused for its template is a named tool refusal that says what the
// vendor needs.
func TestHostedHostRefusedCreateChargesNothing(t *testing.T) {
	for _, tc := range []struct {
		vendor string
		err    error
		want   []string
	}{
		{sandboxremote.VendorE2B, errors.New("e2b: HTTP 403 forbidden"), []string{"create the box"}},
		{sandboxremote.VendorVercel, fmt.Errorf("vercel: create: %w: %w", sandboxremote.ErrTemplateUnavailable, errors.New("vercel: HTTP 404 not_found: Image not found.")), []string{verdictHostedTool, "team owns", "node22"}},
	} {
		t.Run(tc.vendor, func(t *testing.T) {
			hh := newHostedHarness(t, tc.vendor)
			hh.client.createErr = tc.err
			hh.run.plan.Template = "node22"
			v, _ := sandboxremote.VendorFor(tc.vendor)
			hh.run.vendor, hh.run.client, hh.run.start = v, hh.client, time.Now()
			hh.run.layout = v.Layout(hh.run.plan.Root)
			err := hh.run.create(context.Background())
			if err == nil {
				t.Fatal("a refused create passed")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("refusal %q lacks %q", err, w)
				}
			}
			if used := hostedLedgerUsed(hh.run.plan.ObserverDir, tc.vendor, time.Now(), 240); used != 0 {
				t.Errorf("a create that made no box was charged %d minutes", used)
			}
			if recs := hostedLoadRecords(hh.run.plan.ObserverDir); len(recs) != 0 {
				t.Errorf("records %+v", recs)
			}
		})
	}
}

// TestHostedHostRelayDropSaysSoAndReopens (finding F7: the relay over the
// vendor stream dropped mid-run and the terminal said nothing): a dropped
// relay is said plainly, re-opened within the run's own relay keys, and
// its return is said too.
func TestHostedHostRelayDropSaysSoAndReopens(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.ptys) > 0 && len(hh.relays) == 1 })
	hh.mu.Lock()
	first := hh.relays[0]
	hh.mu.Unlock()
	first.Close()
	waitFor(t, func() bool { return strings.Contains(hh.out.String(), "capture relay is re-opened") })
	out := hh.out.String()
	if !strings.Contains(out, "capture relay to the box dropped") || !strings.Contains(out, "blocked until it is re-opened") {
		t.Errorf("the drop was not said: %s", out)
	}
	hh.mu.Lock()
	n := len(hh.relays)
	hh.mu.Unlock()
	if n != 2 {
		t.Errorf("%d relay sessions, want 2", n)
	}
	if c := hostedEndRun(t, hh, code); c != 5 {
		t.Errorf("exit %d", c)
	}
}

// TestHostedBinaryUploadCompressedPartsAndDigest (finding F8: the 113 MB
// binary went up uncompressed in one call and Modal's write failed with
// "remote box not found"): the binary goes up gzip-compressed, in parts, a
// part whose write the vendor reports as a missing box is retried once the
// vendor says the box still runs, and the box installs only what matches
// the binary's SHA-256.
func TestHostedBinaryUploadCompressedPartsAndDigest(t *testing.T) {
	oldSize, oldBack := hostedUploadPartSize, hostedUploadBackoff
	hostedUploadPartSize = 16
	hostedUploadBackoff = func(int) time.Duration { return 0 }
	t.Cleanup(func() { hostedUploadPartSize, hostedUploadBackoff = oldSize, oldBack })
	hh := newHostedHarness(t, sandboxremote.VendorModal)
	raw := bytes.Repeat([]byte("observer binary text "), 64)
	raw = append(raw, []byte(strconv.Itoa(os.Getpid()))...)
	if err := os.WriteFile(hh.run.plan.BoxBinary, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	failed := 0
	hh.client.writeFail = func(p string) error {
		mu.Lock()
		defer mu.Unlock()
		if strings.HasSuffix(p, ".part.001") && failed == 0 {
			failed++
			return fmt.Errorf("modal: write %s: %w", p, sandboxremote.ErrNotFound)
		}
		return nil
	}
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return hh.guests > 0 && len(hh.ptys) > 0 })
	if c := hostedEndRun(t, hh, code); c != 5 {
		t.Errorf("exit %d, output %s", c, hh.out.String())
	}
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorModal)
	hh.client.mu.Lock()
	installed := hh.client.boxes["box1"].files[v.Layout(hh.run.plan.Root).Binary]
	hh.client.mu.Unlock()
	if !bytes.Equal(installed, raw) {
		t.Fatalf("installed %d bytes, want the binary's %d", len(installed), len(raw))
	}
	if hh.mode != "gz" || len(hh.sent) < 2 || hh.sent[0] != 0x1f || hh.sent[1] != 0x8b || len(hh.sent) >= len(raw) {
		t.Errorf("the upload was not compressed: mode %s, %d bytes sent for %d", hh.mode, len(hh.sent), len(raw))
	}
	if failed != 1 || !strings.Contains(strings.Join(hh.client.calls, "|"), "write|get|write") {
		t.Errorf("the failed part was not retried after a box check: %v", hh.client.calls)
	}
}

// TestHostedBinaryDigestMismatchRefuses: an upload that does not match the
// binary's SHA-256 in the box is refused by name, never run, and the box is
// deleted.
func TestHostedBinaryDigestMismatchRefuses(t *testing.T) {
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	hh.corrupt = true
	if c := hh.run.drive(context.Background()); c == 0 {
		t.Fatal("a mismatched binary ran")
	}
	hh.mu.Lock()
	started := len(hh.ptys)
	hh.mu.Unlock()
	if started != 0 || !hh.client.boxes["box1"].deleted {
		t.Errorf("agent started %d, box deleted %v", started, hh.client.boxes["box1"].deleted)
	}
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	if _, ok := hh.client.boxes["box1"].files[v.Layout(hh.run.plan.Root).Binary]; ok {
		t.Error("a binary that failed its digest was installed")
	}
}
