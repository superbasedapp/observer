//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxnet"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_vm_host_linux_test.go covers milestone 4 of lane SBX-P4
// on the in-process rig (terminal_sandbox_vm_fake_linux_test.go): the host
// helper and the guest serve child talking over the fake VMM's hybrid
// vsock socket.

// vmWaitFor polls cond until it holds or the deadline passes.
func vmWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestVMHostRunsTheGuestAndCarriesItsExitStatus: the whole helper path on
// the fake VMM: create, read-back, boot, read-back, the PTY session (input
// to the guest, output home, a resize), the relay tunnel (a connection from
// the guest socket dir reaches the host relay socket), the guest helper's
// exit status home, the secret gone from the boot share once read, the
// state dir removed at the end.
func TestVMHostRunsTheGuestAndCarriesItsExitStatus(t *testing.T) {
	r := newVMRig(t)
	gotSize := make(chan relaymux.Size, 1)
	relayEcho := make(chan string, 1)
	r.run = func(g *relaymux.Guest, a relayStdioArgs) int {
		if len(a.command) < 8 || a.command[2] != "--exec-as" || a.command[3] != "1000:1000" || a.command[5] != "/home/u/proj" {
			t.Errorf("guest command %v", a.command)
		}
		pty := g.PTY()
		br := bufio.NewReader(pty)
		line, _ := br.ReadString('\n')
		_, _ = io.WriteString(pty, "pong:"+line)
		deadline := time.After(5 * time.Second)
	sizes:
		for {
			select {
			case sz := <-g.Resizes():
				if sz.Rows == 40 {
					gotSize <- sz
					break sizes
				}
			case <-deadline:
				break sizes
			}
		}
		r.mu.Lock()
		gs := r.guestSock
		r.mu.Unlock()
		s, err := net.Dial("unix", filepath.Join(gs, sandboxrelayd.RelaySocketName))
		if err == nil {
			_, _ = io.WriteString(s, "via-tunnel\n")
			b := make([]byte, len("via-tunnel\n"))
			_, _ = io.ReadFull(s, b)
			relayEcho <- string(b)
			_ = s.Close()
		}
		return 7
	}
	codeCh := make(chan int, 1)
	go func() { codeCh <- r.runHost() }()
	_, _ = io.WriteString(r.termIn, "ping\n")
	vmWaitFor(t, "the guest's answer", func() bool { return strings.Contains(r.termOut.String(), "pong:ping") })
	boot := filepath.Join(r.plan.VM.StateDir, "boot")
	if _, err := os.Stat(filepath.Join(boot, sandboxvm.GuestSecretName)); !os.IsNotExist(err) {
		t.Errorf("the relay secret is still on the boot share: %v", err)
	}
	r.setSize(40, 120)
	select {
	case sz := <-gotSize:
		if sz.Rows != 40 || sz.Cols != 120 {
			t.Fatalf("size %+v", sz)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no resize reached the guest")
	}
	select {
	case got := <-relayEcho:
		if got != "via-tunnel\n" {
			t.Fatalf("relay echo %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the relay tunnel did not carry a stream")
	}
	select {
	case code := <-codeCh:
		if code != 7 {
			t.Fatalf("exit %d; terminal %q", code, r.termOut.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the helper did not end")
	}
	calls := strings.Join(r.fakeVMNow().calls, ",")
	for _, want := range []string{"GET vmm.ping", "PUT vm.create", "GET vm.info", "PUT vm.boot", "PUT vmm.shutdown"} {
		if !strings.Contains(calls, want) {
			t.Errorf("calls %s lack %s", calls, want)
		}
	}
	if i, j := strings.Index(calls, "PUT vm.create"), strings.Index(calls, "PUT vm.boot"); i < 0 || j < i || !strings.Contains(calls[i:j], "GET vm.info") {
		t.Errorf("no read-back between create and boot: %s", calls)
	}
	if _, err := os.Stat(r.plan.VM.StateDir); !os.IsNotExist(err) {
		t.Errorf("the state dir survived the run: %v", err)
	}
	var vmm, fs int
	for _, s := range r.starts {
		switch {
		case strings.HasPrefix(s, "vmm "):
			vmm++
			if !strings.Contains(s, "--api-socket path="+r.plan.VM.APISocket()) || !strings.Contains(s, "--event-monitor fd=3") {
				t.Errorf("vmm argv %s", s)
			}
		case strings.HasPrefix(s, "virtiofsd "):
			fs++
			if !strings.Contains(s, "--sandbox=none") {
				t.Errorf("virtiofsd argv %s", s)
			}
		}
	}
	if vmm != 1 || fs != 2 {
		t.Fatalf("starts %v", r.starts)
	}
}

// TestVMHostDeadGuestHelperEndsTheRun: the guest helper dying (its session
// closed with no exit status) ends the run honestly and offers native
// resume.
func TestVMHostDeadGuestHelperEndsTheRun(t *testing.T) {
	r := newVMRig(t)
	r.run = func(g *relaymux.Guest, _ relayStdioArgs) int {
		g.Close()
		return -1
	}
	code := r.runHost()
	if code == 0 || !strings.Contains(r.termOut.String(), "Resume the agent's session") {
		t.Fatalf("exit %d, terminal %q", code, r.termOut.String())
	}
	if _, err := os.Stat(r.plan.VM.StateDir); !os.IsNotExist(err) {
		t.Errorf("the state dir survived: %v", err)
	}
}

// TestVMHostRefusesAHotPluggedNIC: a network device appearing after boot
// (vm.add-net through the API socket) ends the run with built_below_plan.
func TestVMHostRefusesAHotPluggedNIC(t *testing.T) {
	r := newVMRig(t)
	blocked := make(chan struct{})
	r.run = func(*relaymux.Guest, relayStdioArgs) int { <-blocked; return 0 }
	defer close(blocked)
	r.vmmHook = func(f *fakeVM) {
		armed := time.Now().Add(300 * time.Millisecond)
		f.tamper = func(m map[string]any) {
			if time.Now().After(armed) {
				m["config"].(map[string]any)["net"] = []any{map[string]any{"tap": "tap0", "id": "_net0"}}
			}
		}
	}
	code := r.runHost()
	if code == 0 || !strings.Contains(r.termOut.String(), "network device") {
		t.Fatalf("exit %d, terminal %q", code, r.termOut.String())
	}
}

// TestVMHostEndsOnAVMEvent: the VMM's event monitor reporting the VM shut
// down ends the run.
func TestVMHostEndsOnAVMEvent(t *testing.T) {
	r := newVMRig(t)
	blocked := make(chan struct{})
	defer close(blocked)
	r.run = func(*relaymux.Guest, relayStdioArgs) int { <-blocked; return 0 }
	done := make(chan int, 1)
	go func() { done <- r.runHost() }()
	vmWaitFor(t, "the PTY session", func() bool {
		boot := filepath.Join(r.plan.VM.StateDir, "boot")
		_, berr := os.Stat(filepath.Join(boot, sandboxvm.GuestSpecName))
		_, err := os.Stat(filepath.Join(boot, sandboxvm.GuestSecretName))
		return berr == nil && os.IsNotExist(err)
	})
	r.sendEvent(`{"source":"vm","event":"shutdown"}`)
	select {
	case code := <-done:
		if code == 0 || !strings.Contains(r.termOut.String(), "vm shutdown") {
			t.Fatalf("exit %d, terminal %q", code, r.termOut.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run did not end on the event")
	}
}

// TestVMHostGuestThatNeverAnswers: a guest that never listens is refused
// with zero bytes by the VMM; the helper gives up after its window.
func TestVMHostGuestThatNeverAnswers(t *testing.T) {
	r := newVMRig(t)
	r.guestOff = true
	env := r.env()
	env.bootWindow = 700 * time.Millisecond
	r.vmmHook = func(f *fakeVM) { f.refusePort = vmPTYPort }
	code := vmHostRun(r.plan, r.h, []string{"/bin/true"}, env)
	if code != sandboxHelperFailCode {
		t.Fatalf("exit %d, terminal %q", code, r.termOut.String())
	}
}

// TestVMHostRefusesAForeignAPIPeer (A9): an API socket whose peer is not
// the recorded VMM pid is refused.
func TestVMHostRefusesAForeignAPIPeer(t *testing.T) {
	dir, _ := os.MkdirTemp("", "vmapi")
	defer func() { _ = os.RemoveAll(dir) }()
	sock := filepath.Join(dir, "api.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if _, err := vmDialAPI(context.Background(), sock, os.Getpid()+1); err == nil || !strings.Contains(err.Error(), "not the VMM") {
		t.Fatalf("a foreign peer: %v", err)
	}
	c, err := vmDialAPI(context.Background(), sock, os.Getpid())
	if err != nil {
		t.Fatalf("the recorded peer: %v", err)
	}
	_ = c.Close()
	link := filepath.Join(dir, "link.sock")
	_ = os.Symlink(sock, link)
	if _, err := vmDialAPI(context.Background(), link, os.Getpid()); err == nil {
		t.Fatal("a symlinked API socket was dialled")
	}
}

// TestVMGuestRefusesALinkWithoutTheSecret (A6, A5 half): a PTY session
// keyed with another secret is refused by the guest, and the right one is
// then accepted on the same listener.
func TestVMGuestRefusesALinkWithoutTheSecret(t *testing.T) {
	ln := newPipeListener()
	secret := []byte(strings.Repeat("s", 64))
	type res struct {
		g   *relaymux.Guest
		err error
	}
	got := make(chan res, 1)
	go func() {
		g, err := vmAcceptPTY(ln, func(net.Conn) bool { return true }, relaymux.Options{RunID: "r1", Secret: secret}, 5*time.Second)
		got <- res{g, err}
	}()
	hostOpts := func(sec []byte) relaymux.HostOptions {
		pr, pw := io.Pipe()
		t.Cleanup(func() { _ = pw.Close() })
		return relaymux.HostOptions{
			Options: relaymux.Options{RunID: "r1", Secret: sec}, Rand: rand.Reader, Kinds: map[string]bool{},
			PTY:  hostedTermConn{in: pr, out: io.Discard},
			Dial: func(context.Context, string) (io.ReadWriteCloser, error) { return nil, errors.New("none") },
		}
	}
	a, b := net.Pipe()
	ln.ch <- b
	if h, err := relaymux.ServeHost(context.Background(), a, hostOpts([]byte(strings.Repeat("x", 64)))); err == nil {
		select {
		case <-h.Ready():
			t.Fatal("a session keyed with another secret became ready")
		case <-time.After(500 * time.Millisecond):
		}
		h.Close()
	}
	a2, b2 := net.Pipe()
	ln.ch <- b2
	h, err := relaymux.ServeHost(context.Background(), a2, hostOpts(secret))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	select {
	case r := <-got:
		if r.err != nil || r.g == nil {
			t.Fatalf("%v", r.err)
		}
		r.g.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the right secret was not accepted")
	}
}

// TestVMGuestRealPTYResizeAndCtrlC: the real guestRunPTY over the relay
// mux's stream 2: a resize reaches the PTY (stty size) and Ctrl-C ends a
// foreground job with 130, no zombie left (cmd.Wait returned).
func TestVMGuestRealPTYResizeAndCtrlC(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	run := func(t *testing.T, script string, drive func(h *relaymux.Host, in io.Writer, out *lockedBuf)) int {
		a, b := net.Pipe()
		secret := []byte(strings.Repeat("k", 64))
		pr, pw := io.Pipe()
		out := &lockedBuf{}
		hostDone := make(chan *relaymux.Host, 1)
		go func() {
			h, err := relaymux.ServeHost(context.Background(), a, relaymux.HostOptions{
				Options: relaymux.Options{RunID: "r2", Secret: secret}, Rand: rand.Reader, Kinds: map[string]bool{},
				PTY:  hostedTermConn{in: pr, out: out},
				Dial: func(context.Context, string) (io.ReadWriteCloser, error) { return nil, errors.New("none") },
			})
			if err != nil {
				t.Error(err)
			}
			hostDone <- h
		}()
		g, err := relaymux.DialGuest(context.Background(), b, relaymux.Options{RunID: "r2", Secret: secret})
		if err != nil {
			t.Fatal(err)
		}
		_ = g.Ready()
		h := <-hostDone
		defer h.Close()
		codeCh := make(chan int, 1)
		go func() {
			codeCh <- guestRunPTY(g, relayStdioArgs{command: []string{"/bin/sh", "-c", script}, rows: 24, cols: 80})
		}()
		drive(h, pw, out)
		select {
		case c := <-codeCh:
			return c
		case <-time.After(15 * time.Second):
			t.Fatalf("the guest PTY did not end; output %q", out.String())
		}
		return -1
	}
	t.Run("resize", func(t *testing.T) {
		code := run(t, "read x; stty size; read y; exit 3", func(h *relaymux.Host, in io.Writer, out *lockedBuf) {
			time.Sleep(200 * time.Millisecond)
			_ = h.Resize(40, 100)
			time.Sleep(200 * time.Millisecond)
			_, _ = io.WriteString(in, "a\n")
			vmWaitFor(t, "stty size", func() bool { return strings.Contains(out.String(), "40 100") })
			_, _ = io.WriteString(in, "b\n")
		})
		if code != 3 {
			t.Fatalf("exit %d", code)
		}
	})
	t.Run("ctrl-c", func(t *testing.T) {
		code := run(t, "echo ready; exec sleep 30", func(h *relaymux.Host, in io.Writer, out *lockedBuf) {
			vmWaitFor(t, "ready", func() bool { return strings.Contains(out.String(), "ready") })
			time.Sleep(200 * time.Millisecond)
			_, _ = io.WriteString(in, "\x03")
		})
		if code != 130 {
			t.Fatalf("exit %d", code)
		}
	})
}

// TestVMProviderBlockA1Unit (A1, the unit half): a proxy-routed tool on the
// internet tier computes full capture only through the gateway's provider
// block on this row; the host services' argv carries the block, and the
// gateway the tunnel offers refuses the provider host and a literal IP.
func TestVMProviderBlockA1Unit(t *testing.T) {
	capture := sandboxRunCaptureFor(vmRow(), true, vocab.TierInternet, "")
	if !capture.ProviderBlock {
		t.Fatalf("capture %+v", capture)
	}
	dir, _ := os.MkdirTemp("", "vma1")
	defer func() { _ = os.RemoveAll(dir) }()
	argv, err := sandbox.RelayHostArgv("/usr/bin/observer", sandbox.NetRequest{Egress: "internet", ProxyPort: 8820, HostSocketDir: filepath.Join(dir, "r1"), ProviderBlock: true}, nil, sandbox.RelayRequest{RunID: "r1", HostObserverDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	h, err := sandbox.ParseHostArgs(append(argv[2:], vmInnerMarker, "x"))
	if err != nil {
		t.Fatal(err)
	}
	if !h.ProviderBlock || !h.Gateway {
		t.Fatalf("host args %+v", h)
	}
	if k := relayTunnelKinds(h.SockDir, h.Gateway); !k[relaymux.KindGateway] || !k[relaymux.KindRelay] {
		t.Fatalf("tunnel kinds %v", k)
	}
	gw := httptest.NewServer(&sandboxnet.Gateway{Providers: providerBlockFor(h)})
	defer gw.Close()
	for _, target := range []string{"api.anthropic.com:443", "1.1.1.1:443"} {
		c, err := net.Dial("tcp", strings.TrimPrefix(gw.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil || resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %v %v", target, resp, err)
		}
		_ = c.Close()
	}
}

// TestVMHostEndsWhenAConfinedPinIsLostAfterBoot (audit finding 1): the
// confined virtiofsd's mount table is read back before boot and again from
// the read-back timer while the VM runs; a read-only pin that turns
// writable after boot ends the run with built_below_plan.
func TestVMHostEndsWhenAConfinedPinIsLostAfterBoot(t *testing.T) {
	r := newVMRig(t)
	ws := r.plan.Shares[0].Dir
	r.plan.Shares[0].Confined = true
	r.plan.Shares[0].Pins = []string{ws + "/.git"}
	r.plan.Shares[0].ReadOnlyPaths = []string{ws + "/.git/config"}
	r.plan.Bwrap = vmConfinedBwrap
	blocked := make(chan struct{})
	defer close(blocked)
	r.run = func(*relaymux.Guest, relayStdioArgs) int { <-blocked; return 0 }
	line := func(n int, p, opts string) string {
		return strconv.Itoa(n) + " 1 0:1 / " + p + " " + opts + " - virtiofs src rw\n"
	}
	good := line(1, "/", "ro") + line(2, ws, "rw") + line(3, ws+"/.git", "rw") + line(4, ws+"/.git/config", "ro")
	lost := line(1, "/", "ro") + line(2, ws, "rw") + line(3, ws+"/.git", "rw") + line(4, ws+"/.git/config", "rw")
	var reads atomic.Int64
	var bootReads atomic.Int64
	env := r.env()
	env.mountInfo = func(int) ([]byte, error) {
		if reads.Add(1) == 1 {
			return []byte(good), nil
		}
		bootReads.Add(1)
		return []byte(lost), nil
	}
	code := vmHostRun(r.plan, r.h, []string{"/home/u/.local/bin/observer", "claude"}, env)
	out := r.termOut.String()
	if code == 0 || !strings.Contains(out, sandboxvm.VerdictBuiltBelowPlan) || !strings.Contains(out, "after boot") || !strings.Contains(out, ".git/config is writable") {
		t.Fatalf("exit %d, terminal %q", code, out)
	}
	if bootReads.Load() == 0 {
		t.Fatal("the mount table was never read again after boot")
	}
	calls := strings.Join(r.fakeVMNow().calls, ",")
	if !strings.Contains(calls, "PUT vm.boot") {
		t.Fatalf("the VM never booted, so the shortfall was not an after-boot one: %s", calls)
	}
	if _, err := os.Stat(r.plan.VM.StateDir); !os.IsNotExist(err) {
		t.Errorf("the state dir survived: %v", err)
	}
}

// TestVMHostObserverOutsideTheGuestRoots (audit finding 3): a host observer
// at /usr/local/bin/observer, outside every writable guest root, still
// launches: the guest spec names the fixed read-only guest path for the
// hooks and the launch, and the launch's first word is that path.
func TestVMHostObserverOutsideTheGuestRoots(t *testing.T) {
	r := newVMRig(t)
	r.plan.Guest.HostBin = "/usr/local/bin/observer"
	r.plan.Guest.HookBin = sandboxvm.GuestHookBinFor(r.plan.Guest.HostBin)
	if r.plan.Guest.HookBin != sandboxvm.GuestHookBin {
		t.Fatalf("hook bin %s", r.plan.Guest.HookBin)
	}
	var cmd []string
	var spec sandboxvm.GuestSpec
	r.run = func(_ *relaymux.Guest, a relayStdioArgs) int {
		cmd = a.command
		b, err := os.ReadFile(filepath.Join(r.plan.VM.StateDir, "boot", sandboxvm.GuestSpecName))
		if err == nil {
			spec, err = sandboxvm.ParseGuestSpec(b)
		}
		if err != nil {
			t.Errorf("the guest spec: %v", err)
		}
		return 0
	}
	if code := vmHostRun(r.plan, r.h, []string{"/usr/local/bin/observer", "claude"}, r.env()); code != 0 {
		t.Fatalf("exit %d, terminal %q", code, r.termOut.String())
	}
	j := strings.Join(cmd, " ")
	if !strings.Contains(j, " -- "+vmGuestBin+" sandbox-guest -- "+sandboxvm.GuestHookBin+" claude") || strings.Contains(j, "/usr/local/bin/observer") {
		t.Fatalf("guest command %s", j)
	}
	if spec.HostBin != "/usr/local/bin/observer" || spec.HookPath() != sandboxvm.GuestHookBin || spec.HookLink() != "" {
		t.Fatalf("spec %+v", spec)
	}
}

// TestVMHostUsesTheShortSocketDir (audit finding 8): a plan whose sockets
// live in a short socket dir runs there (the VMM's API and vsock sockets,
// each virtiofsd's) and the dir goes with the run.
func TestVMHostUsesTheShortSocketDir(t *testing.T) {
	r := newVMRig(t)
	sd := filepath.Join(r.root, "s", r.plan.VM.RunID)
	r.plan.VM.SocketDir = sd
	for i := range r.plan.VM.Shares {
		r.plan.VM.Shares[i].Socket = r.plan.VM.ShareSocket(r.plan.VM.Shares[i].Tag)
	}
	var sawAPI bool
	r.run = func(*relaymux.Guest, relayStdioArgs) int {
		_, err := os.Lstat(filepath.Join(sd, "api.sock"))
		sawAPI = err == nil
		return 0
	}
	if code := r.runHost(); code != 0 {
		t.Fatalf("exit %d: %s", code, r.termOut.String())
	}
	if !sawAPI {
		t.Fatal("the API socket was not in the short socket dir")
	}
	for _, s := range r.starts {
		if strings.HasPrefix(s, "virtiofsd ") && !strings.Contains(s, "--socket-path="+sd+"/fs-") {
			t.Fatalf("a virtiofsd outside the socket dir: %s", s)
		}
	}
	if _, err := os.Stat(sd); !os.IsNotExist(err) {
		t.Fatalf("the socket dir survived the run: %v", err)
	}
}
