//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboximage"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_vm_fake_linux_test.go is the in-process rig of the
// microVM driver's helper and guest (lane SBX-P4 milestone 4): a fake Cloud
// Hypervisor (its REST API on the run's unix API socket, answering from the
// plan it was given, and its hybrid vsock socket implementing CONNECT and
// bridging each accepted port to the real guest serve code over in-memory
// listeners), fake virtiofsds (each just opens its socket) and fake host
// services (a box record and an echo relay socket). Nothing opens /dev/kvm.

// pipeListener is a net.Listener fed by the fake vsock.
type pipeListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	dl     time.Time
}

func newPipeListener() *pipeListener {
	return &pipeListener{ch: make(chan net.Conn, 4), closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	dl := l.dl
	l.mu.Unlock()
	var timeout <-chan time.Time
	if !dl.IsZero() {
		timer := time.NewTimer(time.Until(dl))
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-timeout:
		return nil, os.ErrDeadlineExceeded
	}
}
func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *pipeListener) Addr() net.Addr { return vsockAddr{} }
func (l *pipeListener) SetDeadline(t time.Time) error {
	l.mu.Lock()
	l.dl = t
	l.mu.Unlock()
	return nil
}

// fakeVM is one fake Cloud Hypervisor.
type fakeVM struct {
	t     *testing.T
	plan  sandboxvm.Plan
	ports map[uint32]*pipeListener

	mu      sync.Mutex
	calls   []string
	state   string
	created *sandboxvm.VMConfig
	// tamper changes the vm.info answer after boot (a hot-plugged NIC).
	tamper func(m map[string]any)
	// refusePort makes CONNECT to that port close with zero bytes.
	refusePort uint32
	conns      []net.Conn
	srv        *http.Server
	vsockLn    net.Listener
	done       chan struct{}
	doneOnce   sync.Once
}

func newFakeVM(t *testing.T, plan sandboxvm.Plan) *fakeVM {
	return &fakeVM{
		t: t, plan: plan, state: "Created", done: make(chan struct{}),
		ports: map[uint32]*pipeListener{vmPTYPort: newPipeListener(), vmRelayPort: newPipeListener()},
	}
}

func (f *fakeVM) record(c string) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
}

// start opens the API and vsock sockets.
func (f *fakeVM) start() error {
	api, err := net.Listen("unix", f.plan.APISocket())
	if err != nil {
		return err
	}
	f.srv = &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(f.serveAPI)}
	go func() { _ = f.srv.Serve(api) }()
	vs, err := net.Listen("unix", f.plan.VsockSocket())
	if err != nil {
		return err
	}
	f.vsockLn = vs
	go f.serveVsock(vs)
	return nil
}

func (f *fakeVM) stop() {
	f.doneOnce.Do(func() {
		if f.srv != nil {
			_ = f.srv.Close()
		}
		if f.vsockLn != nil {
			_ = f.vsockLn.Close()
		}
		f.mu.Lock()
		for _, c := range f.conns {
			_ = c.Close()
		}
		f.mu.Unlock()
		close(f.done)
	})
}

func (f *fakeVM) serveAPI(w http.ResponseWriter, r *http.Request) {
	op := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	body, _ := io.ReadAll(r.Body)
	f.record(r.Method + " " + op)
	switch op {
	case "vmm.ping":
		_, _ = w.Write([]byte(`{"build_version":"v54.0","version":"54.0.0","pid":` + strconv.Itoa(os.Getpid()) + `,"features":[]}`))
	case "vm.create":
		var c sandboxvm.VMConfig
		if err := json.Unmarshal(body, &c); err != nil {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		f.created = &c
		f.mu.Unlock()
		w.WriteHeader(204)
	case "vm.boot":
		f.mu.Lock()
		f.state = "Running"
		f.mu.Unlock()
		w.WriteHeader(204)
	case "vm.info":
		f.mu.Lock()
		c, st, tamper := f.created, f.state, f.tamper
		f.mu.Unlock()
		raw, _ := json.Marshal(map[string]any{"config": c, "state": st, "device_tree": map[string]any{}})
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if tamper != nil && st == "Running" {
			tamper(m)
		}
		b, _ := json.Marshal(m)
		_, _ = w.Write(b)
	case "vm.shutdown", "vm.delete":
		w.WriteHeader(204)
	case "vmm.shutdown":
		w.WriteHeader(204)
		go f.stop()
	default:
		w.WriteHeader(404)
	}
}

// serveVsock implements the hybrid vsock CONNECT protocol: OK <hostport>
// once the guest listener exists, zero bytes otherwise.
func (f *fakeVM) serveVsock(ln net.Listener) {
	next := uint32(1 << 30)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		fields := strings.Fields(line)
		if err != nil || len(fields) != 2 || !strings.EqualFold(fields[0], "CONNECT") {
			_ = c.Close()
			continue
		}
		p, _ := strconv.ParseUint(fields[1], 10, 32)
		l, ok := f.ports[uint32(p)]
		f.mu.Lock()
		refused := f.refusePort == uint32(p)
		f.mu.Unlock()
		if !ok || refused {
			_ = c.Close()
			continue
		}
		hostEnd, guestEnd := net.Pipe()
		f.mu.Lock()
		f.conns = append(f.conns, c, hostEnd, guestEnd)
		f.mu.Unlock()
		next++
		if _, err := c.Write([]byte("OK " + strconv.FormatUint(uint64(next), 10) + "\n")); err != nil {
			_ = c.Close()
			continue
		}
		select {
		case l.ch <- guestEnd:
		case <-l.closed:
			_ = c.Close()
			continue
		}
		go func() { _, _ = io.Copy(hostEnd, br); _ = hostEnd.Close() }()
		go func() { _, _ = io.Copy(c, hostEnd); _ = c.Close() }()
	}
}

// fakeProc is a fake process.
type fakeProc struct {
	pid  int
	done chan struct{}
	once sync.Once
	kill func()
}

func (p *fakeProc) PID() int              { return p.pid }
func (p *fakeProc) Done() <-chan struct{} { return p.done }
func (p *fakeProc) Kill() {
	p.once.Do(func() {
		if p.kill != nil {
			p.kill()
		}
		close(p.done)
	})
}

// vmRig is one run's rig.
type vmRig struct {
	t          *testing.T
	root       string
	plan       vmPlanFile
	h          sandbox.HostArgs
	termReader io.Reader
	termIn     *io.PipeWriter
	termOut    *lockedBuf
	resized    chan struct{}
	stopped    chan string
	sizeMu     sync.Mutex
	rows, cols uint16
	// guest receives the guest serve child's exit code.
	guest chan int
	// run is the guest's agent stand-in (the guest PTY's owner).
	run func(g *relaymux.Guest, a relayStdioArgs) int

	mu     sync.Mutex
	vm     *fakeVM
	starts []string
	events *os.File
	// vmmHook adjusts the fake VM before it starts.
	vmmHook func(f *fakeVM)
	// guestDelay holds the guest's listeners back (a slow boot).
	guestDelay time.Duration
	// guestOff never starts the guest (a guest that never answers).
	guestOff  bool
	returnGit func(context.Context, workspace.Step) ([]byte, error)
	// guestSock is the guest socket dir the tunnel serves (set when the
	// guest starts).
	guestSock string
}

// lockedBuf is a goroutine-safe buffer.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// newVMRig builds a plan whose files exist (stand-in image entries, a
// guest observer) under a short private temp root.
func newVMRig(t *testing.T) *vmRig {
	t.Helper()
	root, err := os.MkdirTemp("", "vmrig")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	obs := filepath.Join(root, "obs")
	store := filepath.Join(root, "store")
	_ = os.MkdirAll(store, 0o700)
	img := map[string]string{}
	for _, n := range sandboximage.BulkEntries() {
		p := filepath.Join(store, n)
		if err := os.WriteFile(p, []byte("stand-in "+n), 0o600); err != nil {
			t.Fatal(err)
		}
		img[n] = p
	}
	gb := []byte("#!/bin/false guest observer stand-in\n")
	gp := filepath.Join(store, "observer-guest")
	_ = os.WriteFile(gp, gb, 0o600)
	sum := sha256.Sum256(gb)
	runID := "run-vm-1"
	stateDir := vmRunStateDir(obs, runID)
	ws := filepath.Join(root, "home", "u", "proj")
	_ = os.MkdirAll(ws, 0o700)
	sockDir := filepath.Join(root, "sock", runID)
	vm := sandboxvm.Plan{
		RunID: runID, StateDir: stateDir,
		Kernel: filepath.Join(stateDir, "img", "vmlinuz"), Initramfs: filepath.Join(stateDir, "img", "initrd.img"),
		Rootfs: filepath.Join(stateDir, "img", "rootfs.img"), Verity: filepath.Join(stateDir, "img", "rootfs.verity"),
		VerityRootHash: strings.Repeat("9", 64), CID: 3, GuestPort: vmPTYPort, VCPUs: 2, MemoryMiB: 1024,
		Shares: []sandboxvm.Share{
			{Tag: sandboxvm.BootTag, Socket: filepath.Join(stateDir, "fs-obsboot.sock")},
			{Tag: sandboxvm.WorkspaceTag, Socket: filepath.Join(stateDir, "fs-ws.sock")},
		},
	}
	plan := vmPlanFile{
		Version: vmPlanVersion, VM: vm, VMM: "/usr/local/bin/cloud-hypervisor", Virtiofsd: "/usr/libexec/virtiofsd",
		Image: img, GuestBinary: gp, GuestSHA256: hex.EncodeToString(sum[:]), GuestSize: int64(len(gb)),
		Shares: []vmShare{{Tag: sandboxvm.WorkspaceTag, Dir: ws}},
		Guest: sandboxvm.GuestSpec{
			Schema: sandboxvm.GuestSpecSchema, RunID: runID, UID: 1000, GID: 1000,
			HostBin: "/home/u/.local/bin/observer", Workdir: "/home/u/proj",
			Mounts:  []sandboxvm.GuestMount{{Tag: sandboxvm.WorkspaceTag, Target: "/home/u/proj"}},
			PTYPort: vmPTYPort, RelayPort: vmRelayPort, Rows: 24, Cols: 80, Command: []string{vmGuestBin},
		},
		GuestPrefix: []string{vmGuestBin, "sandbox-guest", "--"},
		Dirs:        macRunDirs{SocketDir: sockDir},
	}
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	return &vmRig{
		t: t, root: root, plan: plan, termReader: pr, termIn: pw, termOut: &lockedBuf{},
		h:       sandbox.HostArgs{SockDir: sockDir, RelayRun: runID, ObserverDir: obs},
		resized: make(chan struct{}, 1), stopped: make(chan string, 1), rows: 24, cols: 80,
		guest: make(chan int, 1),
	}
}

// setSize changes the terminal's size and signals a resize.
func (r *vmRig) setSize(rows, cols uint16) {
	r.sizeMu.Lock()
	r.rows, r.cols = rows, cols
	r.sizeMu.Unlock()
	select {
	case r.resized <- struct{}{}:
	default:
	}
}

// fakeServices are the host services: the socket dir, the box record and
// an echo relay socket.
func (r *vmRig) fakeServices(h sandbox.HostArgs) (func(), error) {
	if err := os.MkdirAll(h.SockDir, 0o700); err != nil {
		return func() {}, err
	}
	if err := os.WriteFile(filepath.Join(h.SockDir, sandboxrelayd.BoxRecordName), []byte(`{"box":"record"}`), 0o600); err != nil {
		return func() {}, err
	}
	ln, err := net.Listen("unix", filepath.Join(h.SockDir, sandboxrelayd.RelaySocketName))
	if err != nil {
		return func() {}, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); _ = c.Close() }()
		}
	}()
	return func() { _ = ln.Close(); _ = os.RemoveAll(h.SockDir) }, nil
}

// fakeStart starts a fake virtiofsd (its socket) or the fake VMM (its
// sockets, then the real guest serve code on the boot share).
func (r *vmRig) fakeStart(role sandboxvm.ProcRole, argv []string, extra []*os.File) (vmProc, error) {
	r.mu.Lock()
	r.starts = append(r.starts, string(role)+" "+strings.Join(argv, " "))
	r.mu.Unlock()
	switch role {
	case sandboxvm.RoleVirtiofsd:
		var sock string
		for _, a := range argv {
			if v, ok := strings.CutPrefix(a, "--socket-path="); ok {
				sock = v
			}
		}
		ln, err := net.Listen("unix", sock)
		if err != nil {
			return nil, err
		}
		return &fakeProc{pid: os.Getpid(), done: make(chan struct{}), kill: func() { _ = ln.Close() }}, nil
	case sandboxvm.RoleVMM:
		vm := newFakeVM(r.t, r.plan.VM)
		if r.vmmHook != nil {
			r.vmmHook(vm)
		}
		if len(extra) > 0 {
			fd, err := syscallDup(extra[0])
			if err == nil {
				r.mu.Lock()
				r.events = fd
				r.mu.Unlock()
			}
		}
		if err := vm.start(); err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.vm = vm
		r.mu.Unlock()
		if !r.guestOff {
			go r.runGuest(vm)
		}
		p := &fakeProc{pid: os.Getpid(), done: make(chan struct{})}
		p.kill = vm.stop
		go func() {
			<-vm.done
			p.Kill()
		}()
		return p, nil
	}
	return nil, errors.New("unknown role")
}

// runGuest runs the real serve child against the fake VM's listeners.
func (r *vmRig) runGuest(vm *fakeVM) {
	time.Sleep(r.guestDelay)
	sock, err := os.MkdirTemp("", "vmg")
	if err != nil {
		r.guest <- -1
		return
	}
	defer func() { _ = os.RemoveAll(sock) }()
	r.mu.Lock()
	r.guestSock = filepath.Join(sock, "net")
	r.mu.Unlock()
	run := r.run
	if run == nil {
		run = func(*relaymux.Guest, relayStdioArgs) int { return 0 }
	}
	code := vmInitServe(filepath.Join(r.plan.VM.StateDir, "boot"), vmGuestEnv{
		listen: func(port uint32) (net.Listener, error) {
			if l, ok := vm.ports[port]; ok {
				return l, nil
			}
			return nil, errors.New("no such port")
		},
		peerOK: func(net.Conn) bool { return true }, window: 5 * time.Second, run: run,
		noChown: true, sockDir: filepath.Join(sock, "net"), setEnv: func([]string) {}, self: "/run/observer-boot/observer-guest",
	})
	r.guest <- code
}

// sendEvent writes one event monitor line from the fake VMM.
func (r *vmRig) sendEvent(line string) {
	r.mu.Lock()
	f := r.events
	r.mu.Unlock()
	if f != nil {
		_, _ = f.Write([]byte(line + "\n"))
	}
}

// fakeVM returns the started fake VM.
func (r *vmRig) fakeVMNow() *fakeVM {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.vm
}

// env is the helper's environment over the rig.
func (r *vmRig) env() vmHostEnv {
	return vmHostEnv{
		term: hostedTerm{
			in: r.termReader, out: r.termOut, resized: r.resized, stopped: r.stopped,
			size: func() (uint16, uint16) { r.sizeMu.Lock(); defer r.sizeMu.Unlock(); return r.rows, r.cols },
			raw:  func() func() { return func() {} },
		},
		services: r.fakeServices, start: r.fakeStart, apiDial: vmDialAPI,
		vsockDial: func(ctx context.Context, sock string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		waitSocket: vmWaitSocket, readBackEvery: 100 * time.Millisecond, bootWindow: 5 * time.Second,
		returnGit: r.returnGit, tool: vmRunTool,
	}
}

// runHost runs the helper to its end and returns its exit code.
func (r *vmRig) runHost() int {
	return vmHostRun(r.plan, r.h, []string{"/home/u/.local/bin/observer", "claude"}, r.env())
}

// syscallDup duplicates f.
func syscallDup(f *os.File) (*os.File, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	var nfd int
	var derr error
	if err := rc.Control(func(fd uintptr) { nfd, derr = unixDup(int(fd)) }); err != nil { //nolint:gosec // G115: a descriptor number
		return nil, err
	}
	if derr != nil {
		return nil, derr
	}
	return os.NewFile(uintptr(nfd), "events"), nil //nolint:gosec // G115: a descriptor number
}
