//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
	"github.com/marmutapp/superbased-observer/internal/sandboxvmm"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_vm_host_linux.go is the microVM row's host helper,
// `observer sandbox-vm-host`, the PTY child of a run (lane SBX-P4):
//
//  1. it starts the host services (the relay, the proxy forward, the
//     gateway and the placeholders, startHostServices: the same owner as
//     every Linux row);
//  2. it makes the run's 0700 state dir under the observer dir: hard links
//     of the verified image entries, the boot share (a re-hashed copy of
//     the verified guest observer, the guest spec, the per-run secret);
//  3. it starts one virtiofsd per share and Cloud Hypervisor, each with
//     PR_SET_PDEATHSIG, each recorded (pid, start time, executable) in the
//     run's locked process record;
//  4. it talks to the VMM only through the API socket in the state dir,
//     refused unless it is a socket there (no symlink) whose peer is the
//     recorded VMM pid; vm.create, the strict vm.info read-back, vm.boot,
//     the read-back again, and again on every VMM event and every few
//     seconds (vm.add-fs hotplug exists);
//  5. it opens the PTY session on guest port 1024 and the capture relay's
//     tunnel on port 1025 through the hybrid vsock socket (CONNECT, then
//     the relay mux, home side first, per-run keyed frames), re-dialling
//     the tunnel after a drop;
//  6. the run ends when the guest helper ends (its exit status comes home
//     on the PTY session), when either side of the PTY session is lost,
//     when a read-back refuses, when the VM or the VMM ends, or when the
//     terminal is closed; teardown shuts the VMM down, kills what is left,
//     removes the state dir and returns a copy's commits through
//     sandboxReturn with its scan.

// vmHostEnv is the helper's injected I/O (tests drive a fake VMM over unix
// sockets with it).
type vmHostEnv struct {
	term hostedTerm
	// services starts the host services for h.
	services func(h sandbox.HostArgs) (func(), error)
	// start starts one process with PR_SET_PDEATHSIG and returns it.
	start func(role sandboxvm.ProcRole, argv []string, extra []*os.File) (vmProc, error)
	// apiDial dials the VMM's API socket (peer-checked against pid).
	apiDial func(ctx context.Context, sock string, pid int) (net.Conn, error)
	// vsockDial opens one raw connection to the VMM's vsock socket.
	vsockDial func(ctx context.Context, sock string) (net.Conn, error)
	// waitSocket waits for a socket file to appear.
	waitSocket func(ctx context.Context, p string) error
	// readBackEvery is the periodic read-back's period.
	readBackEvery time.Duration
	// bootWindow bounds the guest's first answer on the PTY port.
	bootWindow time.Duration
	// returnGit runs one return step's git (nil: no return).
	returnGit func(context.Context, workspace.Step) ([]byte, error)
	// tool runs a host tool (mkfs.ext4, debugfs) to its end.
	tool func(ctx context.Context, argv []string) error
	// mountInfo reads the mount table of a confined virtiofsd from the pid
	// of the bwrap it runs under (nil: vmConfinedMountInfo over /proc).
	mountInfo func(bwrapPID int) ([]byte, error)
}

// vmProc is one started process.
type vmProc interface {
	PID() int
	Kill()
	Done() <-chan struct{}
}

// vmExitPrefix is the guest helper's last log line on the PTY session: the
// agent's exit status (the only way it comes home, inside the
// authenticated session).
const vmExitPrefix = "observer-vm-exit:"

// vmHostTunnelWindow bounds the relay tunnel's re-dial after a drop.
const vmHostTunnelWindow = 45 * time.Second

func helperFailVM(format string, a ...any) int {
	return helperFail("observer sandbox (cloud-hypervisor): "+format, a...)
}

// runVMHost is the PTY child of a microVM run.
func runVMHost(args []string) int {
	t, done := realHostedTerm()
	defer done()
	return vmHostMain(args, vmHostEnv{
		term: t, services: startHostServices, start: vmStartProc, apiDial: vmDialAPI,
		vsockDial: func(ctx context.Context, sock string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		waitSocket: vmWaitSocket, readBackEvery: 3 * time.Second, bootWindow: 60 * time.Second,
		returnGit: runReturnGit, tool: vmRunTool,
	})
}

// vmHostMain reads the plan and runs the VM.
func vmHostMain(args []string, env vmHostEnv) int {
	planPath, h, inner, err := parseMacHostArgs(vmHostVerb, vmInnerMarker, args)
	if err != nil {
		return helperFailVM("%v", err)
	}
	var plan vmPlanFile
	if err := readMacPlan(planPath, &plan); err != nil {
		return helperFailVM("%v", err)
	}
	_ = os.Remove(planPath) //nolint:gosec // G703: the daemon's own plan path, read no-follow and owner-checked
	if plan.Version != vmPlanVersion || plan.Dirs.SocketDir != h.SockDir || plan.VM.RunID != h.RelayRun {
		return helperFailVM("the plan does not match this helper or its host services (restart the daemon after an upgrade)")
	}
	return vmHostRun(plan, h, inner, env)
}

// vmHostRun is one run, start to teardown.
func vmHostRun(plan vmPlanFile, h sandbox.HostArgs, inner []string, env vmHostEnv) int {
	t := env.term
	for _, n := range plan.Notices {
		fmt.Fprintf(t.out, "observer sandbox: %s\r\n", n)
	}
	if err := vmEnsureSocketParent(h.SockDir); err != nil {
		return helperFailVM("%v", err)
	}
	stopServices, err := env.services(h)
	defer stopServices()
	if err != nil {
		return helperFailVM("%v", err)
	}
	run, err := vmPrepareState(plan, h, inner)
	if err != nil {
		return helperFailVM("%v", err)
	}
	defer run.cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ends sync.Once
	ended := make(chan string, 1)
	end := func(why string) {
		ends.Do(func() {
			ended <- why
			cancel()
		})
	}

	if err := vmBuildDiskImages(ctx, plan, env); err != nil {
		return helperFailVM("%v", err)
	}
	client, vmm, evr, err := vmStartProcesses(ctx, plan, run, env, end)
	if err != nil {
		return helperFailVM("%v", err)
	}
	defer vmTeardownVMM(client, vmm)

	if err := vmBootAndReadBack(ctx, client, plan.VM); err != nil {
		_ = evr.Close()
		return helperFailVM("%v", err)
	}
	readBack := make(chan struct{}, 1)
	go vmWatchEvents(evr, readBack, end)
	// The confined virtiofsd's mount table is read back again with every
	// vm.info read-back, from the same timer and event loop, for the whole
	// run: a pin or read-only path lost after boot ends it (built_below_plan).
	go vmWatchReadBack(ctx, client, plan.VM, readBack, env.readBackEvery, end, func() sandboxvm.Verdict {
		return vmConfinedReadBackAll(env, run.shares)
	})

	// The PTY session (guest port 1024): accepted once by the guest
	// helper; its loss ends the run (Reattach none, native resume).
	vsock := plan.VM.VsockSocket()
	dialPort := func(port uint32) func(context.Context) (net.Conn, error) {
		return func(ctx context.Context) (net.Conn, error) {
			c, _, err := sandboxvmm.DialVsock(ctx, func(ctx context.Context) (net.Conn, error) {
				return vmDialRetrying(ctx, run.bootDeadline, func(ctx context.Context) (net.Conn, error) { return env.vsockDial(ctx, vsock) })
			}, port)
			return c, err
		}
	}
	exitCode := -1
	var exitMu sync.Mutex
	ptyHost, err := vmOpenPTYSession(ctx, dialPort(vmPTYPort), env.bootWindow, relaymux.HostOptions{
		Options: relaymux.Options{RunID: plan.VM.RunID, Secret: run.secret}, Rand: rand.Reader,
		Kinds: map[string]bool{}, PTY: hostedTermConn{in: t.in, out: t.out},
		Dial: func(context.Context, string) (io.ReadWriteCloser, error) {
			return nil, errors.New("no connections on the PTY session")
		},
		Env: vmRunEnv(withSandboxTier(os.Environ(), h)),
		Log: func(line string) {
			// The mux prefixes every guest line with "guest: ".
			if v, ok := strings.CutPrefix(line, "guest: "+vmExitPrefix); ok {
				if n, err := strconv.Atoi(v); err == nil {
					exitMu.Lock()
					exitCode = n
					exitMu.Unlock()
				}
			}
		},
	})
	if err != nil {
		return helperFailVM("the guest helper never answered on vsock (%v); the serial log of the boot is at %s until the run ends", err, plan.VM.SerialFile())
	}
	// The guest has read its secret; nothing on the boot share holds it
	// any more.
	run.removeSecret()
	restore := t.raw()
	defer restore()
	rows, cols := t.size()
	_ = ptyHost.Resize(rows, cols)
	go func() {
		for {
			select {
			case <-t.resized:
				r, c := t.size()
				_ = ptyHost.Resize(r, c)
			case <-ctx.Done():
				return
			}
		}
	}()

	// The capture relay's tunnel (guest port 1025), re-dialled after a drop
	// within the window; a lost tunnel ends the run, never left uncaptured.
	go relayTunnelHost(ctx, dialPort(vmRelayPort), relaymux.HostOptions{
		Options: relaymux.Options{RunID: plan.VM.RunID, Secret: run.secret}, Rand: rand.Reader,
		Kinds: relayTunnelKinds(h.SockDir, h.Gateway), Dial: relayTunnelDial(h.SockDir), Record: run.record,
	}, vmHostTunnelWindow, nil, func(err error) {
		end(fmt.Sprintf("the capture relay's tunnel into the VM could not be opened or re-opened (%v); the run was ended, never left uncaptured", err))
	})

	select {
	case <-ptyHost.Done():
		end("")
	case why := <-t.stopped:
		end("stopped (" + why + ")")
	case <-ctx.Done():
	}
	why := <-ended
	restore()
	exitMu.Lock()
	code := exitCode
	exitMu.Unlock()
	vmTeardownVMM(client, vmm)
	run.killAll()
	if err := vmDumpDiskImages(plan, env); err != nil {
		fmt.Fprintf(t.out, "\r\n[observer: the workspace image could not be read back (%v); the box's commits were not returned and the image was removed with the run]\r\n", err)
	} else if plan.Return != nil && env.returnGit != nil {
		vmReturn(plan, env, t)
	} else if env.returnGit != nil {
		vmPrecheckDiskImages(plan, env, t)
	}
	switch {
	case code >= 0 && why == "":
		return code
	case why == "":
		fmt.Fprintf(t.out, "\r\n[observer: the guest helper ended without an exit status; the run ended. Resume the agent's session to continue]\r\n")
		return 1
	}
	fmt.Fprintf(t.out, "\r\n[observer: the microVM run ended: %s. Resume the agent's session to continue]\r\n", why)
	return 125
}

// vmStartProcesses starts the virtiofsds (each read back when confined),
// then the VMM with its event monitor, each recorded before it is used, and
// returns the API client over the peer-checked socket.
func vmStartProcesses(ctx context.Context, plan vmPlanFile, run *vmRunState, env vmHostEnv, end func(string)) (*sandboxvmm.Client, vmProc, *os.File, error) {
	for i := range run.shares {
		sh := &run.shares[i]
		p, err := env.start(sandboxvm.RoleVirtiofsd, sh.argv, nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("start virtiofsd for %s: %w", sh.tag, err)
		}
		run.track(sandboxvm.RoleVirtiofsd, p)
		sh.pid = p.PID()
		go func(tag string) {
			select {
			case <-p.Done():
				end("the virtiofsd serving " + tag + " ended")
			case <-ctx.Done():
			}
		}(sh.tag)
		if err := env.waitSocket(ctx, sh.socket); err != nil {
			return nil, nil, nil, fmt.Errorf("the virtiofsd for %s never opened its socket: %w", sh.tag, err)
		}
		if sh.confined {
			if v := vmConfinedReadBack(env, *sh, false); !v.OK() {
				return nil, nil, nil, errors.New(v.Error())
			}
		}
	}
	evr, evw, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("event monitor: %w", err)
	}
	argv, err := sandboxvm.VMMArgv(plan.VMM, plan.VM)
	if err != nil {
		_ = evr.Close()
		_ = evw.Close()
		return nil, nil, nil, err
	}
	vmm, err := env.start(sandboxvm.RoleVMM, argv, []*os.File{evw})
	run.bootDeadline = time.Now().Add(env.bootWindow)
	_ = evw.Close()
	if err != nil {
		_ = evr.Close()
		return nil, nil, nil, fmt.Errorf("start cloud-hypervisor: %w", err)
	}
	run.track(sandboxvm.RoleVMM, vmm)
	go func() {
		select {
		case <-vmm.Done():
			end("cloud-hypervisor ended")
		case <-ctx.Done():
		}
	}()
	if err := env.waitSocket(ctx, plan.VM.APISocket()); err != nil {
		_ = evr.Close()
		return nil, nil, nil, fmt.Errorf("cloud-hypervisor never opened its API socket: %w", err)
	}
	client, err := sandboxvmm.New(func(ctx context.Context) (net.Conn, error) {
		return vmDialRetrying(ctx, run.bootDeadline, func(ctx context.Context) (net.Conn, error) {
			return env.apiDial(ctx, plan.VM.APISocket(), vmm.PID())
		})
	})
	if err != nil {
		_ = evr.Close()
		return nil, nil, nil, err
	}
	return client, vmm, evr, nil
}

// vmOpenPTYSession dials the guest's PTY port until the handshake succeeds
// or window passes (the guest boots in about a second; a guest that never
// listens is refused with zero bytes and dialled again).
func vmOpenPTYSession(ctx context.Context, dial func(context.Context) (net.Conn, error), window time.Duration, opts relaymux.HostOptions) (*relaymux.Host, error) {
	deadline := time.Now().Add(window)
	var last error = errors.New("no answer")
	for ctx.Err() == nil && time.Now().Before(deadline) {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		c, err := dial(dctx)
		cancel()
		if err == nil {
			h, herr := relaymux.ServeHost(ctx, c, opts)
			if herr == nil {
				return h, nil
			}
			_ = c.Close()
			err = herr
		}
		last = err
		select {
		case <-ctx.Done():
		case <-time.After(150 * time.Millisecond):
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return nil, last
}

// vmBootAndReadBack checks the VMM, creates the VM, reads it back, boots
// it and reads it back again.
func vmBootAndReadBack(ctx context.Context, c *sandboxvmm.Client, plan sandboxvm.Plan) error {
	ping, err := c.Ping(ctx)
	if err != nil {
		return fmt.Errorf("the VMM did not answer vmm.ping: %w", err)
	}
	if v := sandboxvm.ParseVMMVersion("v" + ping.Version); v == "" || vmMajor(v) < sandboxvm.RequiredMajor {
		return fmt.Errorf("the VMM reports version %q, below %d", ping.Version, sandboxvm.RequiredMajor)
	}
	if err := c.Create(ctx, plan); err != nil {
		return fmt.Errorf("vm.create: %w", err)
	}
	info, err := c.Info(ctx)
	if err != nil {
		return fmt.Errorf("vm.info: %w", err)
	}
	if v := sandboxvm.ReadBack(plan, info, false); !v.OK() {
		return errors.New(v.Error())
	}
	if err := c.Boot(ctx); err != nil {
		return fmt.Errorf("vm.boot: %w", err)
	}
	info, err = c.Info(ctx)
	if err != nil {
		return fmt.Errorf("vm.info: %w", err)
	}
	if v := sandboxvm.ReadBack(plan, info, true); !v.OK() {
		return errors.New(v.Error())
	}
	return nil
}

// vmWatchEvents reads the event monitor: an end event ends the run, any
// other asks for an immediate read-back.
func vmWatchEvents(r io.ReadCloser, readBack chan<- struct{}, end func(string)) {
	defer func() { _ = r.Close() }()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		e, err := sandboxvm.ParseEvent(sc.Bytes())
		if err != nil {
			continue
		}
		switch sandboxvm.ActionFor(e) {
		case sandboxvm.EventEnded:
			end("the VM reported " + e.Source + " " + e.Event)
			return
		case sandboxvm.EventReadBack:
			select {
			case readBack <- struct{}{}:
			default:
			}
		}
	}
}

// vmWatchReadBack repeats the strict read-back every period and on every
// event, the VM through vm.info and then each confined virtiofsd's mount
// table through confined (nil: none); a refusal ends the run.
func vmWatchReadBack(ctx context.Context, c *sandboxvmm.Client, plan sandboxvm.Plan, readBack <-chan struct{}, every time.Duration, end func(string), confined func() sandboxvm.Verdict) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-readBack:
		}
		info, err := c.Info(ctx)
		if err != nil {
			if ctx.Err() == nil {
				end("the VM could not be read back: " + err.Error())
			}
			return
		}
		if v := sandboxvm.ReadBackWhileRunning(plan, info); !v.OK() {
			end(v.Error())
			return
		}
		if confined == nil || ctx.Err() != nil {
			continue
		}
		if v := confined(); !v.OK() {
			if ctx.Err() == nil {
				end(v.Error())
			}
			return
		}
	}
}

// vmTeardownVMM asks the VMM to end (vmm.shutdown, short), then kills it.
func vmTeardownVMM(c *sandboxvmm.Client, vmm vmProc) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	_ = c.ShutdownVMM(ctx)
	cancel()
	select {
	case <-vmm.Done():
	case <-time.After(2 * time.Second):
		vmm.Kill()
	}
}

// vmRunState is one run's state dir and processes.
type vmRunState struct {
	dir     string
	boot    string
	secret  []byte
	record  []byte
	shares  []vmStartedShare
	mu      sync.Mutex
	procs   []vmProc
	rec     sandboxvm.ProcRecord
	lock    *os.File
	cleaned bool
	// sockDir is the run's short socket dir ("" when the sockets live in
	// dir).
	sockDir string
	// bootDeadline bounds the retry of a refused API or vsock dial
	// (vmDialRetrying): the VMM's start plus the boot window.
	bootDeadline time.Time
}

// vmStartedShare is one virtiofsd to start.
type vmStartedShare struct {
	tag      string
	socket   string
	argv     []string
	confined bool
	share    vmShare
	// pid is the started process (the bwrap of a confined share), set
	// before any read-back runs.
	pid int
}

// vmPrepareState makes the run's state dir and its boot share.
func vmPrepareState(plan vmPlanFile, h sandbox.HostArgs, inner []string) (*vmRunState, error) {
	root := filepath.Dir(plan.VM.StateDir)
	if err := vmEnsureOwnedDir(filepath.Dir(root)); err != nil {
		return nil, fmt.Errorf("state root: %w", err)
	}
	if err := vmEnsureOwnedDir(root); err != nil {
		return nil, fmt.Errorf("runs dir: %w", err)
	}
	if err := os.Mkdir(plan.VM.StateDir, 0o700); err != nil {
		return nil, fmt.Errorf("run state dir: %w", err)
	}
	s := &vmRunState{dir: plan.VM.StateDir, rec: sandboxvm.ProcRecord{RunID: plan.VM.RunID}}
	lock, err := os.OpenFile(filepath.Join(s.dir, sandboxvm.ProcRecordName+".lock"), os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: a fixed name in the fresh state dir
	if err != nil {
		s.cleanup()
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor number
		_ = lock.Close()
		s.cleanup()
		return nil, fmt.Errorf("lock the process record: %w", err)
	}
	s.lock = lock
	if sd := plan.VM.SocketDir; sd != "" && sd != plan.VM.StateDir {
		if err := vmEnsureOwnedDir(filepath.Dir(sd)); err != nil {
			s.cleanup()
			return nil, fmt.Errorf("socket dir parent: %w", err)
		}
		if err := os.Mkdir(sd, 0o700); err != nil {
			s.cleanup()
			return nil, fmt.Errorf("run socket dir: %w", err)
		}
		s.sockDir = sd
	}
	if err := s.writeRecord(); err != nil {
		s.cleanup()
		return nil, err
	}
	img := filepath.Dir(plan.VM.Kernel)
	if err := os.Mkdir(img, 0o700); err != nil {
		s.cleanup()
		return nil, err
	}
	for name, dst := range map[string]string{
		"vmlinuz": plan.VM.Kernel, "initrd.img": plan.VM.Initramfs, "rootfs.img": plan.VM.Rootfs, "rootfs.verity": plan.VM.Verity,
	} {
		src, ok := plan.Image[name]
		if !ok {
			s.cleanup()
			return nil, fmt.Errorf("the plan names no verified %s", name)
		}
		if err := vmLinkOrCopy(src, dst); err != nil {
			s.cleanup()
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	s.boot = filepath.Join(s.dir, "boot")
	if err := os.Mkdir(s.boot, 0o700); err != nil {
		s.cleanup()
		return nil, err
	}
	if err := vmCopyVerified(plan.GuestBinary, filepath.Join(s.boot, sandboxvm.GuestBinaryName), plan.GuestSize, plan.GuestSHA256); err != nil {
		s.cleanup()
		return nil, fmt.Errorf("the guest observer: %w", err)
	}
	spec := plan.Guest
	// A launch naming the host observer runs the guest's (the host path may
	// not exist in the guest: sandboxvm.GuestHookBin).
	inner = append([]string(nil), inner...)
	if len(inner) > 0 && inner[0] == spec.HostBin {
		inner[0] = spec.HookPath()
	}
	spec.Command = append(append([]string(nil), plan.GuestPrefix...), inner...)
	if len(spec.Command) == 0 {
		spec.Command = []string{vmGuestBin}
	}
	sb, err := spec.Encode()
	if err != nil {
		s.cleanup()
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(s.boot, sandboxvm.GuestSpecName), sb, 0o600); err != nil {
		s.cleanup()
		return nil, err
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		s.cleanup()
		return nil, err
	}
	s.secret = []byte(hex.EncodeToString(raw[:]))
	if err := os.WriteFile(filepath.Join(s.boot, sandboxvm.GuestSecretName), s.secret, 0o600); err != nil {
		s.cleanup()
		return nil, err
	}
	rec, err := os.ReadFile(filepath.Join(h.SockDir, sandboxrelayd.BoxRecordName)) //nolint:gosec // G304: the host services' own per-run socket dir
	if err != nil {
		s.cleanup()
		return nil, fmt.Errorf("box record: %w", err)
	}
	s.record = rec
	boot := vmShare{Tag: sandboxvm.BootTag, Dir: s.boot, ReadOnly: true}
	shares := append([]vmShare{boot}, plan.Shares...)
	for _, sh := range shares {
		sock := plan.VM.ShareSocket(sh.Tag)
		argv, err := vmVirtiofsdArgv(plan, sh, sock)
		if err != nil {
			s.cleanup()
			return nil, err
		}
		s.shares = append(s.shares, vmStartedShare{tag: sh.Tag, socket: sock, argv: argv, confined: sh.Confined, share: sh})
	}
	return s, nil
}

// vmVirtiofsdArgv is a share's virtiofsd (inside the confining bwrap for a
// live share, sandboxvm.ConfinedVirtiofsdArgv).
func vmVirtiofsdArgv(plan vmPlanFile, sh vmShare, sock string) ([]string, error) {
	if sh.Confined {
		return sandboxvm.ConfinedVirtiofsdArgv(sandboxvm.ConfinedShare{
			Bwrap: plan.Bwrap, Virtiofsd: vmConfinedVirtiofsd, Socket: sock, Dir: sh.Dir,
			ReadOnlyPaths: sh.ReadOnlyPaths, Pins: sh.Pins,
		})
	}
	return sandboxvm.VirtiofsdArgv(plan.Virtiofsd, sock, sh.Dir)
}

// track records a started process (pid, /proc start time, executable).
func (s *vmRunState) track(role sandboxvm.ProcRole, p vmProc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.procs = append(s.procs, p)
	if f := vmProcFacts(p.PID()); f.Alive {
		s.rec.Procs = append(s.rec.Procs, sandboxvm.Proc{Role: role, PID: p.PID(), StartTicks: f.StartTicks, Exe: f.Exe})
	}
	_ = s.writeRecordLocked()
}

func (s *vmRunState) writeRecord() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeRecordLocked()
}

func (s *vmRunState) writeRecordLocked() error {
	b, err := json.Marshal(s.rec)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, sandboxvm.ProcRecordName+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil { //nolint:gosec // G703: a fixed name in the run's own state dir
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, sandboxvm.ProcRecordName)) //nolint:gosec // G703: a fixed name in the run's own state dir
}

// removeSecret removes the boot share's secret once the guest read it.
func (s *vmRunState) removeSecret() {
	if s.boot != "" {
		_ = os.Remove(filepath.Join(s.boot, sandboxvm.GuestSecretName)) //nolint:gosec // G703: a fixed name in the run's own boot dir
	}
}

// killAll kills every started process.
func (s *vmRunState) killAll() {
	s.mu.Lock()
	procs := append([]vmProc(nil), s.procs...)
	s.mu.Unlock()
	for _, p := range procs {
		p.Kill()
	}
	for _, p := range procs {
		select {
		case <-p.Done():
		case <-time.After(2 * time.Second):
		}
	}
}

// cleanup kills what is left and removes the state dir (sockets, the
// API socket's lock, the vsock listeners, links, the boot share).
func (s *vmRunState) cleanup() {
	s.killAll()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned {
		return
	}
	s.cleaned = true
	_ = os.RemoveAll(s.dir) //nolint:gosec // G703: the run's own state dir this helper made with Mkdir
	if s.sockDir != "" {
		_ = os.RemoveAll(s.sockDir) //nolint:gosec // G703: the run's own socket dir this helper made with Mkdir
	}
	if s.lock != nil {
		_ = s.lock.Close()
	}
}

// vmLinkOrCopy hard-links a verified store file into the state dir, or
// copies it when the two are on different filesystems.
func vmLinkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	in, err := openNoFollow(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) //nolint:gosec // G304: a fixed name in the run's state dir
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// vmCopyVerified copies src to dst through a no-follow descriptor, hashing
// as it copies, and refuses a size or digest other than the verified ones:
// the guest boots exactly the bytes that were checked.
func vmCopyVerified(src, dst string, size int64, sum string) error {
	in, err := openNoFollow(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o500) //nolint:gosec // G304,G302: the guest observer, executable in the guest
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, size+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if n != size || hex.EncodeToString(h.Sum(nil)) != sum {
		_ = os.Remove(dst)
		return errors.New("the guest observer changed since it was verified")
	}
	return nil
}

// vmProcFacts reads /proc for pid.
func vmProcFacts(pid int) sandboxvm.ProcFacts {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return sandboxvm.ProcFacts{}
	}
	st, err := sandboxvm.ParseProcStatStart(b)
	if err != nil {
		return sandboxvm.ProcFacts{}
	}
	exe, _ := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	return sandboxvm.ProcFacts{Alive: true, StartTicks: st, Exe: exe}
}

// osProc is a started os/exec process.
type osProc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func (p *osProc) PID() int              { return p.cmd.Process.Pid }
func (p *osProc) Kill()                 { _ = p.cmd.Process.Kill() }
func (p *osProc) Done() <-chan struct{} { return p.done }

// vmStartProc starts argv with PR_SET_PDEATHSIG (SIGKILL) in its own
// process group, stdio to /dev/null, a minimal environment.
func vmStartProc(_ sandboxvm.ProcRole, argv []string, extra []*os.File) (vmProc, error) {
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return nil, errors.New("not an absolute program")
	}
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: the probed, owner-checked VMM or virtiofsd with the planned argv
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	cmd.ExtraFiles = extra
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	p := &osProc{cmd: cmd, done: make(chan struct{})}
	started := make(chan error, 1)
	go func() {
		// PR_SET_PDEATHSIG fires when the THREAD that forked the child
		// exits, not the process. This goroutine is locked to its OS thread
		// from the fork until the child is reaped and never unlocks, so the
		// runtime cannot retire that thread under a live child; when it
		// returns, the thread goes with it, after the child is gone.
		runtime.LockOSThread()
		if err := cmd.Start(); err != nil {
			started <- err
			return
		}
		started <- nil
		_ = cmd.Wait()
		close(p.done)
	}()
	if err := <-started; err != nil {
		return nil, err
	}
	return p, nil
}

// vmDialRetrying dials, retrying a refused connection (ECONNREFUSED) with a
// short backoff, 20 ms doubling to 250 ms, until deadline or ctx ends:
// Cloud Hypervisor creates its API and vsock sockets before it listens on
// them, so a dial in between is refused although the VMM is coming up (the
// first live run's "vmm.ping: connection refused", 1 launch in about 16,
// D6). Any other error, and a refusal past the deadline, is returned as is.
func vmDialRetrying(ctx context.Context, deadline time.Time, dial func(context.Context) (net.Conn, error)) (net.Conn, error) {
	wait := 20 * time.Millisecond
	for {
		c, err := dial(ctx)
		if err == nil || !errors.Is(err, syscall.ECONNREFUSED) || !time.Now().Add(wait).Before(deadline) {
			return c, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(wait):
		}
		if wait *= 2; wait > 250*time.Millisecond {
			wait = 250 * time.Millisecond
		}
	}
}

// vmWaitSocket waits for p to be a socket (not a symlink), up to 30 s.
func vmWaitSocket(ctx context.Context, p string) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Lstat(p); err == nil { //nolint:gosec // G703: a socket path in the run's own state dir
			if fi.Mode()&fs.ModeSocket == 0 {
				return fmt.Errorf("%s is not a socket", p)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return errors.New("timed out")
}

// vmDialAPI dials the API socket (A9): it must be a socket in the run's
// state dir, not a symlink, owned by this user, and its peer must be the
// recorded VMM pid.
func vmDialAPI(ctx context.Context, sock string, pid int) (net.Conn, error) {
	fi, err := os.Lstat(sock)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&fs.ModeSocket == 0 || !ownedByMe(fi) {
		return nil, fmt.Errorf("%s is not a socket this user owns", sock)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, err
	}
	if got := vmPeerPID(c); got != pid {
		_ = c.Close()
		return nil, fmt.Errorf("the API socket's peer is pid %d, not the VMM this helper started (%d)", got, pid)
	}
	return c, nil
}

// vmPeerPID is the SO_PEERCRED pid of a unix connection (0 when unknown).
func vmPeerPID(c net.Conn) int {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return 0
	}
	var cred *unix.Ucred
	var cerr error
	if err := rc.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || cerr != nil || cred == nil { //nolint:gosec // G115: a descriptor number
		return 0
	}
	return int(cred.Pid)
}

// vmRunEnv is the guest's environment: the launch environment without the
// host socket and interop variables, the trusted launcher channel and the
// host-only paths, plus the sandbox marker (the Apple container row's rule).
func vmRunEnv(environ []string) []string {
	// The allow-list first (WINFIX2 R-167); the drops below stay.
	environ = sandboxBoxEnv("linux", environ)
	drop := map[string]bool{"XDG_RUNTIME_DIR": true, envOOBFD: true, envOOBAuth: true, sandboxEnvMarker: true}
	for _, k := range sandbox.GuestUnsetEnv {
		drop[k] = true
	}
	out := make([]string, 0, len(environ)+1)
	for _, kv := range environ {
		k, _, _ := strings.Cut(kv, "=")
		if !drop[k] {
			out = append(out, kv)
		}
	}
	return append(out, sandboxEnvMarker+"=1")
}

// vmMajor is a dotted version's major (-1 when unreadable).
func vmMajor(v string) int {
	head, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(head)
	if err != nil {
		return -1
	}
	return n
}

// vmReturn runs a copy's return once the VM is gone, through sandboxReturn
// (or its bare form) with the injected scan, and says what came back.
func vmReturn(plan vmPlanFile, env vmHostEnv, t hostedTerm) {
	ctx, cancel := context.WithTimeout(context.Background(), sandboxReturnTimeout)
	defer cancel()
	req := *plan.Return
	scan := vmReturnScan(plan.ConfigPath)
	var res sandboxReturnResult
	var err error
	if req.Bare {
		res, err = sandboxReturnBare(ctx, req, env.returnGit, scan)
	} else {
		res, err = sandboxReturn(ctx, req, env.returnGit, scan)
	}
	switch {
	case err != nil:
		fmt.Fprintf(t.out, "\r\n[observer: the box's commits were not returned: %v; the copy is kept at %s]\r\n", err, req.CopyDir)
	case res.NothingNew:
		fmt.Fprintf(t.out, "\r\n[observer: the box made no new commit; the copy is kept at %s]\r\n", req.CopyDir)
	case req.Bare:
		fmt.Fprintf(t.out, "\r\n[observer: the box's commits are on %s in the return repository %s (commit %.12s); nothing was pushed. In your checkout run: %s ; the copy is kept at %s]\r\n",
			res.Ref, req.SourceRepo, res.Commit, workspace.ReturnFetchCommand(req.SourceRepo, res.Ref), req.CopyDir)
	default:
		fmt.Fprintf(t.out, "\r\n[observer: the box's commits are on %s in %s (commit %.12s); your branch and working tree are unchanged]\r\n", res.Ref, req.SourceRepo, res.Commit)
	}
}

// vmReturnScan is the bound return scan with the daemon's config path (nil
// while no scan is bound).
func vmReturnScan(configPath string) func(context.Context, sandboxReturnScanInput) error {
	scan := sandboxReturnScan
	if scan == nil {
		return nil
	}
	return func(ctx context.Context, in sandboxReturnScanInput) error {
		in.ConfigPath = configPath
		return scan(ctx, in)
	}
}

// vmConfinedReadBack reads the confined virtiofsd's own mount table and
// judges it against the share's plan: before boot a shortfall refuses the
// live share (source_unsupported, the VM not booted); after boot it ends
// the run (built_below_plan).
func vmConfinedReadBack(env vmHostEnv, sh vmStartedShare, afterBoot bool) sandboxvm.Verdict {
	c := sandboxvm.ConfinedShare{Bwrap: sandboxvm.ConfinedBwrap, Virtiofsd: sandboxvm.ConfinedVirtiofsd, Socket: sh.socket, Dir: sh.share.Dir, ReadOnlyPaths: sh.share.ReadOnlyPaths, Pins: sh.share.Pins}
	judge := sandboxvm.ConfinedReadBack
	if afterBoot {
		judge = sandboxvm.ConfinedReadBackAfterBoot
	}
	read := env.mountInfo
	if read == nil {
		read = vmConfinedMountInfo
	}
	b, err := read(sh.pid)
	if err != nil {
		return judge(c, []string{err.Error()})
	}
	table, err := sandbox.ParseGuestMountInfo(b)
	if err != nil {
		return judge(c, []string{err.Error()})
	}
	mounts, ro := sandboxvm.ConfinedExpectations(c)
	return judge(c, sandbox.GuestMountShortfalls(table, mounts, ro))
}

// vmConfinedReadBackAll is the after-boot read-back of every confined
// share (the first refusal, or a pass).
func vmConfinedReadBackAll(env vmHostEnv, shares []vmStartedShare) sandboxvm.Verdict {
	for _, sh := range shares {
		if !sh.confined {
			continue
		}
		if v := vmConfinedReadBack(env, sh, true); !v.OK() {
			return v
		}
	}
	return sandboxvm.Verdict{Code: sandboxvm.VerdictAvailable}
}

// vmConfinedMountInfo reads the confined virtiofsd's own mount table: the
// child bwrap started (bwrap itself stays outside the namespace with
// --unshare-pid).
func vmConfinedMountInfo(bwrapPID int) ([]byte, error) {
	pid := vmFindChild(bwrapPID, "virtiofsd", 5*time.Second)
	if pid == 0 {
		return nil, errors.New("the confined virtiofsd process was not found under its bwrap")
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/mountinfo")
	if err != nil {
		return nil, fmt.Errorf("its mount table could not be read: %w", err)
	}
	return b, nil
}

// vmFindChild walks pid's descendants (/proc/<pid>/task/<pid>/children) for
// a process whose executable's base name is name, up to wait.
func vmFindChild(pid int, name string, wait time.Duration) int {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		queue := []int{pid}
		for len(queue) > 0 && len(queue) < 64 {
			p := queue[0]
			queue = queue[1:]
			if exe, err := os.Readlink("/proc/" + strconv.Itoa(p) + "/exe"); err == nil && filepath.Base(exe) == name && p != pid {
				return p
			}
			b, err := os.ReadFile("/proc/" + strconv.Itoa(p) + "/task/" + strconv.Itoa(p) + "/children")
			if err != nil {
				continue
			}
			for _, f := range strings.Fields(string(b)) {
				if n, err := strconv.Atoi(f); err == nil {
					queue = append(queue, n)
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return 0
}

// vmEnsureSocketParent makes the parent of the host services' per-run
// socket dir (/tmp/obsbx or the row's per-user parent) owner-only before
// the services make the run's dir in it with a bare Mkdir: created 0700
// when missing, refused when it is a link, not a directory, another user's
// or open to others (the first live run found nothing creating it: "create
// socket dir: no such file or directory", exit 125, D3).
func vmEnsureSocketParent(sockDir string) error {
	if sockDir == "" {
		return nil
	}
	if err := vmEnsureOwnedDir(filepath.Dir(sockDir)); err != nil {
		return fmt.Errorf("the run's socket dir parent: %w", err)
	}
	return nil
}

// vmEnsureOwnedDir creates dir (0700) when it is missing and refuses one
// that is a symlink, not a directory, not this user's, or open to others.
func vmEnsureOwnedDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || !ownedByMe(fi) || fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is not a private directory this user owns (mode %#o)", dir, fi.Mode().Perm())
	}
	return nil
}

// vmRunTool runs a host tool under a deadline with a minimal environment.
func vmRunTool(ctx context.Context, argv []string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: the resolved e2fsprogs program with the planned argv
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 400 {
			msg = msg[:400]
		}
		return fmt.Errorf("%s: %w: %s", filepath.Base(argv[0]), err, msg)
	}
	return nil
}

// vmTreeSize sums the regular files under dir (no link followed).
func vmTreeSize(dir string) (int64, error) {
	var n int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n, err
}

// vmBuildDiskImages writes each disk_image copy into its ext4 image in the
// run's state dir (mkfs.ext4 -d, no root), owned by the host user.
func vmBuildDiskImages(ctx context.Context, plan vmPlanFile, env vmHostEnv) error {
	for _, di := range plan.DiskImages {
		var disk *sandboxvm.Disk
		for i := range plan.VM.Disks {
			if plan.VM.Disks[i].Name == di.Name {
				disk = &plan.VM.Disks[i]
			}
		}
		if disk == nil || plan.Mkfs == "" {
			return fmt.Errorf("the plan has no disk for the workspace image %s", di.Name)
		}
		size, err := vmTreeSize(di.Source)
		if err != nil {
			return fmt.Errorf("measure the workspace copy: %w", err)
		}
		img, err := sandboxvm.DiskImageSize(size)
		if err != nil {
			return err
		}
		argv, err := sandboxvm.MkfsArgv(plan.Mkfs, di.Source, disk.Path, img, os.Getuid(), os.Getgid())
		if err != nil {
			return err
		}
		if err := env.tool(ctx, argv); err != nil {
			return fmt.Errorf("build the workspace image: %w", err)
		}
	}
	return nil
}

// vmPrecheckDiskImages judges a disk_image copy that has no return planned
// with the same precheck every copy's return runs first, so a planted
// execution-risk path is named, and the copy stamped, before anyone runs
// git in it.
func vmPrecheckDiskImages(plan vmPlanFile, env vmHostEnv, t hostedTerm) {
	for _, di := range plan.DiskImages {
		ctx, cancel := context.WithTimeout(context.Background(), sandboxReturnTimeout)
		err := sandboxReturnPrecheck(ctx, di.Source, env.returnGit)
		cancel()
		if err != nil {
			fmt.Fprintf(t.out, "\r\n[observer: the workspace image came back into %s but the copy was refused: %v]\r\n", di.Source, err)
		}
	}
}

// vmDumpDiskImages reads each image back into its copy dir once the VM is
// gone: debugfs, confined in bwrap (sandboxvm.ConfinedDumpArgv), dumps it
// into a fresh sibling dir, which replaces the copy (lost+found dropped),
// so the return step scans exactly what the box left.
// vmImageClosed refuses a workspace image the guest left mounted: debugfs
// does not replay the ext4 journal, so its rdump would silently return the
// tree as it was before the box's last changes (the second live run's
// disk_image return reported "no new commit" over a guest commit). Nothing is
// read back from such an image; the copy stays as it was.
func vmImageClosed(path string) error {
	f, err := os.Open(path) //nolint:gosec // G304: the run's own workspace image
	if err != nil {
		return fmt.Errorf("open the workspace image: %w", err)
	}
	defer func() { _ = f.Close() }()
	dirty, err := sandboxvm.ImageNeedsRecovery(f)
	if err != nil {
		return err
	}
	if dirty {
		return errors.New("the box did not close its workspace image (its ext4 journal still needs recovery), so a read-back would return a stale tree")
	}
	return nil
}

func vmDumpDiskImages(plan vmPlanFile, env vmHostEnv) error {
	for _, di := range plan.DiskImages {
		var path string
		for _, d := range plan.VM.Disks {
			if d.Name == di.Name {
				path = d.Path
			}
		}
		if path == "" || plan.Debugfs == "" {
			return errors.New("the plan has no workspace image")
		}
		if plan.DumpBwrap == "" {
			return errors.New("source_unsupported: the plan names no bwrap, and debugfs never reads a guest-written image unconfined")
		}
		if err := vmImageClosed(path); err != nil {
			return err
		}
		fresh := di.Source + ".vm-return"
		_ = os.RemoveAll(fresh) //nolint:gosec // G703: the copy's own sibling under the managed root
		if err := os.Mkdir(fresh, 0o700); err != nil {
			return err
		}
		argv, err := sandboxvm.ConfinedDumpArgv(plan.DumpBwrap, plan.Debugfs, path, fresh)
		if err != nil {
			return err
		}
		if err := env.tool(context.Background(), argv); err != nil {
			_ = os.RemoveAll(fresh) //nolint:gosec // G703: as above
			return err
		}
		_ = os.RemoveAll(filepath.Join(fresh, "lost+found"))
		// The helper runs with the copy as its working directory (the PTY
		// child starts there) and every return-step git inherits it, so
		// after the swap it re-enters the new copy at the same place: the
		// old dir is removed, and a git started in it fails "Unable to read
		// current working directory" (the first live run, D7).
		wd, _ := os.Getwd()
		old := di.Source + ".vm-before"
		if err := os.Rename(di.Source, old); err != nil {
			return err
		}
		if err := os.Rename(fresh, di.Source); err != nil {
			_ = os.Rename(old, di.Source)
			return err
		}
		if wd != "" && vmWithin(wd, di.Source) {
			if err := os.Chdir(wd); err != nil {
				_ = os.Chdir(di.Source)
			}
		}
		_ = os.RemoveAll(old) //nolint:gosec // G703: the copy's own sibling under the managed root
	}
	return nil
}
