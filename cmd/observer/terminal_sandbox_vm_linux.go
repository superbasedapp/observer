//go:build linux && !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// terminal_sandbox_vm_linux.go is the guest init of the microVM row,
// `observer sandbox-vm-init`, run from the verified guest observer on the
// run's boot share (lane SBX-P4 decision 3; D-751 Q35):
//
//   - as PID 1 (`--boot <dir>`, handed over by the initramfs): it mounts
//     /proc, /sys, /dev and its ptys and a tmpfs on each writable root (the
//     rootfs is read-only), brings up lo (the only interface: no NIC),
//     mounts the run's shares, links the host observer path to itself,
//     runs the in-guest mount check (internal/sandbox/guestmounts.go) and,
//     when the image declares it, the unprivileged user namespace
//     self-test; then it starts the serve child, reaps every orphan,
//     forwards SIGTERM and SIGHUP, and powers the VM off when the serve
//     child ends;
//   - the serve child (`--serve`): it listens on AF_VSOCK (golang.org/x/sys
//     /unix, accepting only the host, CID 2), takes the PTY session on one
//     port and the capture relay's tunnel on the next (relaymux.DialGuest,
//     guestTunnelServe), serves the guest socket dir for the agent's uid
//     and runs the agent on a PTY it opens and HOLDS (guestRunPTY: setsid
//     and the controlling terminal, fine in a VM); the agent's exit status
//     goes home on the PTY session; its own death closes the session and
//     the host ends the run;
//   - the exec step (`--exec-as uid:gid --cwd dir -- <command>`): it drops
//     to the host user's uid and gid with no supplementary groups and
//     execs the command (the guest helper's forwarders, then the agent).
//
// A refused check never starts the agent: the serve child still answers
// the PTY session, says why on the terminal and sends exit status 125.

// registerVMHelpers registers the helper verbs.
func registerVMHelpers() {
	sandboxHelperFuncs[vmHostVerb] = runVMHost
	sandboxHelperFuncs[vmInitVerb] = runVMInit
}

// vmRefusedEnv carries a PID 1 refusal to the serve child.
const vmRefusedEnv = "OBSERVER_VM_REFUSED"

// runVMInit dispatches the three modes.
func runVMInit(args []string) int {
	switch {
	case len(args) >= 1 && args[0] == "--exec-as":
		return vmInitExecAs(args[1:])
	case len(args) == 3 && args[0] == "--serve" && args[1] == "--boot":
		return vmInitServe(args[2], vmRealGuestEnv())
	case len(args) == 1 && args[0] == "--userns-test":
		return vmUsernsTestChild()
	case len(args) == 1 && args[0] == "--userns-leaf":
		return vmUsernsLeaf()
	case len(args) == 2 && args[0] == "--boot":
		if os.Getpid() != 1 {
			fmt.Fprintln(os.Stderr, "observer "+vmInitVerb+": runs as PID 1 inside a microVM only")
			return 127
		}
		return vmInitPID1(args[1])
	}
	fmt.Fprintln(os.Stderr, "usage: observer "+vmInitVerb+" --boot <dir>")
	return 127
}

// vmInitPID1 is the guest's PID 1.
func vmInitPID1(boot string) int {
	refused := vmGuestSetup(boot)
	self := filepath.Join(boot, sandboxvm.GuestBinaryName)
	cmd := exec.Command(self, vmInitVerb, "--serve", "--boot", boot) //nolint:gosec // G204: this verified binary on the read-only boot share
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TERM=linux"}
	if refused != "" {
		cmd.Env = append(cmd.Env, vmRefusedEnv+"="+refused)
	}
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGCHLD, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "observer %s: the serve child did not start: %v\n", vmInitVerb, err)
		vmPowerOff()
		return 127
	}
	child := cmd.Process.Pid
	code := vmReapUntil(child, sigs, func(s os.Signal) { _ = cmd.Process.Signal(s) })
	_ = syscall.Kill(-1, syscall.SIGKILL)
	vmReapAll()
	unix.Sync()
	_ = code
	vmPowerOff()
	return 0
}

// vmReapUntil reaps every child (PID 1 inherits every orphan) until child
// exits, forwarding SIGTERM, SIGHUP and SIGINT to it; it returns child's
// status.
func vmReapUntil(child int, sigs <-chan os.Signal, forward func(os.Signal)) int {
	for s := range sigs {
		if s != syscall.SIGCHLD {
			forward(s)
			continue
		}
		for {
			var ws syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
			if err != nil || pid <= 0 {
				break
			}
			if pid == child {
				if ws.Signaled() {
					return 128 + int(ws.Signal())
				}
				return ws.ExitStatus()
			}
		}
	}
	return 1
}

// vmReapAll reaps what is left after the final kill.
func vmReapAll() {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.ECHILD) {
			return
		}
		if pid <= 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// vmPowerOff ends the VM.
func vmPowerOff() { _ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF) }

// vmGuestSetup does PID 1's mounts and checks; it returns a refusal ("" on
// success).
func vmGuestSetup(boot string) string {
	for _, m := range []struct {
		src, target, fstype string
		flags               uintptr
		data                string
	}{
		{"proc", "/proc", "proc", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"sysfs", "/sys", "sysfs", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID, "mode=0755"},
	} {
		_ = unix.Mount(m.src, m.target, m.fstype, m.flags, m.data)
	}
	_ = os.MkdirAll("/dev/pts", 0o755)
	if err := unix.Mount("devpts", "/dev/pts", "devpts", unix.MS_NOSUID|unix.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620"); err != nil {
		return "the guest could not mount its ptys: " + err.Error()
	}
	_ = unix.Mount("/dev/pts/ptmx", "/dev/ptmx", "", unix.MS_BIND, "")
	for _, r := range sandboxvm.GuestWritableRoots {
		_ = os.MkdirAll(r, 0o755)
		if err := unix.Mount("tmpfs", r, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, vmTmpfsData(r)); err != nil {
			return "the guest could not mount a tmpfs on " + r + ": " + err.Error()
		}
	}
	if err := vmLoopbackUp(); err != nil {
		return "the guest could not bring up lo: " + err.Error()
	}
	b, err := os.ReadFile(filepath.Join(boot, sandboxvm.GuestSpecName)) //nolint:gosec // G304: the read-only boot share
	if err != nil {
		return "the guest spec could not be read: " + err.Error()
	}
	spec, err := sandboxvm.ParseGuestSpec(b)
	if err != nil {
		return err.Error()
	}
	_ = unix.Sethostname([]byte("observer-vm"))
	if spec.WantUserns {
		_ = os.WriteFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns", []byte("0"), 0o600)
		_ = os.WriteFile("/proc/sys/kernel/unprivileged_userns_clone", []byte("1"), 0o600)
	}
	plan := sandboxvm.PlanGuestMounts(spec)
	for _, m := range plan.Shares {
		if err := os.MkdirAll(m.Target, 0o755); err != nil {
			return "the guest could not make " + m.Target + ": " + err.Error()
		}
		var flags uintptr = unix.MS_NOSUID | unix.MS_NODEV
		if m.ReadOnly {
			flags |= unix.MS_RDONLY
		}
		if err := unix.Mount(m.Tag, m.Target, "virtiofs", flags, ""); err != nil {
			return "the share " + m.Tag + " did not mount at " + m.Target + ": " + err.Error()
		}
	}
	for i, d := range plan.Disks {
		dev := "/dev/vd" + string(rune('c'+i))
		if err := os.MkdirAll(d.Target, 0o755); err != nil {
			return "the guest could not make " + d.Target + ": " + err.Error()
		}
		if err := unix.Mount(dev, d.Target, "ext4", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			return "the disk " + d.Name + " did not mount at " + d.Target + ": " + err.Error()
		}
	}
	if err := vmBindHookBin(filepath.Join(boot, sandboxvm.GuestBinaryName)); err != nil {
		return "the guest observer could not be bound at " + sandboxvm.GuestHookBin + ": " + err.Error()
	}
	if link := spec.HookLink(); link != "" {
		if err := vmLinkHostBin(link, sandboxvm.GuestHookBin); err != nil {
			return "the host observer path could not be linked in the guest: " + err.Error()
		}
	}
	vmAgentAccounts(spec)
	info, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "the box could not read its own mount table: " + err.Error()
	}
	mounts, ro := sandboxvm.ExpectedGuestMounts(spec)
	if why := sandbox.GuestCheckShared(info, mounts, ro, sandboxvm.GuestShareReadOnly(spec), func(p string) error { return unix.Access(p, unix.W_OK) }, vmShareWriteProbe); why != "" {
		return sandboxvm.VerdictBuiltBelowPlan + ": " + why
	}
	if spec.WantUserns {
		if err := vmUsernsSelfTest(boot, spec.UID, spec.GID); err != nil {
			return sandboxvm.VerdictBuiltBelowPlan + ": the image set declares unprivileged user namespaces but the guest refuses them (" + err.Error() + "); an agent's own sandbox would not nest (N13)"
		}
	}
	return ""
}

// vmShareWriteProbe is the write witness for a host-pinned read-only path
// inside a virtio-fs share (sandbox.ShareReadOnlyWitness). access(W_OK)
// answers 0 there although a write is refused (the first live run, D4), so
// it attempts a write that changes nothing when refused: a regular file is
// opened for writing (no truncation, no append, no link followed), a
// directory gets a fresh witness entry, removed again at once if it was
// made. The host's read-only bind answers EROFS through virtiofsd; nil
// means the path took the write. Anything that is neither a regular file
// nor a directory (a link included) is an error, never a pass.
func vmShareWriteProbe(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	switch {
	case fi.IsDir():
		w := filepath.Join(p, ".observer-ro-witness-"+strconv.Itoa(os.Getpid())+"-"+strconv.FormatInt(time.Now().UnixNano(), 36))
		if err := unix.Mkdir(w, 0o700); err != nil {
			return err
		}
		_ = unix.Rmdir(w)
		return nil
	case fi.Mode().IsRegular():
		fd, err := unix.Open(p, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		_ = unix.Close(fd)
		return nil
	}
	return fmt.Errorf("%s is a %s, neither a regular file nor a directory", p, fi.Mode().Type())
}

// vmTmpfsData is the tmpfs options of a writable guest root: the shared
// temp dirs world-writable with the sticky bit (1777), the rest 0755. The
// mode is set at mount; the former os.Chmod(path, 0o1777) passed Go's
// FileMode, whose 0o1000 bit is not the sticky bit (os.ModeSticky is), so
// guest /tmp and /var/tmp were 0777 (the first live run, D9).
func vmTmpfsData(root string) string {
	switch root {
	case "/tmp", "/var/tmp":
		return "mode=1777"
	}
	return "mode=0755"
}

// vmAgentEtc is where the guest init writes the passwd and group files it
// binds over the read-only rootfs's.
const vmAgentEtc = "/run/observer-etc"

// vmAgentAccounts names the agent's ids in the guest (the first live run's
// prompt read "I have no name!" and `groups` could not name the gid, D9):
// the image's /etc/passwd and /etc/group with an entry appended for an id
// the image does not name (sandboxvm.GuestAccounts), written to the guest's
// own /run tmpfs and bound read-only over the rootfs's files. Best effort:
// a failure leaves the ids nameless, which changes no permission.
func vmAgentAccounts(spec sandboxvm.GuestSpec) {
	pw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return
	}
	gr, err := os.ReadFile("/etc/group")
	if err != nil {
		return
	}
	npw, ngr := sandboxvm.GuestAccounts(pw, gr, spec.UID, spec.GID, spec.Workdir)
	if err := os.MkdirAll(vmAgentEtc, 0o755); err != nil { //nolint:gosec // G301: world-readable account files on the guest's tmpfs
		return
	}
	for name, b := range map[string][]byte{"passwd": npw, "group": ngr} {
		p := filepath.Join(vmAgentEtc, name)
		if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // G306: account files are world-readable
			continue
		}
		target := filepath.Join("/etc", name)
		if err := unix.Mount(p, target, "", unix.MS_BIND, ""); err == nil {
			_ = unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "")
		}
	}
}

// vmLoopbackUp sets IFF_UP on lo.
func vmLoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return err
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return err
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	return unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr)
}

// vmBindHookBin binds the verified guest observer read-only at the fixed
// guest path sandboxvm.GuestHookBin (on the guest's /run tmpfs), whatever
// the host observer's path: the launch and the guest's hooks name it.
func vmBindHookBin(self string) error {
	if err := os.MkdirAll(filepath.Dir(sandboxvm.GuestHookBin), 0o755); err != nil { //nolint:gosec // G301: a dir on the guest's /run tmpfs
		return err
	}
	f, err := os.OpenFile(sandboxvm.GuestHookBin, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o555) //nolint:gosec // G302,G304: the fixed bind target
	if err != nil {
		return err
	}
	_ = f.Close()
	if err := unix.Mount(self, sandboxvm.GuestHookBin, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	return unix.Mount("", sandboxvm.GuestHookBin, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "")
}

// vmLinkHostBin makes the host observer path resolve to the guest
// observer (an existing path is left alone).
func vmLinkHostBin(hostBin, self string) error {
	if _, err := os.Lstat(hostBin); err == nil { //nolint:gosec // G703: the host observer path inside the guest's own root
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(hostBin), 0o755); err != nil { //nolint:gosec // G301: a bin dir on the guest's tmpfs
		return err
	}
	return os.Symlink(self, hostBin)
}

// vmUsernsSelfTest is N13's self-test, in two steps the way an agent's own
// sandbox (bwrap, unshare -Ur) would take them: the child runs as the
// agent's uid and gid (vmUsernsDropAttr), and it clones a user namespace
// mapping itself to root (vmUsernsTestChild). Asking Go for the Credential
// and CLONE_NEWUSER in one start cannot work: Go applies a Credential in
// the child after the clone, inside the new namespace, where no id is
// mapped yet, so setgroups and setuid fail and the start is EPERM on every
// kernel (the first live run refused every guest_userns set that way, D5).
func vmUsernsSelfTest(boot string, uid, gid int) error {
	cmd := exec.Command(filepath.Join(boot, sandboxvm.GuestBinaryName), vmInitVerb, "--userns-test") //nolint:gosec // G204: this verified binary
	cmd.SysProcAttr = vmUsernsDropAttr(uid, gid)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// vmUsernsDropAttr is the self-test child's start: the agent's ids, set
// with no clone flag (none when this process already runs as them).
func vmUsernsDropAttr(uid, gid int) *syscall.SysProcAttr {
	a := &syscall.SysProcAttr{}
	if os.Geteuid() != uid || os.Getegid() != gid {
		a.Credential = &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)} //nolint:gosec // G115: checked unprivileged by the spec
	}
	return a
}

// vmUsernsCloneAttr is the leaf's start: a new user namespace with this
// process's uid and gid mapped to root, setgroups denied (unshare -Ur).
func vmUsernsCloneAttr(uid, gid int) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: uid, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: gid, Size: 1}},
	}
}

// vmUsernsTestChild is the self-test's child, already running as the
// agent's ids: it starts the leaf in a new user namespace, which is the
// whole test.
func vmUsernsTestChild() int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "the self-test cannot find its own binary:", err)
		return 1
	}
	cmd := exec.Command(self, vmInitVerb, "--userns-leaf") //nolint:gosec // G204: this verified binary
	cmd.SysProcAttr = vmUsernsCloneAttr(os.Getuid(), os.Getgid())
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "uid %d could not clone a user namespace: %v %s\n", os.Getuid(), err, strings.TrimSpace(string(out)))
		return 1
	}
	return 0
}

// vmUsernsLeaf runs inside the new user namespace: the mapping made it
// root there.
func vmUsernsLeaf() int {
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "the new user namespace mapped uid %d, not root\n", os.Getuid())
		return 1
	}
	return 0
}

// vmInitExecAs drops to uid:gid and execs the command.
func vmInitExecAs(args []string) int {
	if len(args) < 5 || args[1] != "--cwd" || args[3] != "--" {
		fmt.Fprintln(os.Stderr, "usage: "+vmInitVerb+" --exec-as uid:gid --cwd dir -- command")
		return 127
	}
	u, g, ok := strings.Cut(args[0], ":")
	uid, err1 := strconv.Atoi(u)
	gid, err2 := strconv.Atoi(g)
	if !ok || err1 != nil || err2 != nil || uid < 1 || gid < 1 {
		fmt.Fprintln(os.Stderr, vmInitVerb+": the agent never runs as root")
		return 127
	}
	cmd := args[4:]
	if err := syscall.Setgroups(nil); err != nil {
		return vmInitFail("setgroups: %v", err)
	}
	if err := syscall.Setgid(gid); err != nil {
		return vmInitFail("setgid: %v", err)
	}
	if err := syscall.Setuid(uid); err != nil {
		return vmInitFail("setuid: %v", err)
	}
	if err := os.Chdir(args[2]); err != nil {
		return vmInitFail("chdir %s: %v", args[2], err)
	}
	prog, err := exec.LookPath(cmd[0])
	if err != nil {
		return vmInitFail("%s: %v", cmd[0], err)
	}
	return vmInitFail("exec %s: %v", cmd[0], syscall.Exec(prog, cmd, sandboxBoxEnv("linux", os.Environ()))) //nolint:gosec // G204: the planned inner launch
}

func vmInitFail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "observer "+vmInitVerb+": "+format+"\n", a...)
	return 127
}

// vmGuestEnv is the serve child's injected I/O (tests use unix listeners
// where AF_VSOCK is absent).
type vmGuestEnv struct {
	listen func(port uint32) (net.Listener, error)
	peerOK func(net.Conn) bool
	// self is the guest observer the exec step runs.
	self   string
	window time.Duration
	// run runs the agent on the guest PTY (guestRunPTY in production).
	run func(g *relaymux.Guest, a relayStdioArgs) int
	// noChown leaves the guest socket dir to the serving user (a test that
	// is not root); the guest init always hands it to the agent's uid.
	noChown bool
	// sockDir overrides the guest socket dir (tests).
	sockDir string
	// setEnv installs the agent's environment (nil: this process's own,
	// the serve child being a process of its own).
	setEnv func([]string)
	// closeDisks closes the guest's block-device mounts before the exit
	// status goes home (vmRealCloseDisks; nil in tests that start no VM).
	closeDisks func(targets []string) error
}

// vmSetProcessEnv replaces this process's environment with env.
func vmSetProcessEnv(env []string) {
	os.Clearenv()
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			_ = os.Setenv(k, v)
		}
	}
}

func vmRealGuestEnv() vmGuestEnv {
	return vmGuestEnv{listen: vmListenVsock, peerOK: vmPeerIsHost, window: 60 * time.Second, run: guestRunPTY, closeDisks: vmRealCloseDisks}
}

// vmInitServe is the serve child.
func vmInitServe(boot string, env vmGuestEnv) int {
	b, err := os.ReadFile(filepath.Join(boot, sandboxvm.GuestSpecName)) //nolint:gosec // G304: the boot share
	if err != nil {
		return vmInitFail("the guest spec: %v", err)
	}
	spec, err := sandboxvm.ParseGuestSpec(b)
	if err != nil {
		return vmInitFail("%v", err)
	}
	secret, err := os.ReadFile(filepath.Join(boot, sandboxvm.GuestSecretName)) //nolint:gosec // G304: the boot share
	if err != nil || len(secret) < 32 {
		return vmInitFail("the run's relay secret is missing; the agent was not started")
	}
	if env.self == "" {
		env.self = filepath.Join(boot, sandboxvm.GuestBinaryName)
	}
	ptyLn, err := env.listen(spec.PTYPort)
	if err != nil {
		return vmInitFail("listen on vsock port %d: %v", spec.PTYPort, err)
	}
	defer func() { _ = ptyLn.Close() }()
	relayLn, err := env.listen(spec.RelayPort)
	if err != nil {
		return vmInitFail("listen on vsock port %d: %v", spec.RelayPort, err)
	}
	opts := relaymux.Options{RunID: spec.RunID, Secret: secret}
	g, err := vmAcceptPTY(ptyLn, env.peerOK, opts, env.window)
	if err != nil {
		return vmInitFail("the PTY session: %v", err)
	}
	defer g.Close()
	// The exit status is the session's last message; closing the session
	// then ends the run at home at once.
	finish := func(code int) int {
		if why := vmCloseGuestDisks(spec, env.closeDisks); why != "" {
			if pty := g.PTY(); pty != nil {
				_, _ = io.WriteString(pty, "\r\nobserver sandbox (cloud-hypervisor): "+why+"\r\n")
			}
		}
		g.Log(vmExitPrefix + strconv.Itoa(code))
		select {
		case <-g.Done():
		case <-time.After(200 * time.Millisecond):
		}
		return code
	}
	if why := os.Getenv(vmRefusedEnv); why != "" {
		_ = relayLn.Close()
		if pty := g.PTY(); pty != nil {
			_, _ = io.WriteString(pty, "\r\nobserver sandbox (cloud-hypervisor): "+why+"; the agent was not started\r\n")
		}
		return finish(sandboxHelperFailCode)
	}
	owner := &guestSocketOwner{uid: spec.UID, gid: spec.GID}
	sockDir := sandbox.GuestSocketDir
	if env.noChown {
		owner = nil
	}
	if env.sockDir != "" {
		sockDir = env.sockDir
	}
	tun, err := guestTunnelServe(relayLn, env.peerOK, spec.RunID, secret, env.window, sockDir, owner)
	if err != nil {
		if pty := g.PTY(); pty != nil {
			_, _ = io.WriteString(pty, "\r\nobserver sandbox (cloud-hypervisor): the capture relay's tunnel did not come up ("+err.Error()+"); the agent was not started\r\n")
		}
		return finish(sandboxHelperFailCode)
	}
	defer tun.stop()
	// The agent's environment is the launch environment the host sent in
	// the authenticated session (keys included), never a file.
	if env.setEnv == nil {
		env.setEnv = vmSetProcessEnv
	}
	env.setEnv(g.Hello().Env)
	argv := append([]string{env.self, vmInitVerb, "--exec-as", strconv.Itoa(spec.UID) + ":" + strconv.Itoa(spec.GID), "--cwd", spec.Workdir, "--"}, spec.Command...)
	code := env.run(g, relayStdioArgs{command: argv, rows: spec.Rows, cols: spec.Cols})
	return finish(code)
}

// vmAcceptPTY accepts the PTY session: the first handshake from the host
// within window (a connection the peer check refuses is closed).
func vmAcceptPTY(ln net.Listener, peerOK func(net.Conn) bool, opts relaymux.Options, window time.Duration) (*relaymux.Guest, error) {
	deadline := time.Now().Add(window)
	var last error = errors.New("no connection from the host helper")
	for time.Now().Before(deadline) {
		if dl, ok := ln.(deadliner); ok {
			_ = dl.SetDeadline(deadline)
		}
		c, err := ln.Accept()
		if err != nil {
			last = err
			continue
		}
		if !peerOK(c) {
			_ = c.Close()
			last = errors.New("a connection from inside the VM was refused")
			continue
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		g, err := relaymux.DialGuest(ctx, c, opts)
		cancel()
		if err != nil {
			_ = c.Close()
			last = err
			continue
		}
		if g.PTY() == nil {
			g.Close()
			last = errors.New("the host opened no PTY stream")
			continue
		}
		if err := g.Ready(); err != nil {
			g.Close()
			return nil, err
		}
		return g, nil
	}
	return nil, last
}

// vmCloseGuestDisks closes the spec's block-device mounts (a disk_image
// copy, the install cache) through closeDisks before the exit status goes
// home: the host tears the VMM down as soon as the session ends, before PID
// 1 reaches its sync, so a guest that only synced at power-off left its
// writes in its page cache and the image's journal unrecovered (the second
// live run: a guest commit missing from the read-back). It returns the
// reason the close failed ("" when there is nothing to close or it closed).
func vmCloseGuestDisks(spec sandboxvm.GuestSpec, closeDisks func([]string) error) string {
	if closeDisks == nil || len(spec.Disks) == 0 {
		return ""
	}
	targets := make([]string, 0, len(spec.Disks))
	for _, d := range spec.Disks {
		targets = append(targets, d.Target)
	}
	if err := closeDisks(targets); err != nil {
		return "the workspace image could not be closed (" + err.Error() + "); its read-back will refuse it"
	}
	return ""
}

// vmDiskCloseOps are vmCloseDisks's system calls (the tests' seam).
type vmDiskCloseOps struct {
	killAll   func()
	sync      func()
	remountRO func(target string) error
	sleep     func(time.Duration)
	tries     int
}

// vmCloseDisks ends what is left of the agent (its files close), syncs, and
// remounts each target read-only, which writes the ext4 journal back and
// clears needs_recovery, so the host's debugfs reads the box's tree. A busy
// target is retried while the killed processes exit.
func vmCloseDisks(targets []string, ops vmDiskCloseOps) error {
	ops.killAll()
	ops.sync()
	for _, t := range targets {
		var err error
		for i := 0; i < ops.tries; i++ {
			if err = ops.remountRO(t); err == nil || !errors.Is(err, unix.EBUSY) {
				break
			}
			if i+1 < ops.tries {
				ops.sleep(100 * time.Millisecond)
			}
		}
		if err != nil {
			return fmt.Errorf("remount %s read-only: %w", t, err)
		}
	}
	return nil
}

// vmRealCloseDisks is vmCloseDisks with the guest's system calls: the
// serve child kills every other process but PID 1 (the agent has ended),
// then remounts for up to three seconds.
func vmRealCloseDisks(targets []string) error {
	if len(targets) == 0 {
		return nil
	}
	return vmCloseDisks(targets, vmDiskCloseOps{
		killAll: func() { _ = syscall.Kill(-1, syscall.SIGKILL) },
		sync:    unix.Sync,
		remountRO: func(t string) error {
			return unix.Mount("", t, "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "")
		},
		sleep: time.Sleep,
		tries: 30,
	})
}
