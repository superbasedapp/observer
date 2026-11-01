//go:build linux && !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxapple"
)

// terminal_sandbox_applecontainer_linux.go: the Apple container row's host
// side runs on macOS only, so on Linux its probe stops at the platform row
// and its host helper refuses. What runs here is the in-image init
// (sandbox-apple-init), the container's main process inside the run's
// Linux VM, as the container's root:
//
//  1. it links the host observer path the agent's hooks name to this binary;
//  2. it checks its own mounts against the plan (the in-guest check:
//     `container inspect` is no witness for this row, live 2026-10-23
//     D-A3): every planned mount is a mount point and every planned
//     read-only path a read-only one, in /proc/self/mountinfo and by
//     access(2) answering EROFS; otherwise built_below_plan and the agent
//     never starts;
//  3. it serves the capture relay's tunnel (--publish-socket, D-A4): it
//     listens in a root-only directory, accepts only a connection from
//     outside the container (the runtime's forwarder: SO_PEERCRED pid 0,
//     uid 0), runs the box side of the relay mux over it with the per-run
//     secret from the env file, and serves the relay, proxy and gateway
//     sockets in the guest socket dir for the agent's uid;
//  4. it drops to the host user's uid and gid and runs the guest helper
//     (and through it the agent) as its child, with the launch environment
//     the host sent inside the tunnel.

func appleProbeEnv(config.TerminalSandboxAppleContainerConfig) sandboxapple.ProbeEnv {
	return sandboxapple.ProbeEnv{GOOS: "linux"}
}

func appleSweep(string, string, string) {}

func runAppleHost([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox (apple-container): runs on macOS only")
	return 125
}

// appleInitFail prints an init refusal (the agent's terminal is the
// container's) and returns the helpers' fail-closed code.
func appleInitFail(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "observer sandbox (apple-container): "+format+"\n", a...)
	return 125
}

// runAppleInit is the container's main process.
func runAppleInit(args []string) int {
	ia, err := sandboxapple.ParseInitArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 127
	}
	secret := os.Getenv(sandboxapple.RelaySecretEnv)
	_ = os.Unsetenv(sandboxapple.RelaySecretEnv)
	if err := appleLinkHostBin(ia.HostBin); err != nil {
		// The hooks would not resolve; the run must not start uncaptured.
		fmt.Fprintf(os.Stderr, "observer %s: %v\n", sandboxapple.InitVerb, err)
		return 127
	}
	if v := appleGuestCheck(ia, appleReadMountInfo, appleAccessWrite); !v.OK() {
		return appleInitFail("%s", v.Error())
	}
	drop := []string{sandboxapple.RelaySecretEnv}
	env := sandboxapple.MergeEnv(os.Environ(), nil, drop)
	if ia.Relay != "" {
		if len(secret) < 32 {
			return appleInitFail("the capture relay's tunnel has no secret; the agent was not started")
		}
		tun, err := appleServeGuestTunnel(ia, []byte(secret), appleTunnelWindow)
		if err != nil {
			return appleInitFail("the capture relay's tunnel did not come up: %v; the agent was not started", err)
		}
		defer tun.stop()
		env = sandboxapple.MergeEnv(os.Environ(), tun.env, drop)
	}
	cmd := exec.Command(ia.Command[0], ia.Command[1:]...) //nolint:gosec // G204: the guest helper argv the host helper composed
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(ia.UID), Gid: uint32(ia.GID)}} //nolint:gosec // G115: checked non-negative by ParseInitArgs
	signal.Ignore(syscall.SIGINT, syscall.SIGQUIT)
	fwd := make(chan os.Signal, 4)
	signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "observer %s: %v\n", sandboxapple.InitVerb, err)
		return 127
	}
	go func() {
		for s := range fwd {
			_ = cmd.Process.Signal(s)
		}
	}()
	err = cmd.Wait()
	signal.Stop(fwd)
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	}
	return 127
}

// appleReadMountInfo reads the init's own mount table.
func appleReadMountInfo() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") }

// appleAccessWrite asks the kernel whether p may be written (access(2) as
// the container's root: only a read-only mount answers EROFS).
func appleAccessWrite(p string) error { return unix.Access(p, unix.W_OK) }

// appleGuestCheck is the in-guest check (I/O injected so a test runs it
// over a recorded table): the mountinfo judge, then the functional witness
// for every read-only path.
func appleGuestCheck(ia sandboxapple.InitArgs, mountInfo func() ([]byte, error), access func(string) error) sandboxapple.Verdict {
	below := func(why string) sandboxapple.Verdict {
		return sandboxapple.Verdict{Code: sandboxapple.VerdictBuiltBelowPlan, Reason: why + "; the agent was not started"}
	}
	b, err := mountInfo()
	if err != nil {
		return below("the box could not read its own mount table: " + err.Error())
	}
	table, err := sandboxapple.ParseMountInfo(b)
	if err != nil {
		return below(err.Error())
	}
	if v := sandboxapple.CheckGuestMounts(table, ia.Mounts, ia.ReadOnly); !v.OK() {
		return v
	}
	if bad := sandbox.ReadOnlyWitness(ia.ReadOnly, access); len(bad) > 0 {
		return below("the box read its own mounts back weaker than planned: " + strings.Join(bad, "; "))
	}
	return sandboxapple.Verdict{Code: sandboxapple.VerdictAvailable}
}

// appleTunnelWindow is how long the init waits for the host helper's first
// tunnel connection.
const appleTunnelWindow = 30 * time.Second

// appleGuestTunnel is the box side of the tunnel while the agent runs (the
// shared guestTunnel, sandbox_relaytunnel_linux.go).
type appleGuestTunnel = guestTunnel

// appleFromOutside reports whether a tunnel connection came from outside the
// container: the runtime's forwarder has no pid in the container's pid
// namespace (SO_PEERCRED pid 0) and is root (live 2026-10-24); any process
// in the box, the agent included, has a pid there.
func appleFromOutside(c net.Conn) bool {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return false
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return false
	}
	var cred *unix.Ucred
	var cerr error
	if err := rc.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || cerr != nil || cred == nil { //nolint:gosec // G115: a descriptor number
		return false
	}
	return cred.Pid == 0 && cred.Uid == 0
}

// appleTunnelPeer is the peer check (a variable so a test over a socket in
// its own pid namespace can stand it in).
var appleTunnelPeer = appleFromOutside

// appleServeGuestTunnel listens at the tunnel path, takes the first
// handshake that succeeds within window, serves the guest sockets for the
// agent and keeps accepting re-opened sessions (a re-keyed reconnect of the
// host helper) until stop.
func appleServeGuestTunnel(ia sandboxapple.InitArgs, secret []byte, window time.Duration) (*appleGuestTunnel, error) {
	return appleServeGuestTunnelAt(ia, secret, window, sandboxapple.GuestTunnelPath, sandboxapple.GuestSocketDir)
}

func appleServeGuestTunnelAt(ia sandboxapple.InitArgs, secret []byte, window time.Duration, tunnelPath, sockDir string) (*appleGuestTunnel, error) {
	dir := filepath.Dir(tunnelPath)
	// A fresh root-only directory: whatever the image put at the path is
	// removed, never followed.
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", tunnelPath)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(tunnelPath, 0o600)
	return guestTunnelServe(ln, func(c net.Conn) bool { return appleTunnelPeer(c) }, ia.Relay, secret, window, sockDir, &guestSocketOwner{uid: ia.UID, gid: ia.GID})
}

// appleLinkHostBin makes the host observer path resolve to this binary in
// the container (its own root filesystem, inside the per-run VM). An
// existing path is left alone.
func appleLinkHostBin(hostBin string) error {
	if _, err := os.Lstat(hostBin); err == nil {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(hostBin), 0o755); err != nil { //nolint:gosec // G301: a bin dir inside the container
		return err
	}
	return os.Symlink(self, hostBin)
}
