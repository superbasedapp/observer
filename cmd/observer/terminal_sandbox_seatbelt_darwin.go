//go:build darwin && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxsbpl"
)

// terminal_sandbox_seatbelt_darwin.go is the Seatbelt driver's macOS side
// (lane SBX-P5): the probe's facts (kern.osproductversion and a no-follow
// stat of /usr/bin/sandbox-exec), the host helper that builds the profile
// and runs the self-test then the agent under sandbox-exec, the self-test
// itself, and the box side of the hook path. Built from vendor
// documentation and cross-compiled only; register section 13.9.

// init points the hook client inside a Seatbelt box at the run's own socket
// dir. A Seatbelt box shares the host's /tmp, so the box record cannot sit
// at the fixed guest path bwrap and a container use; the helper names the
// dir in sandboxsbpl.EnvSocketDir, honoured only with the sandbox marker
// (an unsandboxed host process never carries it: isInternalChildEnv strips
// it from inherited environments).
func init() {
	if os.Getenv(sandboxEnvMarker) != "1" {
		return
	}
	d := os.Getenv(sandboxsbpl.EnvSocketDir)
	if d == "" || !filepath.IsAbs(d) || filepath.Clean(d) != d {
		return
	}
	boxSocketDir = d
	boxRecordPath = filepath.Join(d, sandboxrelayd.BoxRecordName)
	relaySpoolDir = filepath.Join(os.TempDir(), ".observer-relay-spool")
}

// seatbeltProbeEnv reads the probe's facts.
func seatbeltProbeEnv() sandboxsbpl.ProbeEnv {
	return sandboxsbpl.ProbeEnv{
		GOOS: runtime.GOOS,
		// The driver is read with the facts, so the declared fallback is
		// refused by name before anything is stat'ed (lane SBX-UPD, MAC-10).
		Driver:    seatbeltConfiguredDriver(),
		OSVersion: func() (string, error) { return unix.Sysctl("kern.osproductversion") },
		StatExec: func(p string) (sandboxsbpl.ExecFacts, error) {
			fi, err := os.Lstat(p)
			if err != nil {
				return sandboxsbpl.ExecFacts{}, err
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return sandboxsbpl.ExecFacts{}, errors.New("no owner")
			}
			return sandboxsbpl.ExecFacts{Regular: fi.Mode().IsRegular(), OwnerUID: st.Uid, Perm: uint32(fi.Mode().Perm())}, nil
		},
	}
}

// seatbeltInheritedTTY names the PTY slave on the helper's stdin, verified
// by device number; empty when stdin is not a pseudo-terminal.
func seatbeltInheritedTTY() string {
	var st unix.Stat_t
	if err := unix.Fstat(0, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR {
		return ""
	}
	name := sandboxsbpl.TTYName(uint32(st.Rdev) & 0xffffff) //nolint:gosec // G115: the minor bits of a device number
	var named unix.Stat_t
	if err := unix.Stat(name, &named); err != nil || named.Rdev != st.Rdev {
		return ""
	}
	return name
}

// runSeatbeltHost is the PTY child of a Seatbelt run.
func runSeatbeltHost(args []string) int {
	planPath, h, inner, err := parseMacHostArgs(seatbeltHostVerb, seatbeltInnerMarker, args)
	if err != nil {
		return helperFail("observer sandbox (seatbelt): %v", err)
	}
	var plan seatbeltPlanFile
	if err := readMacPlan(planPath, &plan); err != nil {
		return helperFail("observer sandbox (seatbelt): %v", err)
	}
	defer func() { _ = os.Remove(planPath) }() //nolint:gosec // G703: the daemon's own plan path, read no-follow and owner-checked above
	// D-MU7: the plan's lock proves this run live to the daemon's sweep
	// (terminal_sandbox_macplan_sweep_unix.go) for as long as this helper
	// runs, a SIGKILL included.
	releasePlan, err := lockMacPlan(planPath)
	if err != nil {
		return helperFail("observer sandbox (seatbelt): %v", err)
	}
	defer releasePlan()
	if plan.Version != macPlanVersion {
		return helperFail("observer sandbox (seatbelt): plan version %d, this binary reads %d (restart the daemon after an upgrade)", plan.Version, macPlanVersion)
	}
	if plan.Dirs.SocketDir != h.SockDir {
		return helperFail("observer sandbox (seatbelt): the plan and the host services name different socket dirs")
	}
	if err := ensureOwnedDir(filepath.Dir(plan.Dirs.TempDir)); err != nil {
		return helperFail("observer sandbox (seatbelt): temp parent: %v", err)
	}
	if err := os.Mkdir(plan.Dirs.TempDir, 0o700); err != nil {
		return helperFail("observer sandbox (seatbelt): run temp dir: %v", err)
	}
	defer seatbeltRemoveRunDirs(plan.Dirs)

	svc, stop, err := startMacHostServices(h, macServiceOpts{GatewayTCP: true})
	defer stop()
	if err != nil {
		return helperFail("observer sandbox (seatbelt): %v", err)
	}
	req := plan.Profile
	// Build re-checks every path the daemon resolved against the
	// filesystem now (the run's own dirs exist by this point).
	req.Resolve = sandboxCanonicalPath
	req.Net.GatewayPort = svc.GatewayPort
	req.TTY = seatbeltInheritedTTY()
	prof, err := sandboxsbpl.Build(req)
	if err != nil {
		return helperFail("observer sandbox (seatbelt): %v", err)
	}
	if _, err := sandboxsbpl.Check(prof.Text, prof.ParamMap()); err != nil {
		return helperFail("observer sandbox (seatbelt): the profile failed its own check: %v", err)
	}

	env := seatbeltAgentEnv(os.Environ(), plan.Dirs, svc.GatewayPort, plan.NativeEnv, plan.TempDirEnv)
	env = sandboxenv.WithJVMTempDir(env, plan.TempDirJVMEnv, plan.Dirs.TempDir)
	// N3: a JVM ignores the gateway's HTTPS_PROXY; give it the properties.
	env = sandboxenv.WithJVMOptions(env, plan.TempDirJVMEnv, sandboxenv.JVMProxyOptions(env))
	if seatbeltHomeBlinded(req) {
		// D-MU4: git sees bwrap's view, no global config and no global
		// ignore file (terminal_sandbox_seatbelt_git.go).
		var files []seatbeltRunFile
		env, files = seatbeltWithGitIsolation(env, plan.Dirs.TempDir)
		for _, f := range files {
			if err := writeSeatbeltRunFile(f); err != nil {
				return helperFail("observer sandbox (seatbelt): %v", err)
			}
		}
	}
	if v := seatbeltSelfTest(prof, req, env); !v.OK() {
		return helperFail("observer sandbox (seatbelt): %s", v.Error())
	}
	argv := prof.Argv(sandboxsbpl.SandboxExecPath, inner)
	if argv == nil {
		return helperFail("observer sandbox (seatbelt): the inner launch is not a program")
	}
	return runMacChild(argv, env)
}

// writeSeatbeltRunFile creates one run-local file (0600, never through a
// link: the run's TMPDIR was just made 0700 by this helper).
func writeSeatbeltRunFile(f seatbeltRunFile) error {
	fh, err := os.OpenFile(f.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: a fixed name inside the run's own TMPDIR
	if err != nil {
		return fmt.Errorf("run file %s: %w", filepath.Base(f.Path), err)
	}
	if _, err := fh.WriteString(f.Content); err != nil {
		_ = fh.Close()
		return fmt.Errorf("run file %s: %w", filepath.Base(f.Path), err)
	}
	return fh.Close()
}

// seatbeltSelfTest runs the self-test under the very profile and reads its
// verdict (section 4.4's read-back for this row).
func seatbeltSelfTest(prof sandboxsbpl.Profile, req sandboxsbpl.Request, env []string) sandboxsbpl.Verdict {
	argv := prof.Argv(sandboxsbpl.SandboxExecPath, seatbeltSelfTestArgv(req.ObserverBin, req))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: Apple's sandbox-exec with this helper's own profile
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return sandboxsbpl.Verdict{Code: sandboxsbpl.VerdictSelfTestFailed, Reason: "the self-test did not run under sandbox-exec: " + err.Error()}
	}
	rep, err := sandboxsbpl.ParseSelfTest(strings.TrimSpace(out.String()))
	if err != nil {
		return sandboxsbpl.Verdict{Code: sandboxsbpl.VerdictSelfTestFailed, Reason: err.Error()}
	}
	return sandboxsbpl.JudgeSelfTest(rep, seatbeltHomeBlinded(req))
}

// runSeatbeltSelfTest runs INSIDE the profile: it tries what the profile
// must refuse and what it must allow, and prints one report line.
func runSeatbeltSelfTest(args []string) int {
	flags, err := seatbeltSelfTestFlags(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	listable := func(p string) bool { _, err := os.ReadDir(p); return err == nil }
	writable := func(dir string) bool {
		f, err := os.CreateTemp(dir, ".observer-selftest-*")
		if err != nil {
			return false
		}
		name := f.Name()
		_ = f.Close()
		return os.Remove(name) == nil
	}
	rep := sandboxsbpl.SelfTestReport{
		ObserverDirReadable:  listable(flags["--obs"]),
		SocketParentReadable: listable(flags["--sockp"]),
		HomeListable:         listable(flags["--home"]),
		ForbiddenConnect:     seatbeltConnectGotThrough(),
		WorkspaceWritable:    writable(flags["--ws"]),
		TempWritable:         writable(flags["--tmp"]),
	}
	fmt.Println(rep.String())
	return 0
}

// seatbeltConnectGotThrough tries a loopback port no tier allows: Seatbelt
// refuses it with EPERM; any other answer (refused, reset, accepted) means
// the connect reached the network stack, so the profile let it through.
func seatbeltConnectGotThrough() bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(seatbeltForbiddenPort)), 2*time.Second)
	if err == nil {
		_ = c.Close()
		return true
	}
	return !errors.Is(err, syscall.EPERM)
}

// seatbeltForbiddenPort is the loopback port the self-test tries: a port no
// tier ever allows (tcpmux), so a refused connect proves the profile and an
// "connection refused" proves its absence.
const seatbeltForbiddenPort = 1

// seatbeltRemoveRunDirs removes the run's TMPDIR (the agent's temp files)
// on the helper's way out (the host services remove the socket dir).
func seatbeltRemoveRunDirs(dirs macRunDirs) {
	_ = os.RemoveAll(dirs.TempDir) //nolint:gosec // G703: composed by the daemon under the user's own temp dir
}

// seatbeltConfiguredDriver reads [terminal.sandbox.seatbelt].driver (with
// the org's pins applied) from the daemon's config file, or the default
// lookup for a CLI launch; "" (sandbox-exec) when it cannot be read (lane
// SBX-UPD, register MAC-10).
func seatbeltConfiguredDriver() string {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()})
	if err != nil {
		return ""
	}
	return cfg.Terminal.Sandbox.Seatbelt.Driver
}
