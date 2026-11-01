//go:build darwin && !sbo_omit_terminals_sandbox_apple_container && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxapple"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
)

// terminal_sandbox_applecontainer_darwin.go is the Apple container driver's
// macOS side (lane SBX-P5): the probe's facts, the CLI calls, the orphan
// sweep and the host helper. Checked against Apple container 1.6.0 on a
// bare-metal Mac (macOS 26.7.1, 2026-10-24); register section 13.9
// (MAC-11 to MAC-19, MAC-27, MAC-33).

// appleCLITimeout bounds every short CLI call (status, version, help,
// list, inspect, remove).
const appleCLITimeout = 15 * time.Second

// appleRunCLI runs one short CLI call with a minimal environment and returns
// its standard output, capped.
func appleRunCLI(argv []string) ([]byte, error) {
	if err := sandboxapple.CheckArgv(argv); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), appleCLITimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // G204: the CLI the probe resolved, with a fixed argv
	home, _ := os.UserHomeDir()
	cmd.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: 8 << 20}
	err := cmd.Run()
	return out.Bytes(), err
}

// limitedWriter keeps at most n bytes.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	q := p
	if len(q) > l.n {
		q = q[:l.n]
	}
	l.n -= len(q)
	if _, err := l.w.Write(q); err != nil {
		return 0, err
	}
	return len(p), nil
}

// appleProbeEnv reads the probe's facts.
func appleProbeEnv(cfg config.TerminalSandboxAppleContainerConfig) sandboxapple.ProbeEnv {
	return sandboxapple.ProbeEnv{
		GOOS: runtime.GOOS,
		Arm64: func() (bool, error) {
			v, err := unix.SysctlUint32("hw.optional.arm64")
			return v == 1, err
		},
		OSVersion: func() (string, error) { return unix.Sysctl("kern.osproductversion") },
		// An unknown oid (a macOS VM, live check 2026-10-22) is an error:
		// it counts as no hypervisor.
		Hypervisor: func() (bool, bool) {
			v, err := unix.SysctlUint32("kern.hv_support")
			return v == 1, err == nil
		},
		LookCLI: func() (string, error) {
			for _, p := range []string{"/usr/local/bin/container", "/opt/homebrew/bin/container"} {
				if _, err := os.Lstat(p); err == nil {
					return p, nil
				}
			}
			return exec.LookPath("container")
		},
		StatCLI: func(p string) (sandboxapple.CLIFacts, error) {
			fi, err := os.Lstat(p)
			if err != nil {
				return sandboxapple.CLIFacts{}, err
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return sandboxapple.CLIFacts{}, errors.New("no owner")
			}
			return sandboxapple.CLIFacts{
				Regular: fi.Mode().IsRegular(), OwnerOK: st.Uid == 0 || int(st.Uid) == os.Getuid(),
				Perm: uint32(fi.Mode().Perm()),
			}, nil
		},
		Version: func(cli string) (string, error) {
			b, err := appleRunCLI(sandboxapple.VersionArgv(cli))
			return string(b), err
		},
		RunHelp: func(cli string) (string, error) {
			b, err := appleRunCLI(sandboxapple.RunHelpArgv(cli))
			return string(b), err
		},
		SystemRunning: func(cli string) error { _, err := appleRunCLI(sandboxapple.StatusArgv(cli)); return err },
		Image:         cfg.Image,
		ImagePresent: func(cli, ref string) (bool, error) {
			b, err := appleRunCLI(sandboxapple.ImagesArgv(cli))
			if err != nil {
				return false, err
			}
			return sandboxapple.ImagePresent(b, ref)
		},
	}
}

// appleSweep removes this install's containers whose run is gone (daemon
// start and later probe refreshes, after a killed daemon, helper or CLI;
// MAC-17).
func appleSweep(cli, installID, observerDir string) {
	b, err := appleRunCLI(sandboxapple.ListArgv(cli))
	if err != nil {
		return
	}
	list, err := sandboxapple.ParseList(b)
	if err != nil {
		return
	}
	for _, id := range sandboxapple.Orphans(list, installID, appleRunLive(observerDir)) {
		_, _ = appleRunCLI(sandboxapple.RemoveArgv(cli, id))
	}
}

// appleRelaySecret is a fresh per-run tunnel secret (64 hex characters).
func appleRelaySecret() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// runAppleHost is the PTY child of an Apple container run.
func runAppleHost(args []string) int {
	planPath, h, inner, err := parseMacHostArgs(appleHostVerb, appleInnerMarker, args)
	if err != nil {
		return helperFail("observer sandbox (apple-container): %v", err)
	}
	var plan applePlanFile
	if err := readMacPlan(planPath, &plan); err != nil {
		return helperFail("observer sandbox (apple-container): %v", err)
	}
	defer func() { _ = os.Remove(planPath) }() //nolint:gosec // G703: the daemon's own plan path, read no-follow and owner-checked above
	if plan.Version != macPlanVersion || plan.Dirs.SocketDir != h.SockDir {
		return helperFail("observer sandbox (apple-container): the plan does not match this helper or its host services (restart the daemon after an upgrade)")
	}
	if err := ensureOwnedDir(filepath.Dir(plan.Dirs.TempDir)); err != nil {
		return helperFail("observer sandbox (apple-container): temp parent: %v", err)
	}
	if err := os.Mkdir(plan.Dirs.TempDir, 0o700); err != nil {
		return helperFail("observer sandbox (apple-container): run temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(plan.Dirs.TempDir) }() //nolint:gosec // G703: composed by the daemon under the user's temp dir

	_, stop, err := startMacHostServices(h, macServiceOpts{ProxyForward: true})
	defer stop()
	if err != nil {
		return helperFail("observer sandbox (apple-container): %v", err)
	}
	for i, hd := range plan.Hidden {
		src := appleHiddenSource(plan.Dirs, i, hd.Dir)
		if hd.Dir {
			err = os.Mkdir(src, 0o500)
		} else {
			err = os.WriteFile(src, nil, 0o400)
		}
		if err != nil {
			return helperFail("observer sandbox (apple-container): hidden stand-in: %v", err)
		}
	}
	record, err := os.ReadFile(filepath.Join(h.SockDir, sandboxrelayd.BoxRecordName)) //nolint:gosec // G304: the host services' own per-run socket dir
	if err != nil {
		return helperFail("observer sandbox (apple-container): box record: %v", err)
	}
	secret, err := appleRelaySecret()
	if err != nil {
		return helperFail("observer sandbox (apple-container): %v", err)
	}
	// The env file holds only the per-run tunnel secret: the launch
	// environment (keys included) travels inside the authenticated tunnel,
	// so it never lands in the container's stored configuration or in
	// `container inspect` (O3). The file lives in a 0700 dir under the
	// observer dir, which only the launcher reads (every Seatbelt box hides
	// the observer dir), and is removed as soon as the container has
	// started.
	envFile, removeEnv, err := writeAppleEnvFile(h.ObserverDir, h.RelayRun, []byte(sandboxapple.RelaySecretEnv+"="+secret+"\n"))
	defer removeEnv()
	if err != nil {
		return helperFail("observer sandbox (apple-container): env file: %v", err)
	}
	run := appleWithHidden(plan.Run, plan.Hidden, plan.Dirs)
	run.EnvFile = envFile
	if run.Command, err = sandboxapple.GuestCommand(appleInitSpec(run, plan.HostBin, h.RelayRun), plan.Guest, inner); err != nil {
		return helperFail("observer sandbox (apple-container): %v", err)
	}
	argv, err := sandboxapple.RunArgv(run)
	if err != nil {
		return helperFail("observer sandbox (apple-container): %v", err)
	}
	defer func() { _, _ = appleRunCLI(sandboxapple.RemoveArgv(run.CLI, run.Name)) }()

	refused := make(chan string, 2)
	end := make(chan struct{})
	var endOnce bool
	endRun := func(why string) {
		select {
		case refused <- why:
		default:
		}
		if !endOnce {
			endOnce = true
			_, _ = appleRunCLI(sandboxapple.RemoveArgv(run.CLI, run.Name))
			close(end)
		}
	}
	ends := make(chan string, 2)
	go func() {
		for why := range ends {
			endRun(why)
		}
	}()

	// The read-back runs while the container starts. It fails closed: a
	// container that reads back weaker than planned, or that cannot be read
	// back within the window (an inspect answer this build cannot parse
	// included), is removed and the CLI is stopped, which ends the run with
	// built_below_plan; a run never continues unverified. The box's own
	// in-guest check is the second witness (inspect is not a reliable one
	// on this row, D-A3).
	go func() {
		v := sandboxapple.AwaitReadBack(func() ([]byte, error) {
			return appleRunCLI(sandboxapple.InspectArgv(run.CLI, run.Name))
		}, run, sandboxapple.ReadBackWindow, sandboxapple.ReadBackClock{})
		if !v.OK() {
			ends <- v.Error()
		}
	}()

	// The capture relay's tunnel (D-A4): dial the published host end until
	// the box's init answers, then carry the relay, the proxy and the
	// gateway through it. A box whose tunnel never comes up, or is lost and
	// cannot be re-opened, ends the run: it never runs with capture
	// silently missing.
	tctx, tcancel := context.WithCancel(context.Background())
	defer tcancel()
	hostEnd := filepath.Join(h.SockDir, sandboxapple.TunnelSocketName)
	go appleTunnelHost(tctx, func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", hostEnd)
	}, relaymux.HostOptions{
		Options: relaymux.Options{RunID: h.RelayRun, Secret: []byte(secret)}, Rand: rand.Reader,
		Kinds: appleTunnelKinds(h.SockDir, h.Gateway), Dial: appleTunnelDial(h.SockDir),
		Record: record, Env: appleRunEnv(os.Environ()),
	}, appleHostTunnelWindow, removeEnv, func(err error) {
		ends <- fmt.Sprintf("the capture relay's tunnel into the box could not be opened or re-opened (%v); the run was ended, never left uncaptured", err)
	})

	// The CLI's own progress output is off (--progress none), so nothing
	// but the agent's terminal reaches the PTY.
	code := runMacChildUntil(argv, []string{"HOME=" + os.Getenv("HOME"), "TERM=" + os.Getenv("TERM"), "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}, end)
	tcancel()
	select {
	case why := <-refused:
		return helperFail("observer sandbox (apple-container): %s", why)
	default:
	}
	return code
}

// runAppleInit runs inside the container's Linux VM only.
func runAppleInit([]string) int {
	fmt.Fprintln(os.Stderr, "observer "+sandboxapple.InitVerb+": runs inside an Apple container's Linux VM only")
	return 127
}

// appleHostTunnelWindow bounds how long the host helper keeps dialing the
// tunnel before it gives the run up: the guest's init answers only after
// the container booted and its in-guest check passed.
const appleHostTunnelWindow = 45 * time.Second
