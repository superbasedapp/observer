//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// terminal_sandbox_oci_linux.go holds the oci-runc driver's real I/O on
// Linux (and WSL2): the probe's socket, stat and engine calls, the host
// helper's terminal, and the in-container init (PID 1).

// ociHost is the daemon's host for the OCI ladder.
func ociHost() sandboxoci.Host {
	if sandboxHostKind() == sandboxbackend.HostWSL2 {
		return sandboxoci.HostWSL2
	}
	return sandboxoci.HostLinux
}

// ociProbeTimeout bounds the engine calls of one probe.
const ociProbeTimeout = 5 * time.Second

// ociProbeEnv is the probe ladder's real I/O. The client is built only
// inside Query, which the ladder reaches after the socket passed.
func ociProbeEnv(ctx context.Context, cfg config.TerminalSandboxOCIConfig, observerDir string) sandboxoci.ProbeEnv {
	// The run's image: the configured one, or Observer's verified default
	// image once a signed manifest is installed (plan 12.3).
	cfg, trust := ociEffectiveConfig(cfg, observerDir)
	uid, gid := os.Getuid(), os.Getgid()
	var groups []uint32
	if gs, err := os.Getgroups(); err == nil {
		for _, g := range gs {
			groups = append(groups, uint32(g)) //nolint:gosec // G115: a group id from getgroups(2)
		}
	}
	groups = append(groups, uint32(gid)) //nolint:gosec // G115: getgid(2)
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		if d := fmt.Sprintf("/run/user/%d", uid); lexists(d) {
			runtimeDir = d
		}
	}
	var client *sandboxengine.Client
	ids := ociIdentities(observerDir)
	return sandboxoci.ProbeEnv{
		Host: ociHost(), Active: true,
		Config: sandboxoci.ProbeConfig{Socket: cfg.Socket, Image: cfg.Image, AllowRootful: cfg.AllowRootful, PodmanUserns: sandboxoci.PodmanUserns(cfg.PodmanUserns), ImageRefusal: trust.refusal},
		UID:    uint32(uid), GID: uint32(gid), Groups: groups, //nolint:gosec // G115: getuid(2) and getgid(2)
		Endpoint: sandboxoci.EndpointEnv{
			DockerHost: os.Getenv("DOCKER_HOST"), ContainerHost: os.Getenv("CONTAINER_HOST"),
			RuntimeDir: runtimeDir, Exists: lexists,
		},
		StatSocket: statSocketChain,
		Query: func(path string) (sandboxoci.VersionFacts, sandboxoci.InfoFacts, error) {
			c, err := sandboxengine.New(path)
			if err != nil {
				return sandboxoci.VersionFacts{}, sandboxoci.InfoFacts{}, err
			}
			qctx, cancel := context.WithTimeout(ctx, ociProbeTimeout)
			defer cancel()
			v, err := c.Version(qctx)
			if err != nil {
				return v, sandboxoci.InfoFacts{}, err
			}
			pre, _ := sandboxoci.Classify(v, sandboxoci.InfoFacts{})
			info, err := c.Info(qctx, pre.Engine)
			if err != nil {
				return v, info, err
			}
			client = c
			return v, info, nil
		},
		Recorded: func(p string) (sandboxoci.Identity, bool) {
			id, ok := ids[p]
			return id, ok
		},
		ImagePresent: func(ref string) (bool, error) {
			if client == nil {
				return false, errors.New("no engine client")
			}
			qctx, cancel := context.WithTimeout(ctx, ociProbeTimeout)
			defer cancel()
			return client.ImagePresent(qctx, ref)
		},
		Resolvers: hostResolvers,
	}
}

// lexists reports whether p exists, without following a final symlink.
func lexists(p string) bool {
	_, err := os.Lstat(p) //nolint:gosec // G703: a metadata read; the callers pass paths from the run's own plan
	return err == nil
}

// hostResolvers lists the nameservers of /etc/resolv.conf.
func hostResolvers() []string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}

// statSocketChain reads the socket and every parent with lstat (no
// symlink is followed anywhere on the path).
func statSocketChain(p string) (sandboxoci.SocketFacts, error) {
	f := sandboxoci.SocketFacts{Path: p}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return f, fmt.Errorf("%q is not a clean absolute path", p)
	}
	dir := filepath.Dir(p)
	var chain []string
	for d := dir; ; d = filepath.Dir(d) {
		chain = append([]string{d}, chain...)
		if d == "/" {
			break
		}
	}
	for _, d := range chain {
		var st unix.Stat_t
		if err := unix.Lstat(d, &st); err != nil {
			return f, err
		}
		f.Parents = append(f.Parents, sandboxoci.PathFact{
			Path: d, Symlink: st.Mode&unix.S_IFMT == unix.S_IFLNK, UID: st.Uid, Mode: st.Mode & 0o7777,
		})
	}
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOENT) {
			return f, nil
		}
		return f, err
	}
	f.Exists = true
	f.IsSocket = st.Mode&unix.S_IFMT == unix.S_IFSOCK
	f.UID, f.GID, f.Mode = st.Uid, st.Gid, st.Mode&0o7777
	return f, nil
}

// readOwnedNoFollow reads a small regular file owned by this user,
// refusing a symlink.
func readOwnedNoFollow(p string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G703: a fixed file under the observer dir, opened no-follow and owner-checked below
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, fmt.Errorf("terminal_sandbox: %s is not a small regular file", p)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return nil, fmt.Errorf("terminal_sandbox: %s is not yours", p)
	}
	b := make([]byte, fi.Size())
	if _, err := f.Read(b); err != nil && fi.Size() > 0 {
		return nil, err
	}
	return b, nil
}

// ociCreateExcl creates p fresh (0600), refusing an existing path or a
// symlink.
func ociCreateExcl(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G703: callers pass paths under the observer's own owner-only state dirs; no link is followed and nothing existing is opened
}

// ociCheckSocket repeats the socket rules in the host helper, right before
// it drives the engine (the daemon's probe is up to a minute old).
func ociCheckSocket(plan ociPlanFile) error {
	f, err := statSocketChain(plan.Socket)
	if err != nil {
		return fmt.Errorf("%s: %w", sandboxoci.VerdictEngineUnreachable, err)
	}
	var groups []uint32
	if gs, gerr := os.Getgroups(); gerr == nil {
		for _, g := range gs {
			groups = append(groups, uint32(g)) //nolint:gosec // G115: getgroups(2)
		}
	}
	groups = append(groups, uint32(os.Getgid()))                                             //nolint:gosec // G115: getgid(2)
	owner, v := sandboxoci.ValidateSocket(f, uint32(os.Getuid()), groups, plan.AllowRootful) //nolint:gosec // G115: getuid(2)
	if !v.OK() {
		return v
	}
	if v := sandboxoci.CheckOwnerMode(owner, sandboxoci.Identity{Mode: plan.Mode}); !v.OK() {
		return v
	}
	return nil
}

// runOCIHost is the PTY child of an oci-runc run.
func runOCIHost(args []string) int {
	if len(args) > 0 && args[0] == ociDeferredFlag {
		// A dashboard launch whose default image is pulled after the
		// terminal opened (R-037): show the daemon's lines, then run the
		// real host step it planned.
		real, code := ociWaitDeferred(args, os.Stdout, ociDeferredWait(), time.Sleep)
		if real == nil {
			return code
		}
		args = real
	}
	t, done := realOCITerm()
	defer done()
	return runOCIHostWith(args, t, ociCheckSocket)
}

// realOCITerm is the helper's terminal: its stdio, the PTY's size, SIGWINCH
// as resizes, SIGHUP and SIGTERM as stop requests, raw mode when stdin is a
// terminal. SIGINT and SIGQUIT are ignored: in raw mode the keys reach the
// container's own terminal as bytes.
func realOCITerm() (ociTerm, func()) {
	resized := make(chan struct{}, 1)
	stopped := make(chan string, 2)
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, unix.SIGWINCH, unix.SIGHUP, unix.SIGTERM)
	signal.Ignore(unix.SIGINT, unix.SIGQUIT)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-quit:
				return
			case s := <-sigs:
				switch s {
				case unix.SIGWINCH:
					select {
					case resized <- struct{}{}:
					default:
					}
				default:
					select {
					case stopped <- s.String():
					default:
					}
				}
			}
		}
	}()
	fd := int(os.Stdin.Fd()) //nolint:gosec // G115: a descriptor number
	t := ociTerm{
		in: os.Stdin, out: os.Stdout, resized: resized, stopped: stopped,
		size: func() (uint16, uint16) {
			ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
			if err != nil {
				return 0, 0
			}
			return ws.Row, ws.Col
		},
		interactive: func() bool { return term.IsTerminal(fd) },
		raw: func() func() {
			if !term.IsTerminal(fd) {
				return func() {}
			}
			restore, err := ociEnterRaw(fd)
			if err != nil {
				return func() {}
			}
			return restore
		},
	}
	return t, func() {
		signal.Stop(sigs)
		close(quit)
	}
}

// ociEnterRaw puts the terminal on fd in raw mode as term.MakeRaw does, but
// sets it with TCSETSF (tcsetattr TCSAFLUSH): input the terminal received
// and nothing read yet is discarded as the mode changes. Linux live check
// 2026-10-23 (R3): the launch's terminal is still canonical while the
// container is created, and an end of file it receives in that time (the
// typescript's own Ctrl-D when its input ends, or a typed one) waits in the
// canonical buffer as the line discipline's NUL marker; set with TCSETS,
// that marker became a readable NUL byte, the helper sent it to the box as
// a keystroke, and the box's still-canonical terminal echoed it as "^@"
// before the launcher's first line (two printable bytes, so ociNoNUL on the
// output side could not drop it). What is discarded was typed under the
// host's own line editing before the box existed. It returns the restore.
func ociEnterRaw(fd int) (func(), error) {
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	raw := *old
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETSF, &raw); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }, nil
}

// runOCIInit is the container's main process, PID 1 in its PID namespace
// (section 4.6, sandboxoci.ContainerInit): it starts the inner launch in
// its own process group made the terminal's foreground (setpgid plus
// tcsetpgrp, never setsid), ignores SIGTTOU and SIGTTIN itself, forwards
// SIGTERM, SIGHUP, SIGINT and SIGQUIT to the inner launch and SIGWINCH to
// its group, reaps every child, and exits with the inner launch's status.
//
// With --db-copy <dir> (the oci-runsc row's projected state directories,
// lane SBX-P3B) it then runs the db-copy one-shot in each directory, inside
// the box where the stores' locks hold, before it exits with the inner
// launch's status.
func runOCIInit(args []string) int {
	dbCopy, launch, ok := parseOCIInitArgs(args)
	if !ok {
		fmt.Fprintln(os.Stderr, "observer sandbox-oci-init: usage: sandbox-oci-init [--db-copy <dir>]... -- <launch>")
		return 127
	}
	code := ociInit(launch, int(os.Stdin.Fd())) //nolint:gosec // G115: a descriptor number
	ociInitDBCopies(dbCopy)
	return code
}

// parseOCIInitArgs reads `[--db-copy <dir>]... -- <launch...>`.
func parseOCIInitArgs(args []string) (dbCopy, launch []string, ok bool) {
	for len(args) >= 2 && args[0] == ociInitDBCopyFlag {
		dbCopy = append(dbCopy, args[1])
		args = args[2:]
	}
	if len(args) < 2 || args[0] != "--" {
		return nil, nil, false
	}
	return dbCopy, args[1:], true
}

// ociInitDBCopies runs the db-copy one-shot in each projected state
// directory, into its .observer-dbcopy.
func ociInitDBCopies(dbCopy []string) {
	for _, dir := range dbCopy {
		req, ok := sandbox.ParseDBCopyArgs([]string{sandbox.DBCopyRootFlag, dir, sandbox.DBCopyOutFlag, filepath.Join(dir, sandboxoci.DBCopyDirName)})
		if !ok {
			fmt.Fprintf(os.Stderr, "observer sandbox-oci-init: %s is not a projected state directory\n", dir)
			continue
		}
		if _, err := guestDBCopy(req); err != nil {
			fmt.Fprintf(os.Stderr, "observer sandbox-oci-init: db-copy in %s: %v\n", dir, err)
		}
	}
}

// ociInit is runOCIInit over a chosen terminal descriptor (tests pass a
// pty slave).
func ociInit(argv []string, ttyFD int) int {
	plan := sandboxoci.ContainerInit()
	if plan.ReapAll {
		// PID 1 of a container reaps orphans by being PID 1; the subreaper
		// bit gives the same duty when it is not (a test, a nested run).
		_ = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
	}
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, unix.SIGTERM, unix.SIGHUP, unix.SIGINT, unix.SIGQUIT, unix.SIGWINCH, unix.SIGCHLD)
	defer signal.Stop(sigs)

	// The box's OOB socket (lane SBX-P3C): its connection becomes the
	// launcher's fd 3; with none the launch is exactly as planned.
	argv, env, extra, stopOOB := ociInitOOB(argv, os.Environ())
	defer stopOOB()
	//nolint:gosec // G204: argv is the planned inner launch (the guest helper and the observer launcher), never client input
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env, cmd.ExtraFiles = env, extra
	attr := &syscall.SysProcAttr{Setpgid: plan.NewProcessGroup}
	if plan.Foreground && term.IsTerminal(ttyFD) {
		// Go makes the child's new group the terminal's foreground in the
		// child itself, before exec, with signals blocked (so its own
		// tcsetpgrp raises no SIGTTOU), and Ctty is the child's fd 0.
		attr.Foreground, attr.Ctty = true, 0
	}
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "observer sandbox-oci-init: start %s: %v\n", filepath.Base(argv[0]), err)
		return 127
	}
	// Ignored only after the start, so the inner launch does not inherit
	// the ignore.
	ignore := make([]os.Signal, 0, len(plan.Ignore))
	for _, name := range plan.Ignore {
		if s := unix.SignalNum(name); s != 0 {
			ignore = append(ignore, s)
		}
	}
	signal.Ignore(ignore...)
	pid := cmd.Process.Pid
	for {
		if code, ok := reapChildren(pid); ok {
			return code
		}
		s := <-sigs
		switch s {
		case unix.SIGCHLD:
		case unix.SIGWINCH:
			_ = unix.Kill(-pid, unix.SIGWINCH)
		default:
			if sig, ok := s.(syscall.Signal); ok {
				_ = unix.Kill(pid, sig)
			}
		}
	}
}

// reapChildren reaps every exited child; it reports the inner launch's
// exit status once that child is reaped.
func reapChildren(inner int) (int, bool) {
	for {
		var ws unix.WaitStatus
		wpid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
		if err != nil || wpid <= 0 {
			return 0, false
		}
		if wpid == inner {
			return sandboxoci.ExitCode(ws.Exited(), ws.ExitStatus(), ws.Signaled(), int(ws.Signal())), true
		}
	}
}
