//go:build linux && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	exthost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// terminal_sandbox_openshell_linux.go is the Linux half of the OpenShell
// driver: the host facts the probe reads (the kernel's Landlock ABI, the
// docker group, the gateway's bind-mount opt-in), the run lock, the host
// helper that runs the interactive create on the run's terminal, and the
// in-box init.

// openShellGuestLink is sandbox.GuestSocketDir, the guest path the init
// below reads. It is a variable only so that TestOpenShellBoxInitComposed's
// child (the test binary, never the product) can point the init at a
// per-test path instead of the fixed host path (F-023 V10); nothing in the
// product writes it.
var openShellGuestLink = sandbox.GuestSocketDir

// init points the relay clients inside an OpenShell box (the hook client
// and the launcher's box gate) at the run's real socket dir, which the
// in-box init names in openShellEnvSocketDir: read through the guest
// path's link, the relay's private-directory check refuses the launch
// record (live run O1B-L1). Honoured only with the sandbox marker and only
// while the guest path is a link to exactly that dir. The variable is this
// row's own: the process_lite init (terminal_sandbox_landlock_linux.go,
// which runs before this one in file order) reads only the shared
// OBSERVER_SANDBOX_SOCK_DIR, which the openshell init drops, so in an
// OpenShell box this guard alone decides (TestOpenShellBoxInitComposed
// runs the built binary to pin it). relaySpoolDir keeps its default,
// /tmp/.observer-relay-spool: the box's /tmp is the container's own and
// writable to the workload.
func init() {
	if os.Getenv(sandboxEnvMarker) != "1" {
		return
	}
	d, ok := openShellBoxSocketDir(os.Getenv(openShellEnvSocketDir), openShellGuestLink, os.Readlink)
	if !ok {
		return
	}
	boxSocketDir = d
	boxRecordPath = filepath.Join(d, sandboxrelayd.BoxRecordName)
}

// openShellHostFacts reads the host facts.
func openShellHostFacts() openShellHostFactsT {
	return openShellHostFactsT{
		LandlockABI: func() int {
			v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
			if errno != 0 {
				return 0
			}
			return int(v) //nolint:gosec // G115: a small ABI number
		},
		DockerGroup: openShellInDockerGroup,
		IDs:         func() (int, int) { return os.Getuid(), os.Getgid() },
		BindMounts: func(driver string) sandboxopenshell.Tri {
			home, err := os.UserHomeDir()
			if err != nil {
				return sandboxopenshell.TriUnknown
			}
			b, rerr := openShellReadOwned(openShellGatewayConfigPath(os.Getenv, home), 1<<20)
			return openShellBindMountsFrom(b, rerr, driver)
		},
		GatewayImages: func(driver string) sandboxopenshell.RuntimeImages {
			home, err := os.UserHomeDir()
			if err != nil {
				return sandboxopenshell.RuntimeImages{}
			}
			b, rerr := openShellReadOwned(openShellGatewayConfigPath(os.Getenv, home), 1<<20)
			return openShellImagesFrom(b, rerr, driver)
		},
	}
}

// runOpenShellCanary is the runtime canary inside its container
// (sandboxopenshell.CanaryArgv): it asks landlock_create_ruleset for the
// Landlock ABI (the VERSION flag) under the runtime's default seccomp
// profile and prints lane O0's marker line, "<return> <errno>" ("4 0" is
// ABI 4, "-1 38" is ENOSYS). It exits 0 once it printed: the answer is the
// line, never the exit code.
func runOpenShellCanary([]string) int {
	v, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		fmt.Printf("%s-1 %d\n", sandboxopenshell.CanaryMarker, int(errno))
		return 0
	}
	fmt.Printf("%s%d 0\n", sandboxopenshell.CanaryMarker, int(v)) //nolint:gosec // G115: a small ABI number
	return 0
}

// openShellInDockerGroup reports whether this process carries the docker
// group (decision D4: root-equivalent, said plainly).
func openShellInDockerGroup() bool {
	g, err := user.LookupGroup("docker")
	if err != nil {
		return false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return false
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	return slices.Contains(groups, gid) || os.Getgid() == gid
}

// openShellReadOwned reads a small regular file owned by this user,
// refusing a symlink; opened non-blocking, so a FIFO is refused, not
// waited on.
func openShellReadOwned(p string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: a fixed file of the row's state or the user's own gateway config, opened no-follow and owner-checked below
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
	return io.ReadAll(io.LimitReader(f, limit))
}

// openShellLockName is the run lock's file in a run dir.
const openShellLockName = "lock"

// openShellHoldRun takes the run's lock for the host helper's life: the
// reaper never touches a run whose lock is held. The lock dies with the
// process, so a killed helper's run is the reaper's.
func openShellHoldRun(runDir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(runDir, openShellLockName), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: the run dir the daemon made for this run
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil { //nolint:gosec // G115: a file descriptor
		_ = f.Close()
		return nil, fmt.Errorf("the run is already held by another helper: %w", err)
	}
	return func() { _ = f.Close() }, nil
}

// openShellRemoveSockDir removes an abandoned run's socket dir, whose path
// the plan names (audit finding O1B-A11): only the clean absolute dir
// observer-sbx-<run id> directly under the socket root this runtime uses
// (audit finding O1B-R2), owned by this user and not a link; a missing one
// is nothing to do. The reaper calls it only for a run no helper holds.
func openShellRemoveSockDir(pf openShellPlanFile) error {
	d := pf.SockDir
	if pf.RunID == "" || !filepath.IsAbs(d) || filepath.Clean(d) != d || d != openShellSockDir(pf.RunID) {
		return fmt.Errorf("the plan's socket dir %q is not this run's", d)
	}
	fi, err := os.Lstat(d)
	if errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", d)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not yours", d)
	}
	return os.RemoveAll(d) //nolint:gosec // G703: the run's own socket dir, checked above
}

// openShellRunHeld reports whether a host helper holds the run's lock.
func openShellRunHeld(runDir string) bool {
	f, err := os.OpenFile(filepath.Join(runDir, openShellLockName), os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: a run dir under the row's own state dir
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil { //nolint:gosec // G115: a file descriptor
		return errors.Is(err, unix.EWOULDBLOCK)
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN) //nolint:gosec // G115: a file descriptor
	return false
}

// runOpenShellHost is the host helper: `observer sandbox-openshell-host
// --plan <file> -- observer sandbox-host <relay flags> --
// observer-openshell-inner <launch>`. It holds the run, starts the host
// services (the capture relay over the run's socket dir, rule W5), stages
// the copied files and the environment file, runs the interactive create
// as its own child on the run's terminal, syncs the copies back, and
// deletes the box through the pinned gateway.
func runOpenShellHost(args []string) int {
	planPath, h, err := parseOpenShellHostArgs(args)
	if err != nil {
		return helperFail("observer sandbox (openshell): %v", err)
	}
	pf, err := openShellReadPlan(planPath)
	if err != nil {
		return helperFail("observer sandbox (openshell): %v", err)
	}
	if h.SockDir != pf.SockDir || h.RelayRun != pf.RunID {
		return helperFail("observer sandbox (openshell): the plan's socket dir or run does not match the host services' flags")
	}
	runDir := filepath.Dir(planPath)
	unhold, err := openShellHoldRun(runDir)
	if err != nil {
		return helperFail("observer sandbox (openshell): %v", err)
	}
	defer unhold()
	stop, err := startHostServices(h)
	release := sync.OnceFunc(stop)
	defer release()
	if err != nil {
		return helperFail("observer sandbox (openshell): %v", err)
	}
	staged := openShellStagedNames(pf)
	present, err := openShellStage(pf, staged)
	if err != nil {
		return helperFail("observer sandbox (openshell): %v", err)
	}
	env := openShellHelperEnv(h, openShellBoxEnv(os.Environ(), pf.DropEnv...))
	envFile := filepath.Join(pf.CopyDir, openShellEnvFileName)
	if err := openShellWriteExcl(envFile, openShellEncodeEnv(env)); err != nil {
		return helperFail("observer sandbox (openshell): write the box environment: %v", err)
	}
	command := append(openShellInitArgv(pf, staged, envFile), h.Command...)
	argv, err := openShellCreateArgv(pf, pf.Env, command)
	if err != nil {
		return helperFail("observer sandbox (openshell): %v", err)
	}
	cli, err := openShellResolveCLI(context.Background())
	if err != nil {
		return helperFail("observer sandbox (openshell): %v", err)
	}
	// The gateway name must still answer from the server the probe read
	// (audit finding O1B-A14): a name re-registered for another server
	// between the plan and the create is not the run's gateway.
	sctx, scancel := context.WithTimeout(context.Background(), openShellCmdTimeout)
	matches := openShellServerMatches(sctx, openShellRunner(), openShellPin{Target: pf.Target, Server: pf.Server})
	scancel()
	if !matches {
		return helperFail("observer sandbox (openshell): the gateway %s no longer answers from %s, the server it was checked on; the run is refused", openShellTargetName(pf.Target), pf.Server)
	}
	argv[0] = cli
	stopBoxID := openShellTrackBoxID(pf, runDir) // lane O3: the OCSF receiver's box id
	// Lane FU8 (OSH-40): compare the box's effective policy with its rules;
	// a stop the gateway does not carry out ends the supervised child.
	child := &openShellChild{}
	stopEffective := openShellWatchEffectivePolicy(pf, child.kill)
	code := runSupervisedChild(argv, openShellHostCLIEnv(pf.Target), nil, func(pid int) error {
		child.set(pid)
		return nil
	})
	child.clear()
	stopEffective()
	stopBoxID()
	openShellAfterRun(pf, staged, present, runDir)
	release()
	return code
}

// openShellHelperEnv is the box's environment as the host helper builds
// it from boxEnv, the shared allow-list's output (openShellBoxEnv): the
// tier from the helper's own flags, and the credential custody of
// internal/sandboxcred (rule W6, localCredBoxEnv): with a credential lane
// the box holds the run's sentinel, never the key. It goes into the env
// file, never onto the create argv.
func openShellHelperEnv(h sandbox.HostArgs, boxEnv []string) []string {
	return localCredBoxEnv(h, withSandboxTier(boxEnv, h))
}

// openShellHostCLIEnv is the environment of the openshell CLI the host
// helper runs on this machine (the interactive create, which talks to the
// gateway): openShellCLIEnv's fixed list plus the target's gateway
// variables. It never reaches the box; the box's environment is the env
// file openShellHelperEnv builds.
func openShellHostCLIEnv(t sandboxopenshell.Target) []string {
	return openShellCLIEnvFor(os.Environ(), t)
}

// openShellAfterRun syncs the copied files back and deletes the box
// through the pinned gateway; the run dir goes only once the box is shown
// gone (the reaper keeps trying otherwise). Only a file the host had at
// staging is synced back (present, from openShellStage): the box never
// creates a host file the host did not have (OSH-8, audit finding
// O1B-A7), whatever it writes into the copy dir.
func openShellAfterRun(pf openShellPlanFile, staged []string, present []bool, runDir string) {
	for i, c := range pf.CopySync {
		if i >= len(present) || !present[i] {
			continue
		}
		if err := openShellSyncBack(staged[i], c.Source); err != nil {
			fmt.Fprintf(os.Stderr, "\r\n[observer: %s was not synced back from the box: %v]\r\n", c.Source, err)
		}
	}
	_ = os.RemoveAll(pf.CopyDir)
	ctx, cancel := context.WithTimeout(context.Background(), 2*openShellCmdTimeout)
	defer cancel()
	switch openShellDeleteBox(ctx, openShellRunner(), pf) {
	case sandboxopenshell.OutcomeGone:
		_ = os.RemoveAll(runDir) //nolint:gosec // G703: the run dir the daemon made for this run (the plan file's own dir)
	default:
		fmt.Fprintf(os.Stderr, "\r\n[observer: the box %s was not shown gone on gateway %s; the daemon's reaper keeps trying]\r\n", pf.Name, openShellTargetName(pf.Target))
	}
}

// openShellStatBinaryFacts reads the trust rule's facts about a resolved
// OpenShell program (ledger row OSH-44): its real path, the real file's
// owner and mode, and those of its directory and every parent up to /.
func openShellStatBinaryFacts(program, path string) sandboxopenshell.BinaryTrustFacts {
	f := sandboxopenshell.BinaryTrustFacts{Program: program, Path: path}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		f.Detail = err.Error()
		return f
	}
	f.Real = real
	owner := func(p string) (sandboxopenshell.PathOwner, error) {
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			return sandboxopenshell.PathOwner{}, err
		}
		return sandboxopenshell.PathOwner{Path: p, UID: int(st.Uid), Mode: st.Mode & 0o7777}, nil
	}
	if f.File, err = owner(real); err != nil {
		f.Detail = err.Error()
		return f
	}
	for d := filepath.Dir(real); ; d = filepath.Dir(d) {
		o, err := owner(d)
		if err != nil {
			f.Detail = err.Error()
			return f
		}
		f.Dirs = append(f.Dirs, o)
		if d == filepath.Dir(d) {
			break
		}
	}
	f.Read = true
	return f
}

// openShellResolveCLI resolves the openshell CLI the way the runner does
// (toolresolve with Observer's shims excluded, then the runner's own file
// checks): the interactive create cannot go through Runner.Run, which
// captures the program's output, so the helper resolves and checks it here
// and starts it on the run's terminal with fixed argv.
func openShellResolveCLI(ctx context.Context) (string, error) {
	_ = ctx
	r := openShellRunner()
	if r.Resolve == nil {
		return "", errors.New("the runner has no resolver")
	}
	prog, why, found := openShellProgram(r, openShellCLISpec)
	switch {
	case !found:
		return "", errors.New("the openshell CLI is not installed or not on PATH")
	case why != "":
		return "", errors.New(why)
	}
	bin := prog.Path
	facts, err := exthost.Inspect(bin)
	if err != nil {
		return "", err
	}
	reason, detail, real := extrun.CheckFile("linux", bin, facts, true)
	if reason != extrun.RefuseNone {
		return "", fmt.Errorf("the openshell CLI at %s is refused: %s", bin, detail)
	}
	return real, nil
}

// openShellCLIEnv is the interactive CLI's environment: the runner's fixed
// list plus the terminal's type (the CLI renders the box's terminal).
func openShellCLIEnv(environ []string) []string {
	keep := append(slices.Clone(openShellEnvInherit), "TERM", "COLORTERM", "LC_ALL")
	var out []string
	for _, kv := range environ {
		for _, k := range keep {
			if len(kv) > len(k) && kv[:len(k)+1] == k+"=" {
				out = append(out, kv)
			}
		}
	}
	return out
}

// openShellStage creates the copy dir (owner-only, inside the run's socket
// dir, which the host services made) and copies each copied file's and
// seed's source into it, no-follow and capped. It returns, per CopySync
// entry, whether the host had the file: only those are synced back.
func openShellStage(pf openShellPlanFile, staged []string) ([]bool, error) {
	if err := os.Mkdir(pf.CopyDir, 0o700); err != nil {
		return nil, fmt.Errorf("make the copy dir: %w", err)
	}
	present := make([]bool, len(pf.CopySync))
	srcs := make([]string, 0, len(staged))
	for _, c := range pf.CopySync {
		srcs = append(srcs, c.Source)
	}
	for _, c := range pf.Seed {
		srcs = append(srcs, c.Source)
	}
	for i, src := range srcs {
		b, err := openShellReadRegular(src, openShellCopyCap)
		if errors.Is(err, fs.ErrNotExist) {
			continue // the tool has not made it yet: the box starts without it
		}
		if err != nil {
			return nil, fmt.Errorf("stage %s: %w", src, err)
		}
		if err := openShellWriteExcl(staged[i], b); err != nil {
			return nil, fmt.Errorf("stage %s: %w", src, err)
		}
		if i < len(present) {
			present[i] = true
		}
	}
	return present, nil
}

// openShellReadRegular reads a regular file no-follow, capped. It opens
// non-blocking and checks the type before reading (audit finding O1B-A5):
// the copy dir is writable in the box, so a FIFO planted at a staged name
// would otherwise block the host helper's open forever (no writer), and
// the helper would never delete the box or release the run.
func openShellReadRegular(p string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) //nolint:gosec // G304: a tool-state file the planner admitted
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, fmt.Errorf("%s is not a regular file of at most %d bytes", p, limit)
	}
	return io.ReadAll(io.LimitReader(f, limit))
}

// openShellSyncBack writes the box's copy of a file back over its host
// source (last writer wins, U-32 fallback 1), through a temporary file and
// a rename in the source's dir. A source that became a symlink is left
// alone. A copy the box never wrote back leaves the source as it was.
func openShellSyncBack(staged, source string) error {
	b, err := openShellReadRegular(staged, openShellCopyCap)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi, err := os.Lstat(source); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return errors.New("the host file is now a symlink")
	}
	mode := fs.FileMode(0o600)
	if fi, err := os.Lstat(source); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(source), "."+filepath.Base(source)+".sbo-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if werr == nil {
		werr = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(name)
		return werr
	}
	return os.Rename(name, source)
}

// runOpenShellInit is the in-box init: `observer sandbox-openshell-init
// --sock-dir D [--cwd W] [--env-file F] [--copy S=T]... [--seed S=T]... --
// <command>`. It links the fixed guest socket path the relay clients use
// to the run's same-path socket dir, reads and removes the environment
// file, copies the staged files into place, runs the command as its child
// in the run's workspace, copies the copied files back, and exits with the
// child's code.
func runOpenShellInit(args []string) int {
	a, err := parseOpenShellInitArgs(args)
	if err != nil {
		return helperFail("observer sandbox (openshell init): %v", err)
	}
	if a.SockDir != sandbox.GuestSocketDir {
		if err := openShellLinkGuestSockets(a.SockDir); err != nil {
			return helperFail("observer sandbox (openshell init): %v", err)
		}
	}
	env := os.Environ()
	if a.EnvFile != "" {
		b, err := openShellReadRegular(a.EnvFile, 1<<20)
		_ = os.Remove(a.EnvFile)
		if err != nil {
			return helperFail("observer sandbox (openshell init): read the box environment: %v", err)
		}
		env = append(env, openShellDecodeEnv(b)...)
	}
	if a.SockDir != sandbox.GuestSocketDir {
		// The relay clients read the launch record from the real dir, not
		// through the link (openShellBoxSocketDir).
		env = openShellWithSockDirEnv(env, a.SockDir)
	}
	if a.Cwd != "" {
		// The command starts in the run's workspace, never in OpenShell's
		// own workdir; a workspace the box cannot enter refuses the run.
		if fi, err := os.Stat(a.Cwd); err != nil || !fi.IsDir() {
			return helperFail("observer sandbox (openshell init): the workspace %s is not a directory in the box: %v", a.Cwd, err)
		}
		env = openShellSetEnv(env, "PWD", a.Cwd)
	}
	// A seed is a read-only convenience copy (the launcher's settings): one
	// that cannot be placed (a parent the runtime made as root for a bind
	// mount point, for example) is said and the run goes on with defaults.
	for _, p := range a.Seeds {
		if err := openShellCopyIn(p[0], p[1], 0o400); err != nil {
			fmt.Fprintf(os.Stderr, "observer sandbox (openshell init): %s was not copied into the box (%v); the launcher in the box uses its defaults for it\r\n", p[1], err)
		}
	}
	for _, p := range a.Copies {
		if err := openShellCopyIn(p[0], p[1], 0o600); err != nil {
			return helperFail("observer sandbox (openshell init): %v", err)
		}
	}
	code := openShellRunChild(a.Command, env, a.Cwd)
	for _, p := range a.Copies {
		if err := openShellCopyBack(p[1], p[0]); err != nil {
			fmt.Fprintf(os.Stderr, "\r\n[observer: %s was not copied back: %v]\r\n", p[1], err)
		}
	}
	return code
}

// openShellLinkGuestSockets makes the fixed guest socket path (where the
// hook relay and the guest helper look, sandbox.GuestSocketDir) a link to
// the run's same-path socket dir: OpenShell binds are same-path (lane O0
// R1), so the dir sits at its host path in the box. The box's /tmp is its
// own, so the link is visible to this box alone.
func openShellLinkGuestSockets(sockDir string) error {
	if cur, err := os.Readlink(sandbox.GuestSocketDir); err == nil {
		if cur == sockDir {
			return nil
		}
		return fmt.Errorf("%s already points at %s", sandbox.GuestSocketDir, cur)
	}
	if err := os.MkdirAll(filepath.Dir(sandbox.GuestSocketDir), 0o755); err != nil { //nolint:gosec // G301: the box's own /tmp
		return err
	}
	return os.Symlink(sockDir, sandbox.GuestSocketDir)
}

// openShellCopyIn copies a staged file to its place in the box (the tmpfs
// home or a writable bind), parents made owner-only. A staged file that is
// missing (the host had none) is skipped.
func openShellCopyIn(staged, target string, mode fs.FileMode) error {
	b, err := openShellReadRegular(staged, openShellCopyCap)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".sbo-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if werr == nil {
		werr = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(name)
		return werr
	}
	return os.Rename(name, target)
}

// openShellCopyBack copies the box's file back into the copy dir for the
// host helper's sync.
func openShellCopyBack(target, staged string) error {
	b, err := openShellReadRegular(target, openShellCopyCap)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(staged), ".back-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(name)
		return werr
	}
	return os.Rename(name, staged)
}

// openShellRunChild runs the box's command as the init's child on the
// box's terminal, forwarding the signals the CLI delivers, and returns its
// exit code (128 + signal when a signal ended it). dir is the child's
// working dir ("" keeps the init's own).
func openShellRunChild(argv, env []string, dir string) int {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // G204: the planned guest helper and launch argv
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env, cmd.Dir = env, dir
	if err := cmd.Start(); err != nil {
		return helperFail("observer sandbox (openshell init): start %s: %v", filepath.Base(argv[0]), err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				_ = cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return helperFail("observer sandbox (openshell init): wait: %v", err)
}
