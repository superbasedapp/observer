// setup.go: `observer setup`, the per-user install the Windows setup program
// (installer/windows/superbased-setup.nsi) drives, plus the pieces a user can
// run on their own: the user Path entry, start at sign-in, the check for
// another install, and the launch a Start menu entry or a double-click runs.
//
// The decisions live in internal/setup (pure); this file and its
// setup_windows.go / setup_other.go siblings do the reads and writes. The
// setup program copies observer.exe and observerw.exe into a temp folder and
// calls `setup install`, so the copy, the rename-aside upgrade of a running
// binary and the coexistence check have one owner instead of a third copy
// beside scripts/install.sh and scripts/install.ps1.

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/setup"
)

// Exit codes the setup program reads (only with the hidden --exit-codes flag;
// a person running the command sees 0 or 1).
const (
	// setupExitBlocked: another install is on this computer and --force
	// was not given; nothing was written.
	setupExitBlocked = 3
	// setupExitDaemonRunning: `setup uninstall` found a daemon from this
	// install running and --stop-daemon was not given; nothing was changed.
	setupExitDaemonRunning = 4
	// setupExitRestartNotice: installed, but a running daemon keeps the
	// previous binary until it is restarted.
	setupExitRestartNotice = 10
)

// setupOS is the platform half of `observer setup`: the per-user Path, the
// start-at-sign-in entry, detached process start and stop. setup_windows.go
// and setup_other.go provide defaultSetupOS; tests pass fakes.
type setupOS struct {
	// readUserPath / writeUserPath read and write the per-user Path
	// (HKCU\Environment on Windows). writeUserPath also tells running
	// programs the environment changed. Nil means "not on this OS".
	readUserPath  func() (string, error)
	writeUserPath func(string) error
	// readRun / writeRun / deleteRun manage the start-at-sign-in entry.
	// readRun returns "" with no error when the entry is absent.
	readRun   func() (string, error)
	writeRun  func(string) error
	deleteRun func() error
	// spawnDetached starts argv with no console, its output appended to
	// logPath, and returns without waiting.
	spawnDetached func(argv []string, logPath string) error
	// stopPID stops a process and waits up to timeout for it to exit.
	stopPID func(pid int, timeout time.Duration) error
	// link makes alias a hard link to target, or the platform's alias form.
	link func(target, alias string) error
}

// supportsUserPath reports whether this OS has a per-user Path the setup
// commands own.
func (s setupOS) supportsUserPath() bool { return s.readUserPath != nil && s.writeUserPath != nil }

// supportsRun reports whether this OS has a start-at-sign-in entry the setup
// commands own.
func (s setupOS) supportsRun() bool {
	return s.readRun != nil && s.writeRun != nil && s.deleteRun != nil
}

// binaryName returns name with the platform's executable suffix.
func binaryName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// defaultSetupDir is where `observer setup` installs by default: the same
// per-user directory scripts/install.ps1 uses on Windows, so the script and
// the setup program upgrade the same copy and the coexistence check never
// flags one as a foreign install. Elsewhere it is the running binary's own
// directory.
func defaultSetupDir() string {
	if runtime.GOOS == "windows" {
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			return filepath.Join(la, "SuperBased", "Observer", "bin")
		}
	}
	if exe, err := absoluteBinaryPath(); err == nil {
		return filepath.Dir(exe)
	}
	return "."
}

// newSetupCmd builds the `observer setup` group.
func newSetupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Install for this user: Path, start at sign-in, launch (used by the Windows setup program)",
		Long: "Per-user install steps. The Windows setup program from superbased.app/download\n" +
			"runs these for you; you can also run them yourself.\n\n" +
			"    observer setup install --dir <bin dir> [--path] [--autostart]\n" +
			"    observer setup uninstall --dir <bin dir> [--purge] [--stop-daemon]\n" +
			"    observer setup preflight [--dir <bin dir>]   is another install on this computer?\n" +
			"    observer setup path add|remove|status        the per-user Path entry (Windows)\n" +
			"    observer setup autostart on|off|status       start at sign-in (Windows)\n" +
			"    observer setup launch [--open]               start the daemon if needed, open the dashboard\n\n" +
			"On macOS and Linux, start at login is `observer service install --now`.",
	}
	sys := defaultSetupOS()
	cmd.AddCommand(
		newSetupInstallCmd(sys),
		newSetupUninstallCmd(sys),
		newSetupPreflightCmd(),
		newSetupPathCmd(sys),
		newSetupAutostartCmd(sys),
		newSetupLaunchCmd(sys),
	)
	return cmd
}

// --------------------------------------------------------------- preflight

// observersOnPath lists the observer executables on the process Path, the
// first match per directory, in Path order.
func observersOnPath(pathEnv string) []string {
	names := []string{"observer"}
	if runtime.GOOS == "windows" {
		names = []string{"observer.exe", "observer.cmd"}
	}
	var out []string
	for _, dir := range filepath.SplitList(pathEnv) {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		for _, n := range names {
			p := filepath.Join(dir, n)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() { //nolint:gosec // G703: a Path entry is only stat'ed, never opened or written
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// siblingExists is the real filesystem answer to "does <dir>/<name> exist".
func siblingExists(dir, name string) bool {
	_, err := os.Stat(filepath.Join(filepath.FromSlash(dir), filepath.FromSlash(name)))
	return err == nil
}

// liveDaemon returns the running daemon from the start lock, nil for none.
func liveDaemon() *setup.DaemonInfo {
	cfg, err := config.Load(config.LoadOptions{})
	if err != nil {
		return nil
	}
	lock, ok := liveDaemonFor(cfg.Observer.DBPath)
	if !ok {
		return nil
	}
	return &setup.DaemonInfo{PID: lock.PID, BinaryPath: lock.BinaryPath}
}

// runPreflight gathers the facts and asks internal/setup.
func runPreflight(dir string) setup.PreflightResult {
	return setup.Preflight(setup.PreflightInput{
		InstallDir:    dir,
		OnPath:        observersOnPath(os.Getenv("PATH")),
		Daemon:        liveDaemon(),
		GOOS:          runtime.GOOS,
		SiblingExists: siblingExists,
	})
}

func newSetupPreflightCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Report whether another SuperBased install is on this computer",
		RunE: func(cmd *cobra.Command, _ []string) error {
			res := runPreflight(absDir(dir))
			out := cmd.OutOrStdout()
			if !res.Blocked() {
				fmt.Fprintln(out, "No other SuperBased install found.")
				if d := res.OwnDaemon; d != nil {
					fmt.Fprintf(out, "A daemon from this install is running (pid %d).\n", d.PID)
				}
				return nil
			}
			fmt.Fprint(out, setup.PreflightReport(res, ""))
			return exitErr(setupExitBlocked)
		},
		SilenceErrors: true,
	}
	cmd.Flags().StringVar(&dir, "dir", defaultSetupDir(), "Install directory to check against")
	return cmd
}

func absDir(dir string) string {
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

// ---------------------------------------------------------------- install

type setupInstallOptions struct {
	dir       string
	source    string
	observerw string
	addPath   bool
	autostart bool
	force     bool
	exitCodes bool
	out       io.Writer
	now       func() time.Time
	sys       setupOS
	// preflight is the coexistence check (nil = the real one).
	preflight func(dir string) setup.PreflightResult
}

func newSetupInstallCmd(sys setupOS) *cobra.Command {
	o := setupInstallOptions{sys: sys}
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Copy this observer into a per-user directory (and optionally add it to Path and start at sign-in)",
		Long: "Copies observer (and, on Windows, observerw.exe) into --dir, adds the superbased\n" +
			"alias, and with --path / --autostart adds the directory to the per-user Path and\n" +
			"starts SuperBased at sign-in. A running daemon is never stopped: its binary is\n" +
			"renamed aside and keeps running until you restart it. Refuses when another install\n" +
			"is on this computer (npm, pip, the VS Code extension, or another copy) unless --force.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			o.out = cmd.OutOrStdout()
			return renderSetupError(cmd.ErrOrStderr(), "setup install", runSetupInstall(o))
		},
		SilenceErrors: true,
	}
	cmd.Flags().StringVar(&o.dir, "dir", defaultSetupDir(), "Directory to install observer into")
	cmd.Flags().StringVar(&o.source, "source", "", "The observer binary to install (default: this one)")
	cmd.Flags().StringVar(&o.observerw, "observerw", "", "observerw.exe to install beside it (Windows; needed for start at sign-in)")
	cmd.Flags().BoolVar(&o.addPath, "path", false, "Add the directory to the per-user Path (Windows)")
	cmd.Flags().BoolVar(&o.autostart, "autostart", false, "Start SuperBased when you sign in (Windows)")
	cmd.Flags().BoolVar(&o.force, "force", false, "Install even when another SuperBased install is on this computer")
	cmd.Flags().BoolVar(&o.exitCodes, "exit-codes", false, "Report outcomes as exit codes for the setup program (3 blocked, 10 restart needed)")
	_ = cmd.Flags().MarkHidden("exit-codes")
	return cmd
}

func runSetupInstall(o setupInstallOptions) error {
	if o.now == nil {
		o.now = time.Now
	}
	if o.preflight == nil {
		o.preflight = runPreflight
	}
	dir := absDir(o.dir)
	src := o.source
	if src == "" {
		self, err := absoluteBinaryPath()
		if err != nil {
			return err
		}
		src = self
	}

	pre := o.preflight(dir)
	if pre.Blocked() {
		if !o.force {
			fmt.Fprint(o.out, setup.PreflightReport(pre, "To install a second copy anyway, run the setup with /FORCE (or pass --force)."))
			fmt.Fprintln(o.out, "Nothing was installed.")
			if o.exitCodes {
				return exitErr(setupExitBlocked)
			}
			return errors.New("another SuperBased install is on this computer")
		}
		fmt.Fprint(o.out, setup.PreflightReport(pre, ""))
		fmt.Fprintln(o.out, "Installing a second copy anyway (--force).")
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	removeStaleAside(dir)
	stamp := o.now().UTC().Format("20060102150405.000")
	stamp = strings.ReplaceAll(stamp, ".", "")

	exe := filepath.Join(dir, binaryName("observer"))
	_, statErr := os.Stat(exe)
	upgrade := statErr == nil
	if err := placeBinary(src, exe, stamp); err != nil {
		return err
	}
	alias := filepath.Join(dir, binaryName("superbased"))
	if err := placeAlias(o.sys, exe, alias, stamp); err != nil {
		fmt.Fprintf(o.out, "Warning: could not create %s (%v); the observer command still works.\n", alias, err)
	}
	if o.observerw != "" {
		if err := placeBinary(o.observerw, filepath.Join(dir, setup.WindowlessName), stamp); err != nil {
			return err
		}
	}
	if upgrade {
		fmt.Fprintf(o.out, "Upgraded %s.\n", exe)
	} else {
		fmt.Fprintf(o.out, "Installed %s.\n", exe)
	}

	if o.addPath {
		if err := setupStepNote(o.out, setupPathAdd(o.sys, o.out, dir)); err != nil {
			return err
		}
	}
	if o.autostart {
		if err := setupStepNote(o.out, setupAutostartOn(o.sys, o.out, dir)); err != nil {
			return err
		}
	}

	if d := pre.OwnDaemon; d != nil && upgrade {
		fmt.Fprintf(o.out, "\nSuperBased (pid %d) is still running the previous version. It keeps running until you restart it.\n"+
			"The daemon is the proxy your AI tools may route through, so restart it when no AI session uses the proxy:\n"+
			"turn the proxy route off first, then quit SuperBased and start it again (docs/daemon-restart-runbook.md).\n", d.PID)
		if o.exitCodes {
			return exitErr(setupExitRestartNotice)
		}
	}
	return nil
}

// placeBinary copies src to dst. A running binary cannot be overwritten on
// Windows but can be renamed, so when the direct replace fails the existing
// dst is renamed aside first (removed by the next install or uninstall).
func placeBinary(src, dst, stamp string) error {
	if same, _ := setupSameFile(src, dst); same {
		return nil
	}
	tmp := dst + ".new-" + stamp
	if err := copyFileMode(src, tmp, 0o755); err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	if err := os.Rename(tmp, dst); err == nil {
		return nil
	}
	if _, err := os.Stat(dst); err == nil {
		aside := filepath.Join(filepath.Dir(dst), setup.AsideName(filepath.Base(dst), stamp))
		if rerr := os.Rename(dst, aside); rerr != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("could not replace %s (%w). If SuperBased is running from it, quit it and run setup again", dst, rerr)
		}
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("install %s: %w", dst, err)
	}
	return nil
}

// placeAlias makes alias point at exe: a hard link on Windows (half the disk
// of a second copy), a relative symlink elsewhere (the shape the release
// tarball ships). A locked old alias is renamed aside like the binary.
func placeAlias(sys setupOS, exe, alias, stamp string) error {
	if _, err := os.Lstat(alias); err == nil {
		if rerr := os.Remove(alias); rerr != nil {
			aside := filepath.Join(filepath.Dir(alias), setup.AsideName(filepath.Base(alias), stamp))
			if err := os.Rename(alias, aside); err != nil {
				return err
			}
		}
	}
	if sys.link != nil {
		if err := sys.link(exe, alias); err == nil {
			return nil
		}
	}
	return copyFileMode(exe, alias, 0o755)
}

func setupSameFile(a, b string) (bool, error) {
	fa, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	fb, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(fa, fb), nil
}

func copyFileMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) //nolint:gosec // an operator-named local binary
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode) //nolint:gosec // the install dir is the operator's own
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

// removeStaleAside deletes binaries an earlier upgrade renamed aside,
// skipping any a process still runs (Windows refuses to delete those).
func removeStaleAside(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	for _, n := range setup.StaleAsideNames(names) {
		_ = os.Remove(filepath.Join(dir, n)) //nolint:gosec // G703: a stale aside name StaleAsideNames listed in Observer's own dir
	}
}

// ------------------------------------------------------------------- path

// setupStepsElsewhere are the install steps this OS leaves to another
// mechanism (D-MU8): on macOS and Linux the shell profile owns PATH and
// `observer service` owns start at login. Asked for during an install, such
// a step is a note naming that mechanism, never a failure: the copy itself
// succeeded.
var setupStepsElsewhere = []error{errUserPathUnsupported, errRunUnsupported}

// setupStepNote turns err into a printed note when it is one of
// setupStepsElsewhere, and returns any other error unchanged.
func setupStepNote(out io.Writer, err error) error {
	for _, e := range setupStepsElsewhere {
		if errors.Is(err, e) {
			fmt.Fprintf(out, "Note: %v.\n", err)
			return nil
		}
	}
	return err
}

// renderSetupError prints err once for a setup verb that silences cobra's
// own error line (it reports outcomes as exit codes to the setup program):
// before this, an install that failed after copying exited 1 with no
// message at all (D-MU8). An exit-code outcome has already said what
// happened and is returned as is.
func renderSetupError(stderr io.Writer, verb string, err error) error {
	var ec exitErr
	if err != nil && !errors.As(err, &ec) {
		fmt.Fprintf(stderr, "observer %s: %v\n", verb, err)
	}
	return err
}

var errUserPathUnsupported = errors.New("the per-user Path is edited on Windows only; on macOS and Linux add the directory to PATH in your shell profile (scripts/install.sh does this)")

func setupPathAdd(sys setupOS, out io.Writer, dir string) error {
	if !sys.supportsUserPath() {
		return errUserPathUnsupported
	}
	cur, err := sys.readUserPath()
	if err != nil {
		return fmt.Errorf("read the user Path: %w", err)
	}
	next, changed := setup.AddPathEntry(cur, dir)
	if !changed {
		fmt.Fprintf(out, "%s is already on your user Path.\n", dir)
		return nil
	}
	if err := sys.writeUserPath(next); err != nil {
		return fmt.Errorf("write the user Path: %w", err)
	}
	fmt.Fprintf(out, "Added %s to your user Path (new terminals pick it up).\n", dir)
	return nil
}

func setupPathRemove(sys setupOS, out io.Writer, dir string) error {
	if !sys.supportsUserPath() {
		return errUserPathUnsupported
	}
	cur, err := sys.readUserPath()
	if err != nil {
		return fmt.Errorf("read the user Path: %w", err)
	}
	next, changed := setup.RemovePathEntry(cur, dir)
	if !changed {
		fmt.Fprintf(out, "%s is not on your user Path.\n", dir)
		return nil
	}
	if err := sys.writeUserPath(next); err != nil {
		return fmt.Errorf("write the user Path: %w", err)
	}
	fmt.Fprintf(out, "Removed %s from your user Path.\n", dir)
	return nil
}

func newSetupPathCmd(sys setupOS) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:       "path add|remove|status",
		Short:     "Add or remove the install directory on the per-user Path (Windows)",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"add", "remove", "status"},
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			d := absDir(dir)
			switch args[0] {
			case "add":
				return setupPathAdd(sys, out, d)
			case "remove":
				return setupPathRemove(sys, out, d)
			case "status":
				if !sys.supportsUserPath() {
					return errUserPathUnsupported
				}
				cur, err := sys.readUserPath()
				if err != nil {
					return err
				}
				if setup.HasPathEntry(cur, d) {
					fmt.Fprintf(out, "%s is on your user Path.\n", d)
				} else {
					fmt.Fprintf(out, "%s is not on your user Path.\n", d)
				}
				return nil
			}
			return fmt.Errorf("unknown action %q (want add, remove or status)", args[0])
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultSetupDir(), "Directory holding observer")
	return cmd
}

// -------------------------------------------------------------- autostart

var errRunUnsupported = errors.New("start at sign-in is set here on Windows only; on macOS and Linux run `observer service install --now` (launchd or systemd)")

func setupAutostartOn(sys setupOS, out io.Writer, dir string) error {
	if !sys.supportsRun() {
		return errRunUnsupported
	}
	w := filepath.Join(dir, setup.WindowlessName)
	if _, err := os.Stat(w); err != nil {
		return fmt.Errorf("start at sign-in needs %s beside observer.exe (it ships with the Windows setup program from %s)", setup.WindowlessName, setup.DownloadURL)
	}
	if err := sys.writeRun(setup.RunValue(w)); err != nil {
		return fmt.Errorf("write the sign-in entry: %w", err)
	}
	fmt.Fprintln(out, "SuperBased will start when you sign in to Windows.")
	return nil
}

func setupAutostartOff(sys setupOS, out io.Writer) error {
	if !sys.supportsRun() {
		return errRunUnsupported
	}
	cur, err := sys.readRun()
	if err != nil {
		return err
	}
	if cur == "" {
		fmt.Fprintln(out, "SuperBased was not set to start at sign-in.")
		return nil
	}
	if err := sys.deleteRun(); err != nil {
		return fmt.Errorf("remove the sign-in entry: %w", err)
	}
	fmt.Fprintln(out, "SuperBased will no longer start when you sign in.")
	return nil
}

func newSetupAutostartCmd(sys setupOS) *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:       "autostart on|off|status",
		Short:     "Start SuperBased when you sign in to Windows",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"on", "off", "status"},
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			switch args[0] {
			case "on":
				return setupAutostartOn(sys, out, absDir(dir))
			case "off":
				return setupAutostartOff(sys, out)
			case "status":
				if !sys.supportsRun() {
					return errRunUnsupported
				}
				cur, err := sys.readRun()
				if err != nil {
					return err
				}
				if cur == "" {
					fmt.Fprintln(out, "Start at sign-in: off")
				} else {
					fmt.Fprintf(out, "Start at sign-in: on (%s)\n", cur)
				}
				return nil
			}
			return fmt.Errorf("unknown action %q (want on, off or status)", args[0])
		},
	}
	cmd.Flags().StringVar(&dir, "dir", defaultSetupDir(), "Directory holding observer and observerw.exe")
	return cmd
}

// -------------------------------------------------------------- uninstall

type setupUninstallOptions struct {
	dir        string
	purge      bool
	stopDaemon bool
	force      bool
	exitCodes  bool
	out        io.Writer
	sys        setupOS
	daemon     func() *setup.DaemonInfo
	// unwire removes hooks, MCP entries and proxy routes (nil = the real
	// `observer uninstall --all`).
	unwire func(out io.Writer, purge bool) error
}

func newSetupUninstallCmd(sys setupOS) *cobra.Command {
	o := setupUninstallOptions{sys: sys}
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Undo `setup install`: sign-in entry, Path entry, hooks, MCP and proxy routes",
		Long: "Removes the start-at-sign-in entry and the Path entry, then runs\n" +
			"`observer uninstall --all` (hooks, MCP entries and proxy routes that point at this\n" +
			"install). Your data in ~/.observer is kept unless --purge. The binaries themselves\n" +
			"are deleted by the setup program's uninstaller once this command has exited.\n" +
			"A running daemon from this install is stopped only with --stop-daemon.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			o.out = cmd.OutOrStdout()
			return runSetupUninstall(o)
		},
		SilenceErrors: true,
	}
	cmd.Flags().StringVar(&o.dir, "dir", defaultSetupDir(), "Directory holding observer")
	cmd.Flags().BoolVar(&o.purge, "purge", false, "Also delete your SuperBased data (~/.observer)")
	cmd.Flags().BoolVar(&o.stopDaemon, "stop-daemon", false, "Stop a running daemon from this install first (AI sessions routed through its proxy lose their connection)")
	cmd.Flags().BoolVar(&o.force, "force", false, "Carry on when removing hooks or MCP entries reports an error")
	cmd.Flags().BoolVar(&o.exitCodes, "exit-codes", false, "Report outcomes as exit codes for the setup program (4 daemon running)")
	_ = cmd.Flags().MarkHidden("exit-codes")
	return cmd
}

func runSetupUninstall(o setupUninstallOptions) error {
	if o.daemon == nil {
		o.daemon = liveDaemon
	}
	if o.unwire == nil {
		o.unwire = unwireAllTools
	}
	dir := absDir(o.dir)
	pre := setup.Preflight(setup.PreflightInput{InstallDir: dir, Daemon: o.daemon(), GOOS: runtime.GOOS})
	if d := pre.OwnDaemon; d != nil {
		if !o.stopDaemon {
			fmt.Fprintf(o.out, "SuperBased is running from this install (pid %d). Quit it first, or run again with --stop-daemon.\n"+
				"AI sessions that route through its proxy lose their connection until they are restarted.\n", d.PID)
			if o.exitCodes {
				return exitErr(setupExitDaemonRunning)
			}
			return errors.New("SuperBased is still running")
		}
		if o.sys.stopPID == nil {
			return errors.New("stopping a process is not supported here; quit SuperBased and run again")
		}
		if err := o.sys.stopPID(d.PID, 30*time.Second); err != nil {
			return fmt.Errorf("stop SuperBased (pid %d): %w", d.PID, err)
		}
		fmt.Fprintf(o.out, "Stopped SuperBased (pid %d).\n", d.PID)
	}
	if o.sys.supportsRun() {
		if err := setupAutostartOff(o.sys, o.out); err != nil {
			fmt.Fprintf(o.out, "Warning: %v\n", err)
		}
	}
	if o.sys.supportsUserPath() {
		if err := setupPathRemove(o.sys, o.out, dir); err != nil {
			fmt.Fprintf(o.out, "Warning: %v\n", err)
		}
	}
	if err := o.unwire(o.out, o.purge); err != nil {
		if !o.force {
			return fmt.Errorf("%w. The binaries were kept so the hook entries do not point at a missing program; fix the problem or run again with --force", err)
		}
		fmt.Fprintf(o.out, "Warning: %v (carrying on, --force)\n", err)
	}
	removeStaleAside(dir)
	if !o.purge {
		fmt.Fprintln(o.out, "Your SuperBased data in ~/.observer was kept.")
	}
	return nil
}

// unwireAllTools runs `observer uninstall --all [--purge]` in this process,
// so the setup uninstaller removes exactly what the CLI removes.
func unwireAllTools(out io.Writer, purge bool) error {
	c := newUninstallCmd()
	args := []string{"--all"}
	if purge {
		args = append(args, "--purge")
	}
	c.SetArgs(args)
	c.SetOut(out)
	c.SetErr(out)
	c.SilenceUsage = true
	c.SilenceErrors = true
	return c.Execute()
}

// ----------------------------------------------------------------- launch

type setupLaunchOptions struct {
	open    bool
	wait    time.Duration
	out     io.Writer
	sys     setupOS
	running func() bool
	ready   func() bool
	browse  func(url string)
	self    func() (string, error)
	logPath func() string
	sleep   func(time.Duration)
}

func newSetupLaunchCmd(sys setupOS) *cobra.Command {
	o := setupLaunchOptions{sys: sys}
	cmd := &cobra.Command{
		Use:   "launch",
		Short: "Start the daemon in the background if it is not running, then optionally open the dashboard",
		Long: "What the Start menu entry, start at sign-in and a double-click on observer.exe run.\n" +
			"Starts `observer start` with no window when no daemon is running (its output goes to\n" +
			"daemon.log beside your database), waits for it, and with --open opens the dashboard.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			o.out = cmd.OutOrStdout()
			return runSetupLaunch(o)
		},
	}
	cmd.Flags().BoolVar(&o.open, "open", false, "Open the dashboard in your browser")
	cmd.Flags().DurationVar(&o.wait, "wait", 60*time.Second, "How long to wait for the daemon to come up")
	return cmd
}

// daemonLogPath is daemon.log beside the configured database.
func daemonLogPath() string {
	if cfg, err := config.Load(config.LoadOptions{}); err == nil && cfg.Observer.DBPath != "" {
		return filepath.Join(filepath.Dir(cfg.Observer.DBPath), "daemon.log")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".observer", "daemon.log")
	}
	return "daemon.log"
}

// daemonReady reports whether the daemon is answering: the dashboard port
// on a build with the dashboard, the start lock otherwise.
func daemonReady() bool {
	if dashboardInBuild {
		return portUp(defaultDashboardAddr)
	}
	return liveDaemon() != nil
}

func runSetupLaunch(o setupLaunchOptions) error {
	if o.running == nil {
		o.running = func() bool { return portUp(defaultDashboardAddr) || liveDaemon() != nil }
	}
	if o.ready == nil {
		o.ready = daemonReady
	}
	if o.browse == nil {
		o.browse = openBrowser
	}
	if o.self == nil {
		o.self = absoluteBinaryPath
	}
	if o.logPath == nil {
		o.logPath = daemonLogPath
	}
	if o.sleep == nil {
		o.sleep = time.Sleep
	}
	url := "http://" + defaultDashboardAddr
	if o.running() {
		fmt.Fprintln(o.out, "SuperBased is already running.")
	} else {
		if o.sys.spawnDetached == nil {
			return errors.New("starting the daemon in the background is not supported here; run `observer start`")
		}
		self, err := o.self()
		if err != nil {
			return err
		}
		logPath := o.logPath()
		if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(logPath), err)
		}
		if err := o.sys.spawnDetached([]string{self, "start", "--no-open"}, logPath); err != nil {
			return fmt.Errorf("start SuperBased: %w", err)
		}
		fmt.Fprintf(o.out, "Starting SuperBased in the background (log: %s)...\n", logPath)
		deadline := time.Now().Add(o.wait)
		for !o.ready() {
			if time.Now().After(deadline) {
				return fmt.Errorf("SuperBased did not come up within %s; see %s", o.wait, logPath)
			}
			o.sleep(500 * time.Millisecond)
		}
		fmt.Fprintln(o.out, "SuperBased is running.")
	}
	if dashboardInBuild {
		fmt.Fprintf(o.out, "Dashboard: %s\n", url)
		if o.open {
			o.browse(url)
		}
	}
	return nil
}
