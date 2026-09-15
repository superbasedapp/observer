// Package host builds the production toolresolve.Env: the real filesystem
// probes, WSL detection and the Windows homes reached over /mnt (via
// internal/platform/crossmount), and a one-shot login-shell PATH capture that
// surfaces binaries installed into a login-only prefix without a daemon
// restart. It is the impure boundary for the pure internal/toolresolve
// resolver — the only place os / os/exec / crossmount are touched — so the
// resolver itself stays testable with injected fakes.
package host

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// defaultLoginTimeout bounds ONE login-shell PATH capture attempt. A login
// shell that sources a slow rc file must not stall a launch; on timeout the
// attempt is abandoned and resolution proceeds with the next attempt, or on the
// process PATH alone. It is 3s rather than the original 1.5s because the
// capture is now INTERACTIVE first (`-lic`): the interactive rc files are
// exactly where nvm/fnm/oh-my-zsh live, and they are also the slow ones (VS
// Code's equivalent capture defaults to 10s for this reason). The capture is
// memoized per Env, so the cost is paid once per Env, not once per tool.
const defaultLoginTimeout = 3000 * time.Millisecond

// npmPrefixTimeout bounds the `npm prefix -g` probe. npm is a Node process with
// a slow cold start; on timeout the probe is skipped and the resolver records
// an honest Note.
const npmPrefixTimeout = 3 * time.Second

// loginOutputCap bounds the captured stdout (a pathological shell must not OOM
// the daemon). A real $PATH is well under this.
const loginOutputCap = 64 * 1024

// ErrUnsupportedShell is returned by CaptureLoginPath when $SHELL is empty or
// its basename is not a known POSIX-style login shell (nushell, tcsh, …). The
// caller treats it as "no login merge", not a hard error.
var ErrUnsupportedShell = errors.New("toolresolve/host: unsupported or unknown login shell")

// Options tunes NewEnv. Zero values fall back to $SHELL and defaultLoginTimeout.
type Options struct {
	// Shell overrides the login shell to capture PATH from (default $SHELL).
	Shell string
	// Timeout bounds the login-shell capture (default 1500ms).
	Timeout time.Duration
}

// NewEnv builds the production toolresolve.Env. The login-shell PATH capture is
// memoized per returned Env via sync.OnceValues (one subprocess per process,
// no matter how many tools resolve); it is nil on a Windows daemon, where a
// POSIX login shell is not the PATH authority. Callers that resolve many tools
// should themselves memoize NewEnv (a package-level sync.OnceValue) so the
// crossmount walk and env reads happen once.
func NewEnv(opts Options) toolresolve.Env {
	shell := opts.Shell
	if shell == "" {
		shell = os.Getenv("SHELL")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultLoginTimeout
	}

	wsl := crossmount.IsWSL()
	home, _ := os.UserHomeDir()

	var foreign []string
	if wsl {
		for _, h := range crossmount.AllHomes() {
			if h.OS == crossmount.OSWindows {
				foreign = append(foreign, h.Path)
			}
		}
	}

	env := toolresolve.Env{
		GOOS:         runtime.GOOS,
		WSL:          wsl,
		Home:         home,
		ForeignHomes: foreign,
		ProcessPath:  filepath.SplitList(os.Getenv("PATH")),
		PathExt:      windowsPathExt(),
		Stat:         os.Stat,
		EvalSymlinks: filepath.EvalSymlinks,
		Glob:         filepath.Glob,
		Getenv:       os.Getenv,
		ReadHead:     readHead,
	}

	// A Windows daemon has no POSIX login shell to consult; leave LoginPath nil.
	if runtime.GOOS != "windows" {
		once := sync.OnceValues(func() ([]string, error) {
			return CaptureLoginPath(shell, timeout)
		})
		env.LoginPath = func() ([]string, error) { return once() }
	}

	// NpmPrefix is memoized per Env (like LoginPath): one `npm prefix -g`
	// subprocess per Env, however many tools resolve against it, and it is
	// LAZY — nothing runs unless a Resolve actually reaches the probe step.
	// Callers that rebuild the Env on a TTL (the dashboard) get a fresh probe
	// per rebuild, which is what keeps "a fresh install shows up without a
	// daemon restart" honest.
	npmOnce := sync.OnceValues(func() (string, error) { return npmPrefix(env, npmPrefixTimeout) })
	env.NpmPrefix = func() (string, error) { return npmOnce() }

	return env
}

// readHead reads the first n bytes of path — the bounded reader behind
// toolresolve.Env.ReadHead, used ONLY to sniff a `#!/usr/bin/env <name>`
// shebang. A short file is not an error: whatever was read is returned.
func readHead(path string, n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	f, err := os.Open(path) /* #nosec G304 -- path is a binary this resolver itself located on PATH/probe dirs, never request-derived */
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	buf := make([]byte, n)
	got, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:got], nil
}

// runNpmPrefix executes `npm prefix -g`. A package var so tests can drive the
// probe without an npm install on the host.
var runNpmPrefix = func(ctx context.Context, npmBin string) (string, error) {
	cmd := exec.CommandContext(ctx, npmBin, "prefix", "-g") /* #nosec G204 -- npmBin is a file this package located itself by scanning the merged PATH dirs for the literal name "npm"; the arguments are constants */
	cmd.Stdin = nil
	cmd.WaitDelay = 500 * time.Millisecond
	out := &capWriter{limit: loginOutputCap}
	cmd.Stdout = out
	err := cmd.Run()
	return out.String(), err
}

// npmPrefix returns the operator's global npm prefix (`npm prefix -g`), the dir
// npm lays its `-g` shims under. It is a CAPABILITY probe, not a per-tool one:
// a binary found under the operator's own npm prefix is evidence for whichever
// tool is being resolved, so the resolver probes it for every tool.
//
// npm is located by scanning the resolver's own MERGED PATH (process + login
// shell) rather than exec.LookPath, because the daemon's frozen PATH is exactly
// what may be missing it — the same reason this whole ladder exists. Errors are
// returned for the resolver to render as an honest Note; they are never fatal.
func npmPrefix(env toolresolve.Env, timeout time.Duration) (string, error) {
	dirs, _ := toolresolve.MergedPathDirs(env)
	npmBin := findInDirs(dirs, npmNames())
	if npmBin == "" {
		return "", errors.New("toolresolve/host: npm not found on the merged PATH")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, err := runNpmPrefix(ctx, npmBin)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("toolresolve/host: npm prefix -g timed out after %s: %w", timeout, ctx.Err())
		}
		return "", fmt.Errorf("toolresolve/host: npm prefix -g failed: %w", err)
	}
	prefix := strings.TrimSpace(out)
	if prefix == "" {
		return "", errors.New("toolresolve/host: npm prefix -g printed nothing")
	}
	// npm can print several lines when a config warning slips through; the
	// prefix is the LAST non-empty line.
	lines := strings.Split(strings.ReplaceAll(prefix, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l, nil
		}
	}
	return "", errors.New("toolresolve/host: npm prefix -g printed nothing")
}

// npmNames returns the spellings of the npm launcher for this OS. On Windows
// npm ships as npm.cmd (plus a bare shell script for MSYS/Git-Bash).
func npmNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"npm.cmd", "npm.exe", "npm"}
	}
	return []string{"npm"}
}

// findInDirs returns the first dir×name combination that is a regular file,
// walking dirs outer and names inner (PATH order wins over spelling order).
func findInDirs(dirs, names []string) string {
	for _, dir := range dirs {
		for _, name := range names {
			p := filepath.Join(dir, name)
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
				return p
			}
		}
	}
	return ""
}

// windowsPathExt reads the PATHEXT precedence list (used to order the Windows
// candidate spellings) ONLY on a Windows daemon: it splits %PATHEXT% on ';',
// uppercases each entry, and drops empties. It returns nil off Windows, where a
// POSIX daemon has no PATHEXT authority and the spec's candidate order stands.
func windowsPathExt() []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	var out []string
	for _, e := range strings.Split(os.Getenv("PATHEXT"), ";") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		out = append(out, strings.ToUpper(e))
	}
	return out
}

// loginShellPlan is one shell's capture recipe: the flag sets to try IN ORDER
// until one exits 0 AND prints a well-formed marker pair, plus the script that
// prints the marker-wrapped $PATH. It is a table (CLAUDE.md #5), not a switch
// ladder, so a new shell is a row and every row is one test case.
type loginShellPlan struct {
	attempts [][]string
	script   string
}

// posixPathScript prints $PATH wrapped in the marker pair. The leading newline
// keeps the begin marker off the tail of any banner line an rc file printed
// without a trailing newline.
const posixPathScript = "printf '\\n" + toolresolve.PathMarkBegin + "%s" + toolresolve.PathMarkEnd + "\\n' \"$PATH\""

// fishPathScript is the same shape in fish syntax (fish has no $PATH string —
// PATH is a list that must be joined).
const fishPathScript = "printf '\\n" + toolresolve.PathMarkBegin + "%s" + toolresolve.PathMarkEnd + "\\n' (string join : $PATH)"

// loginShellTable maps a shell basename to its capture plan.
//
// bash and zsh are tried INTERACTIVE-login (`-lic`) first and login-only
// (`-lc`) second. This is not cosmetic: measured on this project's WSL2 Ubuntu
// (research §4.1.2), `-lc` misses the operator's npm prefix — Ubuntu's stock
// ~/.bashrc returns early for non-interactive shells, so everything a version
// manager appended there is invisible — and `command -v observer` under `-lc`
// resolves to the WINDOWS interop shim under /mnt while `-lic` resolves to the
// native binary. The capture mode flips a VERDICT, so the richer mode is tried
// first and the cheaper one is the fallback when the interactive rc files are
// hostile (a prompt, an `exec tmux`, a slow auto-update).
//
// sh/ksh/dash get login-only: they have no separate interactive rc worth the
// risk. fish gets login-only BY DESIGN — config.fish is read non-interactively
// and fish_add_path persists a universal variable, so `-i` buys nothing.
var loginShellTable = map[string]loginShellPlan{
	"bash": {attempts: [][]string{{"-lic"}, {"-lc"}}, script: posixPathScript},
	"zsh":  {attempts: [][]string{{"-lic"}, {"-lc"}}, script: posixPathScript},
	"sh":   {attempts: [][]string{{"-lc"}}, script: posixPathScript},
	"ksh":  {attempts: [][]string{{"-lc"}}, script: posixPathScript},
	"dash": {attempts: [][]string{{"-lc"}}, script: posixPathScript},
	"fish": {attempts: [][]string{{"-lc"}}, script: fishPathScript},
}

// captureEnvVars are appended to the child's environment for every capture
// attempt. OBSERVER_RESOLVING_ENVIRONMENT lets an operator guard hostile rc
// lines (`[ -n "$OBSERVER_RESOLVING_ENVIRONMENT" ] && return`), mirroring
// VS Code's VSCODE_RESOLVING_ENVIRONMENT and JetBrains'
// INTELLIJ_ENVIRONMENT_READER; TERM=dumb suppresses the interactive chrome
// (oh-my-zsh auto-update prompts, progress spinners) that `-lic` would
// otherwise invite.
var captureEnvVars = []string{
	"OBSERVER_RESOLVING_ENVIRONMENT=1",
	"TERM=dumb",
}

// runLoginShell executes one capture attempt and returns its (capped) stdout.
// It is a package var so tests can drive the attempt ladder without spawning a
// shell; production keeps the real exec.
var runLoginShell = func(ctx context.Context, argv []string, env []string) (string, error) {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) /* #nosec G204 -- argv[0] is the operator's own login shell ($SHELL / explicit Options.Shell) and the arguments are constants from loginShellTable; nothing request- or network-derived reaches this exec */
	cmd.Stdin = nil                                       // exec wires /dev/null; no inherited terminal
	cmd.Env = env
	// WaitDelay bounds Wait after the context is canceled: a login shell that
	// backgrounds a slow child (which would otherwise hold the stdout pipe open)
	// is force-reaped instead of stalling the launch to the child's lifetime.
	cmd.WaitDelay = 500 * time.Millisecond
	out := &capWriter{limit: loginOutputCap}
	cmd.Stdout = out
	// stderr is intentionally discarded — rc-file chatter is not our concern.
	err := cmd.Run()
	return out.String(), err
}

// CaptureLoginPath runs the login shell and returns its $PATH split into dirs.
// It walks the shell's attempt ladder (bash/zsh: interactive-login then
// login-only; everything else: login-only), running each with stdin detached,
// stdout bounded, the guard env vars set and timeout enforced. An attempt is
// accepted ONLY when it exits 0 AND its output carries exactly one well-formed
// marker pair — banners before or after the pair are discarded, and a capture
// with no markers is rejected rather than half-trusted (the pre-marker code
// would have absorbed banner text into the PATH list). An unknown/empty shell
// yields ErrUnsupportedShell; every attempt failing yields the last wrapped
// error. The caller merges the result BEHIND the process PATH.
func CaptureLoginPath(shell string, timeout time.Duration) ([]string, error) {
	if strings.TrimSpace(shell) == "" {
		return nil, ErrUnsupportedShell
	}
	plan, ok := loginShellTable[filepath.Base(shell)]
	if !ok {
		return nil, ErrUnsupportedShell
	}
	if timeout <= 0 {
		timeout = defaultLoginTimeout
	}
	env := append(os.Environ(), captureEnvVars...)

	var lastErr error
	for _, flags := range plan.attempts {
		argv := make([]string, 0, len(flags)+2)
		argv = append(argv, shell)
		argv = append(argv, flags...)
		argv = append(argv, plan.script)

		out, err := runOneCapture(argv, env, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		dirs, err := toolresolve.ParsePathMarkers(out)
		if err != nil {
			lastErr = fmt.Errorf("toolresolve/host: login PATH capture (%s): %w", strings.Join(flags, " "), err)
			continue
		}
		return dirs, nil
	}
	return nil, lastErr
}

// runOneCapture runs a single attempt under its own timeout context.
func runOneCapture(argv, env []string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, err := runLoginShell(ctx, argv, env)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("toolresolve/host: login PATH capture timed out after %s: %w", timeout, ctx.Err())
		}
		return "", fmt.Errorf("toolresolve/host: login PATH capture failed: %w", err)
	}
	return out, nil
}

// capWriter buffers up to limit bytes and silently drops the rest, so a
// runaway shell cannot exhaust memory.
type capWriter struct {
	buf   bytes.Buffer
	limit int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.limit - w.buf.Len(); room > 0 {
		if room < len(p) {
			w.buf.Write(p[:room])
		} else {
			w.buf.Write(p)
		}
	}
	// Always report the full length so the child's writes never error/block.
	return len(p), nil
}

func (w *capWriter) String() string { return w.buf.String() }
