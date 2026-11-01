package hookbridge

import (
	"errors"
	"path"
	"strings"
	"time"
)

// SentinelFlag is the `observer hook` flag a bridged invocation carries.
const SentinelFlag = "--bridge-sentinel"

// SentinelExit is the exit code `observer hook --bridge-sentinel` uses for
// every answer other than 0 and 2 (a non-blocking error, an argv error the
// hook itself reports). wsl.exe never returns it for a failure of its own
// (its own failures are -1 and HRESULT-sized codes; LC6 records them), so
// the bridge reads it as "the hook ran".
const SentinelExit = 86

// HookExit maps the hook's own exit code under SentinelFlag: 0 (allow) and 2
// (a dialect's exit-code block) pass, everything else becomes SentinelExit.
func HookExit(code int) int {
	if code == 0 || code == 2 {
		return code
	}
	return SentinelExit
}

// MaxDeadline caps the bridge's own deadline. It sits above the hook's own
// watchdog (30 s by default, `observer hook --max-runtime`), so a hook that
// runs answers first, and leaves room for a cold WSL VM to start.
const MaxDeadline = 45 * time.Second

// Deadline is how long the bridge waits for wsl.exe before it blocks the
// call itself: below the host's own hook timeout (hostTimeout, from the
// registry binding; 0 when unknown) by a 2 s margin, or half of it when the
// host allows 4 s or less, and never above MaxDeadline. A host that gives up
// on a hung hook treats it as non-blocking (Claude Code, Codex), so the
// bridge must answer first (second audit of 4767d49c1, item 2), as the
// hook's own watchdog does (cmd/observer hookGateBudget).
func Deadline(hostTimeout time.Duration) time.Duration {
	d := MaxDeadline
	if hostTimeout > 0 {
		margin := 2 * time.Second
		if hostTimeout <= 2*margin {
			margin = hostTimeout / 2
		}
		if c := hostTimeout - margin; c < d {
			d = c
		}
	}
	return d
}

// Run is how one bridged run ended, as the cmd layer observed it.
type Run struct {
	// Started: wsl.exe was started.
	Started bool
	// TimedOut: the bridge's own deadline (Deadline) fired and wsl.exe was
	// killed before it answered.
	TimedOut bool
	// ExitCode is wsl.exe's exit code (meaningful when Started).
	ExitCode int
	// OutputOverflow: the hook's stdout or stderr exceeded the bridge's
	// buffer, so it cannot be replayed byte for byte.
	OutputOverflow bool
}

// Outcome is the bridge's decision.
type Outcome string

// The closed Outcome vocabulary, in table order.
const (
	// OutcomeLaunchFailed: wsl.exe could not be started.
	OutcomeLaunchFailed Outcome = "launch_failed"
	// OutcomeTimedOut: wsl.exe did not answer within Deadline (a VM that
	// is starting, a stuck vmcompute); the bridge blocks with the timeout
	// reason before the host gives up and lets the call through.
	OutcomeTimedOut Outcome = "timed_out"
	// OutcomeOverflow: the hook's output cannot be replayed whole.
	OutcomeOverflow Outcome = "output_overflow"
	// OutcomeAllow: the hook ran and allowed (exit 0).
	OutcomeAllow Outcome = "allow"
	// OutcomeHookBlock: the hook ran and blocked by exit code (exit 2).
	OutcomeHookBlock Outcome = "hook_block"
	// OutcomeHookNonBlocking: the hook ran and answered non-blocking
	// (SentinelExit); the host sees exit 1, its non-blocking error.
	OutcomeHookNonBlocking Outcome = "hook_non_blocking"
	// OutcomeHookNotStarted: wsl.exe ran but returned a code the hook never
	// uses under the sentinel: WSL could not start the hook.
	OutcomeHookNotStarted Outcome = "hook_not_started"
)

// Decision is one row's verdict.
type Decision struct {
	Outcome Outcome
	// Passthrough: replay the hook's stdout and stderr byte for byte and
	// exit with ExitCode. False: discard them and write the dialect's
	// fail-closed reply (cmd/observer).
	Passthrough bool
	// ExitCode is the exit code for a passthrough decision.
	ExitCode int
}

// FailsClosed reports whether the decision is the bridge's own block.
func (d Decision) FailsClosed() bool { return !d.Passthrough }

// rule is one row of the decision table: the first row whose when holds
// decides.
type rule struct {
	decision Decision
	when     func(Run) bool
}

// rules is the ordered decision table (CLAUDE.md #5), one test row each in
// TestDecide. Every row that cannot prove the hook ran fails closed: the
// bridge is written only on an enforcing managed node.
var rules = []rule{
	{Decision{Outcome: OutcomeLaunchFailed}, func(r Run) bool { return !r.Started }},
	{Decision{Outcome: OutcomeTimedOut}, func(r Run) bool { return r.TimedOut }},
	{Decision{Outcome: OutcomeOverflow}, func(r Run) bool { return r.OutputOverflow }},
	{Decision{Outcome: OutcomeAllow, Passthrough: true, ExitCode: 0}, func(r Run) bool { return r.ExitCode == 0 }},
	{Decision{Outcome: OutcomeHookBlock, Passthrough: true, ExitCode: 2}, func(r Run) bool { return r.ExitCode == 2 }},
	{Decision{Outcome: OutcomeHookNonBlocking, Passthrough: true, ExitCode: 1}, func(r Run) bool { return r.ExitCode == SentinelExit }},
	{Decision{Outcome: OutcomeHookNotStarted}, func(Run) bool { return true }},
}

// Decide walks the decision table top-down.
func Decide(r Run) Decision {
	for _, row := range rules {
		if row.when(r) {
			return row.decision
		}
	}
	return Decision{Outcome: OutcomeHookNotStarted}
}

// Entry is the validated content of one bridge entry: what the registrar
// writes and `observer hook-bridge` parses.
type Entry struct {
	Distro string
	// Bin is the WSL-side observer binary (absolute POSIX path).
	Bin string
	// Tool and Event are the `observer hook <tool> <event>` arguments.
	Tool  string
	Event string
	// Config is the WSL-side config path, "" for none.
	Config string
}

// ErrUnsafeEntry is the refusal for a field that is not a closed spelling.
var ErrUnsafeEntry = errors.New("hookbridge: an entry field is not a closed spelling")

// Validate checks every field against a closed spelling. The entry is
// written unquoted into a settings file that Git Bash, PowerShell and
// cmd.exe all parse, so only characters none of them treats specially are
// accepted: the distro and the tool/event names from [A-Za-z0-9._-], the
// paths absolute and from [A-Za-z0-9/._-] with no "..".
func (e Entry) Validate() error {
	for _, name := range []string{e.Distro, e.Tool, e.Event} {
		if !closedName(name) {
			return ErrUnsafeEntry
		}
	}
	if !closedPOSIXPath(e.Bin) {
		return ErrUnsafeEntry
	}
	if e.Config != "" && !closedPOSIXPath(e.Config) {
		return ErrUnsafeEntry
	}
	return nil
}

// Args is the argument list after `hook-bridge` in a settings entry. Every
// absolute path is written with a doubled leading slash, which Git Bash's
// MSYS argument conversion passes to a Windows program untouched (a single
// one it would rewrite into a Git install path) and which ParseArgs undoes.
func (e Entry) Args() []string {
	out := []string{"--distro", e.Distro, "--bin", "/" + e.Bin, "--tool", e.Tool, "--event", e.Event}
	if e.Config != "" {
		out = append(out, "--config", "/"+e.Config)
	}
	return out
}

// Command is the whole settings entry: the Windows observer.exe (a closed
// forward-slash Windows path, CommandExe) followed by `hook-bridge` and
// Args, joined with single spaces and no quoting.
func (e Entry) Command(exe string) (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	if !ClosedWindowsExe(exe) {
		return "", ErrUnsafeEntry
	}
	return exe + " hook-bridge " + strings.Join(e.Args(), " "), nil
}

// Argv is wsl.exe's argument list for the entry: `-d <distro> --exec <bin>
// hook <tool> <event> [--config <cfg>] --bridge-sentinel`. --exec runs the
// hook without the Linux shell, so no argument is re-parsed on that side.
func (e Entry) Argv() ([]string, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	out := []string{"-d", e.Distro, "--exec", e.Bin, "hook", e.Tool, e.Event}
	if e.Config != "" {
		out = append(out, "--config", e.Config)
	}
	return append(out, SentinelFlag), nil
}

// NormalizePath undoes Args' doubled leading slash ("//opt/x" -> "/opt/x");
// any other value is returned as is.
func NormalizePath(p string) string {
	if strings.HasPrefix(p, "//") && !strings.HasPrefix(p, "///") {
		return p[1:]
	}
	return p
}

// WSLExe is the wsl.exe the bridge starts: the System32 copy under
// systemRoot (%SystemRoot%, "C:\Windows" when unset), never a PATH lookup.
func WSLExe(systemRoot string) string {
	if strings.TrimSpace(systemRoot) == "" {
		systemRoot = `C:\Windows`
	}
	return strings.TrimRight(systemRoot, `\/`) + `\System32\wsl.exe`
}

// ClosedWindowsExe reports whether exe is a closed forward-slash Windows path
// to an .exe ("C:/Users/u/AppData/Local/SuperBased/Observer/bin/observer.exe"):
// a drive letter, then only [A-Za-z0-9/._-], no "..". A path with a space or
// any shell-special character is refused (the registrar then keeps today's
// bridge); quoting one portably is what LC6 would have to ground.
func ClosedWindowsExe(exe string) bool {
	if len(exe) < 4 || !isLetter(exe[0]) || exe[1] != ':' || exe[2] != '/' {
		return false
	}
	if !strings.EqualFold(path.Ext(exe), ".exe") || strings.Contains(exe, "..") {
		return false
	}
	for i := 3; i < len(exe); i++ {
		if !pathByte(exe[i]) {
			return false
		}
	}
	return true
}

func closedName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(isLetter(c) || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return s[0] != '-' && s[0] != '.'
}

func closedPOSIXPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.Contains(p, "..") || len(p) > 1024 {
		return false
	}
	for i := 0; i < len(p); i++ {
		if !pathByte(p[i]) {
			return false
		}
	}
	return true
}

func pathByte(c byte) bool {
	return isLetter(c) || c >= '0' && c <= '9' || c == '/' || c == '.' || c == '_' || c == '-'
}

func isLetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// wslNoticePrefix starts the warnings wsl.exe itself writes to stderr
// ("wsl: A localhost proxy configuration was detected ..."). They are
// WSL's, not the hook's.
const wslNoticePrefix = "wsl: "

// SplitWSLNotices separates wsl.exe's own notice lines from the hook's
// stderr, keeping each side's bytes and line endings as written. On a hook
// block (exit 2) the host shows stderr as the block reason, so the caller
// replays only the hook's part; otherwise it replays the notices behind a
// prefix that names them (second audit of 4767d49c1, item 6). Notices
// wsl.exe writes in UTF-16 do not match and stay with the hook's bytes
// (LC6 records wsl.exe's encodings).
func SplitWSLNotices(stderr []byte) (hook, notices []byte) {
	rest := stderr
	for len(rest) > 0 {
		i := strings.IndexByte(string(rest), '\n')
		line := rest
		if i >= 0 {
			line = rest[:i+1]
		}
		rest = rest[len(line):]
		if strings.HasPrefix(string(line), wslNoticePrefix) {
			notices = append(notices, line...)
			continue
		}
		hook = append(hook, line...)
	}
	return hook, notices
}
