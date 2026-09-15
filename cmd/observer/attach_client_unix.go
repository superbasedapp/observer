//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/attachsock"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// maxAutoResumes bounds how many consecutive daemon-death AUTO-resumes one
// attach invocation performs before it degrades to the resume hint. A crash-
// looping daemon must not drive a hot re-attach loop; a handful of automatic
// reattaches covers a real restart while capping the pathological case.
const maxAutoResumes = 3

// autoResumeWaitCap bounds how long the client waits for a departed daemon's
// socket to return before giving up on auto-resume (resilient-attach Layer 1).
const autoResumeWaitCap = 60 * time.Second

// reattachPromptTimeout is the default prompt-with-timeout window before an
// auto-resume proceeds on its own (Enter = now, Ctrl-C = skip).
const reattachPromptTimeout = 5 * time.Second

// clampUint16 narrows a terminal dimension to the uint16 the PTY size fields
// use, flooring negatives to 0 and capping at the uint16 max.
func clampUint16(n int) uint16 {
	switch {
	case n < 0:
		return 0
	case n > 0xFFFF:
		return 0xFFFF
	default:
		return uint16(n)
	}
}

// runAttachSession runs the client side of `observer <tool> --attach`. It
// dispatches on the tool's Attach capability (never a tool-name branch), then
// drives a RESILIENT attach loop (resilient-attach Layer 1): each iteration
// bridges the operator's terminal to the daemon-owned PTY until the child
// exits, the client detaches, or the DAEMON goes away. On a daemon-death
// (ErrDaemonExited / ErrConnLost) — and only when the daemon PUSHED a real
// correlated session id during the session — it waits for the daemon socket to
// return, offers a prompt-with-timeout, and automatically re-attaches with the
// tool's native-resume spec, preserving the original launch's proxy state. With
// no correlated id (non-proxied / undiscovered), or past the retry cap, it
// degrades to today's honest resume hint. The local terminal is always restored
// before any human-facing line is printed and on every early-return path.
func runAttachSession(ctx context.Context, in attachLaunch) error {
	capab, ok := integration.For(in.tool)
	if !ok || capab.Attach == nil {
		// Honest floor: a tool with no grounded Attach capability cannot be
		// attach-launched (a bare child's stdio belongs to the user's shell and
		// is not retrofittable). This is the runtime guard for the "flags may be
		// registered unconditionally" case (session-attach design §3.4).
		msg := fmt.Sprintf(
			"observer: --attach is not available for %q — no grounded attach capability. Launch it without --attach.",
			in.tool,
		)
		fmt.Fprintln(in.stderr, msg)
		return errors.New(msg)
	}
	subcommand := capab.Attach.Subcommand

	// canAutoResume gates the daemon-death AUTO-resume loop on the tool's native
	// resume capability (attach-all-launchers §3). Only a ResumeNative tool has
	// an inner launcher that registers `--resume` and can reattach its REAL
	// transcript, so injectResumeArg's `--resume <id>` argv is only parseable
	// there. For the 17 ResumeNone launchers a daemon restart ENDS the session
	// (honest mortality) — offerAutoResume/resumeSpawn stay unreachable and the
	// ResumeNone hint (nativeResumeHint → `--continue-from`) lands instead.
	// Dispatch on the capability SHAPE, never a tool-name branch (CLAUDE.md #3).
	canAutoResume := capab.Resume.Kind == integration.ResumeNative

	// Attach drives a live TUI: require a real terminal on both ends.
	stdinFd := int(os.Stdin.Fd())
	stdoutFd := int(os.Stdout.Fd())
	if !term.IsTerminal(stdinFd) || !term.IsTerminal(stdoutFd) {
		msg := fmt.Sprintf(
			"observer %s --attach requires an interactive terminal on stdin and stdout (it drives a live TUI). Run it in a real terminal, or launch without --attach.",
			subcommand,
		)
		fmt.Fprintln(in.stderr, msg)
		return errors.New(msg)
	}

	cfg, err := config.Load(config.LoadOptions{GlobalPath: in.configPath})
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	// The endpoint comes from the platform transport, never a local formula, so
	// the client dials exactly what `observer start` listened on. An
	// unusable endpoint (on unix: a socket path past UNIX_PATH_MAX) is reported
	// with the transport's own actionable message rather than surfacing later
	// as a causeless connect failure (DI-09).
	sockPath, eerr := attachEndpoint(cfg.Observer.DBPath)
	if eerr != nil {
		fmt.Fprintf(in.stderr, "observer %s --attach: %v\n", subcommand, eerr)
		return exitErr(1)
	}
	cwd, _ := os.Getwd()

	// The initial spawn. A user-initiated `--attach --resume <id>` carries its
	// resume target so the daemon tracks it live for the double-spawn guard
	// (AutoResume stays false — a manual resume of a cleanly-closed session must
	// NOT be gated on the daemon's rediscovered-orphan set).
	spawn := attachsock.SpawnRequest{
		Tool:          in.tool,
		Subcommand:    subcommand,
		Dir:           cwd,
		Env:           in.proxyEnv,
		ExtraArgs:     in.extraArgs,
		ResumeSession: resumeIDFromExtraArgs(in.extraArgs),
	}

	// currentID retains the strongest correlated session id the daemon PUSHED
	// across attempts. Seeded from a manual `--resume` so an initial-attempt
	// daemon death before the first correlation frame still has a target.
	currentID := spawn.ResumeSession
	autoResumes := 0
	for {
		res := attachAttempt(ctx, sockPath, subcommand, in, spawn)
		if res.setupErr != nil {
			// A hard setup failure (dial/raw-mode/tty). On the first attempt keep
			// today's behavior (the dial-unreachable path already printed + wraps
			// exitErr); on a re-attach, report we could not re-establish.
			if autoResumes == 0 {
				return res.setupErr
			}
			fmt.Fprintf(in.stderr,
				"\nobserver %s --attach: could not re-attach after the daemon restarted: %v\n",
				subcommand, res.setupErr)
			return exitErr(1)
		}
		if res.correlatedID != "" {
			currentID = res.correlatedID
		}

		// Anything other than a daemon-death outcome — a child exit, a clean
		// detach, an input stall, or a server error (INCLUDING a resume-guard
		// refusal, which the client must print and NOT retry) — is reported
		// exactly as today.
		if !isDaemonGone(res.attachErr) {
			return reportAttachResult(in.stderr, subcommand, capab, res.status, res.attachErr)
		}

		// Daemon-death. Auto-resume only with a REAL correlated id (the abstain
		// rule — no fabricated target), a tool that can natively resume
		// (canAutoResume — a ResumeNone tool's inner launcher can't parse the
		// injected `--resume`), and within the retry cap; otherwise the honest
		// resume hint (nativeResumeHint degrades to `--continue-from` for a
		// ResumeNone launcher).
		if currentID == "" || !canAutoResume || autoResumes >= maxAutoResumes {
			return reportAttachResult(in.stderr, subcommand, capab, res.status, res.attachErr)
		}
		if !offerAutoResume(ctx, in.stderr, sockPath, subcommand, currentID, attachsock.Dial) {
			// A canceled context aborts the loop immediately (M5) — never enter
			// another attachAttempt; the terminal is already cooked (the finished
			// attempt restored it). Otherwise the daemon never returned, or the
			// operator pressed Ctrl-C to skip → the honest resume hint.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return reportAttachResult(in.stderr, subcommand, capab, res.status, res.attachErr)
		}
		autoResumes++
		spawn = resumeSpawn(in, subcommand, cwd, currentID)
	}
}

// isDaemonGone reports whether an Attach error is a daemon-death the auto-resume
// loop reacts to. Only a definitive daemon exit or an ambiguous connection loss
// qualify (design §2.4); an input stall stays a today-hint outcome so a wedged
// socket is not mistaken for a restart.
func isDaemonGone(err error) bool {
	return errors.Is(err, attachsock.ErrDaemonExited) || errors.Is(err, attachsock.ErrConnLost)
}

// attemptResult is one attach-bridge attempt's outcome.
type attemptResult struct {
	status       attachsock.ExitStatus
	attachErr    error  // Attach's result error (daemon-gone / stall / server error / nil)
	correlatedID string // the REAL correlated session id the daemon pushed this attempt ("" if none)
	setupErr     error  // a hard setup failure to return directly (dial/raw/tty); nil on success
}

// attachAttempt runs ONE attach bridge: dial the daemon, put the local terminal
// in raw mode, wire signals + stdio, and Attach until the child exits, the
// client detaches, or the daemon goes away. It restores the terminal before
// returning. The correlated session id the daemon pushes during the session is
// captured (resilient-attach Layer 1) and returned so the loop can auto-resume.
// This is the whole T2 client body, made re-runnable so a daemon restart can
// drive a fresh bridge with a native-resume spawn.
func attachAttempt(ctx context.Context, sockPath, subcommand string, in attachLaunch, spawn attachsock.SpawnRequest) attemptResult {
	conn, err := attachsock.Dial(sockPath)
	if err != nil {
		if errors.Is(err, attachsock.ErrDaemonUnreachable) {
			fmt.Fprintf(in.stderr,
				"observer %s --attach: the observer daemon is not running (or attach is disabled) at %s — start it with `observer start`, or launch without --attach.\n",
				subcommand, sockPath)
			return attemptResult{setupErr: exitErr(1)}
		}
		return attemptResult{setupErr: fmt.Errorf("attach dial %s: %w", sockPath, err)}
	}
	defer func() { _ = conn.Close() }()

	stdinFd := int(os.Stdin.Fd())
	stdoutFd := int(os.Stdout.Fd())

	// Seed the initial PTY size from the local terminal (0 lets the OS pick
	// until the first resize).
	var initRows, initCols uint16
	if w, h, gerr := term.GetSize(stdoutFd); gerr == nil {
		initCols, initRows = clampUint16(w), clampUint16(h)
	}
	spawn.Rows, spawn.Cols = initRows, initCols

	// actx cancels the whole attach session (a clean detach that leaves the
	// child alive under the daemon). Every externally-delivered signal path
	// routes here.
	actx, cancel := context.WithCancel(ctx)
	defer cancel()

	// --- SIGNAL SAFETY (B1) -------------------------------------------------
	// Install ALL signal handling BEFORE term.MakeRaw so a signal that lands
	// while (or just after) the terminal is put in raw mode is CAUGHT and runs
	// the restore path, never the default disposition that would leave the tty
	// raw. Terminal-typed Ctrl-C / Ctrl-Z are raw bytes to the child (ISIG is
	// off in raw mode) and do NOT reach these handlers; only EXTERNALLY
	// delivered signals (`kill -INT`, `kill -TSTP`, a parent hangup) do.
	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	// SIGINT/SIGQUIT/SIGTERM/SIGHUP → clean detach (restore + cancel).
	termSig := make(chan os.Signal, 1)
	signal.Notify(termSig, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(termSig)
	// SIGTSTP → suspend (restore cooked, self-STOP); SIGCONT → resume (re-raw,
	// re-send size).
	tstp := make(chan os.Signal, 1)
	signal.Notify(tstp, syscall.SIGTSTP)
	defer signal.Stop(tstp)
	cont := make(chan os.Signal, 1)
	signal.Notify(cont, syscall.SIGCONT)
	defer signal.Stop(cont)

	// Raw mode: every keystroke — including Ctrl-C (0x03) — is delivered to the
	// child as a byte. ISIG is off, so the terminal never raises SIGINT here;
	// SIGINT-as-a-byte is the design (§2.2), and the child (the agent) handles
	// its own interrupt. oldState captures the ORIGINAL cooked termios and is
	// NEVER reassigned — every restore returns the terminal to exactly this
	// state, and a re-raw on resume discards MakeRaw's return value (B2-2).
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return attemptResult{setupErr: fmt.Errorf("attach: enter raw terminal mode: %w", err)}
	}
	// The terminal raw/cooked state is mutated from BOTH this goroutine and the
	// signal-handling goroutine (suspend/resume/detach), so every transition is
	// serialized under termMu. rawActive tracks whether we are CURRENTLY in raw
	// mode so enterRaw/restore are idempotent (a spurious re-raw or double
	// restore is a no-op). suspended latches true only when WE dropped to cooked
	// via the SIGTSTP path, so a spurious/external SIGCONT cannot re-enter raw
	// mode we never left (B2-2). tearingDown latches once shutdown begins so a
	// late SIGCONT can never re-raw after the final restore.
	var termMu sync.Mutex
	var tearingDown atomic.Bool
	rawActive := true
	suspended := false
	restore := func() {
		termMu.Lock()
		defer termMu.Unlock()
		if rawActive {
			_ = term.Restore(stdinFd, oldState)
			rawActive = false
		}
	}
	enterRaw := func() {
		termMu.Lock()
		defer termMu.Unlock()
		if tearingDown.Load() || rawActive {
			return // already raw (or tearing down) — never a spurious re-raw
		}
		if _, merr := term.MakeRaw(stdinFd); merr == nil {
			// Discard MakeRaw's returned (cooked) state: oldState is the ONE
			// saved cooked state we ever restore to, captured once above.
			rawActive = true
		}
	}
	defer restore()

	// --- INTERRUPTIBLE STDIN (B2-5) ----------------------------------------
	// Open /dev/tty directly (O_RDONLY|O_NONBLOCK) for the stdin reader rather
	// than dup'ing fd 0. A dup SHARES fd 0's open-file description, so
	// SetNonblock on the dup poisons stdout when stdout is the same terminal
	// (reviewer-reproduced): the shared description flips O_NONBLOCK for every
	// fd pointing at it. /dev/tty is a SEPARATE open-file description of the
	// controlling terminal — poller-registered (opened non-blocking), so
	// SetReadDeadline pops a parked Read, and closing it touches nothing else.
	// Raw-mode termios is per-tty (set on fd 0 above) and governs reads through
	// this handle too. --attach already required a real TTY, so /dev/tty must
	// exist; if it somehow doesn't, error honestly rather than degrade.
	ttyIn, terr := os.OpenFile("/dev/tty", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if terr != nil {
		tearingDown.Store(true)
		restore()
		msg := fmt.Sprintf(
			"observer %s --attach: cannot open /dev/tty for interruptible input (%v); launch without --attach.",
			subcommand, terr,
		)
		fmt.Fprintln(in.stderr, msg)
		return attemptResult{setupErr: errors.New(msg)}
	}
	// Close the /dev/tty reader unconditionally after Attach returns (A2-3).
	defer func() { _ = ttyIn.Close() }()

	// --- INTERRUPTIBLE STDOUT (A3-3) ---------------------------------------
	// Open a SEPARATE /dev/tty handle (O_WRONLY|O_NONBLOCK) for PTY output,
	// mirroring the reader. os.Stdout may NOT be poller-registered (its
	// SetWriteDeadline would error), so a Write blocked by terminal flow control
	// (Ctrl-S) on os.Stdout could wedge Attach forever with no way to pop it. A
	// non-blocking *os.File over /dev/tty IS poller-registered, so on teardown
	// Attach sets a past write deadline to pop a blocked Write and always
	// return. It is our OWN open-file description, so that deadline never
	// touches the shell's os.Stdout, and we close it right after Attach.
	ttyOut, toerr := os.OpenFile("/dev/tty", os.O_WRONLY|syscall.O_NONBLOCK, 0)
	if toerr != nil {
		tearingDown.Store(true)
		restore()
		msg := fmt.Sprintf(
			"observer %s --attach: cannot open /dev/tty for interruptible output (%v); launch without --attach.",
			subcommand, toerr,
		)
		fmt.Fprintln(in.stderr, msg)
		return attemptResult{setupErr: errors.New(msg)}
	}
	defer func() { _ = ttyOut.Close() }()

	// SIGWINCH → resize control frames (latest-wins: on a full channel drop the
	// OLDEST pending size so the final dimensions always land, B8).
	resizeCh := make(chan attachsock.Winsize, 1)
	pushResize := func(ws attachsock.Winsize) {
		for {
			select {
			case resizeCh <- ws:
				return
			default:
				select {
				case <-resizeCh: // drop oldest, then retry
				default:
				}
			}
		}
	}
	sendCurrentSize := func() {
		if w, h, gerr := term.GetSize(stdoutFd); gerr == nil {
			pushResize(attachsock.Winsize{Rows: clampUint16(h), Cols: clampUint16(w)})
		}
	}

	go func() {
		for {
			select {
			case <-actx.Done():
				return
			case <-winch:
				sendCurrentSize()
			case <-termSig:
				// External kill/hangup → clean detach: restore the cooked
				// terminal, then cancel so Attach detaches (child lives on).
				restore()
				cancel()
			case <-tstp:
				// External suspend: restore cooked mode so the shell is usable
				// while stopped, latch that WE suspended, drop our handler, then
				// STOP ourselves.
				restore()
				termMu.Lock()
				suspended = true
				termMu.Unlock()
				signal.Reset(syscall.SIGTSTP)
				_ = syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)
			case <-cont:
				// Resumed. Only re-raw + re-arm SIGTSTP if WE actually suspended
				// via the SIGTSTP path; a spurious/external SIGCONT that did not
				// follow our own stop must be ignored so it cannot clobber the
				// saved cooked state or force raw mode we never left (B2-2).
				termMu.Lock()
				wasSuspended := suspended
				suspended = false
				termMu.Unlock()
				if wasSuspended {
					signal.Notify(tstp, syscall.SIGTSTP)
					enterRaw()
					sendCurrentSize()
				}
			}
		}
	}()

	// Capture the daemon-pushed correlated session id (resilient-attach Layer
	// 1). Correlated fires on Attach's own read goroutine (readServerLoop runs
	// synchronously inside Attach), so this plain var is read safely AFTER Attach
	// returns on the same goroutine — no lock needed. Setting the callback also
	// advertises AutoResumeCapable in the spawn frame.
	var correlatedID string
	status, aerr := attachsock.Attach(actx, conn, spawn, attachsock.ClientIO{
		Stdin:       ttyIn,
		Stdout:      ttyOut,
		Resize:      resizeCh,
		InitialRows: initRows,
		InitialCols: initCols,
		Notice: func(code, message string) {
			// Non-fatal server notice (e.g. a writer-lease takeover or a reclaim).
			// Surface it in raw mode (so \r\n) without terminating (A5). The
			// revoked/reclaimed pair re-notifies per transition (Feature 1).
			fmt.Fprintf(in.stderr, "\r\nobserver %s --attach: %s\r\n", subcommand, message)
			if code == attachsock.CodeWriterReclaimed {
				// Reclaim also RESTORES the native geometry: the dashboard may
				// have left the PTY at foreign dims while it held control, so
				// re-push our terminal size — a broken TUI heals in the same
				// gesture that reclaimed control.
				sendCurrentSize()
			}
		},
		Correlated: func(id, _ string, _ float64) {
			if id != "" {
				correlatedID = id
			}
		},
	})

	// Teardown: latch tearingDown so any in-flight/late SIGCONT can't re-raw,
	// then restore the cooked terminal BEFORE printing any human-facing line
	// (the deferred restore also covers early returns above).
	tearingDown.Store(true)
	restore()

	return attemptResult{status: status, attachErr: aerr, correlatedID: correlatedID}
}

// resumeIDFromExtraArgs extracts the `--resume <id>` value from the allow-listed
// launcher argv, scanning only the head (before the `--` tool-remainder
// boundary) so a user's trailing tool flag named `--resume` is never mistaken
// for the launcher's. Returns "" when absent.
func resumeIDFromExtraArgs(extraArgs []string) string {
	head, _ := splitAtDashDash(extraArgs)
	for i := 0; i < len(head); i++ {
		if head[i] == "--resume" && i+1 < len(head) {
			return head[i+1]
		}
	}
	return ""
}

// injectResumeArg rewrites the launcher argv to natively resume sessionID: it
// strips any existing `--resume <x>` from the head (before the `--` tool
// remainder), appends `--resume <sessionID>`, and preserves the tool remainder.
// Every OTHER head token — the routing escape hatch (`--no-proxy-route`),
// `--proxy`/`--config` overrides, and launcher wrapper flags (`--claude-path`,
// `--codex-path`, `--no-app-server-check`) — is kept verbatim, so the original
// launch's proxy state is preserved across the auto-resume.
func injectResumeArg(extraArgs []string, sessionID string) []string {
	head, tail := splitAtDashDash(extraArgs)
	cleaned := make([]string, 0, len(head)+2)
	for i := 0; i < len(head); i++ {
		if head[i] == "--resume" {
			i++ // skip the stale value too
			continue
		}
		cleaned = append(cleaned, head[i])
	}
	cleaned = append(cleaned, "--resume", sessionID)
	return append(cleaned, tail...)
}

// splitAtDashDash splits argv at the FIRST bare "--" (the tool-remainder
// boundary): head excludes it, tail includes it. With no "--", head is the whole
// slice and tail is nil.
func splitAtDashDash(argv []string) (head, tail []string) {
	for i, a := range argv {
		if a == "--" {
			return argv[:i], argv[i:]
		}
	}
	return argv, nil
}

// resumeSpawn composes the daemon-death AUTO-resume spawn: the SAME tool,
// subcommand, cwd, and proxy env as the original launch (proxy state preserved),
// the launcher argv rewritten to `--resume <sessionID>`, and the resume metadata
// the daemon's double-spawn guard + orphan validation key off (ResumeSession set,
// AutoResume=true).
func resumeSpawn(in attachLaunch, subcommand, cwd, sessionID string) attachsock.SpawnRequest {
	return attachsock.SpawnRequest{
		Tool:          in.tool,
		Subcommand:    subcommand,
		Dir:           cwd,
		Env:           in.proxyEnv,
		ExtraArgs:     injectResumeArg(in.extraArgs, sessionID),
		ResumeSession: sessionID,
		AutoResume:    true,
	}
}

// offerAutoResume implements the daemon-death reattach handshake (resilient-
// attach Layer 1): wait (bounded backoff, capped at autoResumeWaitCap) for the
// daemon socket to return, then a prompt-with-timeout on the (already cooked)
// terminal. Returns true to proceed with the auto-resume, false to fall back to
// the resume hint (the daemon never returned, the operator pressed Ctrl-C, or
// ctx was canceled). The socket dialer is injected for tests. ctx is threaded
// through every wait/backoff/prompt (M5) so a cancellation aborts immediately.
func offerAutoResume(ctx context.Context, stderr io.Writer, sockPath, subcommand, sessionID string, dial func(string) (net.Conn, error)) bool {
	fmt.Fprintf(stderr,
		"\nobserver %s --attach: observer daemon went away — waiting up to %s for it to return to auto-resume session %s…\n",
		subcommand, autoResumeWaitCap.Round(time.Second), sessionID)
	if !waitForDaemon(ctx, sockPath, autoResumeWaitCap, dial) {
		if ctx.Err() != nil {
			return false // canceled — the caller returns ctx.Err()
		}
		fmt.Fprintf(stderr,
			"\nobserver %s --attach: the observer daemon did not return within %s.\n",
			subcommand, autoResumeWaitCap.Round(time.Second))
		return false
	}
	return promptReattach(ctx, stderr, reattachPromptTimeout, subcommand, sessionID)
}

// waitForDaemon polls the attach socket with a bounded exponential backoff until
// a dial succeeds, the overall cap elapses, or ctx is canceled. Returns true
// once the daemon is reachable again; false on cap/cancel. The dialer is
// injected (attachsock.Dial in production, which carries its own connect
// timeout).
func waitForDaemon(ctx context.Context, sockPath string, cap time.Duration, dial func(string) (net.Conn, error)) bool {
	deadline := time.Now().Add(cap)
	backoff := 200 * time.Millisecond
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		if c, err := dialCtx(ctx, sockPath, dial); err == nil {
			_ = c.Close()
			return true
		}
		if !sleepUntil(ctx, time.Now().Add(backoff), deadline) {
			break
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
	return false
}

// dialCtx runs the injected dialer on a goroutine and abandons its result the
// instant ctx is canceled, so a probe never blocks past cancellation on the
// dialer's own connect timeout (finding: cancel latency — production
// attachsock.Dial carries a context-free ~2s connect timeout, which without this
// would keep waitForDaemon blocked ~2s after the operator pressed Ctrl-C). The
// injected-dialer test seam is preserved (dial keeps its func(string)
// signature). The result channel is buffered so the abandoned goroutine never
// blocks; if it later produces a live connection it is closed so no fd leaks.
func dialCtx(ctx context.Context, sockPath string, dial func(string) (net.Conn, error)) (net.Conn, error) {
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := dial(sockPath)
		ch <- result{c: c, err: err}
	}()
	select {
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.c != nil {
				_ = r.c.Close()
			}
		}()
		return nil, ctx.Err()
	case r := <-ch:
		return r.c, r.err
	}
}

// sleepUntil sleeps for the wake interval but never past the overall deadline,
// waking early if ctx is canceled. It returns false when the deadline has
// already passed (no time left) OR ctx was canceled (M5) — either way the caller
// stops looping.
func sleepUntil(ctx context.Context, wake, deadline time.Time) bool {
	if !wake.Before(deadline) {
		wake = deadline
	}
	d := time.Until(wake)
	if d <= 0 {
		return false
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// promptReattach prints the prompt-with-timeout and reads a single key from the
// controlling terminal with a deadline. It auto-proceeds (returns true) on the
// timeout or on Enter; Ctrl-C (0x03) skips (returns false). The terminal is
// briefly put in raw mode so Ctrl-C arrives as a byte rather than raising
// SIGINT, then restored — the surrounding attach loop is between bridges here,
// so a brief raw window is safe.
//
// SIGNAL SAFETY (review finding H4): the raw window installs signal handlers
// BEFORE MakeRaw, mirroring attachAttempt's restore-on-signal discipline, so an
// externally-delivered SIGINT/SIGTERM/SIGHUP/SIGQUIT/SIGTSTP cannot kill or
// suspend the process while the terminal is raw and leave it wedged. On any such
// signal (and on ctx cancellation, M5) it restores the cooked terminal and
// returns skip (false) — the simpler of the two behaviors the task allows: the
// process then unwinds through the caller and exits with the terminal cooked,
// rather than re-entering raw. If raw mode or /dev/tty is unavailable it falls
// back to a ctx-aware sleep and proceeds (robust default).
func promptReattach(ctx context.Context, stderr io.Writer, timeout time.Duration, subcommand, sessionID string) bool {
	fmt.Fprintf(stderr,
		"observer: daemon restarted — resuming session %s in %s (Enter = now, Ctrl-C = skip)\n",
		sessionID, timeout.Round(time.Second))

	// Install signal handling BEFORE entering raw mode (H4). Externally delivered
	// term/suspend signals route here and trigger the cooked restore.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGTSTP)
	defer signal.Stop(sigCh)

	stdinFd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return sleepPrompt(ctx, timeout)
	}
	var restoreOnce sync.Once
	restore := func() { restoreOnce.Do(func() { _ = term.Restore(stdinFd, oldState) }) }
	defer restore()

	tty, terr := os.OpenFile("/dev/tty", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if terr != nil {
		restore()
		return sleepPrompt(ctx, timeout)
	}
	defer func() { _ = tty.Close() }()

	_ = tty.SetReadDeadline(time.Now().Add(timeout))
	type readRes struct {
		b   byte
		n   int
		err error
	}
	resCh := make(chan readRes, 1)
	go func() {
		var buf [1]byte
		n, rerr := tty.Read(buf[:])
		resCh <- readRes{buf[0], n, rerr}
	}()

	select {
	case <-ctx.Done():
		restore()
		return false // canceled → skip; caller returns ctx.Err()
	case <-sigCh:
		// External term/suspend signal: restore the cooked terminal and skip.
		// The read goroutine's deadline (or the closed tty on return) unblocks it.
		restore()
		return false
	case r := <-resCh:
		return promptProceed(r.b, r.n, r.err)
	}
}

// sleepPrompt waits out the prompt window, waking early on ctx cancellation
// (M5). It returns proceed=true on timeout (the auto-proceed default) and
// proceed=false on cancellation. Used when raw mode / /dev/tty is unavailable.
func sleepPrompt(ctx context.Context, timeout time.Duration) bool {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// promptProceed classifies the prompt read: Ctrl-C (0x03) skips (false);
// everything else — a timeout/deadline, Enter, any other key — proceeds (true).
// Split out (pure) so the auto-proceed policy is unit-tested without a TTY.
func promptProceed(b byte, n int, readErr error) bool {
	if readErr == nil && n > 0 && b == 0x03 { // Ctrl-C
		return false
	}
	return true
}

// reportAttachResult prints the honest human-facing outcome line for an attach
// session and returns the process exit code. Split out of runAttachSession both
// to keep that driver's cyclomatic complexity in bounds and to isolate the
// exit-mapping policy: a child exit forwards its code; an undetermined or
// signal-killed exit maps to an honest failure (never a fabricated 0 / a
// negative os.Exit); a clean detach is exit 0; and the connection-loss variants
// stay honest about what is known (A2-2).
func reportAttachResult(stderr io.Writer, subcommand string, capab integration.Capability, status attachsock.ExitStatus, aerr error) error {
	switch {
	case aerr == nil && status.Exited:
		if !status.Known {
			// The child exited but the daemon could not determine its code —
			// report an honest failure, never a fabricated 0 (A4).
			fmt.Fprintf(stderr,
				"\nobserver %s --attach: the session ended but its exit status could not be determined; reporting failure.\n",
				subcommand)
			return exitErr(1)
		}
		if status.Code < 0 {
			// A signal-terminated child surfaces a negative code; never
			// os.Exit(negative) — map to a clean failure with an honest note
			// (B7).
			fmt.Fprintf(stderr,
				"\nobserver %s --attach: session terminated by a signal; reporting exit 1.\n",
				subcommand)
			return exitErr(1)
		}
		// The child exited normally — forward its exit code.
		return exitErr(status.Code)
	case aerr == nil:
		// Clean detach (external signal or stdin EOF): the child keeps running.
		fmt.Fprintf(stderr,
			"\nobserver %s --attach: detached — session continues under the observer daemon; re-attach or use the dashboard.\n",
			subcommand)
		return nil
	case errors.Is(aerr, attachsock.ErrInputStalled):
		// Keystroke forwarding failed — we detached. We do NOT know the child's
		// fate: the stall may be a wedged socket buffer (the %s session likely
		// still runs under the observer daemon) OR the leading edge of a daemon
		// exit. Stay ambiguous and point at the dashboard to check (A2-2).
		fmt.Fprintf(stderr,
			"\nobserver %s --attach: input stopped reaching the session — detaching. The %s session MAY still be running under the observer daemon; check the dashboard and re-attach, or %s to continue if it ended.\n",
			subcommand, subcommand, nativeResumeHint(capab))
		return exitErr(1)
	case errors.Is(aerr, attachsock.ErrDaemonExited):
		fmt.Fprintf(stderr,
			"\nobserver %s --attach: observer daemon exited — this session ended with it. Your conversation is preserved by the tool; %s to continue.\n",
			subcommand, nativeResumeHint(capab))
		return exitErr(1)
	case errors.Is(aerr, attachsock.ErrConnLost):
		// Ambiguous connection loss — do NOT definitively claim the daemon
		// exited (A2-2).
		fmt.Fprintf(stderr,
			"\nobserver %s --attach: connection to the observer daemon lost (daemon exit or connection failure). Your conversation is preserved by the tool; %s to continue.\n",
			subcommand, nativeResumeHint(capab))
		return exitErr(1)
	default:
		var se *attachsock.ServerError
		if errors.As(aerr, &se) {
			fmt.Fprintf(stderr, "\nobserver %s --attach: %s\n", subcommand, se.Message)
			return exitErr(1)
		}
		fmt.Fprintf(stderr, "\nobserver %s --attach: %v\n", subcommand, aerr)
		return exitErr(1)
	}
}
