package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/statusline"
)

// statuslineDefaultTimeout is the hard cap on the daemon HTTP attempt
// (plan §1.2/§2.3) used when --timeout is unset, zero, or negative.
// Never blocks past this regardless of daemon state.
const statuslineDefaultTimeout = 80 * time.Millisecond

// statuslineMaxDaemonTimeout is the HARD ceiling on the daemon HTTP
// attempt regardless of what --timeout requests (F2b). --timeout is a
// user-controllable flag; without a ceiling, `--timeout 1h` would let a
// single wedged daemon call block this command for an hour despite the
// entire point of the flag being a bound. Documented in
// docs/observer-statusline.md.
const statuslineMaxDaemonTimeout = 2 * time.Second

// statuslineJSONSchema is the stable --json envelope discriminator,
// mirroring the additive-only versioning convention `observer usage`
// uses for its own --json output (oneShotSchema in usage.go).
const statuslineJSONSchema = "superbased.statusline/1"

// statuslineStdinLimit bounds the stdin read (plan §1.1's "bounded
// io.LimitReader", mirroring cmd/observer/hook.go's own stdin-read
// idiom) so a misbehaving host can never make this command buffer an
// unbounded amount of memory before giving up and rendering degraded.
const statuslineStdinLimit = 2 * 1024 * 1024

// statuslineStdinReadTimeout is the hard deadline on the stdin read
// itself (F2a): a host that opens the pipe and never writes or closes
// it must never block this command forever. On expiry the command
// proceeds without stdin data (fail-open, exit 0) — see
// readStatuslineStdin.
const statuslineStdinReadTimeout = 500 * time.Millisecond

// statuslineTotalDeadline is the ONE total wall-clock budget over the
// entire run (F2c): config/lockfile resolution, the stdin wait, the
// daemon HTTP attempt, and rendering, combined. A var (not a const) so
// tests can shrink it to keep a deliberately-slow-body test fast
// without changing the code path under test. On expiry the command
// prints the best line it has assembled so far (at minimum, the bare
// wordmark — env/flag-sourced data merges in essentially instantly, so
// that's the realistic floor) and still exits 0.
var statuslineTotalDeadline = 3 * time.Second

// statuslineDeps are the injectable I/O seams of `observer statusline`
// (mirrors usageDeps in cmd/observer/usage.go). Production wiring is
// defaultStatuslineDeps(); tests substitute a fixed (dbDir, daemonBase)
// pair pointing at a t.TempDir() and an httptest.Server so a test never
// touches the operator's real ~/.observer or binds a real port.
type statuslineDeps struct {
	// getenv is the environment lookup for OBSERVER_STATUSLINE_* (plan
	// §1.1's lowest-precedence input source).
	getenv func(string) string
	// resolve returns the DB directory (for the lockfile pre-flight)
	// and the daemon's HTTP base URL (for the /api/statusline
	// attempt), loaded together so production pays for config.Load
	// once per invocation. Read-only: never creates ~/.observer.
	resolve func() (dbDir, daemonBase string, err error)
	// stdinTTY reports whether stdin is a real interactive terminal.
	// When true, the command never attempts to read stdin at all (plan
	// §1.1 "if stdin is a pipe (not a TTY)") — this is what keeps the
	// command from blocking forever waiting on a human at a keyboard.
	stdinTTY func() bool
	// messages returns the developer's [messages] section (whether the
	// "messages" segment shows, and for which messages). Nil = the defaults.
	// Production reads the config resolve already loaded, so it costs no
	// second config.Load.
	messages func() config.MessagesConfig
	// security returns the "security" segment's text for the payload's
	// project (statusline_security.go, lane sec-c3), nil when it shows
	// nothing. Nil = the segment is off. Production builds it from the
	// config resolve already loaded.
	security func(statusline.Input) *string
}

// messagesSettings is deps.messages, defaulted.
func (d statuslineDeps) messagesSettings() config.MessagesConfig {
	if d.messages != nil {
		return d.messages()
	}
	return config.DefaultMessagesConfig()
}

// defaultStatuslineDeps returns the production seams.
func defaultStatuslineDeps() statuslineDeps {
	msgs := config.DefaultMessagesConfig()
	var security func(statusline.Input) *string
	return statuslineDeps{
		getenv: os.Getenv,
		resolve: func() (string, string, error) {
			cfg, err := config.Load(config.LoadOptions{})
			if err != nil {
				return "", "", err
			}
			msgs = cfg.Messages
			security = statuslineSecurityProvider(cfg)
			dbDir := filepath.Dir(cfg.Observer.DBPath)
			base := "http://" + resolveDashboardAddr("", cfg.Dashboard.Addr, "127.0.0.1:8081")
			return dbDir, base, nil
		},
		stdinTTY: statuslineStdinIsTerminal,
		messages: func() config.MessagesConfig { return msgs },
		security: func(in statusline.Input) *string {
			if security == nil {
				return nil
			}
			return security(in)
		},
	}
}

// statuslineStdinIsTerminal reports whether stdin is an interactive
// console, the same char-device check stdoutIsTerminal/stderrIsTerminal
// already use elsewhere in this package.
func statuslineStdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// statuslineRunOptions is the parsed flag surface of `observer
// statusline` (plan §1.2), decoupled from *cobra.Command so the merge
// logic below is independently testable.
type statuslineRunOptions struct {
	segments []string
	timeout  time.Duration
	noDaemon bool
	color    bool
	noColor  bool
	explain  bool
	jsonOut  bool

	sessionCost    float64
	sessionCostSet bool
	model          string
	modelSet       bool
	cwd            string
	cwdSet         bool

	// host is the registry tool that runs this command (--host, written by
	// `observer init --statusline-tools`); "" is the Claude Code
	// registration, which predates the flag.
	host string
}

// newStatuslineCmd builds the production `observer statusline` command.
func newStatuslineCmd() *cobra.Command {
	return newStatuslineCmdWith(defaultStatuslineDeps())
}

// newStatuslineCmdWith builds `observer statusline` against an injected
// deps seam — the constructor cmd/observer/statusline_test.go uses so
// every test drives a fixed, non-networked daemon/lockfile view.
func newStatuslineCmdWith(deps statuslineDeps) *cobra.Command {
	var (
		segmentsFlag    string
		timeoutFlag     time.Duration
		noDaemon        bool
		colorFlag       bool
		noColorFlag     bool
		explainFlag     bool
		jsonFlag        bool
		sessionCostFlag float64
		modelFlag       string
		cwdFlag         string
		hostFlag        string
	)

	cmd := &cobra.Command{
		Use:   "statusline",
		Short: "One-line, fail-open, wordmarked cost status for a terminal prompt or editor status bar (all dollar figures are estimated list price, not an invoiced total)",
		Long: `observer statusline prints exactly one line: a short wordmark, and (when
the data is available this invocation) the current session's cost, today's
total observed spend, and the active model name.

All dollar figures are estimated list-price totals, not an invoiced amount
(same caveat as the rest of this product).

Input precedence: piped stdin JSON (Claude Code's statusLine contract, or the
CodeBuddy, Kimchi or VT Code status-line payload, detected by shape) wins,
then --session-cost/--model/--cwd flags, then OBSERVER_STATUSLINE_SESSION_COST/
OBSERVER_STATUSLINE_MODEL, then nothing (segments are omitted, never zeroed).

The "today" segment comes from a running observer daemon over a bounded,
loopback-only HTTP call; when no daemon is running (or it doesn't answer in
time) that segment is silently omitted and the command still exits 0.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := statuslineRunOptions{
				segments:       parseStatuslineSegments(segmentsFlag),
				timeout:        timeoutFlag,
				noDaemon:       noDaemon,
				color:          colorFlag,
				noColor:        noColorFlag,
				explain:        explainFlag,
				jsonOut:        jsonFlag,
				sessionCost:    sessionCostFlag,
				sessionCostSet: cmd.Flags().Changed("session-cost"),
				model:          modelFlag,
				modelSet:       cmd.Flags().Changed("model"),
				cwd:            cwdFlag,
				cwdSet:         cmd.Flags().Changed("cwd"),
				host:           hostFlag,
			}
			return runStatusline(cmd, deps, opts)
		},
	}

	cmd.Flags().StringVar(&segmentsFlag, "segments", "",
		"comma-separated ordered segment list (default: wordmark,session,today,model)")
	cmd.Flags().DurationVar(&timeoutFlag, "timeout", statuslineDefaultTimeout,
		fmt.Sprintf("hard cap on the daemon HTTP attempt (clamped to a %s maximum; <=0 uses the %s default)", statuslineMaxDaemonTimeout, statuslineDefaultTimeout))
	cmd.Flags().BoolVar(&noDaemon, "no-daemon", false,
		"skip the daemon attempt entirely (render wordmark + stdin/flag/env data only)")
	cmd.Flags().BoolVar(&colorFlag, "color", false, "force-enable ANSI color on the wordmark")
	cmd.Flags().BoolVar(&noColorFlag, "no-color", false, "force-disable ANSI color")
	cmd.Flags().BoolVar(&explainFlag, "explain", false,
		"print which data path was used to stderr (never stdout): daemon, stdin-only, or none")
	cmd.Flags().BoolVar(&jsonFlag, "json", false,
		"emit a machine-readable JSON line instead of the formatted status line")
	cmd.Flags().Float64Var(&sessionCostFlag, "session-cost", 0,
		"session cost in USD (used when stdin JSON doesn't supply cost.total_cost_usd)")
	cmd.Flags().StringVar(&modelFlag, "model", "",
		"model display name (used when stdin JSON doesn't supply model)")
	cmd.Flags().StringVar(&cwdFlag, "cwd", "",
		"current working directory (used when stdin JSON doesn't supply cwd/workspace)")
	cmd.Flags().StringVar(&hostFlag, "host", "",
		"registry tool id of the host running this command (written by `observer init --statusline-tools`); only a host whose payload carries Claude Code's plan rate_limits forwards them to Plans & limits")

	return cmd
}

// statuslineResult is the fully-formed output of one computeStatusline
// attempt: exactly what to write to stdout/stderr (each already
// newline-terminated when non-empty, so the caller never has to guess
// whether to Fprint vs Fprintln for the plain-line vs --json shapes)
// plus the error to return from RunE. Building this OFF the shared
// stdout/stderr writers, in a value returned over a channel, is what
// lets runStatusline's total-deadline select (F2c) safely race the
// background computation against a timer without either side ever
// touching cmd's io.Writers concurrently — only the single select
// statement in runStatusline writes to them, exactly once.
type statuslineResult struct {
	stdout string
	stderr string
	err    error
}

// statuslineProgress holds whatever partial statusline.Input the
// background computation has assembled so far. runStatusline's
// total-deadline branch (F2c) reads it to render the best available
// line — instead of unconditionally falling back to the bare wordmark —
// when the deadline fires before the full computation (config/lockfile
// resolution, the daemon HTTP attempt) finishes. Guarded by a mutex
// because it's written from the background goroutine and read (at
// most once) from runStatusline's own goroutine.
type statuslineProgress struct {
	mu    sync.Mutex
	input statusline.Input
	// display is the developer cost display known so far (the one the
	// daemon recorded in the budget-status file), so the deadline branch
	// never renders a dollar figure an org chose to hide.
	display string
}

func (p *statuslineProgress) set(in statusline.Input) {
	p.mu.Lock()
	p.input = in
	p.mu.Unlock()
}

func (p *statuslineProgress) setDisplay(d string) {
	p.mu.Lock()
	p.display = d
	p.mu.Unlock()
}

func (p *statuslineProgress) getDisplay() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.display
}

func (p *statuslineProgress) get() statusline.Input {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.input
}

// runStatusline is the command's full body, independent of *cobra.Command
// construction so it's easy to unit test against an injected deps value.
//
// F2c: the entire run (config/lockfile resolution, the stdin wait, the
// daemon HTTP attempt, and rendering) is bounded by ONE total
// wall-clock deadline (statuslineTotalDeadline, ~3s). If that deadline
// fires before computeStatusline finishes, this function renders and
// prints the best line it can from whatever partial data
// computeStatusline has recorded in progress so far — at minimum, the
// bare wordmark — and still returns nil (exit 0). The background
// computation is intentionally allowed to keep running after that (Go
// doesn't offer a way to hard-kill a goroutine); it simply has no
// writer left to write to.
func runStatusline(cmd *cobra.Command, deps statuslineDeps, opts statuslineRunOptions) error {
	stdout := cmd.OutOrStdout()
	stderr := cmd.ErrOrStderr()

	ctx, cancel := context.WithTimeout(cmd.Context(), statuslineTotalDeadline)
	defer cancel()

	progress := &statuslineProgress{}
	resultCh := make(chan statuslineResult, 1)
	go func() {
		resultCh <- computeStatusline(ctx, cmd, deps, opts, progress)
	}()

	select {
	case res := <-resultCh:
		if res.stdout != "" {
			io.WriteString(stdout, res.stdout) //nolint:errcheck // best-effort terminal/status-bar write
		}
		if res.stderr != "" {
			io.WriteString(stderr, res.stderr) //nolint:errcheck // best-effort diagnostic write
		}
		return res.err
	case <-ctx.Done():
		in := progress.get()
		renderOpts := statusline.RenderOptions{
			Color:    resolveStatuslineColor(deps, opts),
			Segments: opts.segments,
		}
		partial := statusline.DaemonTile{CostDisplay: progress.getDisplay()}
		line := statusline.Render(in, partial, renderOpts)
		if opts.jsonOut {
			_ = writeStatuslineJSON(stdout, line, partial, in, "none")
		} else {
			fmt.Fprintln(stdout, line)
		}
		if opts.explain {
			fmt.Fprintf(stderr, "statusline: path=none daemon_reason=%q\n", "total wall-clock deadline exceeded")
		}
		return nil
	}
}

// computeStatusline does the actual work (stdin merge, daemon attempt,
// render) and returns the fully-formed output rather than writing it
// directly — see statuslineResult's doc comment for why.
func computeStatusline(ctx context.Context, cmd *cobra.Command, deps statuslineDeps, opts statuslineRunOptions, progress *statuslineProgress) statuslineResult {
	merged := statuslineInputFromEnv(deps.getenv)
	merged = overlayStatuslineInput(merged, statuslineInputFromFlags(opts))

	// rawStdin is the bounded stdin payload, kept for the Plans & limits
	// feed (statusline_plans.go), which forwards only its rate_limits
	// numbers.
	var (
		rawStdin []byte
		shape    statusline.Shape
	)
	if !deps.stdinTTY() {
		merged, rawStdin, shape = overlayStatuslineStdin(ctx, cmd, merged)
	}
	progress.set(merged)

	var (
		tile             statusline.DaemonTile
		daemonOK         bool
		daemonReason     string
		daemonLatency    time.Duration
		daemonAttempted  bool
		effectiveTimeout time.Duration
		// budgetDBDir is the resolved DB directory the budget segment reads
		// the daemon-owned status file from ("" with --no-daemon: that flag
		// skips every resolution, so the segment is omitted).
		budgetDBDir string
		// fileDisplay is the developer cost display the daemon last recorded
		// in the budget-status file: the fallback when the daemon tile does
		// not answer (unreachable, or an older daemon).
		fileDisplay string
	)

	if opts.noDaemon {
		daemonReason = "skipped (--no-daemon)"
	} else {
		dbDir, daemonBase, resolveErr := deps.resolve()
		if resolveErr == nil {
			budgetDBDir = dbDir
			if dbDir != "" {
				fileDisplay = budgetStatusDisplay(budgetStatusPathInDir(dbDir))
				progress.setDisplay(fileDisplay)
			}
		}
		loopbackBase, loopbackOK := statuslineLoopbackAddr(daemonBase)
		switch {
		case resolveErr != nil || dbDir == "":
			daemonReason = "skipped (could not resolve db directory)"
		case !hasLiveDaemonLock(dbDir):
			daemonReason = "skipped (no live daemon lockfile)"
		case daemonBase == "":
			daemonReason = "skipped (could not resolve daemon address)"
		case !loopbackOK:
			// F4: a poisoned OBSERVER_DASHBOARD_ADDR or a configured
			// non-loopback [dashboard].addr must never cause this
			// command to send a request (which carries session_id)
			// off-machine in plaintext. Skip the daemon path entirely
			// — never dial it, not even once.
			daemonReason = "skipped (daemon addr not loopback - skipped)"
		default:
			daemonAttempted = true
			effectiveTimeout = clampStatuslineTimeout(opts.timeout)
			start := time.Now()
			ok, ferr := fetchStatuslineTile(ctx, loopbackBase, effectiveTimeout, statuslineSessionID(merged), deps.messagesSettings(), &tile)
			daemonLatency = time.Since(start)
			if ok {
				daemonOK = true
				// Plans & limits: forward the payload's rate_limits numbers
				// to the daemon, on change only (statusline_plans.go).
				// Same loopback-and-live-daemon gate as the tile above;
				// fail-open, bounded.
				// Only a host whose payload carries Claude Code's plan
				// rate_limits forwards (a look-alike host never feeds
				// Claude's plan meter).
				if statuslineHostForwardsPlanLimits(opts.host) {
					forwardPlanStatusLine(ctx, loopbackBase, dbDir, rawStdin, time.Now())
				}
			} else {
				daemonReason = fmt.Sprintf("unreachable (%v, %s)", ferr, daemonLatency.Round(time.Millisecond))
			}
		}
	}

	hasStdinData := statuslineInputHasData(merged)
	source := "none"
	switch {
	case daemonOK:
		source = "daemon"
	case hasStdinData:
		source = "stdin"
	}

	// The org budget warning (statusline_budget.go) is read from the
	// daemon-owned file beside the DB, not over HTTP, so it shows even when
	// the dashboard is unreachable (but not with --no-daemon, which skips
	// all resolution).
	//
	// The developer cost display (org display policy) comes from the daemon
	// tile; when the daemon was unreachable it falls back to the display the
	// daemon last recorded in that same file, so an org that chose token
	// usage never gets Claude Code's stdin dollar figure on a daemon blip.
	if tile.CostDisplay == "" {
		tile.CostDisplay = fileDisplay
	}
	if budgetDBDir != "" {
		if label := budgetStatuslineLabel(budgetStatusPathInDir(budgetDBDir), tile.CostDisplay); label != "" {
			tile.Budget = &label
		}
	}

	segments := opts.segments
	// The security segment (lane sec-c3): from the signed posture file,
	// never the daemon; skipped with --no-daemon like every resolution.
	if !opts.noDaemon && budgetDBDir != "" && deps.security != nil {
		if label := deps.security(merged); label != nil {
			tile.Security = label
			segments = withSecuritySegment(segments)
		}
	}
	renderOpts := statusline.RenderOptions{
		Color:    resolveStatuslineColor(deps, opts),
		Segments: segments,
	}
	line := statusline.Render(merged, tile, renderOpts)

	var res statuslineResult

	if opts.jsonOut {
		var buf strings.Builder
		res.err = writeStatuslineJSON(&buf, line, tile, merged, source)
		res.stdout = buf.String()
	} else {
		res.stdout = line + "\n"
	}

	if opts.explain {
		res.stderr = statuslineExplainLine(source, shape, opts.host, daemonAttempted, effectiveTimeout, daemonLatency, daemonReason)
	}

	return res
}

// overlayStatuslineStdin reads the bounded stdin payload and overlays it on
// merged, returning the raw bytes (for the Plans & limits feed) and the
// payload's shape. A stalled, oversized or malformed payload overlays
// nothing (fail-open, never an error).
func overlayStatuslineStdin(ctx context.Context, cmd *cobra.Command, merged statusline.Input) (statusline.Input, []byte, statusline.Shape) {
	var (
		rawStdin []byte
		shape    statusline.Shape
	)
	// F2a: a stalled pipe (opened, never written to, never closed)
	// must never block this command forever — the read itself is
	// deadline-bounded, independent of (and nested inside) the
	// overall F2c total deadline. F3: reading limit+1 bytes lets
	// readStatuslineStdin's caller (here) detect an oversized
	// stream even when its first `limit` bytes happen to parse as
	// complete, valid JSON on their own.
	data, ok := readStatuslineStdin(ctx, cmd.InOrStdin(), statuslineStdinLimit, statuslineStdinReadTimeout)
	switch {
	case !ok:
		// Timed out (or the overall context expired first) —
		// proceed without stdin data. Fail-open, never an error.
	case int64(len(data)) > statuslineStdinLimit:
		// Oversized stream (F3): the true stream was larger than
		// the documented bound even though a truncated prefix
		// might parse cleanly. Treat stdin as wholly absent
		// rather than risk acting on a truncated payload.
	case len(data) > 0:
		// ParseInput is tolerant: on malformed JSON it returns a
		// usable zero Input alongside the error, so a bad payload
		// never panics and never blocks the rest of the merge —
		// we simply overlay nothing from stdin in that case.
		if parsed, sh, perr := statusline.ParsePayload(data); perr == nil {
			merged = overlayStatuslineInput(merged, parsed)
			shape = sh
		}
		rawStdin = data
	}
	return merged, rawStdin, shape
}

// statuslineExplainLine is the --explain line written to stderr: the data
// path, the payload shape, the host, and the daemon attempt.
func statuslineExplainLine(source string, shape statusline.Shape, host string, daemonAttempted bool, effectiveTimeout, daemonLatency time.Duration, daemonReason string) string {
	var buf strings.Builder
	explainSource := source
	if explainSource == "stdin" {
		explainSource = "stdin-only"
	}
	fmt.Fprintf(&buf, "statusline: path=%s", explainSource)
	if shape != "" {
		fmt.Fprintf(&buf, " payload=%s", shape)
	}
	if host != "" {
		fmt.Fprintf(&buf, " host=%q", host)
	}
	if daemonAttempted {
		fmt.Fprintf(&buf, " daemon_timeout=%s daemon_latency=%s", effectiveTimeout, daemonLatency.Round(time.Millisecond))
	}
	if daemonReason != "" {
		fmt.Fprintf(&buf, " daemon_reason=%q", daemonReason)
	}
	buf.WriteString("\n")
	return buf.String()
}

// statuslineHostForwardsPlanLimits reports whether the host running this
// command declares Claude Code's plan rate_limits in its payload
// (integration.StatusLineSpec.PlanRateLimits). No --host is the Claude Code
// registration, written before the flag existed.
func statuslineHostForwardsPlanLimits(host string) bool {
	if host == "" {
		return true
	}
	return integration.StatusLineFor(host).PlanRateLimits
}

// readStatuslineStdin reads at most limit+1 bytes from r within a hard
// deadline (F2a: a stalled pipe — opened, never written to, never
// closed — must never block this command forever). Returns ok=false on
// timeout (including the caller's own context expiring first); a
// timeout is not an error, the caller proceeds without stdin data,
// fail-open, exit 0.
//
// Reading limit+1 (not limit) bytes, rather than the bare
// io.LimitReader(r, limit) this used before, lets the caller detect an
// oversized stream (F3): io.LimitReader silently truncates at exactly
// `limit` bytes, so a stream whose first `limit` bytes happen to
// parse as a complete, valid JSON value on their own would otherwise be
// accepted even though the actual stream was larger than the
// documented bound. The caller checks len(data) > limit and, when true,
// treats stdin as wholly absent rather than parsing the truncated
// prefix.
//
// The background read goroutine is not (and cannot cheaply be)
// canceled on timeout — it keeps blocking on the underlying Read until
// the pipe produces data or is closed, same as any other bounded-read
// idiom over a blocking io.Reader. That's fine: this process exits
// shortly after rendering regardless, and the goroutine's result is
// simply never consumed.
func readStatuslineStdin(ctx context.Context, r io.Reader, limit int64, timeout time.Duration) ([]byte, bool) {
	ch := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(io.LimitReader(r, limit+1))
		ch <- data
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case data := <-ch:
		return data, true
	case <-timer.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

// clampStatuslineTimeout applies F2b's hard ceiling to the --timeout
// flag: zero/negative falls back to statuslineDefaultTimeout (80ms,
// same as before), and anything above statuslineMaxDaemonTimeout (2s)
// is clamped down to it — `--timeout 1h` must never actually let the
// daemon HTTP attempt run anywhere close to an hour.
func clampStatuslineTimeout(requested time.Duration) time.Duration {
	if requested <= 0 {
		return statuslineDefaultTimeout
	}
	if requested > statuslineMaxDaemonTimeout {
		return statuslineMaxDaemonTimeout
	}
	return requested
}

// statuslineLoopbackAddr validates that base's host is loopback-only
// (F4) — 127.0.0.0/8, ::1, or the literal "localhost" — before this
// command ever dials it. A wildcard bind ("0.0.0.0" or "::", meaning
// the daemon is configured to listen on every interface) is mapped to
// 127.0.0.1: dialing the loopback interface still reaches a daemon
// bound to all interfaces on the SAME machine, so this is not a
// weakening of the check, just the address this process should
// actually use. Any other host — in particular a poisoned
// OBSERVER_DASHBOARD_ADDR env var or a configured non-loopback
// [dashboard].addr pointing at a remote host — returns ok=false, and
// the caller must skip the daemon path entirely rather than dial it:
// the request carries session_id, and a non-loopback destination would
// exfiltrate that off-machine in plaintext.
func statuslineLoopbackAddr(base string) (resolved string, ok bool) {
	if base == "" {
		return "", false
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "", false
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host, port = u.Host, ""
	}
	switch host {
	case "0.0.0.0", "::":
		host = "127.0.0.1"
	case "localhost", "127.0.0.1", "::1":
		// Already loopback-shaped; nothing to rewrite.
	default:
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return "", false
		}
	}
	if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
	}
	return u.String(), true
}

// hasLiveDaemonLock reports whether dbDir holds at least one live
// observer lockfile (internal/diag.LiveLocks) that also cheaply
// verifies (F5) it belongs to an actual observer process. A glob/read
// error is treated the same as "no lock": the command must never error
// out just because it couldn't prove a daemon is up.
func hasLiveDaemonLock(dbDir string) bool {
	locks, err := diag.LiveLocks(dbDir)
	if err != nil {
		return false
	}
	for _, lock := range locks {
		if statuslinePIDLooksLikeObserver(lock) {
			return true
		}
	}
	return false
}

// statuslinePIDLooksLikeObserver strengthens a diag.LiveLocks candidate
// beyond bare PID-existence (F5): internal/diag.LiveLocks only checks
// that a process with the recorded PID is still running, which PID
// reuse can fool — a live lockfile whose PID has since been recycled by
// an unrelated process would otherwise look like a live daemon and
// cause one spurious (but bounded, loopback-only per F4) dial.
//
// On Linux this reads /proc/<pid>/cmdline and requires it to contain
// EITHER the literal substring "observer" OR the lock's own recorded
// binary_path basename — a cheap, best-effort corroboration, not a
// security boundary on its own. Matching either needle (not requiring
// the more specific one to override the generic one) means a custom-
// named or symlinked observer binary whose basename doesn't literally
// contain "observer" still corroborates correctly, while the common
// case (a binary path that does contain "observer", e.g. the real
// production binary or this package's own "observer.test" test
// binary) always matches regardless of what BinaryPath happens to
// record. On any other platform, or on ANY read error here (permission
// denied, /proc unmounted, the process having exited in the gap
// between LiveLocks and this read), this FAILS OPEN —
// treats the lock as live. That asymmetry is deliberate: the dial this
// gates is already bounded and loopback-only (F4), so the cost of a
// false positive (one extra bounded local dial) is far lower than the
// cost of a false negative (silently never trying the daemon on a
// platform/permission combination this check can't verify).
func statuslinePIDLooksLikeObserver(lock diag.LockInfo) bool {
	if runtime.GOOS != "linux" {
		return true
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", lock.PID))
	if err != nil || len(raw) == 0 {
		return true
	}
	cmdline := strings.ToLower(strings.ReplaceAll(string(raw), "\x00", " "))
	if strings.Contains(cmdline, "observer") {
		return true
	}
	if base := filepath.Base(lock.BinaryPath); base != "" && base != "." && base != string(filepath.Separator) {
		if strings.Contains(cmdline, strings.ToLower(base)) {
			return true
		}
	}
	return false
}

// statuslineWireResponse mirrors internal/intelligence/dashboard's
// StatuslineResponse field-for-field. It is redefined here (rather than
// importing that package) because cmd/observer/statusline.go's only
// contract with the daemon is this JSON wire shape over HTTP — importing
// the dashboard package itself would pull an unrelated, much larger
// dependency graph into a small CLI command for the sake of one struct.
type statuslineWireResponse struct {
	TodayUSD              *float64 `json:"today_usd"`
	SessionUSD            *float64 `json:"session_usd"`
	SessionCacheReadShare *float64 `json:"session_cache_read_share"`
	GeneratedAt           string   `json:"generated_at"`
	CostDisplay           string   `json:"cost_display"`
	TodayTokens           *int64   `json:"today_tokens"`
	SessionTokens         *int64   `json:"session_tokens"`
	GrantsInForce         int      `json:"grants_in_force"`
	NextGrantExpiryNs     int64    `json:"next_grant_expiry_ns"`
	MessagesUnread        int      `json:"messages_unread"`
	MessagesUnreadAlerts  int      `json:"messages_unread_alerts"`
}

// fetchStatuslineTile makes the one bounded, loopback-only HTTP call
// this command ever makes: GET <base>/api/statusline[?session_id=...],
// with a hard client timeout. Returns ok=false on any failure (network,
// non-200 status, malformed body) — the caller degrades silently in
// every such case (plan §2.3).
func fetchStatuslineTile(ctx context.Context, base string, timeout time.Duration, sessionID string, msgs config.MessagesConfig, tile *statusline.DaemonTile) (bool, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	target := strings.TrimRight(base, "/") + "/api/statusline"
	if sessionID != "" {
		target += "?session_id=" + url.QueryEscape(sessionID)
	}

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return false, err
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("http status %d", resp.StatusCode)
	}

	var body statuslineWireResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return false, err
	}

	tile.TodayUSD = body.TodayUSD
	tile.SessionUSD = body.SessionUSD
	tile.CacheReadShare = body.SessionCacheReadShare
	tile.CostDisplay = body.CostDisplay
	tile.TodayTokens = body.TodayTokens
	tile.SessionTokens = body.SessionTokens
	tile.Grants = statuslineGrantsText(body.GrantsInForce, body.NextGrantExpiryNs, time.Now())
	tile.MessagesUnread = statuslineMessagesUnread(body.MessagesUnread, body.MessagesUnreadAlerts, msgs)
	return true, nil
}

// statuslineMessagesUnread is the count the "messages" segment shows under
// the developer's [messages] choices (T-854): nothing when they turned the
// status line surface off, only alert conversations under alerts_only,
// every unread admin message otherwise.
func statuslineMessagesUnread(all, alerts int, msgs config.MessagesConfig) int {
	switch {
	case !msgs.Statusline:
		return 0
	case msgs.AlertsOnly:
		return alerts
	default:
		return all
	}
}

// statuslineGrantsText renders the grants segment: how many org exceptions
// are in force and how long the nearest one has left. nil when none.
func statuslineGrantsText(n int, nextExpiryNs int64, now time.Time) *string {
	if n <= 0 {
		return nil
	}
	text := "1 exception"
	if n > 1 {
		text = strconv.Itoa(n) + " exceptions"
	}
	if nextExpiryNs > 0 {
		if left := time.Unix(0, nextExpiryNs).Sub(now); left > 0 {
			text += ", " + accessgrant.HumanDuration(left) + " left"
		}
	}
	return &text
}

// resolveStatuslineColor decides ANSI color use: an explicit
// --no-color always wins, then --color, then the same
// TTY+NO_COLOR-aware auto-detection `observer usage` already uses.
func resolveStatuslineColor(deps statuslineDeps, opts statuslineRunOptions) bool {
	if opts.noColor {
		return false
	}
	if opts.color {
		return true
	}
	if deps.getenv("NO_COLOR") != "" {
		return false
	}
	return stdoutIsTerminal()
}

// parseStatuslineSegments splits a comma-separated --segments flag value
// into a trimmed, non-empty segment list. An empty/blank flag value
// yields a nil slice, which statusline.Render treats as "use
// DefaultSegments" (never an error, never an empty rendered line just
// because the flag was passed with stray whitespace).
func parseStatuslineSegments(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// statuslineInputFromEnv builds an Input from the lowest-precedence
// input source (plan §1.1 point 3): OBSERVER_STATUSLINE_SESSION_COST /
// OBSERVER_STATUSLINE_MODEL. An unparseable cost env value is silently
// ignored (never a fatal error over a malformed environment variable).
func statuslineInputFromEnv(getenv func(string) string) statusline.Input {
	var in statusline.Input
	if raw := strings.TrimSpace(getenv("OBSERVER_STATUSLINE_SESSION_COST")); raw != "" {
		if v, err := parseStatuslineCost(raw); err == nil {
			in.Cost = &statusline.Cost{TotalCostUSD: &v}
		}
	}
	if raw := strings.TrimSpace(getenv("OBSERVER_STATUSLINE_MODEL")); raw != "" {
		v := raw
		in.Model = &statusline.Model{DisplayName: &v}
	}
	return in
}

// parseStatuslineCost parses a decimal USD string — the env-var path's
// counterpart to cobra's own Float64Var parsing on --session-cost.
func parseStatuslineCost(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}

// statuslineInputFromFlags builds an Input from the middle-precedence
// input source (plan §1.1 point 2): --session-cost/--model/--cwd. Only
// flags the caller actually SET (cobra's Flags().Changed) populate a
// field — an unset float64/string flag must never be mistaken for an
// explicit "0"/"" value.
func statuslineInputFromFlags(opts statuslineRunOptions) statusline.Input {
	var in statusline.Input
	if opts.sessionCostSet {
		v := opts.sessionCost
		in.Cost = &statusline.Cost{TotalCostUSD: &v}
	}
	if opts.modelSet {
		v := opts.model
		in.Model = &statusline.Model{DisplayName: &v}
	}
	if opts.cwdSet {
		v := opts.cwd
		in.CWD = &v
	}
	return in
}

// overlayStatuslineInput layers `over` on top of `base`, field by field:
// wherever `over` supplies a non-nil value it wins, otherwise `base`'s
// value (possibly also nil) is kept. Callers apply this in ascending
// precedence order (env as the base, then flags, then stdin last) so
// the plan §1.1 ladder — stdin beats flags beats env — falls out of
// three calls in that order.
func overlayStatuslineInput(base, over statusline.Input) statusline.Input {
	out := base
	if over.SessionID != nil {
		out.SessionID = over.SessionID
	}
	if over.TranscriptPath != nil {
		out.TranscriptPath = over.TranscriptPath
	}
	if over.CWD != nil {
		out.CWD = over.CWD
	}
	if over.Model != nil {
		out.Model = overlayStatuslineModel(out.Model, over.Model)
	}
	if over.Workspace != nil {
		out.Workspace = overlayStatuslineWorkspace(out.Workspace, over.Workspace)
	}
	if over.Cost != nil {
		out.Cost = overlayStatuslineCost(out.Cost, over.Cost)
	}
	if over.OutputStyle != nil {
		out.OutputStyle = over.OutputStyle
	}
	if over.Version != nil {
		out.Version = over.Version
	}
	return out
}

// overlayStatuslineModel merges two *Model pointers field-by-field, so
// e.g. an env-supplied DisplayName isn't wiped out by a stdin payload
// that only carries an ID.
func overlayStatuslineModel(base, over *statusline.Model) *statusline.Model {
	if over == nil {
		return base
	}
	if base == nil {
		cp := *over
		return &cp
	}
	out := *base
	if over.ID != nil {
		out.ID = over.ID
	}
	if over.DisplayName != nil {
		out.DisplayName = over.DisplayName
	}
	return &out
}

// overlayStatuslineWorkspace merges two *Workspace pointers field-by-field.
func overlayStatuslineWorkspace(base, over *statusline.Workspace) *statusline.Workspace {
	if over == nil {
		return base
	}
	if base == nil {
		cp := *over
		return &cp
	}
	out := *base
	if over.CurrentDir != nil {
		out.CurrentDir = over.CurrentDir
	}
	if over.ProjectDir != nil {
		out.ProjectDir = over.ProjectDir
	}
	return &out
}

// overlayStatuslineCost merges two *Cost pointers field-by-field.
func overlayStatuslineCost(base, over *statusline.Cost) *statusline.Cost {
	if over == nil {
		return base
	}
	if base == nil {
		cp := *over
		return &cp
	}
	out := *base
	if over.TotalCostUSD != nil {
		out.TotalCostUSD = over.TotalCostUSD
	}
	if over.TotalDurationMS != nil {
		out.TotalDurationMS = over.TotalDurationMS
	}
	if over.TotalLinesAdded != nil {
		out.TotalLinesAdded = over.TotalLinesAdded
	}
	if over.TotalLinesRemoved != nil {
		out.TotalLinesRemoved = over.TotalLinesRemoved
	}
	return &out
}

// statuslineInputHasData reports whether in carries any actual datum at
// all — used to decide the --explain/--json "source" classification
// between "stdin" (something was supplied via stdin/flags/env) and
// "none" (nothing was, and the daemon path also failed or was skipped).
func statuslineInputHasData(in statusline.Input) bool {
	return in.SessionID != nil || in.TranscriptPath != nil || in.CWD != nil ||
		in.Model != nil || in.Workspace != nil || in.Cost != nil ||
		in.OutputStyle != nil || in.Version != nil
}

// statuslineSessionID extracts the session id (if any) from a merged
// Input, for the /api/statusline?session_id=... query parameter.
func statuslineSessionID(in statusline.Input) string {
	if in.SessionID == nil {
		return ""
	}
	return *in.SessionID
}

// statuslineModelDisplay resolves the best available model label for
// --json output, mirroring internal/statusline's own unexported
// modelName precedence (DisplayName over ID) without reaching across
// the package boundary for an unexported helper.
func statuslineModelDisplay(in statusline.Input) string {
	if in.Model == nil {
		return ""
	}
	if in.Model.DisplayName != nil && *in.Model.DisplayName != "" {
		return *in.Model.DisplayName
	}
	if in.Model.ID != nil {
		return *in.Model.ID
	}
	return ""
}

// statuslineJSONOutput is the --json wire shape (plan §1.2): a machine-
// readable line a host tool can compose its own layout from, schema-
// versioned like `observer usage`'s own --json envelope.
type statuslineJSONOutput struct {
	Schema     string   `json:"schema"`
	Line       string   `json:"line"`
	TodayUSD   *float64 `json:"today_usd"`
	SessionUSD *float64 `json:"session_usd"`
	Model      string   `json:"model"`
	Source     string   `json:"source"`
	// CostDisplay is "tokens" when the org chose token usage for developers;
	// TodayUSD / SessionUSD are then null and TodayTokens / SessionTokens
	// carry the figures. Omitted in dollar mode (the pre-change shape).
	CostDisplay   string `json:"cost_display,omitempty"`
	TodayTokens   *int64 `json:"today_tokens,omitempty"`
	SessionTokens *int64 `json:"session_tokens,omitempty"`
}

// writeStatuslineJSON encodes the --json payload. SessionUSD prefers
// the stdin/flag/env-sourced figure (Claude Code's own number, no
// lookup needed) over the daemon's session-scoped figure, matching
// internal/statusline's own renderSessionSegment precedence exactly.
func writeStatuslineJSON(out io.Writer, line string, tile statusline.DaemonTile, in statusline.Input, source string) error {
	sessionUSD := tile.SessionUSD
	if in.Cost != nil && in.Cost.TotalCostUSD != nil {
		sessionUSD = in.Cost.TotalCostUSD
	}
	payload := statuslineJSONOutput{
		Schema:     statuslineJSONSchema,
		Line:       line,
		TodayUSD:   tile.TodayUSD,
		SessionUSD: sessionUSD,
		Model:      statuslineModelDisplay(in),
		Source:     source,
	}
	if tile.CostDisplay == statusline.CostDisplayTokens {
		payload.TodayUSD, payload.SessionUSD = nil, nil
		payload.CostDisplay = statusline.CostDisplayTokens
		payload.TodayTokens, payload.SessionTokens = tile.TodayTokens, tile.SessionTokens
	}
	enc := json.NewEncoder(out)
	return enc.Encode(payload)
}
