package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// HarnessDriver drives one benchmark attempt's harness subprocess and returns
// the outcome. It is the injectable execution abstraction (plan §3.2): the real
// impls shell out to the shipped `observer <tool>` launcher verbs; a fake drives
// the runner in unit tests without spending. The runner dispatches on the
// harness NAME resolved from the spec config — a capability lookup, not a
// tool-name business branch (the name is the driver-registry key).
type HarnessDriver interface {
	// Name is the harness id the spec's config.harness matches ("codex").
	Name() string
	// Drive runs the harness for one cell. A non-nil error is a harness-level
	// failure (spawn/setup of the subprocess); a task the model failed is a
	// successful Drive with a non-zero ExitCode in the result.
	Drive(ctx context.Context, req DriveRequest) (DriveResult, error)
}

// DriveRequest is one cell's harness invocation.
type DriveRequest struct {
	Prompt       string
	Model        string
	WorkspaceDir string // per-attempt isolated repo checkout (correlation cross-check)
	HomeDir      string // isolated CODEX_HOME / HOME (auth.json copied in by the runner)
	ProxyURL     string // observer proxy base (route on)
	TimeoutSec   int    // per-attempt wall cap; 0 = no cap
	MaxTurns     int    // per-attempt turn cap where the harness supports it
	// TaskRepo is the task's source repository as the spec names it; a
	// local directory is the accept root of the attempt's trust check
	// (benchmarkTrustLaunch).
	TaskRepo string
	// TrustEnv are the environment entries the launch-gate walk gives the
	// harness process (the checked marker, the task source for an inner
	// launcher), layered after the inherited environment.
	TrustEnv []string
}

// DriveResult is the harness outcome. SessionIDs is the captured/minted
// correlation id(s) (primary first) — the runner resolves them to sessions.
type DriveResult struct {
	ExitCode    int
	WallMS      int64
	FinalAnswer string   // extracted, ANSI-stripped final response (pre-scrub)
	SessionIDs  []string // codex thread_id(s) / claude minted session id
	TimedOut    bool
}

// ErrHarnessNotSupported is returned by a driver whose harness is not enabled
// (a future harness pending its own Phase-0 fidelity spike). No shipped driver
// returns it today — codex and claude-code are both real; claude-code's gate is
// ErrClaudeCodeNotIsolated, not unsupportedness.
var ErrHarnessNotSupported = errors.New("harness not supported in benchmark v1")

// codexDriver drives Codex CLI through the shipped `observer codex` launcher
// verb (spike Q1 command shape). It captures the thread_id from the first
// `--json` stdout line and the final answer from the `-o` output file.
type codexDriver struct {
	observerBin string // os.Executable() — the same binary hosting the runner
}

func (codexDriver) Name() string { return "codex" }

// ChecksLaunchAgain reports that the harness process is the `observer
// codex` launcher, which walks the launch-gate table again in the
// workspace (benchmarkRelauncher).
func (codexDriver) ChecksLaunchAgain() bool { return true }

func (d codexDriver) Drive(ctx context.Context, req DriveRequest) (DriveResult, error) {
	lastMsg := filepath.Join(req.WorkspaceDir, ".sbo-last-message.txt")
	args := []string{
		"codex", "--no-app-server-check", "--proxy", req.ProxyURL, "--",
		"exec", req.Prompt,
		"-s", "workspace-write", "--skip-git-repo-check",
		"-m", req.Model, "-C", req.WorkspaceDir,
		"--json", "-o", lastMsg,
	}
	if req.TimeoutSec > 0 {
		ctxTimeout, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutSec)*time.Second)
		defer cancel()
		ctx = ctxTimeout
	}
	cmd := exec.CommandContext(ctx, d.observerBin, args...) //nolint:gosec // G204: args are built from the operator-authored spec TOML (local trust boundary), not external/untrusted input
	cmd.Dir = req.WorkspaceDir
	cmd.Stdin = nil // < /dev/null — codex exec is non-interactive
	cmd.Env = append(benchmarkTrustChildEnv(os.Environ(), req.TrustEnv), "CODEX_HOME="+req.HomeDir)
	setProcGroup(cmd)
	// Kill the whole process group on ctx cancellation so a hung grandchild
	// (app-server) can't outlive the cell (plan §3.2 step 2).
	cmd.Cancel = func() error { return killProcGroup(cmd) }

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout

	start := time.Now()
	runErr := cmd.Run()
	wallMS := time.Since(start).Milliseconds()

	res := DriveResult{WallMS: wallMS}
	res.SessionIDs = parseCodexThreadIDs(stdout.Bytes())
	if ans, err := os.ReadFile(lastMsg); err == nil {
		res.FinalAnswer = stripANSI(string(ans))
	}
	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			res.TimedOut = true
		}
		res.ExitCode = exitCodeOf(runErr)
		return res, nil // a non-zero harness exit is an outcome, not a Drive error
	}
	return res, nil
}

// parseCodexThreadIDs extracts thread_id values from codex `--json` stdout. The
// `{"type":"thread.started","thread_id":"…"}` line is the FIRST line and is
// emitted even on a failed turn (spike finding). Returns primary first.
func parseCodexThreadIDs(stdout []byte) []string {
	var ids []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev struct {
			Type     string `json:"type"`
			ThreadID string `json:"thread_id"`
		}
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		if ev.ThreadID != "" && !seen[ev.ThreadID] {
			seen[ev.ThreadID] = true
			ids = append(ids, ev.ThreadID)
		}
	}
	return ids
}

// ErrClaudeCodeNotIsolated is returned by claudeCodeDriver.Preflight when the
// run is pointed at the operator's default (or an oversized) observer DB. The
// 2026-07-12 re-spike proved the v1 §Q2 NO-GO was purely environmental — the
// auto-registered PreToolUse hook did db.Open on a 7.66 GB production DB while
// foreign sessions hammered the WAL (~100 s/Bash call). On a fresh isolated
// daemon with its own small DB the identical hook is 20–30 ms. The fix is DB
// isolation, not hook disablement (hooks stay ON — they carry the correlation
// seam in the sandbox). See docs/plans/benchmarks-claude-code-respike-findings-
// 2026-07-12.md §6.
var ErrClaudeCodeNotIsolated = errors.New("claude-code benchmark requires an isolated daemon DB")

// defaultBenchmarkDBCeilingBytes is the isolation size ceiling Preflight
// enforces. The re-spike measured isolated DBs at 18–117 MB (hook stayed flat
// at ~0.02 s across that growth) versus the 7.66 GB production DB that stalled;
// 512 MiB is comfortably above a claude-code-only benchmark daemon's footprint
// and far below the production aggregate.
const defaultBenchmarkDBCeilingBytes int64 = 512 << 20 // 512 MiB

// claudeCodeDriver drives Claude Code headless (print mode) through the
// isolated benchmark proxy, per the re-spike §6 recommendation. It mints a
// --session-id (== sessions.id, the codex-identical correlation seam), runs in
// a unique workspace root, and keeps the observer hooks ON (they create the
// sandbox session row the correlation resolver reads). The isolated-daemon
// requirement is enforced in Preflight, before any spend.
type claudeCodeDriver struct {
	claudeBin  string        // configured `claude` path; "" → resolve on PATH at Drive
	dbPath     string        // resolved observer DB path (cfg.Observer.DBPath) — the isolation gate subject
	maxDBBytes int64         // Preflight size ceiling; 0 → defaultBenchmarkDBCeilingBytes
	mintID     func() string // session-id minter; injectable for tests
}

// newClaudeCodeDriver builds the driver from the resolved claude binary path
// (may be "") and the observer DB path Preflight gates on.
func newClaudeCodeDriver(claudeBin, dbPath string) claudeCodeDriver {
	return claudeCodeDriver{
		claudeBin:  claudeBin,
		dbPath:     dbPath,
		maxDBBytes: defaultBenchmarkDBCeilingBytes,
		mintID:     newBenchmarkSessionID,
	}
}

func (claudeCodeDriver) Name() string { return "claude-code" }

// NeedsIsolatedDaemon reports that claude-code benchmarking requires a dedicated
// isolated observer daemon (its own small DB) — the capability the runner keys
// the ephemeral-daemon auto-engage decision on (CLAUDE.md #3: a capability, not
// a harness-name branch). See Preflight for why the operator-default DB is
// refused.
func (claudeCodeDriver) NeedsIsolatedDaemon() bool { return true }

// Preflight encodes the isolated-daemon requirement (re-spike §6.3): it fails
// loudly BEFORE any spend unless the run is pointed at a dedicated benchmark
// daemon. Two independent gates, either of which rejects: (a) the resolved DB
// path must NOT be the operator's default ~/.observer/observer.db, and (b) the
// DB file must be under the size ceiling. A not-yet-created DB (fresh isolated
// daemon) passes. The stronger, fully-hermetic alternative — the runner stands
// up its own ephemeral daemon (fresh DB, non-default ports, auto_register=false)
// and tears it down after — is the RUNNER's job (documented in the findings
// doc); this check is the cheap, robust guard when the operator wires up the
// isolated daemon by hand (what the re-spike did).
func (d claudeCodeDriver) Preflight() error {
	if strings.TrimSpace(d.dbPath) == "" {
		return fmt.Errorf("%w: no observer DB path resolved - re-run with --ephemeral-daemon to auto-provision an isolated benchmark daemon (or pass --config for your own)", ErrClaudeCodeNotIsolated)
	}
	if def, err := defaultObserverDBPath(); err == nil && sameDBPath(d.dbPath, def) {
		return fmt.Errorf("%w: refusing to run against the operator default DB %q - "+
			"claude-code hooks db.Open a large shared DB and stall (~100 s/Bash call, re-spike §Q2). "+
			"Re-run with --ephemeral-daemon to auto-provision an isolated daemon, or point --config at "+
			"one yourself (own db_path, non-default ports, auto_register=false)",
			ErrClaudeCodeNotIsolated, d.dbPath)
	}
	ceiling := d.maxDBBytes
	if ceiling <= 0 {
		ceiling = defaultBenchmarkDBCeilingBytes
	}
	info, err := os.Stat(d.dbPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // fresh isolated daemon — DB not written yet; clearly not the 7.66 GB prod DB
		}
		return fmt.Errorf("%w: stat DB %q: %w", ErrClaudeCodeNotIsolated, d.dbPath, err)
	}
	if info.Size() > ceiling {
		return fmt.Errorf("%w: observer DB %q is %d MiB (> %d MiB ceiling) - this is the "+
			"large-DB stall condition the re-spike identified; re-run with --ephemeral-daemon "+
			"to auto-provision a fresh claude-code-only daemon (18-117 MiB in the re-spike)",
			ErrClaudeCodeNotIsolated, d.dbPath, info.Size()>>20, ceiling>>20)
	}
	return nil
}

func (d claudeCodeDriver) Drive(ctx context.Context, req DriveRequest) (DriveResult, error) {
	bin, err := resolveClaudeBin(d.claudeBin)
	if err != nil {
		return DriveResult{}, fmt.Errorf("locate claude binary: %w (install claude or set it on PATH)", err)
	}
	mint := d.mintID
	if mint == nil {
		mint = newBenchmarkSessionID
	}
	sessionID := mint()
	args, extraEnv := claudeInvocation(req, sessionID)

	if req.TimeoutSec > 0 {
		ctxTimeout, cancel := context.WithTimeout(ctx, time.Duration(req.TimeoutSec)*time.Second)
		defer cancel()
		ctx = ctxTimeout
	}
	cmd := exec.CommandContext(ctx, bin, args...) //nolint:gosec // G204: prompt/model from the operator-authored spec TOML + a minted uuid (local trust boundary), not external input
	cmd.Dir = req.WorkspaceDir
	cmd.Stdin = nil // < /dev/null — print mode is non-interactive
	cmd.Env = append(benchmarkTrustChildEnv(os.Environ(), req.TrustEnv), extraEnv...)
	setProcGroup(cmd)
	// Kill the whole process group on ctx cancellation so a hung tool child
	// can't outlive the cell (re-spike §6.1 / plan §3.2 step 2).
	cmd.Cancel = func() error { return killProcGroup(cmd) }

	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stdout

	start := time.Now()
	runErr := cmd.Run()
	wallMS := time.Since(start).Milliseconds()

	// The minted --session-id IS the correlation key: claude echoes it back as
	// sessions.id verbatim (re-spike §"Correlation seam"). We resolve on the
	// minted id, not the parsed one, so an unparseable tail can't lose the seam.
	res := DriveResult{WallMS: wallMS, SessionIDs: []string{sessionID}}
	if ans, ok := parseClaudeResult(stdout.Bytes()); ok {
		res.FinalAnswer = stripANSI(ans)
	}
	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			res.TimedOut = true
		}
		res.ExitCode = exitCodeOf(runErr)
		return res, nil // a non-zero harness exit is an outcome, not a Drive error
	}
	return res, nil
}

// claudeInvocation builds the argv + the harness-specific env additions for one
// claude-code print-mode attempt (re-spike §6.1). Kept pure so the command
// shape is unit-tested without executing (or spending on) claude.
func claudeInvocation(req DriveRequest, sessionID string) (args, env []string) {
	args = []string{
		"-p", req.Prompt,
		"--model", req.Model,
		"--output-format", "json",
		"--session-id", sessionID,
		"--dangerously-skip-permissions",
	}
	env = []string{
		"CLAUDE_CONFIG_DIR=" + claudeSandboxConfigDir(req.HomeDir),
		"ANTHROPIC_BASE_URL=" + req.ProxyURL,
		"ENABLE_TOOL_SEARCH=true", // CC-under-proxy recovery flag (re-spike Method)
	}
	return args, env
}

// claudeSandboxConfigDir is the throwaway CLAUDE_CONFIG_DIR for one attempt —
// the flat dir that holds the sandbox settings.json (observer hooks) and the
// copied .credentials.json. Both the home preparer (writer) and the driver
// (CLAUDE_CONFIG_DIR env) must agree on this path.
func claudeSandboxConfigDir(homeDir string) string {
	return filepath.Join(homeDir, ".claude")
}

// claudeResultDoc is the shape of `claude -p --output-format json` output.
type claudeResultDoc struct {
	Type      string `json:"type"`
	Result    string `json:"result"`
	SessionID string `json:"session_id"`
	IsError   bool   `json:"is_error"`
}

// parseClaudeResult extracts the final answer from claude print-mode JSON. The
// happy path is a single JSON object; the line scan is a safety net for any
// interleaved stderr the merged stream carries.
func parseClaudeResult(out []byte) (string, bool) {
	var doc claudeResultDoc
	if json.Unmarshal(bytes.TrimSpace(out), &doc) == nil && (doc.Type == "result" || doc.Result != "") {
		return doc.Result, true
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var last string
	var found bool
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var d claudeResultDoc
		if json.Unmarshal(line, &d) != nil {
			continue
		}
		if d.Type == "result" || d.Result != "" {
			last, found = d.Result, true
		}
	}
	return last, found
}

// resolveClaudeBin returns the configured claude path or resolves the claude
// binary through the registry ladder (registry key "claude-code"). A missing
// binary is a Drive-time harness error (no spend), not a Preflight failure —
// Preflight owns only the isolated-daemon gate, so a dry-run cost estimate
// still works on a host without claude installed. stderr is discarded (the
// harness is non-interactive); any PATH-hygiene note is dropped, and an
// unresolvable binary surfaces as the returned error at Drive time.
func resolveClaudeBin(configured string) (string, error) {
	return resolveToolBin("claude-code", configured, "--claude-path", "", io.Discard)
}

// defaultObserverDBPath returns the operator default observer DB path
// (~/.observer/observer.db) — the path Preflight refuses to benchmark against.
func defaultObserverDBPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".observer", "observer.db"), nil
}

// sameDBPath compares two DB paths after cleaning, tolerant of trailing
// separators. Both are already absolute (config expands ~ at load).
func sameDBPath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// newBenchmarkSessionID mints a random RFC-4122 v4 UUID for --session-id. Uses
// crypto/rand directly to avoid a go.mod dependency-class change for one call.
func newBenchmarkSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read never fails on supported platforms; fall back to a
		// timestamp-derived id so a benchmark attempt is never silently lost.
		return fmt.Sprintf("sbo-bench-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// exitCodeOf extracts a process exit code from a Run error.
func exitCodeOf(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// stripANSI removes ANSI escape sequences so a deterministic text scorer sees
// clean output (plan §3.4).
func stripANSI(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			// Skip until a letter terminates the CSI sequence.
			j := i + 2
			for j < len(s) && !((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z')) {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// benchmarkTrustChildEnv is the environment a harness process starts with:
// base without any inherited trust variable, then the attempt's own
// entries, so an attempt with no source never carries another's.
func benchmarkTrustChildEnv(base, own []string) []string {
	out := make([]string, 0, len(base)+len(own))
	for _, kv := range base {
		if strings.HasPrefix(kv, repoTrustBenchmarkSourceEnv+"=") || strings.HasPrefix(kv, repoTrustBenchmarkMarkerEnv+"=") ||
			strings.HasPrefix(kv, repoTrustSourceEnv+"=") || strings.HasPrefix(kv, repoTrustCheckedEnv+"=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, own...)
}
