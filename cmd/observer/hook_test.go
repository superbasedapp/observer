package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/store"
)

func TestDecidePreToolRewrite(t *testing.T) {
	bin := "/opt/observer"
	shellOn := config.Default()
	shellOn.Compression.Shell.Enabled = true
	shellOn.Compression.Shell.ExcludeCommands = []string{"curl"}

	shellOff := config.Default()
	shellOff.Compression.Shell.Enabled = false

	cases := []struct {
		name       string
		body       string
		cfg        config.Config
		cfgErr     error
		binary     string
		binErr     error
		hostOS     string // runtime.GOOS of the hook process ("" => not Windows)
		wantRW     bool
		wantCmd    string
		wantReason string
	}{
		{
			name:       "bash rewrite",
			body:       `{"tool_name":"Bash","tool_input":{"command":"git status"}}`,
			cfg:        shellOn,
			binary:     bin,
			wantRW:     true,
			wantCmd:    bin + " run -- git status",
			wantReason: "ok",
		},
		{
			name:       "non-bash tool ignored",
			body:       `{"tool_name":"Read","tool_input":{"file_path":"foo.go"}}`,
			cfg:        shellOn,
			binary:     bin,
			wantRW:     false,
			wantReason: "",
		},
		{
			name:       "empty command ignored",
			body:       `{"tool_name":"Bash","tool_input":{"command":""}}`,
			cfg:        shellOn,
			binary:     bin,
			wantRW:     false,
			wantReason: "",
		},
		{
			name:       "excluded command passthrough",
			body:       `{"tool_name":"Bash","tool_input":{"command":"curl example.com"}}`,
			cfg:        shellOn,
			binary:     bin,
			wantRW:     false,
			wantReason: "not-rewritable",
		},
		{
			name:       "piped command passthrough",
			body:       `{"tool_name":"Bash","tool_input":{"command":"git log | head -5"}}`,
			cfg:        shellOn,
			binary:     bin,
			wantRW:     false,
			wantReason: "not-rewritable",
		},
		{
			name:       "shell disabled passthrough",
			body:       `{"tool_name":"Bash","tool_input":{"command":"git status"}}`,
			cfg:        shellOff,
			binary:     bin,
			wantRW:     false,
			wantReason: "shell-disabled",
		},
		{
			name:       "config error passthrough",
			body:       `{"tool_name":"Bash","tool_input":{"command":"git status"}}`,
			cfg:        config.Config{},
			cfgErr:     errors.New("load boom"),
			binary:     bin,
			wantRW:     false,
			wantReason: "config-error",
		},
		{
			name:       "binary lookup error passthrough",
			body:       `{"tool_name":"Bash","tool_input":{"command":"git status"}}`,
			cfg:        shellOn,
			binary:     "",
			binErr:     errors.New("no binary"),
			wantRW:     false,
			wantReason: "binary-lookup-error",
		},
		{
			name:       "garbage payload tolerated",
			body:       `not json`,
			cfg:        shellOn,
			binary:     bin,
			wantRW:     false,
			wantReason: "",
		},
		{
			// Bridged hook: Linux observer binary, but the cwd is a Windows
			// path → the shell that runs the rewrite is on Windows and can't
			// exec the WSL observer path. Skip the rewrite.
			name:       "cross-os bridged windows shell skips",
			body:       `{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"D:\\programsx\\superbased-observer"}`,
			cfg:        shellOn,
			binary:     bin,
			hostOS:     "linux",
			wantRW:     false,
			wantReason: "cross-os-shell",
		},
		{
			// Native Windows hook + Windows cwd: same OS-context, the
			// rewrite's binary path is valid for the shell → proceed.
			name:       "native windows shell rewrites",
			body:       `{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"D:\\programsx\\superbased-observer"}`,
			cfg:        shellOn,
			binary:     bin,
			hostOS:     "windows",
			wantRW:     true,
			wantCmd:    bin + " run -- git status",
			wantReason: "ok",
		},
		{
			// WSL Claude Code working under /mnt/c: cwd is a POSIX path, so
			// the hook and shell share the WSL filesystem → rewrite proceeds.
			name:       "wsl shell in mnt path rewrites",
			body:       `{"tool_name":"Bash","tool_input":{"command":"git status"},"cwd":"/mnt/c/Users/marmu/proj"}`,
			cfg:        shellOn,
			binary:     bin,
			hostOS:     "linux",
			wantRW:     true,
			wantCmd:    bin + " run -- git status",
			wantReason: "ok",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rw, cmd, reason := decidePreToolRewrite([]byte(tc.body), tc.cfg, tc.cfgErr, tc.binary, tc.binErr, tc.hostOS)
			if rw != tc.wantRW {
				t.Fatalf("rewrite: got %v want %v", rw, tc.wantRW)
			}
			if reason != tc.wantReason {
				t.Fatalf("reason: got %q want %q", reason, tc.wantReason)
			}
			if rw && cmd != tc.wantCmd {
				t.Fatalf("command: got %q want %q", cmd, tc.wantCmd)
			}
		})
	}
}

func TestHandleClaudeCodePreToolAlwaysApproves(t *testing.T) {
	// Even with bogus JSON the hook must reply approve so the host doesn't
	// hang. This exercises the full handler wiring via config.Load against
	// the real (possibly missing) config file — safe because Load returns
	// defaults when the file doesn't exist.
	stdin := strings.NewReader(`{"tool_name":"Read","tool_input":{"file_path":"x"}}`)
	var stdout, stderr bytes.Buffer
	handleClaudeCodePreTool(stdin, &stdout, &stderr, "claude-code:pre-tool", "")

	var reply preToolReply
	if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
		t.Fatalf("reply not JSON: %v — %q", err, stdout.String())
	}
	if reply.Decision != "approve" {
		t.Fatalf("decision: got %q want approve", reply.Decision)
	}
	if !reply.Continue {
		t.Fatal("continue should be true")
	}
	if reply.HookSpecificOutput != nil {
		t.Fatal("Read tool should not carry an updatedInput")
	}
}

func TestHandleClaudeCodePreToolEmptyPayload(t *testing.T) {
	var stdout, stderr bytes.Buffer
	handleClaudeCodePreTool(strings.NewReader(""), &stdout, &stderr, "claude-code:pre-tool", "")
	var reply preToolReply
	if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
		t.Fatalf("reply not JSON: %v", err)
	}
	if reply.Decision != "approve" {
		t.Fatal("empty payload must still approve")
	}
}

// ancestorsList returns a fake ancestors function that always yields
// the given PIDs. Used by tests to avoid touching /proc.
func ancestorsList(pids ...int) ancestorsFunc {
	return func(int) []int { return pids }
}

func TestHandleClaudeCodeSessionStart_WritesBridge(t *testing.T) {
	payload := `{"session_id":"s-123","cwd":"/repo","hook_event_name":"SessionStart","source":"startup"}`
	var stdout, stderr bytes.Buffer
	var captured pidbridge.Entry
	var called int
	writer := func(_ context.Context, e pidbridge.Entry) error {
		called++
		captured = e
		return nil
	}
	handleClaudeCodeSessionStart(context.Background(), 4242, ancestorsList(4242),
		strings.NewReader(payload), &stdout, &stderr,
		"claude-code:session-start", writer)

	// Must always approve.
	var reply map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
		t.Fatalf("reply not JSON: %v — %q", err, stdout.String())
	}
	if reply["decision"] != "approve" {
		t.Fatalf("decision: %v", reply["decision"])
	}
	if called != 1 {
		t.Fatalf("writer called %d times, want 1", called)
	}
	if captured.PID != 4242 || captured.SessionID != "s-123" || captured.CWD != "/repo" || captured.Tool != "claude-code" {
		t.Fatalf("entry: %+v", captured)
	}
}

func TestHandleClaudeCodeSessionStart_WritesAllAncestors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var got []int
	writer := func(_ context.Context, e pidbridge.Entry) error {
		got = append(got, e.PID)
		if e.SessionID != "s-multi" {
			t.Errorf("session_id on pid=%d: %q", e.PID, e.SessionID)
		}
		return nil
	}
	// Simulates hook spawned off a short-lived worker (worker=999,
	// claude-main=100). Both should land in the bridge so the
	// resolver still finds claude-main after the worker exits.
	handleClaudeCodeSessionStart(context.Background(), 999, ancestorsList(999, 100),
		strings.NewReader(`{"session_id":"s-multi","cwd":"/repo"}`),
		&stdout, &stderr, "claude-code:session-start", writer)
	if len(got) != 2 || got[0] != 999 || got[1] != 100 {
		t.Errorf("registered pids = %v, want [999 100]", got)
	}
}

func TestHandleClaudeCodeSessionStart_NoAncestorsWarns(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var called int
	writer := func(_ context.Context, _ pidbridge.Entry) error {
		called++
		return nil
	}
	// Empty ancestor list simulates the "immediate parent is a shell"
	// case — we never register shells, so there's nothing to do.
	handleClaudeCodeSessionStart(context.Background(), 4242, ancestorsList(),
		strings.NewReader(`{"session_id":"s"}`), &stdout, &stderr,
		"claude-code:session-start", writer)
	if called != 0 {
		t.Errorf("writer called %d times, want 0 when ancestors is empty", called)
	}
	if !strings.Contains(stderr.String(), "no ancestor pids") {
		t.Errorf("stderr should explain the empty ancestors: %q", stderr.String())
	}
}

func TestHandleClaudeCodeSessionStart_NoSessionID(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var called int
	writer := func(_ context.Context, _ pidbridge.Entry) error {
		called++
		return nil
	}
	handleClaudeCodeSessionStart(context.Background(), 4242, ancestorsList(4242),
		strings.NewReader(`{"cwd":"/x"}`), &stdout, &stderr,
		"claude-code:session-start", writer)

	var reply map[string]any
	_ = json.Unmarshal(stdout.Bytes(), &reply)
	if reply["decision"] != "approve" {
		t.Fatal("must still approve without session_id")
	}
	if called != 0 {
		t.Fatalf("writer called %d times, want 0 on missing session_id", called)
	}
	if !strings.Contains(stderr.String(), "no session_id") {
		t.Errorf("stderr should mention missing session_id: %q", stderr.String())
	}
}

func TestHandleClaudeCodeSessionStart_RefusesInitPID(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var called int
	writer := func(_ context.Context, _ pidbridge.Entry) error {
		called++
		return nil
	}
	// ppid=1 means we were reparented to init; don't register.
	handleClaudeCodeSessionStart(context.Background(), 1, ancestorsList(1),
		strings.NewReader(`{"session_id":"s"}`), &stdout, &stderr,
		"claude-code:session-start", writer)
	if called != 0 {
		t.Fatalf("writer called %d times, want 0 for pid 1", called)
	}
}

func TestHandleClaudeCodeSessionStart_WriterErrorStillApproves(t *testing.T) {
	var stdout, stderr bytes.Buffer
	writer := func(_ context.Context, _ pidbridge.Entry) error {
		return errors.New("boom")
	}
	handleClaudeCodeSessionStart(context.Background(), 4242, ancestorsList(4242),
		strings.NewReader(`{"session_id":"s"}`), &stdout, &stderr,
		"claude-code:session-start", writer)

	var reply map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
		t.Fatalf("reply not JSON: %v", err)
	}
	if reply["decision"] != "approve" {
		t.Fatal("writer error must not block approval")
	}
	if !strings.Contains(stderr.String(), "pidbridge pid=4242: boom") {
		t.Errorf("stderr should log writer error with pid: %q", stderr.String())
	}
}

// captureWriter returns a pidbridgeWriter that appends every entry to
// *out for assertions.
func captureWriter(out *[]pidbridge.Entry) pidbridgeWriter {
	return func(_ context.Context, e pidbridge.Entry) error {
		*out = append(*out, e)
		return nil
	}
}

// TestHandleCodexUserPromptSubmit_EndToEnd mirrors the Claude Code
// end-to-end test, pinned against Codex's top-level-block dialect
// (legacy {"decision":"block","reason":…}): register (wired into
// handleCodexHook below) → a live-shaped secret → a block reply → an
// identical (same finding set) resend → no decision field (allowed).
func TestHandleCodexUserPromptSubmit_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	configPath := filepath.Join(dir, "config.toml")
	cfgBody := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(dbPath)) + "\n\n" +
		"[guard]\nenabled = true\nmode = \"enforce\"\n\n" +
		"[guard.prompt]\nenabled = true\nmode = \"ask-once\"\nhook_lane = true\nreconsider_min_delay = \"0s\"\n"
	if err := os.WriteFile(configPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	const secretPrompt = `{"session_id":"s1","cwd":"/r","hook_event_name":"UserPromptSubmit","prompt":"my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`
	const secretPromptResend = `{"session_id":"s1","cwd":"/r","hook_event_name":"UserPromptSubmit","prompt":"sending again: my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`

	runOnce := func(payload string) map[string]any {
		t.Helper()
		stdinR, stdinW, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		go func() {
			_, _ = stdinW.Write([]byte(payload))
			_ = stdinW.Close()
		}()
		stdoutR, stdoutW, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		oldStdin, oldStdout := os.Stdin, os.Stdout
		os.Stdin, os.Stdout = stdinR, stdoutW
		handleCodexHook(context.Background(), "UserPromptSubmit", configPath)
		os.Stdin, os.Stdout = oldStdin, oldStdout
		_ = stdoutW.Close()
		out, _ := io.ReadAll(stdoutR)
		var reply map[string]any
		if err := json.Unmarshal(out, &reply); err != nil {
			t.Fatalf("reply not JSON: %v (%q)", err, out)
		}
		return reply
	}

	first := runOnce(secretPrompt)
	if got, _ := first["decision"].(string); got != "block" {
		t.Fatalf("first submission decision = %q, want block (reply=%+v)", got, first)
	}
	if reason, _ := first["reason"].(string); reason == "" {
		t.Fatalf("first submission carried no reason")
	} else if strings.Contains(reason, "sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz") {
		t.Fatalf("reason leaked the raw secret value: %q", reason)
	}

	second := runOnce(secretPromptResend)
	if _, hasDecision := second["decision"]; hasDecision {
		t.Fatalf("identical resend must carry NO decision field (allowed), got %+v", second)
	}

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()
	events, err := store.New(database).LoadRecentGuardEvents(ctx, time.Time{}, 10)
	if err != nil {
		t.Fatalf("LoadRecentGuardEvents: %v", err)
	}
	found := false
	for _, e := range events {
		if e.RuleID == "R-172" && e.Tool == models.ToolCodex {
			found = true
		}
	}
	if !found {
		t.Errorf("no codex R-172 guard_events row found among %+v", events)
	}

	// NIT (phase-2 review): the guard verdict is not the only thing
	// that must land — a denied prompt is still an attempt worth
	// recording (same posture as every other guarded receiver), so
	// BOTH resends must also produce an actions row via the EXISTING
	// codexadapter.BuildHookEvent -> Ingest capture path (handled in
	// the "handled" branch of handleCodexHook, unconditional on the
	// verdict).
	var actionCount int
	if err := database.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM actions WHERE session_id = ? AND action_type = ?",
		"s1", string(models.ActionUserPrompt),
	).Scan(&actionCount); err != nil {
		t.Fatalf("query actions: %v", err)
	}
	if actionCount != 2 {
		t.Errorf("actions row count for session s1/action_type=user_prompt = %d, want 2 (one per submission, guard verdict notwithstanding)", actionCount)
	}
}

// --- Part B item 2 (phase-3a, docs/plans/prompt-submit-intervention-
// exploration-2026-09-07.md §2.1b): end-to-end deny→resend-allow
// coverage for the documented long-tail vendors' JSON-reply dialects
// (zcode, commandcode) through their REAL hookReceivers entry — same
// pattern as TestHandleCodexUserPromptSubmit_EndToEnd above. Qoder and
// Devin/Cascade are NOT covered here: their blockExitCode dialects
// call os.Exit directly inside handlePromptSubmitOnlyHook, which would
// kill this test binary if invoked in-process — see the "qoder"/
// "devin" subtests of TestRunProbeHook_EndToEnd (probehook_test.go)
// for their subprocess-based coverage instead. Poolside moved to that
// SAME subprocess pattern as of F3 (phase-3a review) —
// TestHandlePoolsidePromptSubmit_EndToEnd, below hook_test.go's
// in-process helpers — once its promptDialects row also gained a
// non-zero blockExitCode (dual-signal: JSON reply + exit-2 fallback),
// it would os.Exit(2) and kill this test binary exactly like
// Qoder/Cascade already do; see that test (in this same file) for the
// subprocess replacement.

// runPromptSubmitHookOnce runs one hookReceivers[tool] invocation with
// payload on stdin and returns the parsed JSON stdout reply.
func runPromptSubmitHookOnce(t *testing.T, tool, event, configPath, payload string) map[string]any {
	t.Helper()
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() {
		_, _ = stdinW.Write([]byte(payload))
		_ = stdinW.Close()
	}()
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdin, oldStdout := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = stdinR, stdoutW
	hookReceivers[tool](context.Background(), event, configPath)
	os.Stdin, os.Stdout = oldStdin, oldStdout
	_ = stdoutW.Close()
	out, _ := io.ReadAll(stdoutR)
	var reply map[string]any
	if err := json.Unmarshal(out, &reply); err != nil {
		t.Fatalf("reply not JSON: %v (%q)", err, out)
	}
	return reply
}

func writePromptGuardConfig(t *testing.T, dbPath string) string {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	cfgBody := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(dbPath)) + "\n\n" +
		"[guard]\nenabled = true\nmode = \"enforce\"\n\n" +
		"[guard.prompt]\nenabled = true\nmode = \"ask-once\"\nhook_lane = true\nreconsider_min_delay = \"0s\"\n"
	if err := os.WriteFile(configPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath
}

// runPromptSubmitHookSubprocess execs a REAL compiled observer binary
// as `observer hook <tool> <event> [--config <path>]`, feeding payload
// on stdin, and returns (parsed JSON stdout reply, process exit code).
// Needed for a dialect whose promptDialects row sets a non-zero
// blockExitCode (F3, phase-3a review) — such a dialect's block path
// calls os.Exit directly inside handlePromptSubmitOnlyHook, which
// would kill this test binary if invoked in-process via
// runPromptSubmitHookOnce/hookReceivers (see Qoder/Cascade's existing
// subprocess-only coverage in TestRunProbeHook_EndToEnd).
func runPromptSubmitHookSubprocess(t *testing.T, binary, tool, event, configPath, payload string) (reply map[string]any, exitCode int) {
	t.Helper()
	args := []string{"hook", tool, event}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	c := exec.Command(binary, args...)
	c.Stdin = strings.NewReader(payload)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	runErr := c.Run()
	exitCode = 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to invoke %s %v: %v (stderr=%s)", binary, args, runErr, stderr.String())
		}
	}
	if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
		t.Fatalf("reply not JSON: %v (stdout=%q stderr=%q)", err, stdout.String(), stderr.String())
	}
	return reply, exitCode
}

// TestHandlePoolsidePromptSubmit_EndToEnd pins the deny->resend-allow
// flow through a REAL subprocess (F3, phase-3a review moved this off
// the in-process hookReceivers helper — see the doc comment above this
// section — because Poolside's promptDialects row now ALSO sets
// blockExitCode:2 as a fail-closed fallback alongside its JSON reply,
// and handlePromptSubmitOnlyHook os.Exits on a block for such a
// dialect). This ALSO verifies F3's own dual-signal classification
// question directly: a dialect with reply!=nil (JSON) AND a non-zero
// blockExitCode must still classify a block from its JSON body, not
// just its exit code — Poolside is deliberately NOT in
// probeHookExitCodeDialects (cmd/observer/probehook.go), so
// runProbeHook's own classification of it is covered by
// TestRunProbeHook_EndToEnd; this test instead checks the raw
// subprocess contract HandlePromptSubmitGuarded promises: JSON
// decision AND exit code 2 both fire together on a block, and neither
// on an allow.
func TestHandlePoolsidePromptSubmit_EndToEnd(t *testing.T) {
	binary := probeHookTestBinary(t)
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	configPath := writePromptGuardConfig(t, dbPath)

	const secret = `{"hook_api_version":"1.0","hook_event_name":"UserPromptSubmit","event_id":"e1","session_id":"s1","cwd":"/r","trajectory_path":"/t","prompt":"my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`
	const resend = `{"hook_api_version":"1.0","hook_event_name":"UserPromptSubmit","event_id":"e2","session_id":"s1","cwd":"/r","trajectory_path":"/t","prompt":"sending again: my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`

	first, firstExit := runPromptSubmitHookSubprocess(t, binary, "poolside", "UserPromptSubmit", configPath, secret)
	if got, _ := first["decision"].(string); got != "block" {
		t.Fatalf("first submission decision = %q, want block (reply=%+v)", got, first)
	}
	if firstExit != 2 {
		t.Errorf("first submission exit code = %d, want 2 (dual-signal: JSON decision + exit-2 fallback)", firstExit)
	}
	second, secondExit := runPromptSubmitHookSubprocess(t, binary, "poolside", "UserPromptSubmit", configPath, resend)
	if _, hasDecision := second["decision"]; hasDecision {
		t.Fatalf("identical resend must carry NO decision field (allowed), got %+v", second)
	}
	if secondExit != 0 {
		t.Errorf("resend (allowed) exit code = %d, want 0", secondExit)
	}

	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()
	events, err := store.New(database).LoadRecentGuardEvents(ctx, time.Time{}, 10)
	if err != nil {
		t.Fatalf("LoadRecentGuardEvents: %v", err)
	}
	found := false
	for _, e := range events {
		if e.RuleID == "R-172" && e.Tool == models.ToolPoolside {
			found = true
		}
	}
	if !found {
		t.Errorf("no poolside R-172 guard_events row found among %+v", events)
	}
}

func TestHandleZcodePromptSubmit_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	configPath := writePromptGuardConfig(t, dbPath)

	const secret = `{"session_id":"s1","transcript_path":"/t","cwd":"/r","permission_mode":"default","hook_event_name":"UserPromptSubmit","prompt":"my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`
	const resend = `{"session_id":"s1","transcript_path":"/t","cwd":"/r","permission_mode":"default","hook_event_name":"UserPromptSubmit","prompt":"sending again: my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`

	first := runPromptSubmitHookOnce(t, "zcode", "UserPromptSubmit", configPath, secret)
	if cont, ok := first["continue"].(bool); !ok || cont {
		t.Fatalf("first submission continue = %v, want false (reply=%+v)", first["continue"], first)
	}
	second := runPromptSubmitHookOnce(t, "zcode", "UserPromptSubmit", configPath, resend)
	if cont, ok := second["continue"].(bool); !ok || !cont {
		t.Fatalf("identical resend continue = %v, want true (allowed)", second["continue"])
	}
}

func TestHandleCommandCodePromptSubmit_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	configPath := writePromptGuardConfig(t, dbPath)

	// commandcode's transformInput carries no session id at all
	// (extractCommandCodePrompt) — EvaluatePrompt's documented
	// empty-session-id rule fails closed to a hard block with no
	// resend override, so this is a single-shot block test, not a
	// deny→resend-allow pair like every other vendor here (see
	// internal/guard/conformance.go's commandcode row for the
	// disclosed tradeoff).
	const secret = `{"text":"my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`
	const resend = `{"text":"sending again: my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`

	first := runPromptSubmitHookOnce(t, "command-code", "transformInput", configPath, secret)
	if got, _ := first["action"].(string); got != "handled" {
		t.Fatalf("first submission action = %q, want handled (reply=%+v)", got, first)
	}
	second := runPromptSubmitHookOnce(t, "command-code", "transformInput", configPath, resend)
	if got, _ := second["action"].(string); got != "handled" {
		t.Errorf("resend action = %q, want handled too — no session id means no reconsider-once override", got)
	}
}

func TestSeedCodexSessionPidbridge_WritesBridge(t *testing.T) {
	var got []pidbridge.Entry
	var stderr bytes.Buffer
	body := []byte(`{"session_id":"cx-1","cwd":"/cx","hook_event_name":"SessionStart"}`)
	seedCodexSessionPidbridge(context.Background(), "SessionStart", body, 4242,
		ancestorsList(4242, 100), captureWriter(&got), &stderr)
	if len(got) != 2 {
		t.Fatalf("entries = %d; want 2", len(got))
	}
	if got[0].SessionID != "cx-1" || got[0].Tool != models.ToolCodex || got[0].CWD != "/cx" {
		t.Errorf("entry[0] = %+v", got[0])
	}
	if got[0].PID != 4242 || got[1].PID != 100 {
		t.Errorf("pids = %d,%d; want 4242,100", got[0].PID, got[1].PID)
	}
}

func TestSeedCodexSessionPidbridge_NonSessionStartNoWrite(t *testing.T) {
	var got []pidbridge.Entry
	var stderr bytes.Buffer
	body := []byte(`{"session_id":"cx-2","hook_event_name":"PreToolUse"}`)
	seedCodexSessionPidbridge(context.Background(), "PreToolUse", body, 4242,
		ancestorsList(4242), captureWriter(&got), &stderr)
	if len(got) != 0 {
		t.Fatalf("entries = %d; want 0 for non-SessionStart", len(got))
	}
}

func TestSeedCursorSessionPidbridge_WritesBridge(t *testing.T) {
	var got []pidbridge.Entry
	var stderr bytes.Buffer
	body := []byte(`{"hook_event_name":"sessionStart","conversation_id":"cv-1","workspace_roots":["/ws"],"source":"startup"}`)
	seedCursorSessionPidbridge(context.Background(), "sessionStart", body, 4242,
		ancestorsList(4242), captureWriter(&got), nil, &stderr)
	if len(got) != 1 {
		t.Fatalf("entries = %d; want 1", len(got))
	}
	if got[0].SessionID != "cv-1" || got[0].Tool != models.ToolCursor || got[0].CWD != "/ws" {
		t.Errorf("entry = %+v", got[0])
	}
}

func TestSeedCursorSessionPidbridge_BackgroundAgentSkipped(t *testing.T) {
	var got []pidbridge.Entry
	var stderr bytes.Buffer
	body := []byte(`{"hook_event_name":"sessionStart","conversation_id":"cv-2","is_background_agent":true}`)
	seedCursorSessionPidbridge(context.Background(), "sessionStart", body, 4242,
		ancestorsList(4242), captureWriter(&got), nil, &stderr)
	if len(got) != 0 {
		t.Fatalf("entries = %d; want 0 for a background agent", len(got))
	}
}

func TestSeedCursorSessionPidbridge_NonSessionStartNoWrite(t *testing.T) {
	var got []pidbridge.Entry
	var stderr bytes.Buffer
	body := []byte(`{"hook_event_name":"beforeShellCommand","conversation_id":"cv-3","command":"ls"}`)
	seedCursorSessionPidbridge(context.Background(), "beforeShellCommand", body, 4242,
		ancestorsList(4242), captureWriter(&got), nil, &stderr)
	if len(got) != 0 {
		t.Fatalf("entries = %d; want 0 for non-sessionStart", len(got))
	}
}

func TestSeedHermesSessionPidbridge_UsesPluginPID(t *testing.T) {
	var got []pidbridge.Entry
	var stderr bytes.Buffer
	// Plugin supplies pid=7777; the ancestor walk (100,200) must be
	// bypassed in favour of the single plugin pid.
	body := []byte(`{"event":"session_start","session_id":"hz-1","cwd":"/hz","pid":7777,"ppid":100}`)
	seedHermesSessionPidbridge(context.Background(), "session_start", body, 999,
		ancestorsList(100, 200), captureWriter(&got), &stderr)
	if len(got) != 1 {
		t.Fatalf("entries = %d; want 1 (plugin pid only)", len(got))
	}
	if got[0].PID != 7777 || got[0].SessionID != "hz-1" || got[0].Tool != models.ToolHermes {
		t.Errorf("entry = %+v; want pid=7777 hz-1 hermes", got[0])
	}
}

func TestSeedHermesSessionPidbridge_FallsBackToAncestorWalk(t *testing.T) {
	var got []pidbridge.Entry
	var stderr bytes.Buffer
	// Older plugin: no pid field → ancestor-walk the exec'd hook child.
	body := []byte(`{"event":"session_start","session_id":"hz-2","cwd":"/hz"}`)
	seedHermesSessionPidbridge(context.Background(), "session_start", body, 999,
		ancestorsList(555, 556), captureWriter(&got), &stderr)
	if len(got) != 2 {
		t.Fatalf("entries = %d; want 2 (ancestor walk)", len(got))
	}
	if got[0].PID != 555 || got[1].PID != 556 || got[0].Tool != models.ToolHermes {
		t.Errorf("entries = %+v; want 555,556 hermes", got)
	}
}

func TestSeedHermesSessionPidbridge_NonSessionStartNoWrite(t *testing.T) {
	var got []pidbridge.Entry
	var stderr bytes.Buffer
	body := []byte(`{"event":"tool_call","session_id":"hz-3","pid":7777}`)
	seedHermesSessionPidbridge(context.Background(), "tool_call", body, 999,
		ancestorsList(1, 2), captureWriter(&got), &stderr)
	if len(got) != 0 {
		t.Fatalf("entries = %d; want 0 for non-session_start", len(got))
	}
}

// writeFakeProc creates /proc/<pid>/{comm,status,cmdline} under base
// so tests can exercise collectClaudeCodeAncestors without touching
// /proc. cmdline is NUL-separated argv; empty cmdline omits the file
// (mirrors a kernel thread).
func writeFakeProc(t *testing.T, base string, pid int, comm string, ppid int, cmdline ...string) {
	t.Helper()
	d := filepath.Join(base, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "status"), []byte(fmt.Sprintf("Name:\t%s\nPPid:\t%d\n", comm, ppid)), 0o644); err != nil {
		t.Fatal(err)
	}
	if len(cmdline) > 0 {
		var buf []byte
		for _, a := range cmdline {
			buf = append(buf, a...)
			buf = append(buf, 0)
		}
		if err := os.WriteFile(filepath.Join(d, "cmdline"), buf, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestCollectClaudeCodeAncestors_CrossesBashDashCWrapper reproduces
// the observed Claude Code hook-spawn shape: `bash -c 'observer hook
// ...'`. The walker must skip the bash wrapper and reach the real
// long-lived claude parent behind it.
func TestCollectClaudeCodeAncestors_CrossesBashDashCWrapper(t *testing.T) {
	procDir := t.TempDir()
	// bash -c (wrapper, 200) -> claude (100) -> bash login shell (50)
	writeFakeProc(t, procDir, 200, "bash", 100, "/bin/bash", "-c", "/path/to/observer hook claude-code session-start")
	writeFakeProc(t, procDir, 100, "claude", 50, "claude")
	writeFakeProc(t, procDir, 50, "bash", 1, "-bash")

	got := collectClaudeCodeAncestors(200, procDir, 10)
	want := []int{100}
	if !equalInts(got, want) {
		t.Errorf("got %v want %v (bash -c should be skipped, interactive bash should stop)", got, want)
	}
}

// TestCollectClaudeCodeAncestors_InteractiveShellStartStops verifies
// the manual-invocation case (user types the hook command directly in
// their shell): we refuse to register an interactive shell.
func TestCollectClaudeCodeAncestors_InteractiveShellStartStops(t *testing.T) {
	procDir := t.TempDir()
	writeFakeProc(t, procDir, 300, "bash", 1, "bash")
	if got := collectClaudeCodeAncestors(300, procDir, 10); len(got) != 0 {
		t.Errorf("interactive shell at start should return empty, got %v", got)
	}
}

// TestCollectClaudeCodeAncestors_DeadStartPID verifies that when the
// immediate parent has vanished (no /proc/<pid>/comm), we still
// best-effort register startPID so we preserve the pre-fix floor
// behaviour.
func TestCollectClaudeCodeAncestors_DeadStartPID(t *testing.T) {
	procDir := t.TempDir()
	// no /proc entry for 999 — simulates a zombie reaped before we read.
	got := collectClaudeCodeAncestors(999, procDir, 10)
	want := []int{999}
	if !equalInts(got, want) {
		t.Errorf("got %v want %v (dead parent should still be registered)", got, want)
	}
}

func TestCollectClaudeCodeAncestors_StopsAtShell(t *testing.T) {
	procDir := t.TempDir()
	// hook parent=200 (node worker) -> 100 (claude) -> 50 (bash)
	writeFakeProc(t, procDir, 200, "node", 100)
	writeFakeProc(t, procDir, 100, "claude", 50)
	writeFakeProc(t, procDir, 50, "bash", 42)

	got := collectClaudeCodeAncestors(200, procDir, 10)
	want := []int{200, 100}
	if !equalInts(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

// TestCollectClaudeCodeAncestors_BridgedHookRegistersNothing
// reproduces the wsl.exe-bridged hook shape (Windows AI tool + WSL
// daemon, D17): the hook's WSL-side ancestry is relay processes with
// comm "init" up to the distro init at pid 2. None of them is the AI
// tool — registering them poisons the bridge for every later hookless
// connection. The walk must stop at the first init-class ancestor and
// register nothing.
func TestCollectClaudeCodeAncestors_BridgedHookRegistersNothing(t *testing.T) {
	procDir := t.TempDir()
	// relay init (345777) -> session init (345776) -> distro init (2) -> 1
	writeFakeProc(t, procDir, 345777, "init", 345776, "/init")
	writeFakeProc(t, procDir, 345776, "init", 2, "/init")
	writeFakeProc(t, procDir, 2, "init", 1, "/init")

	if got := collectClaudeCodeAncestors(345777, procDir, 10); len(got) != 0 {
		t.Errorf("bridged init chain should register nothing, got %v", got)
	}
}

// TestCollectClaudeCodeAncestors_InitClassMidChainStops verifies a
// real ancestor below an init-class process is still registered while
// the init-class boundary (and everything above) is not — and that
// pid<=2 is never registered even when its /proc entry is unreadable
// (the dead-start best-effort floor must not apply to system pids).
func TestCollectClaudeCodeAncestors_InitClassMidChainStops(t *testing.T) {
	procDir := t.TempDir()
	writeFakeProc(t, procDir, 400, "node", 300)
	writeFakeProc(t, procDir, 300, "systemd", 1, "/usr/lib/systemd/systemd", "--user")

	got := collectClaudeCodeAncestors(400, procDir, 10)
	want := []int{400}
	if !equalInts(got, want) {
		t.Errorf("got %v want %v (systemd ancestor must not register)", got, want)
	}

	// startPID 2 with no /proc entry: no best-effort registration.
	if got := collectClaudeCodeAncestors(2, t.TempDir(), 10); len(got) != 0 {
		t.Errorf("pid 2 should never register, got %v", got)
	}
}

func TestCollectClaudeCodeAncestors_StopsAtInit(t *testing.T) {
	procDir := t.TempDir()
	writeFakeProc(t, procDir, 300, "node", 200)
	writeFakeProc(t, procDir, 200, "node", 100)
	writeFakeProc(t, procDir, 100, "claude", 1)

	got := collectClaudeCodeAncestors(300, procDir, 10)
	want := []int{300, 200, 100}
	if !equalInts(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestCollectClaudeCodeAncestors_CapsAtMaxDepth(t *testing.T) {
	procDir := t.TempDir()
	for i := 10; i > 0; i-- {
		writeFakeProc(t, procDir, 1000+i, "node", 1000+i-1)
	}
	writeFakeProc(t, procDir, 1000, "node", 1)

	got := collectClaudeCodeAncestors(1010, procDir, 3)
	if len(got) != 3 {
		t.Fatalf("expected len 3 got %d: %v", len(got), got)
	}
}

func TestCollectClaudeCodeAncestors_MissingProcEntry(t *testing.T) {
	procDir := t.TempDir()
	writeFakeProc(t, procDir, 200, "node", 100)
	// PID 100 intentionally absent — simulates the observed bug:
	// immediate parent recorded, grandparent already dead.
	got := collectClaudeCodeAncestors(200, procDir, 10)
	want := []int{200}
	if !equalInts(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestCollectClaudeCodeAncestors_StartPIDIsShell(t *testing.T) {
	procDir := t.TempDir()
	writeFakeProc(t, procDir, 80, "zsh", 1)
	if got := collectClaudeCodeAncestors(80, procDir, 10); len(got) != 0 {
		t.Errorf("shell at start should return empty, got %v", got)
	}
}

func TestCollectClaudeCodeAncestors_InitOrBadStart(t *testing.T) {
	if got := collectClaudeCodeAncestors(0, "/nonexistent", 10); len(got) != 0 {
		t.Errorf("pid=0 should return empty, got %v", got)
	}
	if got := collectClaudeCodeAncestors(1, "/nonexistent", 10); len(got) != 0 {
		t.Errorf("pid=1 should return empty, got %v", got)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBuildClaudeSessionEndEvent(t *testing.T) {
	body := []byte(`{"session_id":"703fe8c5","cwd":"/home/u/repo","hook_event_name":"SessionEnd"}`)
	ev, ok := buildClaudeSessionEndEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.SessionID != "703fe8c5" {
		t.Errorf("SessionID=%q", ev.SessionID)
	}
	if ev.ActionType != models.ActionSessionEnd {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.ProjectRoot != "/home/u/repo" {
		t.Errorf("ProjectRoot=%q", ev.ProjectRoot)
	}
	if ev.SourceFile != "claude-code:hook" {
		t.Errorf("SourceFile=%q", ev.SourceFile)
	}
	if !ev.Success {
		t.Errorf("Success=false")
	}
}

func TestBuildClaudeUserPromptSubmitEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","permission_mode":"default","hook_event_name":"UserPromptSubmit","prompt":"How does main.go work?"}`)
	ev, ok := buildClaudeUserPromptSubmitEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionUserPrompt {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.RawToolInput != "How does main.go work?" {
		t.Errorf("RawToolInput=%q", ev.RawToolInput)
	}
	if ev.Target != "How does main.go work?" {
		t.Errorf("Target=%q", ev.Target)
	}
}

// TestHandleClaudeCodeUserPromptSubmit_EndToEnd is the Part B item 7
// end-to-end contract: register (wired into the dispatch below) → a
// fake payload with a live-shaped secret → a deny reply carrying a
// reason → an identical resend → allow. Also pins that the pre-existing
// capture (the actions.user_prompt row) still lands regardless of the
// verdict, and that a guard_events row was persisted with the
// fingerprint (never the secret) as its target.
func TestHandleClaudeCodeUserPromptSubmit_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	configPath := filepath.Join(dir, "config.toml")
	cfgBody := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(dbPath)) + "\n\n" +
		"[guard]\nenabled = true\nmode = \"enforce\"\n\n" +
		"[guard.prompt]\nenabled = true\nmode = \"ask-once\"\nhook_lane = true\nreconsider_min_delay = \"0s\"\n"
	if err := os.WriteFile(configPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	const secretPrompt = `{"session_id":"s1","cwd":"/r","hook_event_name":"UserPromptSubmit","user_prompt":"my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`
	// The RECONSIDER-ONCE fingerprint covers the finding set (the
	// normalized secret span), not the raw prompt text — so a second
	// submission with the SAME secret still counts as "identical" for
	// confirm-by-resend purposes even with different surrounding
	// prose. Using slightly different text here (rather than the
	// byte-identical body) also avoids colliding with the pre-existing
	// capture builder's own content-hash dedup
	// (buildClaudeUserPromptSubmitEvent's SourceEventID includes a hash
	// of the body — an EXACT repeat collapses to one actions row by
	// design, a documented, unrelated behavior this test must not
	// conflate with the guard's own confirm-by-resend semantics).
	const secretPromptResend = `{"session_id":"s1","cwd":"/r","hook_event_name":"UserPromptSubmit","user_prompt":"sending again: my key is sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz"}`

	// LIVE CORRECTION (2026-09-07 operator step-in): Claude Code blocks
	// UserPromptSubmit ONLY via process exit code 2 (stderr = the
	// user-visible reason, prompt erased); the JSON permissionDecision
	// form is PreToolUse-only and was silently ignored live. Capture the
	// exit through the hookOSExit seam so a block does not end the test
	// binary, and capture stderr for the reason/leak checks.
	var exitCodes []int
	prevExit := hookOSExit
	hookOSExit = func(code int) { exitCodes = append(exitCodes, code) }
	t.Cleanup(func() { hookOSExit = prevExit })

	runOnce := func(payload string) (reply map[string]any, stdout, stderr string) {
		t.Helper()
		stdinR, stdinW, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		go func() {
			_, _ = stdinW.Write([]byte(payload))
			_ = stdinW.Close()
		}()
		stdoutR, stdoutW, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		stderrR, stderrW, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		oldStdin, oldStdout, oldStderr := os.Stdin, os.Stdout, os.Stderr
		os.Stdin, os.Stdout, os.Stderr = stdinR, stdoutW, stderrW
		handleClaudeCodeUserPromptSubmit(context.Background(), "claude-code:user-prompt-submit", configPath)
		os.Stdin, os.Stdout, os.Stderr = oldStdin, oldStdout, oldStderr
		_ = stdoutW.Close()
		_ = stderrW.Close()
		outB, _ := io.ReadAll(stdoutR)
		errB, _ := io.ReadAll(stderrR)
		stdout, stderr = string(outB), string(errB)
		if strings.TrimSpace(stdout) != "" {
			if err := json.Unmarshal(outB, &reply); err != nil {
				t.Fatalf("reply not JSON: %v (%q)", err, outB)
			}
		}
		return reply, stdout, stderr
	}

	// First submission: a live-shaped secret must be blocked — exit code
	// 2, NOTHING on stdout, the house reason on stderr, value never leaked.
	_, firstOut, firstErr := runOnce(secretPrompt)
	if len(exitCodes) != 1 || exitCodes[0] != 2 {
		t.Fatalf("first submission exit codes = %v, want exactly [2] (stdout=%q stderr=%q)", exitCodes, firstOut, firstErr)
	}
	if strings.TrimSpace(firstOut) != "" {
		t.Fatalf("a block must write nothing to stdout (permissionDecision is PreToolUse-only): %q", firstOut)
	}
	if strings.TrimSpace(firstErr) == "" {
		t.Fatalf("first submission carried no stderr reason (Claude Code shows exit-2 stderr to the user)")
	}
	if strings.Contains(firstErr, "sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz") {
		t.Fatalf("stderr leaked the raw secret value: %q", firstErr)
	}

	// Identical (same finding set) resend: allowed through (confirmed) —
	// exit 0 (no further exit recorded) and the bare allow envelope.
	second, secondOut, _ := runOnce(secretPromptResend)
	if len(exitCodes) != 1 {
		t.Fatalf("identical resend must not exit non-zero: exit codes = %v", exitCodes)
	}
	hso, _ := second["hookSpecificOutput"].(map[string]any)
	if got, _ := hso["hookEventName"].(string); got != "UserPromptSubmit" {
		t.Fatalf("identical resend reply = %q, want the UserPromptSubmit allow envelope", secondOut)
	}
	if _, stray := hso["permissionDecision"]; stray {
		t.Fatalf("allow envelope must not carry the PreToolUse-only permissionDecision field: %q", secondOut)
	}

	// The pre-existing capture (actions.user_prompt row) must have
	// landed for BOTH submissions regardless of the verdict.
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	var actionCount int
	if err := database.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM actions WHERE action_type = ?`, models.ActionUserPrompt,
	).Scan(&actionCount); err != nil {
		t.Fatalf("query actions: %v", err)
	}
	if actionCount != 2 {
		t.Errorf("actions.user_prompt rows = %d, want 2 (capture must proceed regardless of the guard verdict)", actionCount)
	}

	events, err := store.New(database).LoadRecentGuardEvents(ctx, time.Time{}, 10)
	if err != nil {
		t.Fatalf("LoadRecentGuardEvents: %v", err)
	}
	if len(events) == 0 {
		t.Fatalf("expected at least one guard_events row")
	}
	found := false
	for _, e := range events {
		if e.RuleID != "R-172" {
			continue
		}
		found = true
		if strings.Contains(e.Reason, "sk-ant-api03-1234567890ABCDEFGhijKLmnopqRSTuvwxyz") {
			t.Errorf("guard_events.reason leaked the raw secret: %q", e.Reason)
		}
		if strings.Contains(e.TargetExcerpt, "sk-ant") {
			t.Errorf("guard_events.target_excerpt leaked the raw secret: %q", e.TargetExcerpt)
		}
	}
	if !found {
		t.Errorf("no R-172 guard_events row found among %+v", events)
	}
}

// TestHandleClaudeCodeUserPromptSubmit_FallbackUsesModernEnvelope pins
// FIX cluster item 7a: when the guard is disabled (or errors), the
// `!handled` fallback in handleClaudeCodeUserPromptSubmit must still
// reply with the MODERN hookSpecificOutput envelope
// (hook.ClaudeCodePromptApproveReply) rather than the legacy bare
// {"decision":"approve"} shape — the wrong reply contract for
// UserPromptSubmit specifically. Every other event's own
// hook.Decision{Decision:"approve"} fallback is untouched by this fix
// and stays out of scope for this test.
func TestHandleClaudeCodeUserPromptSubmit_FallbackUsesModernEnvelope(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	configPath := filepath.Join(dir, "config.toml")
	// guard.prompt disabled -> promptGuardEnabled(cfg) is false ->
	// handled stays false -> the fallback branch under test fires.
	cfgBody := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(dbPath)) + "\n\n" +
		"[guard]\nenabled = false\n"
	if err := os.WriteFile(configPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	const payload = `{"session_id":"s1","cwd":"/r","hook_event_name":"UserPromptSubmit","user_prompt":"How does main.go work?"}`

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	go func() {
		_, _ = stdinW.Write([]byte(payload))
		_ = stdinW.Close()
	}()
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	oldStdin, oldStdout := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = stdinR, stdoutW
	handleClaudeCodeUserPromptSubmit(context.Background(), "claude-code:user-prompt-submit", configPath)
	os.Stdin, os.Stdout = oldStdin, oldStdout
	_ = stdoutW.Close()
	out, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("read stdout: %v", err)
	}

	var reply map[string]any
	if err := json.Unmarshal(out, &reply); err != nil {
		t.Fatalf("reply not JSON: %v (%q)", err, out)
	}
	if _, hasLegacy := reply["decision"]; hasLegacy {
		t.Errorf("fallback reply still carries the legacy top-level %q key: %q", "decision", out)
	}
	hso, ok := reply["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("fallback reply missing hookSpecificOutput envelope: %q", out)
	}
	if got, _ := hso["hookEventName"].(string); got != "UserPromptSubmit" {
		t.Errorf("hookSpecificOutput.hookEventName = %q, want %q", got, "UserPromptSubmit")
	}
	if _, stray := hso["permissionDecision"]; stray {
		t.Errorf("fallback allow envelope must not carry the PreToolUse-only permissionDecision field: %q", out)
	}
}

func TestBuildClaudePostToolFailureEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"PostToolUseFailure","tool_name":"Agent","tool_input":{"prompt":"x"},"tool_use_id":"toolu_01","error":"WorktreeCreate hook failed: no successful output","is_interrupt":false,"duration_ms":25}`)
	ev, ok := buildClaudePostToolFailureEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionToolFailure {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Success {
		t.Errorf("Success should be false on failure")
	}
	if ev.RawToolName != "Agent" {
		t.Errorf("RawToolName=%q", ev.RawToolName)
	}
	if ev.DurationMs != 25 {
		t.Errorf("DurationMs=%d", ev.DurationMs)
	}
	if ev.ErrorMessage != "WorktreeCreate hook failed: no successful output" {
		t.Errorf("ErrorMessage=%q", ev.ErrorMessage)
	}
	if ev.SourceEventID != "toolu_01:post_tool_failure" {
		t.Errorf("SourceEventID=%q", ev.SourceEventID)
	}
}

func TestBuildClaudePostToolFailureEvent_InterruptMarker(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_input":{},"tool_use_id":"toolu_02","error":"user cancelled","is_interrupt":true,"duration_ms":12000}`)
	ev, ok := buildClaudePostToolFailureEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	// Migration 017: is_interrupt is a typed bool on
	// metadata.is_interrupt, no longer lossy-encoded into ErrorMessage.
	if ev.Metadata == nil || !ev.Metadata.IsInterrupt {
		t.Fatalf("Metadata=%+v (want IsInterrupt=true)", ev.Metadata)
	}
	if ev.ErrorMessage != "user cancelled" {
		t.Errorf("ErrorMessage=%q (want raw error, no [interrupt] prefix)", ev.ErrorMessage)
	}
}

func TestBuildClaudeStopFailureEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"StopFailure","error":"unknown","last_assistant_message":"API Error: Stream idle timeout - partial response received"}`)
	ev, ok := buildClaudeStopFailureEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionAPIError {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "unknown" {
		t.Errorf("Target=%q (want error class)", ev.Target)
	}
	if !strings.Contains(ev.ErrorMessage, "Stream idle timeout") {
		t.Errorf("ErrorMessage=%q", ev.ErrorMessage)
	}
	if ev.Success {
		t.Errorf("Success should be false")
	}
}

func TestBuildClaudeSubagentStartEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"SubagentStart","agent_id":"a5fa617a","agent_type":"Explore","prompt":"find foo"}`)
	ev, ok := buildClaudeSubagentStartEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionSubagentStart {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "Explore" {
		t.Errorf("Target=%q (want agent_type)", ev.Target)
	}
	if ev.RawToolName != "a5fa617a" {
		t.Errorf("RawToolName=%q (want agent_id)", ev.RawToolName)
	}
	if !ev.IsSidechain {
		t.Errorf("IsSidechain should be true")
	}
}

func TestBuildClaudeSubagentStopEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"SubagentStop","agent_id":"ab0251a3","agent_type":"Explore","agent_transcript_path":"/p/sub.jsonl","last_assistant_message":"main.go line 79"}`)
	ev, ok := buildClaudeSubagentStopEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionSubagentStop {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "Explore" {
		t.Errorf("Target=%q (want agent_type)", ev.Target)
	}
	// last_assistant_message must land in BOTH raw_tool_input
	// (dashboard renders this) and ToolOutput (FTS5 index). Pre-fix
	// it only went to ToolOutput, so the dashboard rendered the row
	// as blank — verified live on a real session.
	if ev.RawToolInput != "main.go line 79" {
		t.Errorf("RawToolInput=%q (want last_assistant_message)", ev.RawToolInput)
	}
	if ev.ToolOutput != "main.go line 79" {
		t.Errorf("ToolOutput=%q", ev.ToolOutput)
	}
	if !ev.IsSidechain {
		t.Errorf("IsSidechain should be true")
	}
}

// TestBuildClaudeSubagentStopEvent_EmptyShellSuppressed pins the
// empty-shell suppression introduced after observing claude-code
// firing SubagentStop with only agent_id + envelope (no agent_type,
// no last_assistant_message, no agent_transcript_path). Verified
// live: 11 of 12 historical rows on a real DB had this shape and
// rendered as blank rows in the dashboard. Suppression returns
// ok=false so the row is never inserted.
func TestBuildClaudeSubagentStopEvent_EmptyShellSuppressed(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"SubagentStop","agent_id":"a45e1c0090c7163fb"}`)
	if _, ok := buildClaudeSubagentStopEvent(body); ok {
		t.Errorf("expected ok=false for empty-shell SubagentStop (only agent_id), got ok=true")
	}
}

// TestBuildClaudeSubagentStopEvent_FallbackTargetWhenAgentTypeEmpty
// pins the dashboard-friendly fallback: when agent_type is empty
// but last_assistant_message is non-empty, Target gets a preview
// of the message so the listing isn't blank.
func TestBuildClaudeSubagentStopEvent_FallbackTargetWhenAgentTypeEmpty(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"SubagentStop","agent_id":"a1","last_assistant_message":"Found 3 occurrences across 2 files."}`)
	ev, ok := buildClaudeSubagentStopEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.Target != "Found 3 occurrences across 2 files." {
		t.Errorf("Target=%q (want preview of last_assistant_message)", ev.Target)
	}
	if ev.RawToolInput != "Found 3 occurrences across 2 files." {
		t.Errorf("RawToolInput=%q", ev.RawToolInput)
	}
}

// TestBuildClaudeSubagentStopEvent_FallbackTargetWhenOnlyTranscriptPath
// covers the third fallback: just the transcript path (no
// agent_type, no last_assistant_message). Target gets the path
// basename so the row points at where the data lives.
func TestBuildClaudeSubagentStopEvent_FallbackTargetWhenOnlyTranscriptPath(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"SubagentStop","agent_id":"a1","agent_transcript_path":"/home/u/.claude/projects/p/abc/subagents/agent-x.jsonl"}`)
	ev, ok := buildClaudeSubagentStopEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.Target != "agent-x.jsonl" {
		t.Errorf("Target=%q (want transcript basename)", ev.Target)
	}
}

// TestBuildClaudeStopEvent pins the field shape of the new claudecode.assistant_text
// rows emitted from the Stop hook. Pre-v1.4.49 this dispatch fell through to
// the generic approve-reply path, so the assistant's final message was lost.
func TestBuildClaudeStopEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"Stop","stop_hook_active":false,"last_assistant_message":"Refactored the auth middleware and pushed the tests."}`)
	ev, ok := buildClaudeStopEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionTaskComplete {
		t.Errorf("ActionType=%q want %q", ev.ActionType, models.ActionTaskComplete)
	}
	if ev.RawToolName != "claudecode.assistant_text" {
		t.Errorf("RawToolName=%q want claudecode.assistant_text", ev.RawToolName)
	}
	if ev.Target != "Refactored the auth middleware and pushed the tests." {
		t.Errorf("Target=%q (want last_assistant_message preview)", ev.Target)
	}
	if ev.ToolOutput != "Refactored the auth middleware and pushed the tests." {
		t.Errorf("ToolOutput=%q", ev.ToolOutput)
	}
	if ev.PrecedingReasoning != ev.Target {
		t.Errorf("PrecedingReasoning should mirror Target")
	}
	if ev.SourceFile != "claude-code:hook" {
		t.Errorf("SourceFile=%q want claude-code:hook", ev.SourceFile)
	}
	if ev.SessionID != "s1" {
		t.Errorf("SessionID=%q", ev.SessionID)
	}
	// SourceEventID must embed a content hash so replayed captures dedupe
	// via the (source_file, source_event_id) UPSERT path. The exact hash
	// is implementation detail; assert only the prefix shape.
	if !strings.HasPrefix(ev.SourceEventID, "s1:stop:") {
		t.Errorf("SourceEventID=%q want prefix s1:stop:", ev.SourceEventID)
	}
	if ev.IsSidechain {
		t.Errorf("IsSidechain must be false for top-level Stop (not a subagent)")
	}
}

// TestBuildClaudeStopEvent_EmptySuppressed pins the empty-message
// suppression: Stop fires on every turn-end including interruptions where
// there's no model output. Empty/whitespace last_assistant_message returns
// (zero, false) so the table doesn't accumulate marker-only rows.
func TestBuildClaudeStopEvent_EmptySuppressed(t *testing.T) {
	cases := []string{
		`{"session_id":"s1","cwd":"/r","hook_event_name":"Stop"}`,
		`{"session_id":"s1","cwd":"/r","hook_event_name":"Stop","last_assistant_message":""}`,
		`{"session_id":"s1","cwd":"/r","hook_event_name":"Stop","last_assistant_message":"   "}`,
	}
	for i, body := range cases {
		if _, ok := buildClaudeStopEvent([]byte(body)); ok {
			t.Errorf("case[%d]: expected ok=false for empty last_assistant_message, got ok=true (body=%s)", i, body)
		}
	}
}

// TestBuildClaudeStopEvent_StableSourceEventID pins that replaying the same
// envelope produces the same SourceEventID — required for the watcher's
// at-least-once delivery semantics to dedupe via UPSERT instead of
// inserting duplicate rows.
func TestBuildClaudeStopEvent_StableSourceEventID(t *testing.T) {
	body := []byte(`{"session_id":"s2","cwd":"/r","hook_event_name":"Stop","last_assistant_message":"Done."}`)
	ev1, ok1 := buildClaudeStopEvent(body)
	ev2, ok2 := buildClaudeStopEvent(body)
	if !ok1 || !ok2 {
		t.Fatalf("ok1=%v ok2=%v", ok1, ok2)
	}
	if ev1.SourceEventID != ev2.SourceEventID {
		t.Errorf("SourceEventID drift across re-builds: %q vs %q", ev1.SourceEventID, ev2.SourceEventID)
	}
}

func TestBuildClaudeNotificationEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"Notification","notification_type":"idle_prompt","message":"Claude is waiting for your input"}`)
	ev, ok := buildClaudeNotificationEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionNotification {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "idle_prompt" {
		t.Errorf("Target=%q", ev.Target)
	}
	if !strings.Contains(ev.ErrorMessage, "waiting for your input") {
		t.Errorf("ErrorMessage=%q", ev.ErrorMessage)
	}
}

func TestBuildClaudeCwdChangedEvent_OldNewFields(t *testing.T) {
	// Captured payload uses old_cwd / new_cwd (not previous_cwd as docs claim).
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"CwdChanged","old_cwd":"/home/u/old","new_cwd":"/tmp"}`)
	ev, ok := buildClaudeCwdChangedEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionCwdChange {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "/tmp" {
		t.Errorf("Target=%q (want new_cwd)", ev.Target)
	}
	if ev.PrecedingReasoning != "/home/u/old" {
		t.Errorf("PrecedingReasoning=%q (want old_cwd)", ev.PrecedingReasoning)
	}
}

func TestBuildClaudeCwdChangedEvent_DocsField(t *testing.T) {
	// previous_cwd is the docs field name; builder must accept both
	// shapes for forward-compat across Claude Code releases.
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"CwdChanged","previous_cwd":"/old","new_cwd":"/new"}`)
	ev, ok := buildClaudeCwdChangedEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.PrecedingReasoning != "/old" {
		t.Errorf("PrecedingReasoning=%q (want previous_cwd)", ev.PrecedingReasoning)
	}
}

func TestBuildClaudeSetupEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"Setup","trigger":"init"}`)
	ev, ok := buildClaudeSetupEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionSetup {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "init" {
		t.Errorf("Target=%q (want trigger)", ev.Target)
	}
	if ev.SourceEventID != "s1:setup:init" {
		t.Errorf("SourceEventID=%q (want session_id:setup:trigger)", ev.SourceEventID)
	}
}

func TestBuildClaudeUserPromptExpansionEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","permission_mode":"default","hook_event_name":"UserPromptExpansion","expansion_type":"slash_command","command_name":"review","command_args":"PR#42","command_source":"plugin","prompt":"/review PR#42"}`)
	ev, ok := buildClaudeUserPromptExpansionEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionUserPromptExpansion {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "review" {
		t.Errorf("Target=%q (want command_name)", ev.Target)
	}
	if ev.RawToolName != "slash_command" {
		t.Errorf("RawToolName=%q (want expansion_type)", ev.RawToolName)
	}
	if ev.RawToolInput != "/review PR#42" {
		t.Errorf("RawToolInput=%q (want raw prompt)", ev.RawToolInput)
	}
	if !strings.Contains(ev.PrecedingReasoning, "command_source") || !strings.Contains(ev.PrecedingReasoning, "plugin") {
		t.Errorf("PrecedingReasoning=%q (want command_source+command_args JSON)", ev.PrecedingReasoning)
	}
	// SourceEventID uses content hash so two distinct expansions in
	// one session don't collide on ON CONFLICT UPDATE.
	if !strings.HasPrefix(ev.SourceEventID, "s1:user_prompt_expansion:") {
		t.Errorf("SourceEventID=%q (want session_id:user_prompt_expansion:hash)", ev.SourceEventID)
	}
}

func TestBuildClaudePostToolBatchEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","permission_mode":"default","hook_event_name":"PostToolBatch","tool_calls":[{"tool_name":"Read","tool_input":{"file_path":"/a.go"},"tool_use_id":"toolu_01","tool_response":"     1\tpackage a"},{"tool_name":"Grep","tool_input":{"pattern":"foo"},"tool_use_id":"toolu_02","tool_response":"a.go:5"}]}`)
	ev, ok := buildClaudePostToolBatchEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionPostToolBatch {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "2 tool call(s)" {
		t.Errorf("Target=%q (want batch size)", ev.Target)
	}
	if ev.RawToolName != "Read" {
		t.Errorf("RawToolName=%q (want first tool_name)", ev.RawToolName)
	}
	if !strings.Contains(ev.RawToolInput, `"Read"`) || !strings.Contains(ev.RawToolInput, `"Grep"`) {
		t.Errorf("RawToolInput=%q (want tool_calls JSON)", ev.RawToolInput)
	}
}

func TestBuildClaudePostToolBatchEvent_EmptyBatchSuppressed(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"PostToolBatch","tool_calls":[]}`)
	if _, ok := buildClaudePostToolBatchEvent(body); ok {
		t.Error("expected ok=false for empty tool_calls batch")
	}
}

func TestBuildClaudePermissionRequestEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","permission_mode":"default","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"rm -rf node_modules"},"permission_suggestions":[{"type":"addRules","rules":[{"toolName":"Bash","ruleContent":"rm -rf node_modules"}],"behavior":"allow","destination":"localSettings"}]}`)
	ev, ok := buildClaudePermissionRequestEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionPermissionRequest {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "Bash" {
		t.Errorf("Target=%q (want tool_name)", ev.Target)
	}
	if !strings.Contains(ev.RawToolInput, "rm -rf node_modules") {
		t.Errorf("RawToolInput=%q (want tool_input)", ev.RawToolInput)
	}
	if !strings.Contains(ev.PrecedingReasoning, "addRules") {
		t.Errorf("PrecedingReasoning=%q (want permission_suggestions JSON)", ev.PrecedingReasoning)
	}
	if !ev.Success {
		t.Errorf("Success=false; PermissionRequest is just a prompt — outcome lands on a sibling row")
	}
}

func TestBuildClaudePermissionDeniedEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","permission_mode":"auto","hook_event_name":"PermissionDenied","tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/build"},"tool_use_id":"toolu_01ABC","reason":"Auto mode denied: command targets a path outside the project"}`)
	ev, ok := buildClaudePermissionDeniedEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionPermissionDenied {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "Bash" {
		t.Errorf("Target=%q (want tool_name)", ev.Target)
	}
	if ev.SourceEventID != "toolu_01ABC:permission_denied" {
		t.Errorf("SourceEventID=%q (want tool_use_id:permission_denied)", ev.SourceEventID)
	}
	if !strings.Contains(ev.ErrorMessage, "Auto mode denied") {
		t.Errorf("ErrorMessage=%q (want reason)", ev.ErrorMessage)
	}
	if ev.Success {
		t.Errorf("Success should be false on denied")
	}
}

// TestClaudeToolInputScrubbing_SecretInJSONStaysValidJSON pins MHC-4
// (docs/audits/codebase-audit-2026-09-16.md): every builder that carries
// a JSON `tool_input` into RawToolInput must scrub it with
// scrub.Scrubber.RawJSON (structure-aware), not .String (line-oriented
// regexes). CLAUDE.md's "Don'ts" spells out why this matters — String's
// generic `(api[_-]?key)(\s*[=:]\s*)(\S+)` pattern is greedy across
// compact JSON's total lack of whitespace, so on a secret sitting next
// to other fields it doesn't just redact the secret, it swallows and
// truncates everything after it, corrupting the stored JSON.
//
// Table-driven across the four builders MHC-4 named (post_tool_failure,
// post_tool_batch, permission_request, permission_denied): each gets a
// COMPACT (no-whitespace) tool_input JSON body with a secret-shaped
// value sitting next to an innocuous sibling field. The fix must (1)
// keep the result valid JSON, (2) redact the secret, and (3) preserve
// the sibling field — proving the JSON wasn't truncated.
func TestClaudeToolInputScrubbing_SecretInJSONStaysValidJSON(t *testing.T) {
	const secret = "sk_live_abcdef1234567890"
	const sibling = "echo hi"

	tests := []struct {
		name  string
		body  string
		build func([]byte) (models.ToolEvent, bool)
	}{
		{
			name:  "post_tool_failure",
			body:  `{"session_id":"s1","cwd":"/r","hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_input":{"api_key":"` + secret + `","command":"` + sibling + `"},"tool_use_id":"toolu_01","error":"failed","is_interrupt":false,"duration_ms":1}`,
			build: buildClaudePostToolFailureEvent,
		},
		{
			name:  "post_tool_batch",
			body:  `{"session_id":"s1","cwd":"/r","hook_event_name":"PostToolBatch","tool_calls":[{"tool_name":"Bash","tool_input":{"api_key":"` + secret + `","command":"` + sibling + `"},"tool_use_id":"toolu_01","tool_response":"ok"}]}`,
			build: buildClaudePostToolBatchEvent,
		},
		{
			name:  "permission_request",
			body:  `{"session_id":"s1","cwd":"/r","hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"api_key":"` + secret + `","command":"` + sibling + `"}}`,
			build: buildClaudePermissionRequestEvent,
		},
		{
			name:  "permission_denied",
			body:  `{"session_id":"s1","cwd":"/r","hook_event_name":"PermissionDenied","tool_name":"Bash","tool_input":{"api_key":"` + secret + `","command":"` + sibling + `"},"tool_use_id":"toolu_01","reason":"denied"}`,
			build: buildClaudePermissionDeniedEvent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := tc.build([]byte(tc.body))
			if !ok {
				t.Fatal("ok=false")
			}
			if !json.Valid([]byte(ev.RawToolInput)) {
				t.Fatalf("RawToolInput is not valid JSON after scrubbing: %q", ev.RawToolInput)
			}
			if strings.Contains(ev.RawToolInput, secret) {
				t.Errorf("secret survived scrubbing: %q", ev.RawToolInput)
			}
			if !strings.Contains(ev.RawToolInput, sibling) {
				t.Errorf("sibling field lost — scrubbing truncated/corrupted the JSON: %q", ev.RawToolInput)
			}
		})
	}
}

func TestBuildClaudeInstructionsLoadedEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"InstructionsLoaded","file_path":"/r/CLAUDE.md","memory_type":"Project","load_reason":"session_start"}`)
	ev, ok := buildClaudeInstructionsLoadedEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionInstructionsLoaded {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "/r/CLAUDE.md" {
		t.Errorf("Target=%q (want file_path)", ev.Target)
	}
	if ev.RawToolName != "Project" {
		t.Errorf("RawToolName=%q (want memory_type)", ev.RawToolName)
	}
	if !strings.Contains(ev.RawToolInput, "session_start") {
		t.Errorf("RawToolInput=%q (want load_reason in JSON)", ev.RawToolInput)
	}
	if ev.SourceEventID != "s1:instructions_loaded:/r/CLAUDE.md" {
		t.Errorf("SourceEventID=%q (want session_id:instructions_loaded:file_path)", ev.SourceEventID)
	}
}

func TestBuildClaudeInstructionsLoadedEvent_OptionalFields(t *testing.T) {
	// path_glob_match loads carry globs + trigger_file_path; include
	// loads carry parent_file_path. All must land in RawToolInput JSON.
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"InstructionsLoaded","file_path":"/r/skills/foo/CLAUDE.md","memory_type":"Local","load_reason":"path_glob_match","globs":["**/*.go"],"trigger_file_path":"/r/main.go"}`)
	ev, ok := buildClaudeInstructionsLoadedEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	for _, want := range []string{"path_glob_match", "**/*.go", "/r/main.go"} {
		if !strings.Contains(ev.RawToolInput, want) {
			t.Errorf("RawToolInput=%q missing %q", ev.RawToolInput, want)
		}
	}
}

func TestBuildClaudeConfigChangeEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"ConfigChange","source":"project_settings","file_path":"/r/.claude/settings.json"}`)
	ev, ok := buildClaudeConfigChangeEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionConfigChange {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "/r/.claude/settings.json" {
		t.Errorf("Target=%q (want file_path)", ev.Target)
	}
	if ev.RawToolName != "project_settings" {
		t.Errorf("RawToolName=%q (want source)", ev.RawToolName)
	}
}

func TestBuildClaudeConfigChangeEvent_SkillsSourceFallback(t *testing.T) {
	// `skills` source has no file_path per docs; Target falls back to
	// the source name so the dashboard listing isn't blank.
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"ConfigChange","source":"skills"}`)
	ev, ok := buildClaudeConfigChangeEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.Target != "skills" {
		t.Errorf("Target=%q (want source fallback)", ev.Target)
	}
}

func TestBuildClaudeWorktreeRemoveEvent(t *testing.T) {
	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"WorktreeRemove","worktree_path":"/home/u/.claude/worktrees/feature-auth"}`)
	ev, ok := buildClaudeWorktreeRemoveEvent(body)
	if !ok {
		t.Fatal("ok=false")
	}
	if ev.ActionType != models.ActionWorktreeRemove {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "/home/u/.claude/worktrees/feature-auth" {
		t.Errorf("Target=%q (want worktree_path)", ev.Target)
	}
	if ev.SourceEventID != "s1:worktree_remove:/home/u/.claude/worktrees/feature-auth" {
		t.Errorf("SourceEventID=%q", ev.SourceEventID)
	}
}

func TestBuildClaudeWorktreeCreateReply_DocumentedPayload(t *testing.T) {
	t.Setenv("OBSERVER_CLAUDE_WORKTREE_ROOT", "")
	// Stub HOME so the test is deterministic across hosts.
	t.Setenv("HOME", "/home/testuser")
	t.Setenv("USERPROFILE", "/home/testuser") // os.UserHomeDir reads USERPROFILE on Windows

	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"WorktreeCreate","name":"feature-auth"}`)
	worktreePath, ev, hasSession := buildClaudeWorktreeCreateReply(body)
	if !hasSession {
		t.Fatal("hasSession=false")
	}
	// ToSlash: the daemon emits these paths on Linux/WSL ('/'); on a
	// Windows test host filepath.Join uses '\\'. The path COMPONENTS are
	// the invariant, not the separator.
	wantPath := "/home/testuser/.claude/worktrees/feature-auth"
	if filepath.ToSlash(worktreePath) != wantPath {
		t.Errorf("worktreePath=%q want %q", worktreePath, wantPath)
	}
	if ev.ActionType != models.ActionWorktreeCreate {
		t.Errorf("ActionType=%q", ev.ActionType)
	}
	if ev.Target != "feature-auth" {
		t.Errorf("Target=%q (want name)", ev.Target)
	}
	if filepath.ToSlash(ev.RawToolInput) != wantPath {
		t.Errorf("RawToolInput=%q want echoed path", ev.RawToolInput)
	}
	if ev.SourceEventID != "s1:worktree_create:feature-auth" {
		t.Errorf("SourceEventID=%q", ev.SourceEventID)
	}
}

func TestBuildClaudeWorktreeCreateReply_EmptyNameSynthesizes(t *testing.T) {
	t.Setenv("HOME", "/home/testuser")
	t.Setenv("USERPROFILE", "/home/testuser") // os.UserHomeDir reads USERPROFILE on Windows
	t.Setenv("OBSERVER_CLAUDE_WORKTREE_ROOT", "")

	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"WorktreeCreate"}`)
	worktreePath, ev, hasSession := buildClaudeWorktreeCreateReply(body)
	if !hasSession {
		t.Fatal("hasSession=false")
	}
	// Synthesized name has the "worktree-" prefix + base36 nanos.
	if !strings.HasPrefix(ev.Target, "worktree-") {
		t.Errorf("Target=%q (want worktree-<...> prefix)", ev.Target)
	}
	if !strings.HasPrefix(filepath.ToSlash(worktreePath), "/home/testuser/.claude/worktrees/worktree-") {
		t.Errorf("worktreePath=%q (want default-root prefix + synthesized name)", worktreePath)
	}
}

func TestBuildClaudeWorktreeCreateReply_EnvRootOverride(t *testing.T) {
	t.Setenv("OBSERVER_CLAUDE_WORKTREE_ROOT", "/mnt/fast/wts")
	t.Setenv("HOME", "/home/testuser")
	t.Setenv("USERPROFILE", "/home/testuser") // os.UserHomeDir reads USERPROFILE on Windows

	body := []byte(`{"session_id":"s1","cwd":"/r","hook_event_name":"WorktreeCreate","name":"feature-x"}`)
	worktreePath, _, hasSession := buildClaudeWorktreeCreateReply(body)
	if !hasSession {
		t.Fatal("hasSession=false")
	}
	if filepath.ToSlash(worktreePath) != "/mnt/fast/wts/feature-x" {
		t.Errorf("worktreePath=%q (want env-override root)", worktreePath)
	}
}

func TestBuildClaudeWorktreeCreateReply_NoSessionIDStillEchosPath(t *testing.T) {
	// Missing session_id must NOT cause an empty stdout reply —
	// that would fail every Agent spawn. The path computation
	// still runs; only the DB-write portion is skipped.
	t.Setenv("HOME", "/home/testuser")
	t.Setenv("USERPROFILE", "/home/testuser") // os.UserHomeDir reads USERPROFILE on Windows
	t.Setenv("OBSERVER_CLAUDE_WORKTREE_ROOT", "")
	body := []byte(`{"cwd":"/r","hook_event_name":"WorktreeCreate","name":"feature-y"}`)
	worktreePath, _, hasSession := buildClaudeWorktreeCreateReply(body)
	if hasSession {
		t.Error("hasSession=true; want false when session_id missing")
	}
	if filepath.ToSlash(worktreePath) != "/home/testuser/.claude/worktrees/feature-y" {
		t.Errorf("worktreePath=%q (want path computed even without session_id)", worktreePath)
	}
}

// TestHandleClaudeCodeWorktreeCreate_AlwaysReplies pins the
// invariant that no matter what's on stdin, observer's WorktreeCreate
// handler writes a valid `{"hookSpecificOutput":{"worktreePath":...}}`
// JSON to stdout. The DB write is best-effort (config path is
// intentionally invalid here to force a config-load failure) — the
// reply must still go out so Claude Code's Agent spawn doesn't fail.
func TestHandleClaudeCodeWorktreeCreate_AlwaysReplies(t *testing.T) {
	t.Setenv("HOME", "/home/testuser")
	t.Setenv("USERPROFILE", "/home/testuser") // os.UserHomeDir reads USERPROFILE on Windows
	t.Setenv("OBSERVER_CLAUDE_WORKTREE_ROOT", "")
	var stdout, stderr bytes.Buffer
	// A MALFORMED config (not merely a missing path) deterministically
	// forces a config-load failure on every OS: a non-existent path is
	// tolerated by the loader (it falls back to defaults), and on Windows
	// the default '~' db_path then resolves via USERPROFILE and opens
	// cleanly — so the missing-path variant produced no error there. This
	// matches the test's stated intent ("force a config-load failure").
	badCfg := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(badCfg, []byte("[observer\nthis is = = not valid toml"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := `{"session_id":"s1","cwd":"/r","hook_event_name":"WorktreeCreate","name":"feature-z"}`
	handleClaudeCodeWorktreeCreate(
		context.Background(),
		"claude-code:worktree-create",
		badCfg,
		strings.NewReader(payload),
		&stdout, &stderr,
	)
	var reply struct {
		HookSpecificOutput struct {
			WorktreePath string `json:"worktreePath"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &reply); err != nil {
		t.Fatalf("stdout not JSON: %v — %q", err, stdout.String())
	}
	if filepath.ToSlash(reply.HookSpecificOutput.WorktreePath) != "/home/testuser/.claude/worktrees/feature-z" {
		t.Errorf("worktreePath=%q", reply.HookSpecificOutput.WorktreePath)
	}
	// stderr should contain SOME error note (config or db) — the
	// invalid config path triggers either a config-load failure or a
	// downstream db-open failure depending on whether the loader
	// falls back to defaults. Either way the handler logs and
	// continues; the reply still goes out (asserted above).
	got := stderr.String()
	if !strings.Contains(got, "config") && !strings.Contains(got, "db") {
		t.Errorf("expected stderr to mention config or db error; got: %q", got)
	}
}

// TestBuildClaude_EnvelopePopulatesMetadata pins migration 017: the
// permission_mode + effort.level fields ride on every Claude Code hook
// payload's envelope, and every builder inherits them via baseToolEvent.
// Pre-fix these fields were unparsed; post-fix they land on
// ev.Metadata.{PermissionMode,EffortLevel}.
func TestBuildClaude_EnvelopePopulatesMetadata(t *testing.T) {
	cases := []struct {
		name       string
		body       []byte
		build      claudeActionBuilder
		wantPerm   string
		wantEffort string
	}{
		{
			name:       "user_prompt_with_permission_mode",
			body:       []byte(`{"session_id":"s1","cwd":"/r","permission_mode":"plan","prompt":"hi"}`),
			build:      buildClaudeUserPromptSubmitEvent,
			wantPerm:   "plan",
			wantEffort: "",
		},
		{
			name:       "session_end_with_both",
			body:       []byte(`{"session_id":"s1","cwd":"/r","permission_mode":"default","effort":{"level":"high"}}`),
			build:      buildClaudeSessionEndEvent,
			wantPerm:   "default",
			wantEffort: "high",
		},
		{
			name:       "notification_no_metadata_keeps_nil",
			body:       []byte(`{"session_id":"s1","cwd":"/r","notification_type":"idle_prompt","message":"x"}`),
			build:      buildClaudeNotificationEvent,
			wantPerm:   "",
			wantEffort: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev, ok := c.build(c.body)
			if !ok {
				t.Fatal("ok=false")
			}
			if c.wantPerm == "" && c.wantEffort == "" {
				if ev.Metadata != nil {
					t.Errorf("Metadata=%+v; want nil for envelope without metadata", ev.Metadata)
				}
				return
			}
			if ev.Metadata == nil {
				t.Fatalf("Metadata=nil; want PermissionMode=%q EffortLevel=%q",
					c.wantPerm, c.wantEffort)
			}
			if ev.Metadata.PermissionMode != c.wantPerm {
				t.Errorf("PermissionMode=%q want %q", ev.Metadata.PermissionMode, c.wantPerm)
			}
			if ev.Metadata.EffortLevel != c.wantEffort {
				t.Errorf("EffortLevel=%q want %q", ev.Metadata.EffortLevel, c.wantEffort)
			}
		})
	}
}

func TestBuildClaudeAllRejectMissingSessionID(t *testing.T) {
	cases := map[string]claudeActionBuilder{
		"SessionEnd":          buildClaudeSessionEndEvent,
		"UserPromptSubmit":    buildClaudeUserPromptSubmitEvent,
		"PostToolUseFailure":  buildClaudePostToolFailureEvent,
		"StopFailure":         buildClaudeStopFailureEvent,
		"SubagentStart":       buildClaudeSubagentStartEvent,
		"SubagentStop":        buildClaudeSubagentStopEvent,
		"Notification":        buildClaudeNotificationEvent,
		"CwdChanged":          buildClaudeCwdChangedEvent,
		"Setup":               buildClaudeSetupEvent,
		"UserPromptExpansion": buildClaudeUserPromptExpansionEvent,
		"PostToolBatch":       buildClaudePostToolBatchEvent,
		"PermissionRequest":   buildClaudePermissionRequestEvent,
		"PermissionDenied":    buildClaudePermissionDeniedEvent,
		"InstructionsLoaded":  buildClaudeInstructionsLoadedEvent,
		"ConfigChange":        buildClaudeConfigChangeEvent,
		"WorktreeRemove":      buildClaudeWorktreeRemoveEvent,
		"Stop":                buildClaudeStopEvent,
	}
	body := []byte(`{"cwd":"/r"}`)
	for name, b := range cases {
		if _, ok := b(body); ok {
			t.Errorf("%s: built ok despite missing session_id", name)
		}
	}
}

// TestResolveHookMaxRuntime exercises the flag/env/default precedence.
func TestResolveHookMaxRuntime(t *testing.T) {
	cases := []struct {
		name string
		flag time.Duration
		env  string
		want time.Duration
	}{
		{"default when nothing set", 0, "", defaultHookMaxRuntime},
		{"env wins over default", 0, "5s", 5 * time.Second},
		{"flag wins over env", 7 * time.Second, "5s", 7 * time.Second},
		{"flag wins over default", 4 * time.Second, "", 4 * time.Second},
		{"bad env falls back to default", 0, "not-a-duration", defaultHookMaxRuntime},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveHookMaxRuntime(tc.flag, tc.env); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestInstallHookWatchdogFiresOnExceededRuntime pins the V3-1 fix + the
// fail-open hardening: when a hook runs past its budget, the watchdog
// must fire promptly so the host AI tool isn't pinned — and it must exit
// 0 (fail-OPEN), because a non-zero PreToolUse exit BLOCKS the tool. A
// timeout is not a deny decision.
func TestInstallHookWatchdogFiresOnExceededRuntime(t *testing.T) {
	var stderr bytes.Buffer
	exitCh := make(chan int, 1)
	stop := installHookWatchdog(20*time.Millisecond, func(code int) {
		exitCh <- code
	}, &stderr)
	defer stop()

	select {
	case code := <-exitCh:
		if code != 0 {
			t.Errorf("exit code = %d, want 0 (fail-open; non-zero would block the tool)", code)
		}
		if !strings.Contains(stderr.String(), "max-runtime") {
			t.Errorf("stderr missing max-runtime message: %q", stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog didn't fire within 2 s of a 20 ms budget")
	}
}

// TestInstallHookWatchdogStopDisarmsTimer verifies the clean-exit path:
// when the hook completes inside the budget, calling the returned stop
// func must prevent the watchdog from firing afterwards.
func TestInstallHookWatchdogStopDisarmsTimer(t *testing.T) {
	var stderr bytes.Buffer
	exitCh := make(chan int, 1)
	stop := installHookWatchdog(20*time.Millisecond, func(code int) {
		exitCh <- code
	}, &stderr)
	stop()

	select {
	case code := <-exitCh:
		t.Errorf("watchdog fired after stop(): exit=%d", code)
	case <-time.After(100 * time.Millisecond):
		// expected: timer disarmed, no firing
	}
}

// TestInstallHookWatchdogZeroRuntimeIsNoop is the escape hatch: a
// non-positive budget disables the watchdog entirely (diagnostics only).
func TestInstallHookWatchdogZeroRuntimeIsNoop(t *testing.T) {
	var stderr bytes.Buffer
	exitCh := make(chan int, 1)
	stop := installHookWatchdog(0, func(code int) {
		exitCh <- code
	}, &stderr)
	defer stop()

	select {
	case code := <-exitCh:
		t.Errorf("watchdog fired despite zero budget: exit=%d", code)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

// resetHookVerdictState restores the package-level verdict-tracking
// vars (hookReplied/hookPendingExitCode/hookExpectsStdoutReply — see
// their doc comment) to newHookCmd's Run-time reset values, so a test
// that exercises recoverHookPanic directly isn't affected by state a
// PRIOR test in the same binary left behind, mirroring the reset
// Run itself performs at the top of every real invocation.
func resetHookVerdictState() {
	hookReplied = false
	hookPendingExitCode = 0
	hookExpectsStdoutReply = true
}

// TestRecoverHookPanicFailsOpen pins P1-4/RES-2 (docs/audits/
// codebase-audit-2026-09-16.md): a panic anywhere inside a hook
// receiver must never surface as a non-zero exit, because a non-zero
// exit from a PreToolUse-class hook BLOCKS the host AI tool — the
// exact inversion of this command's documented fail-open contract.
// Simulates newHookCmd's `defer recoverHookPanic(...)` wiring directly:
// a handler injected to panic BEFORE anything has been decided (the
// default fresh-invocation state) must still leave recoverHookPanic
// writing the {"decision":"approve"} fail-open reply to stdout (never
// stdout+stderr mixed), logging the panic + stack to stderr only, and
// calling exitFn(0) — mirroring TestInstallHookWatchdogFiresOnExceededRuntime's
// injected-exitFn pattern so the test never actually terminates the
// process.
func TestRecoverHookPanicFailsOpen(t *testing.T) {
	resetHookVerdictState()
	var stdout, stderr bytes.Buffer
	exitCh := make(chan int, 1)

	func() {
		defer recoverHookPanic("claude-code:PreToolUse", &stdout, &stderr, func(code int) {
			exitCh <- code
		})
		// Simulates a receiver panicking (e.g. handleClaudeCodePreTool's
		// hook.RewriteBash over a pathological command) BEFORE any
		// reply has gone out and before any exit code was decided.
		panic("simulated hook receiver panic")
	}()

	select {
	case code := <-exitCh:
		if code != 0 {
			t.Errorf("exit code = %d, want 0 (fail-open; non-zero would block the tool)", code)
		}
	default:
		t.Fatal("recoverHookPanic did not call exitFn after a panic")
	}

	var decision struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &decision); err != nil {
		t.Fatalf("stdout is not valid JSON: %v (stdout=%q)", err, stdout.String())
	}
	if decision.Decision != "approve" {
		t.Errorf("decision = %q, want %q", decision.Decision, "approve")
	}

	if !strings.Contains(stderr.String(), "PANIC") || !strings.Contains(stderr.String(), "simulated hook receiver panic") {
		t.Errorf("stderr missing panic diagnostics: %q", stderr.String())
	}
	if strings.Contains(stdout.String(), "PANIC") {
		t.Errorf("panic diagnostics leaked onto stdout, corrupting the hook protocol reply: %q", stdout.String())
	}
}

// TestRecoverHookPanicPreservesAlreadyDecidedBlock pins P2-1
// (adversarial review of the P1-4 fix, docs/audits/
// codebase-audit-2026-09-16.md): once a receiver has ALREADY written
// its reply and decided a blocking exit code (e.g.
// handleClaudeCodeUserPromptSubmit's Claude Code dialect: the JSON
// block reply goes out, exitCode is set to 2, THEN the capture
// ingest — which can panic — runs, THEN hookOSExit(2)), a panic in
// that post-decision work must NEVER let recoverHookPanic (a) write a
// second stdout object on top of the one already sent, or (b)
// downgrade the decided exit code to 0, silently turning the block
// into an allow.
func TestRecoverHookPanicPreservesAlreadyDecidedBlock(t *testing.T) {
	resetHookVerdictState()
	var stdout, stderr bytes.Buffer
	exitCh := make(chan int, 1)

	const blockReply = `{"decision":"block","reason":"secret detected"}` + "\n"

	func() {
		defer recoverHookPanic("claude-code:UserPromptSubmit", &stdout, &stderr, func(code int) {
			exitCh <- code
		})
		// Simulates the sequence handleClaudeCodeUserPromptSubmit
		// actually runs: HandlePromptSubmitGuarded already wrote the
		// block reply and decided exitCode=2 — the caller marks both
		// BEFORE doing the capture-ingest work that follows.
		_, _ = stdout.WriteString(blockReply)
		markHookReplied()
		markHookPendingExit(2)
		// Simulates a panic in the capture-ingest closure that runs
		// AFTER the verdict is decided but BEFORE hookOSExit(2).
		panic("simulated ingest panic")
	}()

	select {
	case code := <-exitCh:
		if code != 2 {
			t.Errorf("exit code = %d, want 2 (an already-decided BLOCK must survive the panic, never silently become an ALLOW)", code)
		}
	default:
		t.Fatal("recoverHookPanic did not call exitFn after a panic")
	}

	if got := stdout.String(); got != blockReply {
		t.Errorf("stdout = %q, want EXACTLY the one block reply already written (no second JSON object appended)", got)
	}
}

// TestRecoverHookPanicOnNilReplyDialectStaysSilent pins P2-1: Qoder and
// Cascade are exit-code-only prompt-submit dialects with NO stdout
// JSON channel for this event at all (see
// promptDialectsWithoutStdoutReply) — a panic before anything has been
// decided on one of these dialects must leave stdout completely empty
// (never the generic {"decision":"approve"} fail-open body, which is
// unexpected output no such host parses) and still exit 0, since
// nothing was ever decided.
func TestRecoverHookPanicOnNilReplyDialectStaysSilent(t *testing.T) {
	resetHookVerdictState()
	// Simulates handlePromptSubmitOnlyHook's dialect-contract flip,
	// made right before it enters the guarded evaluation for a
	// nil-reply dialect.
	hookExpectsStdoutReply = !promptDialectsWithoutStdoutReply[hook.PromptDialectQoder]
	var stdout, stderr bytes.Buffer
	exitCh := make(chan int, 1)

	func() {
		defer recoverHookPanic("qoder:UserPromptSubmit", &stdout, &stderr, func(code int) {
			exitCh <- code
		})
		// Simulates a panic before HandlePromptSubmitGuarded ever
		// returned — nothing has been replied or decided yet.
		panic("simulated pre-decision panic")
	}()

	select {
	case code := <-exitCh:
		if code != 0 {
			t.Errorf("exit code = %d, want 0 (nothing was ever decided)", code)
		}
	default:
		t.Fatal("recoverHookPanic did not call exitFn after a panic")
	}

	if got := stdout.String(); got != "" {
		t.Errorf("stdout = %q, want empty — this dialect has no stdout JSON channel at all", got)
	}
}

// TestPromptLaneHookRowsHaveAReceiver pins BLOCK-1 (phase-2 review):
// every internal/integration registry row that claims
// integration.PromptLaneHook (a VERIFIED prompt-submit hook dialect
// exists AND is registered) must have a corresponding entry in
// hookReceivers — otherwise `observer hook <tool> UserPromptSubmit`
// silently falls through to the unconditional approve default, which
// can never block, no matter what the registry/conformance/docs claim.
// This is a coverage test, not a behavior test: it walks the LIVE
// registry so a future PromptLaneHook row added without a receiver
// fails loudly here instead of shipping a claimed-but-fake guard.
func TestPromptLaneHookRowsHaveAReceiver(t *testing.T) {
	for _, c := range integration.Capabilities() {
		if c.PromptLane != integration.PromptLaneHook {
			continue
		}
		if _, ok := hookReceivers[c.Tool]; !ok {
			t.Errorf("registry row %q claims PromptLaneHook (a verified, registered hook dialect) but has no entry in cmd/observer's hookReceivers table — observer hook %s UserPromptSubmit would silently fall through to the approve-only default and could never block", c.Tool, c.Tool)
		}
	}
}
