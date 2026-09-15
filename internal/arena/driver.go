package arena

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// driver.go — headless one-shot drivers for the grounded harness set. The
// argv shapes mirror cmd/observer/benchmark_driver.go's LIVE-VERIFIED
// drives (claudeCodeDriver / codexDriver) but are composed through the
// registry HeadlessSpec so adding a tool means grounding its row, not
// editing this file.

// driveRequest is one candidate drive's inputs.
type driveRequest struct {
	Tool         string
	Model        string
	WorktreePath string
	Prompt       string
	// ContextFiles are validated project-relative paths selected for this run.
	// The registry HeadlessSpec decides whether/how they land on argv.
	ContextFiles []string
	// ProxyURL is the observer proxy base; when empty the run goes direct
	// and token capture rides whatever the tool's own logs carry.
	ProxyURL string
	Timeout  time.Duration
	// ConfigDir, when set, is exported as CLAUDE_CONFIG_DIR for the
	// claude-code lane — the per-slot sandbox prepared by the runner
	// (claudesandbox.go) so operator deny rules can't veto worktree edits.
	ConfigDir string
	// OnStart runs immediately after the harness process starts and before the
	// runner waits for it. Arena uses it to install the candidate's synthetic
	// pid bridge before the first provider request. Returning an error kills the
	// process rather than spending through an unattributable lane.
	OnStart func(pid int) error
	// OnExit retracts the exact pid bridge after the direct child exits.
	OnExit func(pid int)
	// Admission runs immediately before the harness process starts. Nil keeps
	// the standalone Arena engine behavior unchanged.
	Admission func(context.Context, string, string) error
}

// driveResult is one candidate drive's outcome.
type driveResult struct {
	ExitCode    int
	WallMS      int64
	FinalAnswer string
	SessionIDs  []string
	TimedOut    bool
	// PID of the spawned root process (>0 after a real drive) so the
	// runner can record a launch seed for daemon-side attribution.
	PID int
}

var (
	// procGroupMu serializes Setpgid on spawn (setpgid races if two
	// children in the same group start simultaneously).
	procGroupMu sync.Mutex
	// driveOverrides lets tests substitute fake binaries + env.
	driveBinOverrides = map[string]string{}
)

// setProcGroup is defined per-platform in procgroup_unix.go /
// procgroup_other.go (Setpgid into a new process group on unix; no-op
// elsewhere).

// driveHarness resolves the tool's binary and dispatches to its
// HeadlessSpec-driven invocation.
func driveHarness(ctx context.Context, req driveRequest) (driveResult, error) {
	ic, ok := integration.For(req.Tool)
	if !ok || ic.Headless == nil {
		return driveResult{}, fmt.Errorf("arena.driveHarness: tool %q has no grounded headless contract", req.Tool)
	}
	bin, err := driveBinaryFor(req.Tool)
	if err != nil {
		return driveResult{}, fmt.Errorf("arena.driveHarness: %w", err)
	}
	return executeDrive(ctx, bin, ic.Headless, req)
}

func driveBinaryFor(tool string) (string, error) {
	if bin := driveBinOverrides[tool]; bin != "" {
		return bin, nil
	}
	return resolveToolBinary(tool)
}

// executeDrive builds argv from the HeadlessSpec, runs the binary inside
// the worktree with a whole-process-group kill on timeout, and extracts
// the final answer per Result kind. A non-zero harness exit is an
// outcome (recorded), not a Go error.
func executeDrive(ctx context.Context, bin string, spec *integration.HeadlessSpec, req driveRequest) (driveResult, error) {
	model, err := headlessModelFor(spec, req)
	if err != nil {
		return driveResult{}, fmt.Errorf("arena.executeDrive: %w", err)
	}
	args, sessionID, outPath := buildDriveArgv(spec, req, model)

	stdout, captured, res, err := spawnDrive(ctx, bin, args, spec, req)
	if err != nil {
		return driveResult{}, err
	}
	if captured {
		if extract, ok := driveResultExtractors[spec.Result]; ok {
			res.FinalAnswer, res.SessionIDs = extract(stdout, outPath, sessionID)
		}
	}
	return res, nil
}

// buildDriveArgv composes the harness argv from the HeadlessSpec plus this
// request's prompt/model/context files — one branch per capability the spec
// declares (session-id minting + skip-permissions for the stdout-JSON lane,
// workspace-write flags for the file-output lane, positional context files,
// the output-file flag). Returns the argv, the session id minted for a
// stdout-JSON lane (empty otherwise), and the output-file path for a lane
// that extracts its answer from a file (empty otherwise).
func buildDriveArgv(spec *integration.HeadlessSpec, req driveRequest, model string) (args []string, sessionID string, outPath string) {
	args = make([]string, 0, len(spec.Lead)+len(spec.OutputArgs)+8)
	args = append(args, spec.Lead...)

	switch spec.Result {
	case integration.HeadlessResultStdoutJSON:
		// claude-code lane: mint the correlation id up front — the tool
		// echoes it back as sessions.id verbatim, which is what binds
		// proxy api_turns to this candidate.
		sessionID = mintSessionID()
		args = append(args, "--session-id", sessionID)
		args = append(args, "--dangerously-skip-permissions")
	case integration.HeadlessResultOutputFile:
		args = append(args, "--skip-git-repo-check", "-s", "workspace-write")
		if req.WorktreePath != "" {
			args = append(args, "-C", req.WorktreePath)
		}
	}
	if spec.PromptFlag != "" {
		args = append(args, spec.PromptFlag, req.Prompt)
	} else {
		args = append(args, req.Prompt)
	}
	if model != "" {
		if flag := modelFlagFor(req.Tool); flag != "" {
			args = append(args, flag, model)
		}
	}
	args = append(args, spec.OutputArgs...)
	if spec.ContextMode == integration.HeadlessContextPositional {
		args = append(args, req.ContextFiles...)
	}

	if spec.Result == integration.HeadlessResultOutputFile {
		outPath = filepath.Join(req.WorktreePath, ".arena-last-message.txt")
		args = append(args, spec.ResultFlag, outPath)
	}
	return args, sessionID, outPath
}

// spawnDrive runs the harness binary to completion inside its own process
// group, killing the whole group on a context timeout, and returns the
// captured stdout+stderr bytes alongside the outcome (exit code / wall time
// / pid). captured reports whether the temp-file capture could be read back
// afterward; when false the caller must skip result extraction (mirrors the
// original inline behavior of silently skipping extraction on a read
// failure rather than failing the drive). A non-nil error means the harness
// never produced an outcome at all (setup, start, or attribution failure) —
// distinct from a non-zero harness exit, which is folded into the returned
// driveResult instead.
func spawnDrive(ctx context.Context, bin string, args []string, spec *integration.HeadlessSpec, req driveRequest) (stdout []byte, captured bool, res driveResult, err error) {
	dctx := ctx
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(dctx, bin, args...) //nolint:gosec // G204: operator-authored prompt/model + registry-grounded flags (local trust boundary)
	cmd.Dir = req.WorktreePath
	cmd.Stdin = nil // non-interactive
	env := os.Environ()
	if req.ProxyURL != "" {
		env = append(env, proxyEnvFor(req.Tool, req.ProxyURL)...)
	}
	if req.ConfigDir != "" && spec.Result == integration.HeadlessResultStdoutJSON {
		// claude-code lane only: isolated config dir + the CC-under-proxy
		// recovery flag carried over from the benchmark driver's
		// live-verified invocation.
		env = append(env, "CLAUDE_CONFIG_DIR="+req.ConfigDir, "ENABLE_TOOL_SEARCH=true")
	}
	cmd.Env = env
	setProcGroup(cmd)
	cmd.Cancel = func() error { return killProcGroup(cmd) }

	// File-backed output capture. Pipe buffers (bytes.Buffer) make
	// cmd.Run wait until EVERY writer closes the read end — a harness that
	// spawns a background grandchild (a hook, an MCP server, a daemonizer)
	// inherits the pipe and wedges the drive until its deadline even
	// though the harness itself exited long ago (live: headless-20260823-01,
	// grok timed out at 600s while the binary finished in ~15s). With an
	// *os.File, Wait returns at direct-child exit; we read the file after.
	tmpOut, terr := os.CreateTemp("", "sbo-drive-out-*")
	if terr != nil {
		return nil, false, driveResult{}, fmt.Errorf("arena.executeDrive: %w", terr)
	}
	tmpName := tmpOut.Name()
	defer func() {
		tmpOut.Close()
		os.Remove(tmpName)
	}()
	cmd.Stdout = tmpOut
	cmd.Stderr = tmpOut

	if req.Admission != nil {
		if admissionErr := req.Admission(dctx, req.Tool, req.ProxyURL); admissionErr != nil {
			return nil, false, driveResult{}, fmt.Errorf("arena.executeDrive: admission: %w", admissionErr)
		}
	}
	start := time.Now()
	runErr := cmd.Start()
	if runErr != nil {
		return nil, false, driveResult{}, fmt.Errorf("arena.executeDrive: start: %w", runErr)
	}
	pid := cmd.Process.Pid
	if req.OnStart != nil {
		if attErr := req.OnStart(pid); attErr != nil {
			_ = killProcGroup(cmd)
			_ = cmd.Wait()
			return nil, false, driveResult{}, fmt.Errorf("arena.executeDrive: process attribution: %w", attErr)
		}
	}
	if req.OnExit != nil {
		defer req.OnExit(pid)
	}
	runErr = cmd.Wait()
	wallMS := time.Since(start).Milliseconds()

	res = driveResult{WallMS: wallMS, PID: pid}
	if runErr != nil {
		if errors.Is(dctx.Err(), context.DeadlineExceeded) || ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			res.TimedOut = true
			_ = killProcGroup(cmd)
		}
		res.ExitCode = exitCodeOf(runErr)
	}

	stdout, rerr := os.ReadFile(tmpName)
	return stdout, rerr == nil, res, nil
}

// driveResultExtractors maps a HeadlessSpec's Result kind to the parser that
// pulls the final answer + session ids out of a drive's captured stdout (and,
// for the file-output lane, the sidecar output file). Table-driven so a new
// result kind is one row here, not another branch inside executeDrive.
var driveResultExtractors = map[integration.HeadlessResultKind]func(stdout []byte, outPath, sessionID string) (answer string, sessionIDs []string){
	integration.HeadlessResultStdoutJSON:     extractStdoutJSON,
	integration.HeadlessResultOutputFile:     extractOutputFile,
	integration.HeadlessResultGrokJSON:       extractGrokJSON,
	integration.HeadlessResultOpenCodeEvents: extractOpenCodeEvents,
	integration.HeadlessResultStdoutText:     extractStdoutText,
}

// extractStdoutJSON pulls the final answer out of claude print-mode JSON and
// pairs it with the session id minted before the drive started.
func extractStdoutJSON(stdout []byte, _ string, sessionID string) (string, []string) {
	answer, _ := parseClaudeResult(stdout)
	var sessionIDs []string
	if sessionID != "" {
		sessionIDs = []string{sessionID}
	}
	return stripANSI(answer), sessionIDs
}

// extractOutputFile pulls thread ids out of codex's --json stdout and the
// final answer out of the sidecar file the harness was told to write to.
func extractOutputFile(stdout []byte, outPath, _ string) (string, []string) {
	sessionIDs := parseCodexThreadIDs(stdout)
	answer := ""
	if b, err := os.ReadFile(outPath); err == nil {
		answer = stripANSI(string(b))
	}
	return answer, sessionIDs
}

// extractGrokJSON pulls the final answer + session id out of grok's
// `--output-format json` envelope.
func extractGrokJSON(stdout []byte, _ string, _ string) (string, []string) {
	answer, sid, ok := parseGrokResult(stdout)
	if !ok {
		return "", nil
	}
	var sessionIDs []string
	if sid != "" {
		sessionIDs = []string{sid}
	}
	return stripANSI(answer), sessionIDs
}

// extractOpenCodeEvents pulls the last text part + distinct session ids out
// of opencode's NDJSON event stream.
func extractOpenCodeEvents(stdout []byte, _ string, _ string) (string, []string) {
	answer, sessionIDs := parseOpenCodeEvents(stdout)
	if answer != "" {
		answer = stripANSI(answer)
	}
	return answer, sessionIDs
}

// extractStdoutText treats the harness's entire captured stdout as the
// answer — for tools with no structured result channel (aider).
func extractStdoutText(stdout []byte, _ string, _ string) (string, []string) {
	return stripANSI(string(stdout)), nil
}

// headlessModelFor resolves the candidate model for a direct or proxy-routed
// headless drive. A provider-scoped route fails closed: an empty selection gets
// the registry-grounded routed default, while an explicitly incompatible
// provider is rejected before the harness starts or spends.
func headlessModelFor(spec *integration.HeadlessSpec, req driveRequest) (string, error) {
	model := strings.TrimSpace(req.Model)
	if req.ProxyURL == "" || spec.ProxyModelPrefix == "" {
		return model, nil
	}
	if model == "" {
		model = spec.ProxyDefaultModel
	}
	if model == "" || !strings.HasPrefix(model, spec.ProxyModelPrefix) {
		return "", fmt.Errorf("model %q cannot use the routed proxy lane; expected prefix %q", model, spec.ProxyModelPrefix)
	}
	return model, nil
}

// parseGrokResult extracts the final answer + session id from grok's
// `--output-format json` envelope (single JSON object keyed text /
// sessionId / usage / total_cost_usd; live-verified 2026-08-22).
func parseGrokResult(out []byte) (answer, sessionID string, ok bool) {
	var doc struct {
		Text      string `json:"text"`
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &doc); err != nil || doc.Text == "" {
		return "", "", false
	}
	return doc.Text, doc.SessionID, true
}

// parseOpenCodeEvents walks opencode run --format json's NDJSON event
// stream (step_start / text / step_finish, each carrying sessionID) and
// returns the LAST text part plus the distinct session ids seen
// (live-verified 2026-08-22).
func parseOpenCodeEvents(out []byte) (answer string, sessionIDs []string) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	seen := map[string]bool{}
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev struct {
			SessionID string `json:"sessionID"`
			Part      struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"part"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		if ev.SessionID != "" && !seen[ev.SessionID] {
			seen[ev.SessionID] = true
			sessionIDs = append(sessionIDs, ev.SessionID)
		}
		if ev.Part.Type == "text" && ev.Part.Text != "" {
			answer = ev.Part.Text
		}
	}
	return answer, sessionIDs
}

// proxyEnvFor returns the base-url env a tool needs to route through the
// observer proxy, mirroring the promoted launcher routes. Codex rides its
// config.toml route (already written by init on routed machines), so no env
// addition applies. The remaining grounded arena tools use launch-local env
// routes so candidates cannot silently bypass api_turn capture.
func proxyEnvFor(tool, proxyURL string) []string {
	base := strings.TrimRight(proxyURL, "/")
	switch tool {
	case "claude-code":
		return []string{"ANTHROPIC_BASE_URL=" + base}
	case "grok":
		return []string{"GROK_CLI_CHAT_PROXY_BASE_URL=" + base + "/up/grok/v1"}
	case "opencode":
		// OpenCode's named OpenRouter provider has no base-URL env knob. Its
		// documented inline-config overlay is process-local and merges with
		// disk config, so route only this candidate through Observer's named
		// OpenRouter lane without rewriting operator-owned configuration.
		config := fmt.Sprintf(`{"provider":{"openrouter":{"options":{"baseURL":%q}}}}`, base+"/up/openrouter/api/v1")
		return []string{"OPENCODE_CONFIG_CONTENT=" + config}
	case "aider":
		return []string{"OPENAI_API_BASE=" + base + "/v1"}
	default:
		return nil
	}
}

// modelFlagFor resolves the model delivery flag through the registry's
// ModelSpec (arg-kind only; env-kind tools get their model via the env
// lane which the launcher family already covers).
func modelFlagFor(tool string) string {
	ic, ok := integration.For(tool)
	if !ok || ic.Model.Kind != integration.ModelArg {
		return ""
	}
	if ic.Model.Flag != "" {
		return ic.Model.Flag
	}
	return "--model"
}

// resolveToolBinary locates the real tool binary via the registry ladder,
// then falls back to PATH. Kept separate from toolresolve internals so
// the arena package depends only on the registry surface.
func resolveToolBinary(tool string) (string, error) {
	ic, ok := integration.For(tool)
	if !ok || ic.Binary == nil || len(ic.Binary.Names.Unix) == 0 {
		return "", fmt.Errorf("tool %q has no grounded binary resolution", tool)
	}
	var lastErr error
	for _, name := range ic.Binary.Names.Unix {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		} else {
			lastErr = err
		}
	}
	return "", fmt.Errorf("binary for %q not found on PATH: %w", tool, lastErr)
}

// claudeResultDoc is the shape of `claude -p --output-format json` output
// (mirrors the benchmark driver's parser).
type claudeResultDoc struct {
	Type      string `json:"type"`
	Result    string `json:"result"`
	SessionID string `json:"session_id"`
	IsError   bool   `json:"is_error"`
}

// parseClaudeResult extracts the final answer from claude print-mode JSON;
// the line scan is the safety net for interleaved stderr in the merged
// stream.
func parseClaudeResult(out []byte) (string, bool) {
	var doc claudeResultDoc
	if json.Unmarshal(out, &doc) == nil && (doc.Type == "result" || doc.Result != "") {
		return doc.Result, true
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	var last string
	found := false
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

// parseCodexThreadIDs extracts thread_id values from codex --json stdout
// (the first {"type":"thread.started","thread_id":…} line is emitted even
// on failed turns). Primary id first, deduped.
func parseCodexThreadIDs(stdout []byte) []string {
	var ids []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var ev struct {
			Type     string `json:"type"`
			ThreadID string `json:"thread_id"`
		}
		if json.Unmarshal(line, &ev) != nil {
			continue
		}
		if ev.ThreadID != "" && !seen[ev.ThreadID] {
			seen[ev.ThreadID] = true
			ids = append(ids, ev.ThreadID)
		}
	}
	return ids
}

func exitCodeOf(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

// stripANSI removes ANSI escape sequences so judge prompts and stored
// excerpts see clean text.
func stripANSI(s string) string {
	return stripANSIRe.ReplaceAllString(s, "")
}
