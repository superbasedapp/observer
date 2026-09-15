package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// allowlistedBackfillModes is every mode the dashboard's Run-Now button
// is allowed to invoke, mapped to the observer argv tail it execs
// (--config is appended by the handler). The set mirrors the modes
// surfaced on /api/backfill/status — file-walking + SQL-checkable +
// the registry-derived per-adapter scan lane added by init() below.
// Locked down to prevent shell injection or arbitrary mode strings
// landing in `os/exec`. "all" is the umbrella that runs every backfill.
var allowlistedBackfillModes = map[string][]string{
	"all":                      {"backfill", "--all"},
	"is-sidechain":             {"backfill", "--is-sidechain"},
	"cache-tier":               {"backfill", "--cache-tier"},
	"message-id":               {"backfill", "--message-id"},
	"opencode-message-id":      {"backfill", "--opencode-message-id"},
	"opencode-parts":           {"backfill", "--opencode-parts"},
	"opencode-tokens":          {"backfill", "--opencode-tokens"},
	"openclaw-action-types":    {"backfill", "--openclaw-action-types"},
	"openclaw-model":           {"backfill", "--openclaw-model"},
	"openclaw-reasoning":       {"backfill", "--openclaw-reasoning"},
	"codex-reasoning":          {"backfill", "--codex-reasoning"},
	"cursor-model":             {"backfill", "--cursor-model"},
	"copilot-message-id":       {"backfill", "--copilot-message-id"},
	"pi-message-id":            {"backfill", "--pi-message-id"},
	"claudecode-user-prompts":  {"backfill", "--claudecode-user-prompts"},
	"claudecode-api-errors":    {"backfill", "--claudecode-api-errors"},
	"cowork-rescan":            {"backfill", "--cowork-rescan"},
	"cowork-project-root":      {"backfill", "--cowork-project-root"},
	"codex-rescan":             {"backfill", "--codex-rescan"},
	"antigravity":              {"backfill", "--antigravity-rescan"},
	"antigravity-project-root": {"backfill", "--antigravity-project-root"},
	"gemini-cli":               {"backfill", "--gemini-cli-rescan"},
	"copilot-cli":              {"backfill", "--copilot-cli-rescan"},
	"hermes-rescan":            {"backfill", "--hermes-rescan"},
	"clinecli-rescan":          {"backfill", "--clinecli-rescan"},
	"cache-rescan":             {"backfill", "--cache-rescan"},
	"zed-rescan":               {"backfill", "--zed-rescan"},
	"openclaw-project-root":    {"backfill", "--openclaw-project-root"},
	"openclaw-session-id":      {"backfill", "--openclaw-session-id"},
	"codex-project-root":       {"backfill", "--codex-project-root"},
	"claudecode-project-root":  {"backfill", "--claudecode-project-root"},
	"cursor-user-prompts":      {"backfill", "--cursor-user-prompts"},
	"cursor-subagents":         {"backfill", "--cursor-subagents"},
	"tasks":                    {"backfill", "--tasks"},
}

// init derives one `scan-<tool>` mode per integration-registry adapter,
// backed by the generic `observer scan --force --adapter <tool>` lane
// (the 2026-07-09 adapter-wave backfill decision: generic path, no
// per-tool backfill flags). Registry-derived so a future adapter's
// Settings → Backfill row appears automatically instead of trailing a
// hand-maintained list — the drift this panel has had before (P1.1).
// The dedicated `*-rescan` modes above remain the surgical lanes.
func init() {
	for _, c := range integration.Capabilities() {
		allowlistedBackfillModes["scan-"+c.Tool] = []string{"scan", "--force", "--adapter", c.Tool}
	}
}

// backfillJob is one in-flight or completed run kicked from the
// dashboard. Stored in Server.backfillJobs keyed by its Id; the
// registry is in-memory, so a daemon restart drops history.
type backfillJob struct {
	ID        string    `json:"id"`
	Mode      string    `json:"mode"`
	Status    string    `json:"status"` // running | done | failed
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitempty"`
	ExitCode  int       `json:"exit_code,omitempty"`
	Output    string    `json:"output"` // captured stdout+stderr
	Error     string    `json:"error,omitempty"`
	// OutFile is the artifact path for jobs that write a file (guard
	// evidence exports, G2.3) — the download endpoint serves it once
	// the job completes. Empty for output-only jobs.
	OutFile string `json:"out_file,omitempty"`
	// seq is a registry-local creation counter. The jobs list sorts on
	// it (newest first) instead of StartedAt: two jobs created within
	// the same clock tick (coarse Windows timer) have EQUAL timestamps,
	// which made the order ambiguous — the documented
	// TestBackfillJobsList ordering flake. Not serialized; creation
	// order is an internal detail.
	seq int64
}

// backfillExecFn spawns an observer subprocess. Args are the FULL
// argument vector after the binary (subcommand first — "backfill",
// "prune", …) passed verbatim to os/exec; callers sanitize via their
// allowlists. onChunk is invoked whenever a chunk of stdout/stderr
// becomes available so the caller can stream output into the job
// registry; it may be called zero times (e.g. silent successful run)
// or many. Returns the exit code + any process-level error after the
// child terminates. Tests inject a fake.
type backfillExecFn func(ctx context.Context, args []string, onChunk func([]byte)) (int, error)

// realExecBackfill resolves the running observer binary via
// os.Executable() and invokes `<binary> <args...>`. The child
// inherits the parent's env so OBSERVER_* overrides + $HOME are
// preserved.
//
// Streaming: stdout and stderr are piped (rather than CombinedOutput's
// all-at-once buffering) so onChunk can deliver chunks as they're
// produced. The dashboard poll endpoint then surfaces incremental
// progress — long-running file-walk backfills feel responsive rather
// than appearing dead until completion.
func realExecBackfill(ctx context.Context, args []string, onChunk func([]byte)) (int, error) {
	binary, err := osExecutable()
	if err != nil {
		return 0, fmt.Errorf("locate observer binary: %w", err)
	}
	cmd := exec.CommandContext(ctx, binary, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return 0, fmt.Errorf("stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start: %w", err)
	}

	// Drain both pipes concurrently. 4 KiB read buffer is small enough
	// to surface progress promptly but big enough not to syscall on
	// every line. onChunk is single-threaded across stdout+stderr via
	// a tiny mutex so chunks land in the order they arrive without
	// interleaving across pipes.
	var pipeMu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(r interface{ Read([]byte) (int, error) }) {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, readErr := r.Read(buf)
			if n > 0 && onChunk != nil {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				pipeMu.Lock()
				onChunk(chunk)
				pipeMu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}
	go pipe(stdout)
	go pipe(stderr)
	wg.Wait()

	runErr := cmd.Wait()
	exit := 0
	if cmd.ProcessState != nil {
		exit = cmd.ProcessState.ExitCode()
	}
	return exit, runErr
}

// osExecutable is a var so tests can override. Default delegates to
// os.Executable via osExecutableImpl.
var osExecutable = osExecutableImpl

// handleBackfillRun spawns a subprocess to run `observer backfill
// --<mode>` with the dashboard's resolved config path. Returns the
// generated job id immediately; the caller polls /api/backfill/jobs/<id>
// until status flips off "running".
//
// The job goroutine uses context.Background() so it survives the
// originating HTTP request — important for long-running file-walk
// modes the user kicked from the UI then closed the tab.
func (s *Server) handleBackfillRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	argv, ok := allowlistedBackfillModes[req.Mode]
	if !ok {
		http.Error(w, "unknown mode "+req.Mode+" — see /api/backfill/status for valid values",
			http.StatusBadRequest)
		return
	}

	jobID, err := newJobID()
	if err != nil {
		writeErr(w, fmt.Errorf("generate job id: %w", err))
		return
	}
	job := &backfillJob{
		ID:        jobID,
		Mode:      req.Mode,
		Status:    "running",
		StartedAt: time.Now().UTC(),
	}
	s.backfillMu.Lock()
	s.backfillSeq++
	job.seq = s.backfillSeq
	s.backfillJobs[jobID] = job
	s.backfillMu.Unlock()

	args := append([]string{}, argv...)
	if s.opts.ConfigPath != "" {
		args = append(args, "--config", s.opts.ConfigPath)
	}

	go s.runBackfillJob(jobID, args)

	writeJSON(w, map[string]any{
		"job_id":     jobID,
		"mode":       req.Mode,
		"status":     "running",
		"started_at": job.StartedAt.Format(time.RFC3339),
	})
}

// handlePruneRun spawns `observer prune` — the on-demand retention
// sweep (usability arc P1.10). Reuses the backfill job registry +
// streaming runner wholesale: the job appears in /api/backfill/jobs
// with mode "prune" and is polled the same way. No request body —
// prune takes its thresholds from [observer.retention] config.
func (s *Server) handlePruneRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	jobID, err := newJobID()
	if err != nil {
		writeErr(w, fmt.Errorf("generate job id: %w", err))
		return
	}
	job := &backfillJob{
		ID:        jobID,
		Mode:      "prune",
		Status:    "running",
		StartedAt: time.Now().UTC(),
	}
	s.backfillMu.Lock()
	s.backfillSeq++
	job.seq = s.backfillSeq
	s.backfillJobs[jobID] = job
	s.backfillMu.Unlock()

	args := []string{"prune"}
	if s.opts.ConfigPath != "" {
		args = append(args, "--config", s.opts.ConfigPath)
	}
	go s.runBackfillJob(jobID, args)

	writeJSON(w, map[string]any{
		"job_id":     jobID,
		"mode":       "prune",
		"status":     "running",
		"started_at": job.StartedAt.Format(time.RFC3339),
	})
}

// handleScanRun spawns `observer scan --force [--adapter <name>]` —
// the full re-walk recovery path (usability arc P4.13 / review row
// E2). Reuses the backfill job registry + streaming runner, mode
// "scan" / "scan:<adapter>". The adapter value is validated against
// the injected tool catalog (the same allow-list discipline as
// backfill modes — nothing user-typed reaches os/exec argv).
func (s *Server) handleScanRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Adapter string `json:"adapter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Adapter != "" {
		known := false
		for _, entry := range s.opts.ToolCatalog {
			if entry.Tool == req.Adapter {
				known = true
				break
			}
		}
		if !known {
			http.Error(w, "unknown adapter "+req.Adapter+" — see /api/tools/status for valid names",
				http.StatusBadRequest)
			return
		}
	}

	jobID, err := newJobID()
	if err != nil {
		writeErr(w, fmt.Errorf("generate job id: %w", err))
		return
	}
	mode := "scan"
	if req.Adapter != "" {
		mode = "scan:" + req.Adapter
	}
	job := &backfillJob{
		ID:        jobID,
		Mode:      mode,
		Status:    "running",
		StartedAt: time.Now().UTC(),
	}
	s.backfillMu.Lock()
	s.backfillSeq++
	job.seq = s.backfillSeq
	s.backfillJobs[jobID] = job
	s.backfillMu.Unlock()

	args := []string{"scan", "--force"}
	if req.Adapter != "" {
		args = append(args, "--adapter", req.Adapter)
	}
	if s.opts.ConfigPath != "" {
		args = append(args, "--config", s.opts.ConfigPath)
	}
	go s.runBackfillJob(jobID, args)

	writeJSON(w, map[string]any{
		"job_id":     jobID,
		"mode":       mode,
		"status":     "running",
		"started_at": job.StartedAt.Format(time.RFC3339),
	})
}

// backfillJobTimeout caps wall-clock for a single dashboard-kicked
// backfill subprocess. Set high enough that `--all` (full Rescan from
// offset 0 + every surgical backfill in sequence) completes on a
// many-year action history without the dashboard hard-killing it
// mid-run. Originally 30m; bumped to 2h after a v1.4.49-era `--all`
// got killed at 30m on a ~67k-action DB. Surgical individual modes
// finish in single-digit minutes, so the cap mostly bites only on
// `--all` against heavy installs.
const backfillJobTimeout = 2 * time.Hour

func (s *Server) runBackfillJob(id string, args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), backfillJobTimeout)
	defer cancel()

	// onChunk appends to job.Output under the registry mutex so
	// concurrent /api/backfill/jobs/<id> polls see partial output as
	// it accumulates. Cap the buffer at 1 MiB to keep memory bounded
	// — pathological backfills that print megabytes of debug get
	// truncated with a one-line note.
	const outputCap = 1 << 20 // 1 MiB
	onChunk := func(chunk []byte) {
		s.backfillMu.Lock()
		defer s.backfillMu.Unlock()
		job, ok := s.backfillJobs[id]
		if !ok {
			return
		}
		// Truncated already? Skip; once capped, ignore further chunks
		// so the truncation marker stays at the bottom.
		if len(job.Output) >= outputCap {
			return
		}
		room := outputCap - len(job.Output)
		if len(chunk) > room {
			job.Output += string(chunk[:room]) + "\n…(output truncated at 1 MiB)…\n"
		} else {
			job.Output += string(chunk)
		}
	}

	exit, err := s.execBackfill(ctx, args, onChunk)

	s.backfillMu.Lock()
	defer s.backfillMu.Unlock()
	job, ok := s.backfillJobs[id]
	if !ok {
		return
	}
	job.EndedAt = time.Now().UTC()
	job.ExitCode = exit
	if err != nil {
		job.Status = "failed"
		job.Error = err.Error()
		return
	}
	if exit != 0 {
		job.Status = "failed"
		job.Error = fmt.Sprintf("backfill exited with code %d", exit)
		return
	}
	job.Status = "done"
}

// handleBackfillJobsList serves GET /api/backfill/jobs — every job in
// the registry, sorted newest started_at first. The dashboard's
// BackfillSection calls this on mount to restore in-flight + recent
// state after the user navigated away and back; without it, the
// component's local jobs map starts empty on every remount and the
// "running" indicator disappears even though the subprocess is still
// alive in the observer.
//
// The registry is process-local (in-memory map), so a daemon restart
// drops history. That's acceptable — restarting the observer also kills
// any in-flight backfill subprocesses (they were spawned with this
// process as parent), so an empty list post-restart correctly reflects
// "nothing is running anymore."
func (s *Server) handleBackfillJobsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	s.backfillMu.Lock()
	snaps := make([]backfillJob, 0, len(s.backfillJobs))
	for _, j := range s.backfillJobs {
		snaps = append(snaps, *j)
	}
	s.backfillMu.Unlock()
	// Newest first so the frontend can collapse to one-job-per-mode by
	// keeping the first occurrence per mode (mirrors its UI model:
	// each mode has one current job). Sorted on the creation sequence,
	// not StartedAt — equal timestamps under a coarse clock made the
	// order ambiguous (the old TestBackfillJobsList flake).
	sort.Slice(snaps, func(i, j int) bool {
		return snaps[i].seq > snaps[j].seq
	})
	writeJSON(w, map[string]any{"jobs": snaps})
}

// handleBackfillJob serves GET /api/backfill/jobs/<id>. Returns a
// snapshot of the job, including partial output as it accumulates —
// realExecBackfill pipes stdout / stderr concurrently and onChunk
// appends to job.Output under the registry mutex, so polling this
// endpoint while a job is running surfaces live progress (drives the
// dashboard's BackfillTrackerDialog).
func (s *Server) handleBackfillJob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/backfill/jobs/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "job id required", http.StatusBadRequest)
		return
	}
	s.backfillMu.Lock()
	job, ok := s.backfillJobs[id]
	if !ok {
		s.backfillMu.Unlock()
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	// Snapshot under the lock so the caller doesn't see a partially-mutated
	// job (the goroutine writes to it atomically under the same mutex).
	snap := *job
	s.backfillMu.Unlock()
	writeJSON(w, snap)
}

func newJobID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
