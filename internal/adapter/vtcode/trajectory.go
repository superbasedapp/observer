package vtcode

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// trajectoryRecord is the subset of a `.vtcode/logs/trajectory*.jsonl`
// line the adapter reads. The trajectory is VT Code's per-workspace
// telemetry log (`[telemetry] trajectory_enabled`, rotated by
// trajectory_max_files / _max_size_mb / _max_age_days); it is NOT a
// session file. Its `prompt_cache_metrics` and `history_projection_metrics`
// records carry the (run_id, turn_id, model) of every LLM request — the
// only place the per-turn SERVED model is recorded (events.jsonl carries
// none, and the archive's metadata.model is the model at session START,
// stale after a `/model` switch).
//
// `prompt_cache_metrics` is written once per SUCCESSFUL request and also
// carries that request's usage (grounded live, both OSes, 0.180.2):
// input_tokens (== prompt_tokens, GROSS of the cached part),
// cache_read_tokens (== cached_prompt_tokens), cache_creation_tokens,
// completion_tokens, elapsed_ms (the request's wall time) and ts (Unix
// SECONDS). Summed over a turn they equal the turn's events.jsonl usage
// exactly (verified on every turn of the WSL and Windows fixtures).
type trajectoryRecord struct {
	Kind             string `json:"kind"`
	RunID            string `json:"run_id"`
	TurnID           string `json:"turn_id"`
	Provider         string `json:"provider"`
	Model            string `json:"model"`
	InputTokens      int64  `json:"input_tokens"`
	CacheReadTokens  int64  `json:"cache_read_tokens"`
	CacheWriteTokens int64  `json:"cache_creation_tokens"`
	CompletionTokens int64  `json:"completion_tokens"`
	ElapsedMs        int64  `json:"elapsed_ms"`
	TS               int64  `json:"ts"`
}

// requestKind is the record kind carrying one request's usage.
const requestKind = "prompt_cache_metrics"

// turnModelKinds ranks the trajectory record kinds that name a turn's
// model, most authoritative first: prompt_cache_metrics is written per
// SUCCESSFUL request (it carries the request's usage), while
// history_projection_metrics is written per attempted request.
var turnModelKinds = map[string]int{
	requestKind:                  2,
	"history_projection_metrics": 1,
}

// trajRequest is one successful LLM request of a turn.
type trajRequest struct {
	provider   string
	model      string
	input      int64 // gross prompt tokens (includes cacheRead)
	cacheRead  int64
	cacheWrite int64
	output     int64
	elapsedMs  int64
	ts         time.Time
}

// turnTraj is everything the trajectory says about one turn.
type turnTraj struct {
	model    string
	rank     int
	requests []trajRequest
}

// trajectoryCache memoizes per-file trajectory decodes keyed on the
// file's size + mtime, so the lookup costs one read per change of the
// trajectory, not one per events.jsonl tick.
type trajectoryCache struct {
	mu    sync.Mutex
	files map[string]trajectoryFile
}

// trajectoryFile is one cached trajectory file's decode:
// session id -> turn id -> turn data.
type trajectoryFile struct {
	size  int64
	mtime time.Time
	runs  map[string]map[string]*turnTraj
}

// turns returns turn id -> trajectory data for sessionID, merged across
// every `trajectory*.jsonl` in logsDir. Files are visited oldest-name-first
// (the live trajectory.jsonl last). The model: within a turn the
// highest-ranked record kind wins, and among equal ranks the LAST record
// in visit order (a mid-turn model change ends on the model that served
// the final request). Requests concatenate in visit order (a turn lives in
// one run, so in practice in one file). Missing or unreadable files
// contribute nothing.
func (c *trajectoryCache) turns(logsDir, sessionID string) map[string]*turnTraj {
	names, _ := filepath.Glob(filepath.Join(logsDir, "trajectory*.jsonl"))
	sort.Slice(names, func(i, j int) bool { return trajectoryOrder(names[i]) < trajectoryOrder(names[j]) })
	merged := map[string]*turnTraj{}
	for _, name := range names {
		for turn, tt := range c.load(name)[sessionID] {
			m := merged[turn]
			if m == nil {
				m = &turnTraj{}
				merged[turn] = m
			}
			if tt.model != "" && tt.rank >= m.rank {
				m.model, m.rank = tt.model, tt.rank
			}
			m.requests = append(m.requests, tt.requests...)
		}
	}
	return merged
}

// trajectoryOrder sorts rotated `trajectory-<ts>.jsonl` files by name and
// the live `trajectory.jsonl` after all of them.
func trajectoryOrder(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "trajectory.jsonl" {
		return "\xff"
	}
	return base
}

// load returns the decode of one trajectory file, re-reading it only when
// its size or mtime changed.
func (c *trajectoryCache) load(path string) map[string]map[string]*turnTraj {
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	c.mu.Lock()
	if c.files == nil {
		c.files = map[string]trajectoryFile{}
	}
	if f, ok := c.files[path]; ok && f.size == fi.Size() && f.mtime.Equal(fi.ModTime()) {
		c.mu.Unlock()
		return f.runs
	}
	c.mu.Unlock()

	runs := readTrajectory(path)
	c.mu.Lock()
	c.files[path] = trajectoryFile{size: fi.Size(), mtime: fi.ModTime(), runs: runs}
	c.mu.Unlock()
	return runs
}

// readTrajectory scans one trajectory file. Only lines that name a turn
// id are JSON-decoded (a cheap byte pre-filter skips the tool / budget /
// retry records). A trailing partial line is ignored.
func readTrajectory(path string) map[string]map[string]*turnTraj {
	f, err := os.Open(path) //nolint:gosec // sibling logs dir of a watched session
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]map[string]*turnTraj{}
	r := bufio.NewReaderSize(f, 64*1024)
	marker := []byte(`"turn_id"`)
	for {
		line, err := r.ReadBytes('\n')
		if err == nil && bytes.Contains(line, marker) {
			var rec trajectoryRecord
			if json.Unmarshal(bytes.TrimSpace(line), &rec) == nil {
				addTrajectoryRecord(out, &rec)
			}
		}
		if err != nil {
			break
		}
	}
	return out
}

// addTrajectoryRecord folds one decoded record into the run map.
func addTrajectoryRecord(out map[string]map[string]*turnTraj, rec *trajectoryRecord) {
	rank, ok := turnModelKinds[rec.Kind]
	if !ok || rec.RunID == "" || rec.TurnID == "" {
		return
	}
	turns := out[rec.RunID]
	if turns == nil {
		turns = map[string]*turnTraj{}
		out[rec.RunID] = turns
	}
	tt := turns[rec.TurnID]
	if tt == nil {
		tt = &turnTraj{}
		turns[rec.TurnID] = tt
	}
	model := strings.TrimSpace(rec.Model)
	if model != "" && rank >= tt.rank {
		tt.model, tt.rank = model, rank
	}
	if rec.Kind != requestKind {
		return
	}
	var ts time.Time
	if rec.TS > 0 {
		ts = time.Unix(rec.TS, 0).UTC()
	}
	tt.requests = append(tt.requests, trajRequest{
		provider:   strings.TrimSpace(rec.Provider),
		model:      model,
		input:      rec.InputTokens,
		cacheRead:  rec.CacheReadTokens,
		cacheWrite: rec.CacheWriteTokens,
		output:     rec.CompletionTokens,
		elapsedMs:  rec.ElapsedMs,
		ts:         ts,
	})
}

// coversTurn reports whether the requests sum EXACTLY to the turn's
// usage envelope — the proof that the trajectory saw every request of
// the turn (not rotated away, not still being written).
func coversTurn(reqs []trajRequest, u *usage) bool {
	if len(reqs) == 0 || u == nil {
		return false
	}
	var in, cr, cw, out int64
	for _, r := range reqs {
		in += r.input
		cr += r.cacheRead
		cw += r.cacheWrite
		out += r.output
	}
	return in == u.InputTokens && cr == u.CachedInputTokens && cw == u.CacheCreationTokens && out == u.OutputTokens
}

// genMs is the turn's generation duration: the sum of its requests'
// elapsed_ms (each request's own wall time; tool execution between
// requests is excluded). 0 when any request lacks a duration.
func genMs(reqs []trajRequest) int64 {
	var total int64
	for _, r := range reqs {
		if r.elapsedMs <= 0 {
			return 0
		}
		total += r.elapsedMs
	}
	return total
}
