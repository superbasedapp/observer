package codebuddy

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CodeBuddy's own diagnostic log (`<data home>/logs/<YYYY-MM-DD>/<workspace>__<hash>.log`,
// one file per workspace per local day, shared by every CLI process that ran
// in that workspace) is the only on-disk place that records three facts the
// transcript omits. Grounded 2026-10-21 (v2.171.0, Windows + WSL):
//
//   - the CLI VERSION and PROCESS ID, once per process start:
//     `[pid=22612] [CliDispatcher]  [ColdStart] cli onStart pid=22612 version=2.171.0`
//     (the vendor reads `CLIENT_INFO_PRODUCT_VERSION`; a `CliDispatcher`
//     start is a terminal run, which is the surface discriminator);
//   - the pid↔session join: every line a process writes carries `[pid=N]`,
//     and session-scoped lines name the session (`sessionId=<id>`, a JSON
//     `"conversation_id":"<id>"`, `Session <id> model resolved: <m>`);
//   - the per-model-call GENERATION DURATION, a structured telemetry line
//     `{"event_name":"agent.model_call.completed","duration_ms":..,
//     "time_to_first_token_ms":..,"conversation_message_id":"<messageId>",
//     "result":"success",...}` whose conversation_message_id equals the
//     transcript's providerData.messageId.
//
// The log also carries prompt text, absolute paths and (post-login) auth
// notes, so the reader is a line FILTER: it extracts only the fields above,
// keeps nothing else, and never returns a line.
//
// Lines are `[dd/mm/yyyy, h:mm:ss pm.mmm] [Level] [pid=N] message` in the
// machine's local time. The timestamp format follows the installing
// machine's locale, so a timestamp that does not parse is treated as
// unknown (zero), never guessed: the version, pid and duration facts do not
// depend on it.

const (
	// maxLogLineBytes bounds one retained log line; a longer line (stack
	// traces) is truncated, which only loses fields the reader never uses.
	maxLogLineBytes = 64 << 10
	// maxLogFileBytes bounds how much of one log file is read.
	maxLogFileBytes = 192 << 20
	// maxLogFilesPerDay bounds the *.log files read per day directory.
	maxLogFilesPerDay = 64
	// maxLogIndexFiles bounds the in-memory cache of parsed logs.
	maxLogIndexFiles = 24
	// maxPIDsPerFile / maxSessionsPerFile / maxModelCallsPerFile bound the
	// per-file index so a hostile or huge log cannot balloon memory.
	maxPIDsPerFile       = 8192
	maxSessionsPerFile   = 32768
	maxModelCallsPerFile = 65536
	maxSessionsPerPID    = 64
)

// logPID is what one log file recorded about one process.
type logPID struct {
	version  string
	cli      bool
	coldAt   time.Time
	lastSeen time.Time
	sessions []string
}

// logSession is a session as seen from the process that logged it, captured
// when the session id was first logged by that process so a later reuse of
// the pid cannot rewrite it.
type logSession struct {
	pid      int
	version  string
	cli      bool
	lastSeen time.Time
}

// modelCall is one agent.model_call.completed telemetry line.
type modelCall struct {
	durationMs int64
	ttftMs     int64
}

// logIndex is the parsed, incrementally extended view of one log file.
type logIndex struct {
	size       int64
	modTime    time.Time
	offset     int64
	pids       map[int]*logPID
	sessions   map[string]*logSession
	modelCalls map[string]modelCall
}

func newLogIndex() *logIndex {
	return &logIndex{
		pids:       map[int]*logPID{},
		sessions:   map[string]*logSession{},
		modelCalls: map[string]modelCall{},
	}
}

// logCache caches parsed logs by absolute path. A CodeBuddy log is
// append-only, so a changed file is extended from the last complete line.
var logCache = struct {
	sync.Mutex
	m     map[string]*logIndex
	order []string
}{m: map[string]*logIndex{}}

// resetLogCache clears the cache (tests).
func resetLogCache() {
	logCache.Lock()
	defer logCache.Unlock()
	logCache.m = map[string]*logIndex{}
	logCache.order = nil
}

// loadLog returns the index of the log file, reading only what is new since
// the last call. A missing / unreadable file yields nil.
func loadLog(path string) *logIndex {
	logCache.Lock()
	defer logCache.Unlock()
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil
	}
	idx := logCache.m[path]
	if idx != nil && idx.size == info.Size() && idx.modTime.Equal(info.ModTime()) {
		return idx
	}
	if idx == nil || info.Size() < idx.offset {
		idx = newLogIndex()
		if _, seen := logCache.m[path]; !seen {
			logCache.order = append(logCache.order, path)
			if len(logCache.order) > maxLogIndexFiles {
				delete(logCache.m, logCache.order[0])
				logCache.order = logCache.order[1:]
			}
		}
		logCache.m[path] = idx
	}
	f, err := os.Open(path) //nolint:gosec // path is a CodeBuddy log under the adapter's data home
	if err != nil {
		return nil
	}
	defer f.Close()
	if _, err := f.Seek(idx.offset, io.SeekStart); err != nil {
		return nil
	}
	r := bufio.NewReaderSize(f, 256<<10)
	for idx.offset < maxLogFileBytes {
		line, n, terminated, rerr := readBoundedLine(r, maxLogLineBytes)
		if !terminated {
			// A partial trailing line is still being written: leave it for
			// the next pass.
			break
		}
		idx.offset += int64(n)
		idx.consume(line)
		if rerr != nil {
			break
		}
	}
	idx.size = info.Size()
	idx.modTime = info.ModTime()
	return idx
}

// readBoundedLine reads one line, retaining at most max bytes of it. n is
// the full byte length consumed (retained or not); terminated reports a
// trailing newline.
func readBoundedLine(r *bufio.Reader, max int) (line string, n int, terminated bool, err error) {
	var buf []byte
	for {
		chunk, e := r.ReadSlice('\n')
		n += len(chunk)
		if room := max - len(buf); room > 0 {
			if len(chunk) > room {
				chunk = chunk[:room]
			}
			buf = append(buf, chunk...)
		}
		if errors.Is(e, bufio.ErrBufferFull) {
			continue
		}
		return strings.TrimRight(string(buf), "\r\n"), n, e == nil, e
	}
}

// consume extracts the fields the adapter uses from one log line.
func (idx *logIndex) consume(line string) {
	p := strings.Index(line, "[pid=")
	if p < 0 {
		return
	}
	pid, ok := atoiPrefix(line[p+len("[pid="):])
	if !ok || pid <= 0 {
		return
	}
	ts := parseLogTime(line)
	info := idx.pids[pid]
	if info == nil {
		if len(idx.pids) >= maxPIDsPerFile {
			return
		}
		info = &logPID{}
		idx.pids[pid] = info
	}
	if !ts.IsZero() {
		info.lastSeen = ts
	}

	if i := strings.Index(line, "[ColdStart] cli onStart pid="); i >= 0 {
		// A (re)start of this pid: whatever the log said about an earlier
		// process that held the same pid no longer applies.
		*info = logPID{cli: true, coldAt: ts, lastSeen: ts}
		if j := strings.Index(line[i:], "version="); j >= 0 {
			info.version = versionToken(line[i+j+len("version="):])
		}
	}

	for _, marker := range []string{"sessionId=", `"conversation_id":"`} {
		if i := strings.Index(line, marker); i >= 0 {
			if sid := uuidPrefix(line[i+len(marker):]); sid != "" {
				idx.noteSession(pid, info, sid)
			}
		}
	}
	if i := strings.Index(line, "Session "); i >= 0 && strings.Contains(line, " model resolved") {
		if sid := uuidPrefix(line[i+len("Session "):]); sid != "" {
			idx.noteSession(pid, info, sid)
		}
	}

	if strings.Contains(line, `"event_name":"agent.model_call.completed"`) {
		idx.noteModelCall(line)
	}
}

func (idx *logIndex) noteSession(pid int, info *logPID, sid string) {
	cur := idx.sessions[sid]
	switch {
	case cur == nil:
		if len(idx.sessions) >= maxSessionsPerFile {
			return
		}
		idx.sessions[sid] = &logSession{pid: pid, version: info.version, cli: info.cli, lastSeen: info.lastSeen}
	case cur.pid == pid:
		cur.lastSeen = info.lastSeen
	default:
		// The session was resumed by another process: the latest wins.
		*cur = logSession{pid: pid, version: info.version, cli: info.cli, lastSeen: info.lastSeen}
	}
	for _, s := range info.sessions {
		if s == sid {
			return
		}
	}
	if len(info.sessions) < maxSessionsPerPID {
		info.sessions = append(info.sessions, sid)
	}
}

func (idx *logIndex) noteModelCall(line string) {
	start := strings.IndexByte(line, '{')
	if start < 0 {
		return
	}
	var ev struct {
		MessageID  string `json:"conversation_message_id"`
		Result     string `json:"result"`
		DurationMs int64  `json:"duration_ms"`
		TTFTMs     int64  `json:"time_to_first_token_ms"`
	}
	if json.Unmarshal([]byte(line[start:]), &ev) != nil {
		return
	}
	if ev.MessageID == "" || ev.Result != "success" || ev.DurationMs <= 0 {
		return
	}
	if _, ok := idx.modelCalls[ev.MessageID]; !ok && len(idx.modelCalls) >= maxModelCallsPerFile {
		return
	}
	// A retried call logs one line per attempt; the last success wins.
	idx.modelCalls[ev.MessageID] = modelCall{durationMs: ev.DurationMs, ttftMs: ev.TTFTMs}
}

// atoiPrefix parses the leading decimal digits of s.
func atoiPrefix(s string) (int, bool) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 || end > 9 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:end])
	return n, err == nil
}

// versionToken returns the leading semver-ish token of s.
func versionToken(s string) string {
	end := 0
	for end < len(s) {
		c := s[end]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '.' || c == '-' || c == '+' {
			end++
			continue
		}
		break
	}
	v := s[:end]
	if v == "" || v == "unknown" || v[0] < '0' || v[0] > '9' {
		return ""
	}
	return v
}

// uuidPrefix returns the 36-character dashed id at the start of s, else "".
func uuidPrefix(s string) string {
	if len(s) < 36 {
		return ""
	}
	id := s[:36]
	for i := 0; i < 36; i++ {
		c := id[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return ""
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return ""
			}
		}
	}
	return id
}

// parseLogTime parses the line's `[dd/mm/yyyy, h:mm:ss pm.mmm]` stamp in the
// local zone; zero when absent or not in that (locale-dependent) shape.
func parseLogTime(line string) time.Time {
	if len(line) < 3 || line[0] != '[' {
		return time.Time{}
	}
	end := strings.IndexByte(line, ']')
	if end < 0 || end > 48 {
		return time.Time{}
	}
	stamp := line[1:end]
	ms := 0
	if dot := strings.LastIndexByte(stamp, '.'); dot > 0 && len(stamp)-dot-1 == 3 {
		if v, err := strconv.Atoi(stamp[dot+1:]); err == nil {
			ms = v
			stamp = stamp[:dot]
		}
	}
	// "pm.965" puts the millis after the meridiem; after trimming them the
	// remainder is "21/10/2026, 5:36:44 pm".
	t, err := time.ParseInLocation("02/01/2006, 3:04:05 pm", strings.TrimSpace(stamp), time.Local)
	if err != nil {
		return time.Time{}
	}
	return t.Add(time.Duration(ms) * time.Millisecond)
}

// dataHome returns the CodeBuddy data home of a transcript path
// (`<home>/projects/<slug>/<id>.jsonl` -> `<home>`), "" when the path does
// not have that shape.
func dataHome(transcript string) string {
	slug := filepath.Dir(transcript)
	projects := filepath.Dir(slug)
	if !strings.EqualFold(filepath.Base(projects), "projects") {
		return ""
	}
	return filepath.Dir(projects)
}

// logDayDirs returns the existing `<home>/logs/<date>` directories a session
// active at the given times can have logged to (the local day of each time,
// plus the neighbouring day when a time sits near local midnight).
func logDayDirs(home string, times ...time.Time) []string {
	seen := map[string]bool{}
	var dirs []string
	add := func(t time.Time) {
		d := filepath.Join(home, "logs", t.In(time.Local).Format("2006-01-02"))
		if seen[d] {
			return
		}
		seen[d] = true
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			dirs = append(dirs, d)
		}
	}
	for _, t := range times {
		if t.IsZero() {
			continue
		}
		add(t)
		lt := t.In(time.Local)
		if lt.Hour() < 3 {
			add(t.Add(-24 * time.Hour))
		}
		if lt.Hour() >= 21 {
			add(t.Add(24 * time.Hour))
		}
	}
	sort.Strings(dirs)
	return dirs
}

// dayLogs lists the *.log files of one day directory (bounded, sorted).
func dayLogs(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
		if len(out) >= maxLogFilesPerDay {
			break
		}
	}
	sort.Strings(out)
	return out
}

// sessionLogFacts is everything the log says about one session.
type sessionLogFacts struct {
	// PID is the OS process id of the (latest) CLI process that logged the
	// session id, 0 when the session is not in any candidate log.
	PID int
	// Version is that process's CLI version, "" when its start line is not
	// in the log.
	Version string
	// CLI marks a process started through the terminal dispatcher.
	CLI bool
	// InstallVersion is the newest CLI version seen on any process start in
	// the candidate logs — the install-level fallback.
	InstallVersion string
	// ModelCalls maps providerData.messageId to the call's timing.
	ModelCalls map[string]modelCall
}

// lookupSessionLog gathers the facts the CodeBuddy logs hold for a session
// active at the given times. Safe to call with no logs present.
func lookupSessionLog(home, sessionID string, times ...time.Time) sessionLogFacts {
	facts := sessionLogFacts{ModelCalls: map[string]modelCall{}}
	if home == "" || sessionID == "" {
		return facts
	}
	var bestSeen time.Time
	var newestCold time.Time
	for _, dir := range logDayDirs(home, times...) {
		for _, path := range dayLogs(dir) {
			idx := loadLog(path)
			if idx == nil {
				continue
			}
			for _, info := range idx.pids {
				if info.version != "" && !info.coldAt.Before(newestCold) {
					newestCold = info.coldAt
					facts.InstallVersion = info.version
				}
			}
			for id, mc := range idx.modelCalls {
				facts.ModelCalls[id] = mc
			}
			ls := idx.sessions[sessionID]
			if ls == nil {
				continue
			}
			if facts.PID == 0 || !ls.lastSeen.Before(bestSeen) {
				bestSeen = ls.lastSeen
				facts.PID = ls.pid
				facts.Version = ls.version
				facts.CLI = ls.cli
			}
		}
	}
	return facts
}

// pidSession is a session a process logged.
type pidSession struct {
	SessionID string
	LastSeen  time.Time
	Path      string
}

// sessionsOfPID returns every session id the process logged after its most
// recent start in the candidate logs, plus the time of its last log line.
// Only a pid whose start line (and so whose identity as a CodeBuddy CLI
// process) is in the same log qualifies.
func sessionsOfPID(home string, pid int, times ...time.Time) []pidSession {
	var out []pidSession
	for _, dir := range logDayDirs(home, times...) {
		for _, path := range dayLogs(dir) {
			idx := loadLog(path)
			if idx == nil {
				continue
			}
			info := idx.pids[pid]
			if info == nil || !info.cli || info.coldAt.IsZero() {
				continue
			}
			for _, sid := range info.sessions {
				out = append(out, pidSession{SessionID: sid, LastSeen: info.lastSeen, Path: path})
			}
		}
	}
	return out
}
