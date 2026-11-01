package cortexcode

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// The vendor log (`<data home>/logs/coco.log`) is the only on-disk place
// that ties a session to the process that ran it, the build it ran on
// and the client that launched it. Each line is one JSON object with
// EXACTLY the keys ts, level, logger, session_id, request_id, pid, msg and
// terminal_launcher_source (the v1.2.18 bundle's logger field allow-list,
// confirmed on 3,261 live lines across both OSes 2026-10-21).
//
// Privacy: `msg` is free text and can carry prompt excerpts ("Initial
// message: ...", "Print query: ...", image extraction notices). The
// reader therefore decodes `msg` ONLY for the four logger/prefix pairs in
// logMsgRules and keeps only a derived token (a run boundary, a version
// directory name, a boolean); no message text is retained, stored or
// emitted. Operator ruling 2026-10-21 allows reading vendor logs under
// exactly that discipline.
const (
	logDir  = "logs"
	logFile = "coco.log"
	// maxLogTail bounds the bytes read from the END of coco.log. The
	// vendor rotates at 100 MiB (bundle `maxBytes:100*1024*1024`); 32 MiB
	// covers roughly a month of the live grounding rate.
	maxLogTail = 32 << 20
	// maxLogLine skips a pathological line instead of buffering it.
	maxLogLine = 1 << 20
	// execHint is the identity guard a pid seed must match: the vendor
	// binary is `cortex` (Linux ELF) / `cortex.exe` (Windows).
	execHint = "cortex"
)

// logRun is one process run in coco.log: the lines one pid wrote after
// its `=== Cortex Code logging initialized ===` boundary.
type logRun struct {
	pid      int
	start    string   // ts of the run's first line (evidence key)
	sessions []string // session ids in first-seen order
	version  string   // build directory version, build metadata stripped
	launcher string   // last non-empty terminal_launcher_source
	acp      bool     // a coco.acp.* logger wrote in this run
	desktop  bool     // "Desktop sidecar mode: true"
	exited   bool     // "Starting app exit cleanup" seen
}

func (r *logRun) addSession(id string) {
	for _, s := range r.sessions {
		if s == id {
			return
		}
	}
	r.sessions = append(r.sessions, id)
}

// logIndex is the parsed tail of one coco.log.
type logIndex struct {
	runs []*logRun
	// bySession lists the run indexes each session appears in,
	// chronological.
	bySession map[string][]int
}

// logLine is the decoded subset of one line; msg stays raw until a rule
// asks for it.
type logLine struct {
	TS       string          `json:"ts"`
	Logger   string          `json:"logger"`
	Session  string          `json:"session_id"`
	PID      int             `json:"pid"`
	Msg      json.RawMessage `json:"msg"`
	Launcher string          `json:"terminal_launcher_source"`
}

// logMsgRule is one (logger, msg prefix) pair whose msg is decoded, and
// what it contributes to the run. Walked top-down; the first match wins.
type logMsgRule struct {
	logger string
	prefix string
	apply  func(r *logRun, rest string)
}

// logMsgRules is the closed allow-list of messages the reader looks at.
// The run boundary is handled before these rules (it opens a new run).
var logMsgRules = []logMsgRule{
	{"coco.utils.bundle", "Found bundled resource at:", func(r *logRun, rest string) {
		if r.version == "" {
			r.version = versionFromInstallPath(rest)
		}
	}},
	{"coco.main", "Desktop sidecar mode:", func(r *logRun, rest string) {
		r.desktop = strings.EqualFold(strings.TrimSpace(rest), "true")
	}},
	{"coco.app-exit-manager", "Starting app exit cleanup", func(r *logRun, _ string) {
		r.exited = true
	}},
}

const (
	runBoundaryLogger = "coco.init"
	runBoundaryPrefix = "=== Cortex Code logging initialized"
	acpLoggerPrefix   = "coco.acp."
)

// installDirVersion matches a versioned install directory name
// (`1.2.18+192728.aa2238062732`).
var installDirVersion = regexp.MustCompile(`^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?:\+[0-9A-Za-z.-]+)?$`)

// versionFromInstallPath returns the version of the install directory a
// bundle path sits in (`...\cortex\<version>\bundled_skills`): the path
// segment right after a `cortex` segment that is version-shaped, with the
// build metadata dropped so it reads like `cortex --version` (`v1.2.18`
// prints as 1.2.18).
func versionFromInstallPath(p string) string {
	segs := strings.FieldsFunc(strings.TrimSpace(p), func(r rune) bool { return r == '/' || r == '\\' })
	for i := 1; i < len(segs); i++ {
		if !strings.EqualFold(segs[i-1], "cortex") {
			continue
		}
		if m := installDirVersion.FindStringSubmatch(segs[i]); m != nil {
			return m[1]
		}
	}
	return ""
}

// parseLog builds the index from a coco.log reader positioned at a line
// start (or mid-line when skipFirst).
func parseLog(r io.Reader, skipFirst bool) *logIndex {
	idx := &logIndex{bySession: map[string][]int{}}
	current := map[int]int{} // pid -> index of its open run
	br := bufio.NewReaderSize(r, 64*1024)
	first := true
	for {
		line, err := readBoundedLine(br)
		if first && skipFirst {
			first = false
			if err != nil {
				break
			}
			continue
		}
		first = false
		if len(line) > 0 {
			idx.addLine(line, current)
		}
		if err != nil {
			break
		}
	}
	return idx
}

// readBoundedLine returns the next line without its terminator; a line
// longer than maxLogLine is returned empty (skipped) after being drained.
func readBoundedLine(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > maxLogLine {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if tooLong {
			return nil, err
		}
		return bytes.TrimRight(buf, "\r\n"), err
	}
}

func (idx *logIndex) addLine(raw []byte, current map[int]int) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return // the pre-JSON plain-text log format carries no keys
	}
	var ln logLine
	if json.Unmarshal(raw, &ln) != nil || ln.PID <= 0 {
		return
	}
	boundary := ln.Logger == runBoundaryLogger && strings.HasPrefix(decodeMsg(ln.Msg), runBoundaryPrefix)
	ri, open := current[ln.PID]
	if boundary || !open {
		idx.runs = append(idx.runs, &logRun{pid: ln.PID, start: ln.TS})
		ri = len(idx.runs) - 1
		current[ln.PID] = ri
	}
	run := idx.runs[ri]
	if l := strings.ToLower(strings.TrimSpace(ln.Launcher)); l != "" {
		run.launcher = l
	}
	if strings.HasPrefix(ln.Logger, acpLoggerPrefix) {
		run.acp = true
	}
	if !boundary {
		for _, rule := range logMsgRules {
			if ln.Logger != rule.logger {
				continue
			}
			if msg := decodeMsg(ln.Msg); strings.HasPrefix(msg, rule.prefix) {
				rule.apply(run, strings.TrimPrefix(msg, rule.prefix))
				break
			}
		}
	}
	if id := strings.TrimSpace(ln.Session); validStem(id) && !strings.ContainsAny(id, `/\`) {
		before := len(run.sessions)
		run.addSession(id)
		if len(run.sessions) != before {
			idx.bySession[id] = append(idx.bySession[id], ri)
		}
	}
}

// decodeMsg decodes a raw JSON string msg; anything else is "".
func decodeMsg(raw json.RawMessage) string {
	var s string
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// cachedLog is one memoized index, valid while the file's size and
// mtime are unchanged.
type cachedLog struct {
	size  int64
	mtime time.Time
	idx   *logIndex
}

// logCache memoizes parsed coco.log tails per path; every parse of every
// session of a data home shares one read.
type logCache struct {
	mu      sync.Mutex
	entries map[string]cachedLog
}

// index returns the parsed tail of the log at path, or nil when absent.
func (c *logCache) index(path string) *logIndex {
	if c == nil {
		return nil // zero-value Adapter: no log stamps, never a panic
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[path]; ok && e.size == st.Size() && e.mtime.Equal(st.ModTime()) {
		return e.idx
	}
	f, err := os.Open(path) //nolint:gosec // the vendor log beside a watched conversations dir
	if err != nil {
		return nil
	}
	defer f.Close()
	skip := false
	if st.Size() > maxLogTail {
		if _, err := f.Seek(st.Size()-maxLogTail, io.SeekStart); err != nil {
			return nil
		}
		skip = true
	}
	idx := parseLog(io.LimitReader(f, maxLogTail), skip)
	if c.entries == nil {
		c.entries = map[string]cachedLog{}
	}
	c.entries[path] = cachedLog{size: st.Size(), mtime: st.ModTime(), idx: idx}
	return idx
}

// dataHomeOf returns the cortex data home a store file sits in
// (`<data home>/conversations/<file>`).
func dataHomeOf(storePath string) string {
	return filepath.Dir(filepath.Dir(filepath.FromSlash(strings.ReplaceAll(storePath, `\`, "/"))))
}

// logPathFor returns the coco.log path of a data home.
func logPathFor(dataHome string) string {
	return filepath.Join(dataHome, logDir, logFile)
}

// surfaceRule maps a run's launcher evidence to a surface. Walked
// top-down; the first match wins. Values are the bundle's closed
// launcher-source set (`["sandbox","desktop","vscode","cli"]`, default
// "cli"); ACP mode is recognised by its own coco.acp.* loggers (an ACP
// client whose name contains "vscode" flips the source to vscode).
// `sandbox` (a Snowflake-hosted sandbox run) has no grounded surface and
// is left unstamped.
var surfaceRules = []struct {
	match   func(r *logRun) bool
	surface string
	host    string
}{
	{func(r *logRun) bool { return r.acp && r.launcher == "vscode" }, models.SurfaceIDE, "vscode"},
	{func(r *logRun) bool { return r.acp }, models.SurfaceIDE, ""},
	{func(r *logRun) bool { return r.desktop || r.launcher == "desktop" }, models.SurfaceDesktop, ""},
	{func(r *logRun) bool { return r.launcher == "vscode" }, models.SurfaceIDE, "vscode"},
	{func(r *logRun) bool { return r.launcher == "cli" }, models.SurfaceCLI, ""},
}

// surfaceOf classifies a run, ok=false when no rule matches.
func surfaceOf(r *logRun) (models.SessionSurface, bool) {
	for _, rule := range surfaceRules {
		if rule.match(r) {
			return models.SessionSurface{Surface: rule.surface, SurfaceHost: rule.host}, true
		}
	}
	return models.SessionSurface{}, false
}

// stampFromLog adds the session's surface, tool version(s) and live
// process seed to res, from the data home's coco.log, falling back to the
// install-level version (cortex-version.txt) when the log names none.
func (a *Adapter) stampFromLog(res *adapter.ParseResult, storePath, sessID, cwd string) {
	dataHome := dataHomeOf(storePath)
	logPath := logPathFor(dataHome)
	idx := a.logs.index(logPath)
	var runs []*logRun
	if idx != nil {
		for _, ri := range idx.bySession[sessID] {
			runs = append(runs, idx.runs[ri])
		}
	}
	// Versions in run order: the store keeps the FIRST as the origin
	// build and moves tool_version_last forward on a later, higher one.
	seenVer := map[string]bool{}
	for _, r := range runs {
		if r.version != "" && !seenVer[r.version] {
			seenVer[r.version] = true
			res.SessionToolVersions = append(res.SessionToolVersions, models.SessionToolVersion{SessionID: sessID, Version: r.version})
		}
	}
	if len(res.SessionToolVersions) == 0 {
		if v := installVersion(dataHome); v != "" {
			res.SessionToolVersions = append(res.SessionToolVersions, models.SessionToolVersion{SessionID: sessID, Version: v})
		}
	}
	for _, r := range runs {
		if s, ok := surfaceOf(r); ok {
			s.SessionID = sessID
			res.SessionSurfaces = append(res.SessionSurfaces, s)
			break
		}
	}
	if len(runs) == 0 || isForeignMountPath(logPath) {
		return // a foreign-OS pid is meaningless on this host
	}
	if !historyExists(storePath) {
		// A metadata-only session never got a message: the run died on
		// sign-in or was killed before the first prompt (live, Windows
		// 2026-10-22: four such runs, none with an exit line). There is
		// nothing for the pid to attribute, and the pid is likely dead
		// and recyclable, so no seed.
		return
	}
	if last := runs[len(runs)-1]; !last.exited && last.pid > 1 {
		res.SessionProcessSeeds = append(res.SessionProcessSeeds, models.SessionProcessSeed{
			PID:       last.pid,
			SessionID: sessID,
			Tool:      models.ToolCortexCode,
			CWD:       strings.TrimSpace(cwd),
			ExecHint:  execHint,
		})
	}
}

// installRoots are the per-home install directories of the official
// install scripts: install.sh (Linux; `~/.local/bin/cortex` symlinks into
// it) and install.ps1 (Windows; `bin\cortex.cmd` launches it). macOS is
// not grounded.
var installRoots = []string{
	filepath.Join(".local", "share", "cortex"),
	filepath.Join("AppData", "Local", "cortex"),
}

// installVersion returns the highest installed version under the home
// that owns dataHome (`<home>/.snowflake/cortex`), read from each
// `<install root>/<version dir>/cortex-version.txt`. It is the CURRENT
// install, an install-level fallback (operator ruling 2026-10-21) used
// only when the log names no per-run build. "" when the data home is not
// in its default place or nothing is installed.
func installVersion(dataHome string) string {
	if !strings.EqualFold(filepath.Base(dataHome), "cortex") || !strings.EqualFold(filepath.Base(filepath.Dir(dataHome)), ".snowflake") {
		return ""
	}
	home := filepath.Dir(filepath.Dir(dataHome))
	best := ""
	for _, rel := range installRoots {
		dir := filepath.Join(home, rel)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			v := readVersionFile(filepath.Join(dir, e.Name(), "cortex-version.txt"))
			if v != "" && (best == "" || compareVersions(v, best) > 0) {
				best = v
			}
		}
	}
	return best
}

// readVersionFile reads a bounded cortex-version.txt and returns its
// version with build metadata dropped, or "".
func readVersionFile(p string) string {
	f, err := os.Open(p) //nolint:gosec // vendor install-dir version file
	if err != nil {
		return ""
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, 128))
	if err != nil {
		return ""
	}
	if m := installDirVersion.FindStringSubmatch(strings.TrimSpace(string(buf))); m != nil {
		return m[1]
	}
	return ""
}

// compareVersions orders MAJOR.MINOR.PATCH numerically (pre-release
// suffixes compare as text after the numbers).
func compareVersions(a, b string) int {
	na, ra := splitVersion(a)
	nb, rb := splitVersion(b)
	for i := 0; i < 3; i++ {
		if na[i] != nb[i] {
			if na[i] < nb[i] {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(ra, rb)
}

func splitVersion(v string) ([3]int, string) {
	var n [3]int
	core, rest, _ := strings.Cut(v, "-")
	for i, p := range strings.SplitN(core, ".", 3) {
		n[i], _ = strconv.Atoi(p)
	}
	return n, rest
}

// allHomesFunc is the cross-mount home source; tests swap it.
var allHomesFunc = crossmount.AllHomes

// isForeignMountPath reports whether path lies under a cross-mount
// (foreign-OS) home, where a pid names a process on another OS.
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" || h.Path == "" {
			continue
		}
		if crossmount.PathUnder(h.Path, path) {
			return true
		}
	}
	return false
}
