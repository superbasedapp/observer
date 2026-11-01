package dirac

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// Vendor-log constants (operator ruling 2026-10-21: logs the tool writes
// locally may be read for pid / version / surface; credential stores may
// not). `<data>/logs/dirac-cli.log` is a pino log, one record per line,
// each line prefixed by an ISO timestamp:
//
//	2026-10-21T06:14:51.188Z {"level":30,"time":"…","pid":17376,
//	  "hostname":"…","channel":"Dirac CLI","msg":"…"}
//
// Only four message shapes are read, each through a fixed regexp, and
// only the captured token is kept (a task id, a pid, a 64-hex install
// id, a package directory) — never a message body, a prompt, a command
// or a hostname.
const (
	logDirName  = "logs"
	logFileName = "dirac-cli.log"
	// logScanBytes caps the read: the TAIL of the log (a long-lived
	// install's early lines are stale; Dirac prunes the file itself).
	logScanBytes = 4 << 20
	// pkgScanBytes caps the package.json read.
	pkgScanBytes = 64 * 1024
	// pkgName is the npm package whose version is the install-level tool
	// version fallback.
	pkgName = "dirac-cli"
)

var (
	// reTask matches `[Task <id>]`, the prefix of every task-scoped line
	// (task ids are Unix-millisecond numbers, the session id).
	reTask = regexp.MustCompile(`\[Task (\d{6,})\]`)
	// reDistinct matches the per-install telemetry id Dirac logs at
	// startup (`LOG [DistinctId] initialized: <64 hex>`): a hashed device
	// id, identical to the `userId` of every hook payload.
	reDistinct = regexp.MustCompile(`\[DistinctId\] initialized: ([0-9a-f]{32,128})\b`)
	// reExtDir matches the startup banner's package directory
	// (`Dirac CLI initialized. Data dir: …, Extension dir: <dir>, Log dir: …`).
	reExtDir = regexp.MustCompile(`Extension dir: (.+?), Log dir:`)
)

// logSnapshot is what one pass over the log yields, keyed by the owning
// OS process id (every pino record carries the writer's pid).
type logSnapshot struct {
	// taskPID is the LAST pid seen on a `[Task <id>]` line: the process
	// that most recently worked the task (a `--taskId` resume runs in a
	// new process).
	taskPID map[string]int
	// pidDistinct / pidExtDir / pidChannel are the per-process startup
	// facts: the hashed install id, the package directory and the log
	// channel name.
	pidDistinct map[int]string
	pidExtDir   map[int]string
	pidChannel  map[int]string
}

func newLogSnapshot() *logSnapshot {
	return &logSnapshot{
		taskPID:     map[string]int{},
		pidDistinct: map[int]string{},
		pidExtDir:   map[int]string{},
		pidChannel:  map[int]string{},
	}
}

// pidFor returns the process that worked the task (0 = none logged).
func (s *logSnapshot) pidFor(taskID string) int {
	if s == nil {
		return 0
	}
	return s.taskPID[taskID]
}

// accountFor returns the hashed device/install id of the task's process.
func (s *logSnapshot) accountFor(taskID string) string {
	if pid := s.pidFor(taskID); pid > 0 {
		return s.pidDistinct[pid]
	}
	return ""
}

// channelFor returns the log channel ("Dirac CLI") of the task's process.
func (s *logSnapshot) channelFor(taskID string) string {
	if pid := s.pidFor(taskID); pid > 0 {
		return s.pidChannel[pid]
	}
	return ""
}

// versionFor returns the installed package version of the task's process
// (the install-level fallback when the task has no environment record).
func (s *logSnapshot) versionFor(taskID string) string {
	pid := s.pidFor(taskID)
	if pid <= 0 {
		return ""
	}
	dir := s.pidExtDir[pid]
	if dir == "" {
		return ""
	}
	return packageVersion(dir)
}

// packageVersion reads `<dir>/package.json` and returns its version when
// the package is dirac-cli. A directory named by a log line is only ever
// asked for that one file; a symlink or an oversize file is refused.
func packageVersion(dir string) string {
	dir = crossmount.TranslateForeignPath(dir)
	body, ok := readCapped(filepath.Join(dir, "package.json"), pkgScanBytes)
	if !ok {
		return ""
	}
	var p struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(body, &p) != nil || p.Name != pkgName {
		return ""
	}
	return strings.TrimSpace(p.Version)
}

// logIndex caches one parsed log per data dir, keyed by (size, mtime) so
// an unchanged log is read once, not once per parse.
type logIndex struct {
	mu      sync.Mutex
	entries map[string]logCacheEntry
}

type logCacheEntry struct {
	size  int64
	mtime int64
	snap  *logSnapshot
}

// snapshot returns the parsed log of dataDir (nil when absent).
func (l *logIndex) snapshot(dataDir string) *logSnapshot {
	path := filepath.Join(dataDir, logDirName, logFileName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.entries == nil {
		l.entries = map[string]logCacheEntry{}
	}
	if c, ok := l.entries[path]; ok && c.size == info.Size() && c.mtime == info.ModTime().UnixNano() {
		return c.snap
	}
	snap := scanLog(path, info.Size())
	l.entries[path] = logCacheEntry{size: info.Size(), mtime: info.ModTime().UnixNano(), snap: snap}
	return snap
}

// scanLog reads the tail of the log and extracts the four fact shapes.
func scanLog(path string, size int64) *logSnapshot {
	f, err := os.Open(path) //nolint:gosec // regular file under the watched data dir; symlink refused by the caller
	if err != nil {
		return nil
	}
	defer f.Close()
	skipFirst := false
	if size > logScanBytes {
		if _, err := f.Seek(size-logScanBytes, io.SeekStart); err != nil {
			return nil
		}
		skipFirst = true // we landed mid-line
	}
	snap := newLogSnapshot()
	r := bufio.NewReaderSize(f, 64*1024)
	for {
		line, err := r.ReadString('\n')
		if skipFirst {
			skipFirst = false
		} else if line != "" {
			snap.scanLine(strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			break
		}
	}
	return snap
}

// logRecord is the pino envelope subset read.
type logRecord struct {
	PID     int    `json:"pid"`
	Channel string `json:"channel"`
	Msg     string `json:"msg"`
}

// scanLine folds one log line into the snapshot.
func (s *logSnapshot) scanLine(line string) {
	// Cheap pre-filter before any JSON decode.
	if !strings.Contains(line, "[Task ") && !strings.Contains(line, "[DistinctId]") &&
		!strings.Contains(line, "Extension dir:") {
		return
	}
	i := strings.IndexByte(line, '{')
	if i < 0 {
		return
	}
	var rec logRecord
	if json.Unmarshal([]byte(line[i:]), &rec) != nil || rec.PID <= 0 {
		return
	}
	if m := reTask.FindStringSubmatch(rec.Msg); m != nil {
		s.taskPID[m[1]] = rec.PID
		if rec.Channel != "" {
			s.pidChannel[rec.PID] = rec.Channel
		}
		return
	}
	if m := reDistinct.FindStringSubmatch(rec.Msg); m != nil {
		s.pidDistinct[rec.PID] = m[1]
		if rec.Channel != "" {
			s.pidChannel[rec.PID] = rec.Channel
		}
		return
	}
	if m := reExtDir.FindStringSubmatch(rec.Msg); m != nil {
		s.pidExtDir[rec.PID] = m[1]
		if rec.Channel != "" {
			s.pidChannel[rec.PID] = rec.Channel
		}
	}
}

// channelSurfaces maps the log channel name onto the surface vocabulary
// (the log twin of surfaceByHostName, used only when a task has no
// environment record). "Dirac CLI" is grounded on disk (both OSes).
var channelSurfaces = map[string]surfaceRow{
	"dirac cli": {kind: models.SurfaceCLI, host: "dirac-cli"},
}

// pidSeed builds the (OS pid -> session) seed for a task from its log
// lines. ok is false when no pid was logged. A pid read from a
// foreign-mount log is a pid of the OTHER OS (a Windows pid is
// meaningless on a WSL daemon's /proc), so the caller skips those.
func pidSeed(sessionID string, pid int, cwd string) (models.SessionProcessSeed, bool) {
	if pid <= 1 || sessionID == "" {
		return models.SessionProcessSeed{}, false
	}
	return models.SessionProcessSeed{
		PID:       pid,
		SessionID: sessionID,
		Tool:      models.ToolDirac,
		CWD:       cwd,
		ExecHint:  "dirac",
	}, true
}

// isForeignMountPath reports whether path lies under a cross-mounted
// foreign-OS home (the clinecli precedent: /mnt/c/... seen by a WSL
// daemon). Both separators are accepted.
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" {
			continue
		}
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}
