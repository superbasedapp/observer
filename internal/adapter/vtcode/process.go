package vtcode

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// pidFromSessionID returns the OS pid VT Code embeds at the end of a
// `session-<label>-<UTC ts>_<n>-<pid>` id, or 0 for any other shape
// (`auto-task-<unix secs>` carries none).
//
// Grounded live 2026-10-21: on every hook-probed WSL session the hook's
// `$PPID` (the `sh` VT Code spawns per hook) was a few above the id's
// trailing number (343634 → 343685, 347179 → 347235, 390421 → 390463),
// i.e. the trailing number is the vtcode process that spawned it.
func pidFromSessionID(id string) int {
	if !strings.HasPrefix(strings.ToLower(id), sessionPrefix) {
		return 0
	}
	us := strings.LastIndexByte(id, '_')
	if us < 0 {
		return 0
	}
	n, pid, ok := strings.Cut(id[us+1:], "-")
	if !ok || n == "" || !allDigits(n) || !allDigits(pid) {
		return 0
	}
	v, err := strconv.Atoi(pid)
	if err != nil || v <= 1 {
		return 0
	}
	return v
}

// allDigits reports whether s is a non-empty ASCII digit run.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isForeignOSPath reports whether path reaches another OS's filesystem
// through a cross-mount (a Windows drive under /mnt/<x>/ read by a Linux
// process, a `\\wsl.localhost\` / `\\wsl$\` share read by a Windows one).
// A pid recorded by a process of that other OS is meaningless here.
func isForeignOSPath(path string) bool {
	if runtime.GOOS == "windows" {
		return wslUNCPrefix(path) != ""
	}
	slash := filepath.ToSlash(path)
	if !strings.HasPrefix(slash, "/mnt/") || len(slash) < 7 {
		return false
	}
	drive := slash[5]
	return ((drive >= 'a' && drive <= 'z') || (drive >= 'A' && drive <= 'Z')) && slash[6] == '/'
}

// processSeeds returns the (pid → session) attribution candidate for a
// LIVE session: the pid embedded in the session id, only when the session
// manifest does not say "completed" and the event log is on this OS's own
// filesystem. The store still validates liveness and that the process is
// vtcode (ExecHint) before writing the bridge row.
func processSeeds(sessionID, eventsPath, cwd, manifestStatus string) []models.SessionProcessSeed {
	pid := pidFromSessionID(sessionID)
	if pid == 0 || strings.EqualFold(strings.TrimSpace(manifestStatus), "completed") || isForeignOSPath(eventsPath) {
		return nil
	}
	return []models.SessionProcessSeed{{
		PID:       pid,
		SessionID: sessionID,
		Tool:      models.ToolVTCode,
		CWD:       cwd,
		ExecHint:  "vtcode",
	}}
}

// terminalFirstLineLimit bounds the events.jsonl prefix read to confirm a
// session's thread id.
const terminalFirstLineLimit = 64 << 10

// ResolveTerminalSession implements adapter.TerminalSessionResolver.
//
// A live VT Code process holds files inside its own session directory
// (`<workspace>/.vtcode/sessions/<id>/events.jsonl`, `session.lock`).
// Ownership evidence, per candidate file:
//
//   - a `session-*` id must embed THIS process's pid (`..._<n>-<pid>`),
//     so a process that merely has another session's file open (a resume
//     reads an old log) is never bound to it;
//   - an `auto-task-*` id embeds no pid, so it needs the process to hold
//     that session's events.jsonl open for append + write;
//   - when the event log is readable, its first record must be
//     thread.started naming the same id.
//
// Two different candidate ids → ambiguous → no identity.
func (a *Adapter) ResolveTerminalSession(ctx context.Context, process adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	if process.PID <= 1 {
		return adapter.TerminalSessionIdentity{}, nil
	}
	var found adapter.TerminalSessionIdentity
	for _, file := range process.Files {
		if err := ctx.Err(); err != nil {
			return adapter.TerminalSessionIdentity{}, err
		}
		id, ok := terminalCandidate(file, process.PID)
		if !ok {
			continue
		}
		candidate := adapter.TerminalSessionIdentity{
			SessionID: id,
			Evidence:  filepath.Clean(filepath.Join(filepath.Dir(file.Path), eventsFileName)),
		}
		if found.SessionID != "" && found.SessionID != candidate.SessionID {
			return adapter.TerminalSessionIdentity{}, nil
		}
		found = candidate
	}
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	return found, nil
}

// terminalCandidate checks one held file and returns the session id it
// proves ownership of.
func terminalCandidate(file adapter.TerminalSessionFile, pid int) (string, bool) {
	base := strings.ToLower(filepath.Base(file.Path))
	if base != eventsFileName && base != "session.lock" {
		return "", false
	}
	eventsPath := filepath.Join(filepath.Dir(file.Path), eventsFileName)
	if !isEventsShape(eventsPath) {
		return "", false
	}
	id := sessionIDFromEventsPath(eventsPath)
	switch {
	case pidFromSessionID(id) == pid:
	case strings.HasPrefix(strings.ToLower(id), autoTaskPrefix) && base == eventsFileName && file.Append && file.Writable:
	default:
		return "", false
	}
	readPath := eventsPath
	if base == eventsFileName && file.ReadPath != "" {
		readPath = file.ReadPath
	}
	if tid, ok := firstThreadID(readPath); ok && tid != id {
		return "", false
	}
	return id, true
}

// firstThreadID reads the bounded first record of an event log and returns
// thread.started's thread_id. ok is false when the log is unreadable or
// does not open with thread.started (no evidence either way).
func firstThreadID(path string) (string, bool) {
	f, err := os.Open(path) //nolint:gosec // a session dir the validated process holds
	if err != nil {
		return "", false
	}
	defer f.Close()
	line, err := bufio.NewReaderSize(f, terminalFirstLineLimit).ReadSlice('\n')
	if err != nil {
		return "", false
	}
	var env envelope
	if json.Unmarshal(line, &env) != nil || env.Event.Type != "thread.started" || env.Event.ThreadID == "" {
		return "", false
	}
	return env.Event.ThreadID, true
}

var _ adapter.TerminalSessionResolver = (*Adapter)(nil)
