package codebuddy

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// terminalFreshness bounds how stale the owning process's last log line may
// be for the log to count as evidence about a still-running process: a pid
// that has been silent for longer may have been recycled.
const terminalFreshness = 15 * time.Minute

// ResolveTerminalSession implements adapter.TerminalSessionResolver. A
// CodeBuddy CLI process prefixes every line of its diagnostic log with its
// own pid and names its session on session-scoped lines (logs.go), so a
// validated primary process whose pid started a CLI run in a log and logged
// exactly one session since resolves to that session. The same abstention
// rules as the other resolvers apply: only data homes of the running OS are
// consulted (a pid is meaningless across a WSL / Windows boundary), the
// process's start line must be in the log (it proves the pid is a CodeBuddy
// CLI process the log saw start), its last log line must be recent, the
// session's transcript must exist under a watch root, and two sessions
// claiming the pid is an abstention (an interactive process that switched
// session with /clear or --resume).
//
// Grounding: the pid / session join and the start line are live (hook probe,
// 2026-10-21, headless runs on Windows and WSL). No INTERACTIVE session was
// available, so the idle-logging cadence behind terminalFreshness is
// unverified; a process quiet past the window abstains rather than guesses.
func (a *Adapter) ResolveTerminalSession(ctx context.Context, process adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	if process.PID <= 1 {
		return adapter.TerminalSessionIdentity{}, nil
	}
	now := time.Now()
	var found adapter.TerminalSessionIdentity
	var claimed string
	for _, root := range a.WatchPaths() {
		if err := ctx.Err(); err != nil {
			return adapter.TerminalSessionIdentity{}, err
		}
		if !strings.EqualFold(filepath.Base(filepath.Clean(root)), "projects") {
			continue
		}
		home := filepath.Dir(filepath.Clean(root))
		if !ownsHome(home) {
			continue
		}
		for _, s := range sessionsOfPID(home, process.PID, now, now.Add(-24*time.Hour)) {
			if s.LastSeen.IsZero() || now.Sub(s.LastSeen) > terminalFreshness || s.LastSeen.After(now.Add(time.Minute)) {
				continue
			}
			// Ambiguity is judged BEFORE the transcript check: a second
			// session the pid logged makes the identity uncertain even when
			// its transcript is gone.
			if claimed != "" && claimed != s.SessionID {
				return adapter.TerminalSessionIdentity{}, nil
			}
			claimed = s.SessionID
			if _, ok := a.transcriptPath(s.SessionID, nil); !ok {
				continue
			}
			found = adapter.TerminalSessionIdentity{
				SessionID: s.SessionID,
				Evidence:  filepath.Clean(s.Path) + "#pid=" + strconv.Itoa(process.PID) + "#" + s.SessionID,
			}
		}
	}
	return found, ctx.Err()
}

var _ adapter.TerminalSessionResolver = (*Adapter)(nil)
