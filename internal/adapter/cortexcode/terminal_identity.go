package cortexcode

import (
	"context"
	"path/filepath"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// ResolveTerminalSession implements adapter.TerminalSessionResolver from
// the vendor's own process log. Cortex holds no per-session lock or pid
// sidecar; the one native record tying a live process to its session is
// coco.log, where every line the process writes carries its `pid` and the
// current `session_id`, and a run opens with a `logging initialized`
// boundary (so a recycled pid starts a NEW run rather than inheriting an
// old one's session).
//
// The resolver abstains (empty identity) unless all of these hold for the
// pid's LATEST run in a native (not cross-mounted) data home:
//
//   - the run has not logged its exit cleanup;
//   - exactly ONE session id logged by the run has a metadata file in the
//     conversations directory, and that session is not a subagent (the
//     first-run onboarding mints a hook-only id with no file, which is
//     ignored; a `/new` or resume inside one process leaves two files and
//     is ambiguous);
//   - no second data home resolves the pid to a different session.
//
// Evidence is the log path plus the pid and the run's first timestamp, so
// a new run of the same pid changes it.
func (a *Adapter) ResolveTerminalSession(ctx context.Context, process adapter.TerminalProcess) (adapter.TerminalSessionIdentity, error) {
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	if process.PID <= 1 {
		return adapter.TerminalSessionIdentity{}, nil
	}
	var found adapter.TerminalSessionIdentity
	for _, root := range a.roots {
		if err := ctx.Err(); err != nil {
			return adapter.TerminalSessionIdentity{}, err
		}
		dataHome := filepath.Dir(filepath.Clean(root))
		logPath := logPathFor(dataHome)
		if isForeignMountPath(logPath) {
			continue
		}
		idx := a.logs.index(logPath)
		if idx == nil {
			continue
		}
		var run *logRun
		for i := len(idx.runs) - 1; i >= 0; i-- {
			if idx.runs[i].pid == process.PID {
				run = idx.runs[i]
				break
			}
		}
		if run == nil {
			continue
		}
		if run.exited {
			return adapter.TerminalSessionIdentity{}, nil
		}
		sessID := ""
		for _, id := range run.sessions {
			meta, _, ok := readMeta(filepath.Join(root, id+metaSuffix))
			if !ok || meta.SessionType == "subagent" {
				continue
			}
			if sessID != "" {
				return adapter.TerminalSessionIdentity{}, nil // ambiguous
			}
			sessID = id
		}
		if sessID == "" {
			continue
		}
		identity := adapter.TerminalSessionIdentity{
			SessionID: sessID,
			Evidence:  logPath + "#pid=" + strconv.Itoa(run.pid) + "@" + run.start,
		}
		if found.SessionID != "" && found.SessionID != identity.SessionID {
			return adapter.TerminalSessionIdentity{}, nil
		}
		if found.SessionID == "" {
			found = identity
		}
	}
	if err := ctx.Err(); err != nil {
		return adapter.TerminalSessionIdentity{}, err
	}
	return found, nil
}
