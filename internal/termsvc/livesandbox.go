package termsvc

import (
	"context"
	"sort"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// livesandbox.go lists and ends the live sandboxed runs (sandbox plan v2
// section 5.5, ledger SBX-UPD-1). A daemon restart, an update apply or a
// module deactivation asks before it ends one of these runs; the question
// shows this list, and the "end them" answer goes through EndLiveSandboxed,
// which records why each run ended before its terminal is closed.

// LiveSandboxedRun is one live run launched through the Sandboxer seam, as
// the live-run question shows it.
type LiveSandboxedRun struct {
	// RunID is the durable run identity (terminal_run.run_id).
	RunID string
	// Handle is the run's PTY handle.
	Handle string
	// Tool is the run's tool id.
	Tool string
	// Backend is the outermost isolation backend id the run was built on
	// (its isolation class when the stack is empty).
	Backend string
	// StartedAt is when the run was registered.
	StartedAt time.Time
	// NativeResume reports whether the tool continues its conversation by
	// its own resume after the run ends (the registry's resume capability).
	NativeResume bool
}

// LiveSandboxedRuns lists the live sandboxed runs, oldest first (ties by run
// id), so the question and the count agree: len(LiveSandboxedRuns()) ==
// LiveSandboxedCount() under the same lock state.
func (s *Service) LiveSandboxedRuns() []LiveSandboxedRun {
	s.mu.Lock()
	out := make([]LiveSandboxedRun, 0)
	for handle, m := range s.byMeta {
		if !m.sandboxed || !m.endedAt.IsZero() {
			continue
		}
		out = append(out, LiveSandboxedRun{
			RunID:     s.byHandle[handle],
			Handle:    handle,
			Tool:      m.Tool,
			Backend:   backendOf(m.isolation.Class, m.isolation.Stack),
			StartedAt: m.startedAt,
		})
	}
	s.mu.Unlock()
	for i := range out {
		if c, ok := integration.For(out[i].Tool); ok && c.Resume.Kind == integration.ResumeNative {
			out[i].NativeResume = true
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].StartedAt.Equal(out[j].StartedAt) {
			return out[i].StartedAt.Before(out[j].StartedAt)
		}
		return out[i].RunID < out[j].RunID
	})
	return out
}

// backendOf names a run's backend: the outermost layer of its stack, else
// its isolation class.
func backendOf(class string, stack []string) string {
	if len(stack) > 0 && stack[0] != "" {
		return stack[0]
	}
	return class
}

// EndLiveSandboxed ends every live sandboxed run: for each one it records
// reason on the stored run through stamp (before the terminal closes, so the
// natural exit that follows keeps it), then calls closeRun with the run's
// handle and notice (the terminal's last line). It returns the run ids it
// ended. A stamp error is reported through onStampErr and the run is still
// ended: the owner chose to end it. A nil closeRun ends nothing.
func (s *Service) EndLiveSandboxed(ctx context.Context, reason, notice string,
	stamp func(ctx context.Context, runID, reason string) error,
	closeRun func(handle, notice string),
	onStampErr func(runID string, err error),
) []string {
	if closeRun == nil {
		return nil
	}
	var ended []string
	for _, r := range s.LiveSandboxedRuns() {
		if stamp != nil && reason != "" && r.RunID != "" {
			if err := stamp(ctx, r.RunID, reason); err != nil && onStampErr != nil {
				onStampErr(r.RunID, err)
			}
		}
		s.MarkEnding(r.Handle, reason)
		closeRun(r.Handle, notice)
		ended = append(ended, r.RunID)
	}
	return ended
}
