//go:build !sbo_omit_terminals

package main

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/termsession"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// termsvcLiveRuns adapts the terminal service and its session manager to
// the live-run gate (sandbox_liveruns.go): the list comes from the service,
// the end goes through the service's end path (stamp, then close).
type termsvcLiveRuns struct {
	svc    *termsvc.Service
	mgr    *termsession.Manager
	stamp  func(ctx context.Context, runID, reason string) error
	logger *slog.Logger
}

// liveRunSourceFor adapts the daemon's terminal manager (nil when it is not
// the terminal stack's counting manager, so there is nothing live to ask
// about).
func liveRunSourceFor(mgr terminalLiveCounter, database *sql.DB, logger *slog.Logger) liveRunSource {
	cm, ok := mgr.(sandboxCountingManager)
	if !ok {
		return nil
	}
	svc, ok := cm.svc.(*termsvc.Service)
	if !ok || svc == nil {
		return nil
	}
	tm, ok := cm.terminalManager.(*termsession.Manager)
	if !ok || tm == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	src := termsvcLiveRuns{svc: svc, mgr: tm, logger: logger}
	if database != nil {
		src.stamp = stampTerminalEnd(database)
	}
	return src
}

// LiveSandboxedCount implements liveRunSource.
func (t termsvcLiveRuns) LiveSandboxedCount() int {
	return t.svc.LiveSandboxedCount() + readoptLiveExtra()
}

func (t termsvcLiveRuns) liveRuns(now time.Time) []dashapi.LiveSandboxRun {
	runs := t.svc.LiveSandboxedRuns()
	out := make([]dashapi.LiveSandboxRun, 0, len(runs))
	for _, r := range runs {
		age := int64(0)
		if !r.StartedAt.IsZero() && now.After(r.StartedAt) {
			age = int64(now.Sub(r.StartedAt) / time.Second)
		}
		out = append(out, dashapi.LiveSandboxRun{RunID: r.RunID, Tool: r.Tool, Backend: r.Backend, AgeSeconds: age, NativeResume: r.NativeResume})
	}
	return out
}

func (t termsvcLiveRuns) endLiveRuns(ctx context.Context, reason, notice string) int {
	ended := t.svc.EndLiveSandboxed(ctx, reason, notice, t.stamp,
		func(handle, notice string) {
			if notice != "" {
				t.mgr.Notice(handle, notice)
			}
			t.mgr.Close(handle)
		},
		func(runID string, err error) {
			t.logger.Warn("terminal: record why the sandboxed run is ended", "run", runID, "end_reason", reason, "err", err)
		})
	return len(ended)
}
