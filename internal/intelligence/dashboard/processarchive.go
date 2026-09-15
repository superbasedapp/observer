package dashboard

import (
	"context"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/archive"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// P3.5 of the corpus archival arc: the DIRECT-READ fallback for process
// capture that has moved to cold storage
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md §4.3).
//
// What §4.4 requires and this preserves: the endpoint keeps its shape and its
// response contract. `GET /api/session/<id>/processes` takes no new parameter,
// returns no new field, and does not become a different endpoint per hot/cold.
// An archived session's trail simply arrives — possibly a little slower.
//
// What it must NOT do, and does not: write anything back. Copying archived rows
// into the hot tables on a read would re-grow the database this arc exists to
// bound, and would feed historical rows to the live correlation sweep, which is
// about recent attribution and not history.

// ProcessArchiveReader is the slice of cold storage the process surfaces need.
//
// Declared HERE, at the consumer, so this package depends on a two-method
// behaviour contract rather than on internal/archivestore — the dashboard never
// learns that cold storage is a second SQLite file, and a test can supply a
// fake without one.
type ProcessArchiveReader interface {
	// HasArchivedSessionProcesses is the cheap "is it worth looking?" probe.
	HasArchivedSessionProcesses(ctx context.Context, sessionID string) (bool, error)
	// ProcessRunsForSession streams the archived runs for one session.
	ProcessRunsForSession(ctx context.Context, sessionID string, batchRows int, sink archive.WindowSink) error
}

// collectSink accumulates streamed batches for decoding.
type collectSink struct{ batches []archive.RowBatch }

func (c *collectSink) WriteRows(_ context.Context, b archive.RowBatch) error {
	c.batches = append(c.batches, b)
	return nil
}

// archivedProcessRuns answers a session's process trail from cold storage,
// returning nil when there is nothing archived for it.
//
// THE COST CONTRACT. This runs only after the hot read came back EMPTY, and it
// begins with one indexed marker lookup against a table holding one row per
// archived day. So the overwhelmingly common case — archival off, or nothing
// archived yet — pays exactly that one query and then answers empty, the way it
// always did. The archive file is opened only when there is something to find.
//
// FAIL-OPEN throughout: any error here logs and yields nil, so a fault in cold
// storage degrades an archived session's panel to the empty panel it showed
// before this arc, never to a 500 on a session that is merely old.
func (s *Server) archivedProcessRuns(ctx context.Context, sessionID string) []store.ProcessRunRow {
	reader := s.opts.ProcessArchive
	if reader == nil || sessionID == "" {
		return nil
	}
	st := store.New(s.db())
	anyArchived, err := st.AnyProcessWindowArchived(ctx)
	if err != nil || !anyArchived {
		return nil
	}
	has, err := reader.HasArchivedSessionProcesses(ctx, sessionID)
	if err != nil {
		slog.Debug("archived process probe failed", "session", sessionID, "error", err)
		return nil
	}
	if !has {
		return nil
	}
	var sink collectSink
	if err := reader.ProcessRunsForSession(ctx, sessionID, 0, &sink); err != nil {
		slog.Warn("archived process read failed", "session", sessionID, "error", err)
		return nil
	}
	runs, err := store.DecodeArchivedProcessRuns(sink.batches...)
	if err != nil {
		slog.Warn("archived process decode failed", "session", sessionID, "error", err)
		return nil
	}
	return runs
}
