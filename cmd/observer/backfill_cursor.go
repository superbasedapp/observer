//go:build !sbo_omit_adapter_cursor

package main

// backfill_cursor.go holds the backfill passes that parse with
// internal/adapter/cursor (--cursor-hook-usage, --cursor-user-prompts,
// --cursor-subagents and the cursor half of --message-id), built unless
// adapter.cursor is compiled out (lane MP-L1D, T-598);
// backfill_cursor_omit.go refuses them.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cursorHookLogRoots is every Cursor IDE log root the hooks-log replay
// walks: one per cross-mount home (cursor.HooksLogRoots), plus the
// legacy $APPDATA-derived location for a native Windows install, de-duped.
func cursorHookLogRoots() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range append(cursor.HooksLogRoots(), cursorLogsDir()) {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// backfillCursorHookUsage replays every Cursor IDE hooks output log
// under roots through the cursor adapter's hooks-log reader (the same
// builders the live hook uses, so identities match and a re-run is a
// no-op) and ingests the result; a mislabelled-stop squatter is removed
// only where the replayed log proves it (see the comment in the body). A
// missing root is skipped silently; an unreadable file is skipped and not
// counted.
func backfillCursorHookUsage(ctx context.Context, db *sql.DB, roots []string, fileLimit int) (CursorHookUsageBackfill, error) {
	res := CursorHookUsageBackfill{}
	st := store.New(db)
	a := cursor.New()
	wireCursorReplaySeams(a, st)
	// Mislabelled-stop squatters are removed only as PROVEN pairs, inside
	// the ingest of each replayed log (review finding F3, 2026-09-26): a
	// stop the log itself shows restating the preceding afterAgentResponse
	// (TokenEvent.Restates) removes a row still carrying exactly that usage,
	// and a replayed afterAgentResponse evicts a squatter under its own key
	// before its real usage lands, so nothing is MAX-blended. There is no
	// counter-equality sweep any more: a historical squatter whose log has
	// rotated out cannot be proven and is left in place.
	for _, root := range roots {
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// A missing root is normal (no Cursor on that home);
				// anything else is reported, never silently skipped.
				if !errors.Is(err, fs.ErrNotExist) {
					res.FilesFailed++
					res.problem(fmt.Sprintf("walk %s: %v", path, err))
				}
				return nil
			}
			if d.IsDir() || !cursor.IsHooksLog(path) {
				return nil
			}
			if fileLimit > 0 && res.FilesScanned >= fileLimit {
				return fs.SkipAll
			}
			pr, perr := a.ParseHooksLog(ctx, path)
			if perr != nil {
				res.FilesFailed++
				res.problem(perr.Error())
				return nil
			}
			res.ReplayWarnings += len(pr.Warnings)
			for _, w := range pr.Warnings {
				res.problem(path + ": " + w)
			}
			res.FilesScanned++
			res.EventsReplayed += len(pr.ToolEvents) + len(pr.TokenEvents) + len(pr.OutcomeUpdates)
			if len(pr.ToolEvents) == 0 && len(pr.TokenEvents) == 0 && len(pr.OutcomeUpdates) == 0 && len(pr.ToolAccounts) == 0 {
				return nil
			}
			ir, ierr := st.Ingest(ctx, pr.ToolEvents, pr.TokenEvents, store.IngestOptions{
				RecordFailures:      true,
				OutcomeUpdates:      pr.OutcomeUpdates,
				SessionToolVersions: pr.SessionToolVersions,
				// The adapter's tool-account observations, as the watcher
				// forwards them (store.IngestOptions.ToolAccounts).
				ToolAccounts: pr.ToolAccounts,
			})
			if ierr != nil {
				return fmt.Errorf("%s: %w", path, ierr)
			}
			res.ActionsInserted += ir.ActionsInserted
			res.TokenRowsWritten += ir.TokensInserted
			res.DuplicatesRemoved += int64(ir.TokenRestatementsRemoved)
			res.OutcomesApplied += len(pr.OutcomeUpdates)
			return nil
		})
		if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
			return res, fmt.Errorf("backfill cursor hook usage: walk: %w", walkErr)
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			break
		}
	}
	return res, nil
}

// wireCursorReplaySeams injects the two store-backed seams the Cursor
// hooks-log replay (and state.vscdb reader) consult: whether a
// conversation's activity was already captured by a NON-hook source
// (so the replay adds only usage + outcomes), and a session's stored
// project root (so a root-less payload never moves a folder session
// onto the "[cursor]" placeholder). One wiring for the daemon and the
// backfill, so the two paths cannot drift.
func wireCursorReplaySeams(a *cursor.Adapter, st *store.Store) {
	a.WithSessionTranscriptChecker(func(ctx context.Context, sessionID string) (bool, error) {
		return st.SessionHasActionsOutside(ctx, sessionID, "cursor:hook",
			models.ActionSystemPrompt, models.ActionPromptContext)
	}).WithSessionRootLookup(st.ProjectRootForSession)
}

// backfillCursorUserPrompts walks every cursor agent-transcripts JSONL
// file under projectsDir and ingests user_prompt action rows for the
// turn-opening user lines. The cursor adapter's live path emits user
// prompts via the beforeSubmitPrompt hook; this catches sessions that
// pre-date the hook installation (or sessions where the hook fires for
// some prompts but not others).
//
// Each user line's text is unwrapped via stripUserQueryWrapper so the
// row carries the user-typed prompt rather than the
// `<user_query>...</user_query>` envelope cursor's runtime injects.
//
// Idempotent via the (source_file, source_event_id) UNIQUE index -
// re-running over a session that already has user_prompt rows is a
// no-op. Skips subagents/*.jsonl explicitly; those are handled in
// the parallel --cursor-subagents pass.
func backfillCursorUserPrompts(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (CursorUserPromptsBackfill, error) {
	res := CursorUserPromptsBackfill{}
	st := store.New(db)
	// Backfill reads the same transcripts the live hook path does, so it
	// must scrub the same way: store.Ingest has no scrub backstop.
	sc := scrub.New()

	type turnRef struct {
		MessageID string
		Timestamp string
	}

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" || strings.Contains(path, string(filepath.Separator)+"subagents"+string(filepath.Separator)) {
			return nil
		}
		sessionID := filepath.Base(filepath.Dir(path))
		if strings.TrimSuffix(filepath.Base(path), ".jsonl") != sessionID {
			return nil
		}
		if !strings.Contains(path, string(filepath.Separator)+"agent-transcripts"+string(filepath.Separator)) {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return fs.SkipAll
		}
		res.FilesScanned++

		var projectRoot string
		_ = db.QueryRowContext(ctx, `
			SELECT COALESCE(p.root_path, '')
			  FROM sessions s
			  LEFT JOIN projects p ON p.id = s.project_id
			 WHERE s.id = ?`, sessionID).Scan(&projectRoot)
		if projectRoot == "" {
			return nil
		}

		rows, err := db.QueryContext(ctx, `
			SELECT message_id, timestamp
			  FROM token_usage
			 WHERE tool = 'cursor' AND session_id = ? AND message_id IS NOT NULL AND message_id != ''
			 ORDER BY timestamp ASC, id ASC`, sessionID)
		if err != nil {
			return err
		}
		var refs []turnRef
		for rows.Next() {
			var ref turnRef
			if err := rows.Scan(&ref.MessageID, &ref.Timestamp); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, ref)
		}
		rows.Close()
		if len(refs) == 0 {
			return nil
		}

		turns, err := cursor.ParseTranscriptTurns(path)
		if err != nil {
			return nil
		}
		n := len(turns)
		if len(refs) < n {
			n = len(refs)
		}
		var events []models.ToolEvent
		for i := 0; i < n; i++ {
			ts, _ := time.Parse(time.RFC3339Nano, refs[i].Timestamp)
			ev, ok := cursor.BuildTranscriptUserPromptEvent(turns[i], sessionID, projectRoot, refs[i].MessageID, path, ts, sc)
			if !ok {
				continue
			}
			events = append(events, ev)
		}
		res.UserEventsFound += len(events)
		if len(events) == 0 {
			return nil
		}
		ingestRes, err := st.Ingest(ctx, events, nil, store.IngestOptions{})
		if err != nil {
			return fmt.Errorf("backfill cursor-user-prompts: ingest: %w", err)
		}
		res.ActionsInserted += ingestRes.ActionsInserted
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return res, fmt.Errorf("backfill cursor-user-prompts: walk %s: %w", projectsDir, walkErr)
	}
	return res, nil
}

// backfillCursorSubagents walks the
// agent-transcripts/<parent_uuid>/subagents/<sub_uuid>.jsonl files
// Cursor writes when the parent agent spawns a sub-agent. The current
// cursor backfill explicitly skips these (the parent transcript only
// records a `Subagent` tool_use; the sub-agent's actual work is
// in the sub-file). This pass ingests those nested transcripts as
// sidechain rows under the parent session (IsSidechain=true,
// SessionID = parent_uuid), mirroring claudecode's isSidechain
// semantics.
//
// Each sub-agent line is timestamped from the file's mtime (the
// sub transcript carries no per-line timestamps). MessageID is
// synthesized as "sub:<sub_uuid>:turn<N>" so rows from the same
// sub-agent thread group together; SourceEventID prefixes ensure
// idempotency on re-runs.
func backfillCursorSubagents(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (CursorSubagentsBackfill, error) {
	res := CursorSubagentsBackfill{}
	st := store.New(db)
	// Backfill reads the same transcripts the live hook path does, so it
	// must scrub the same way: store.Ingest has no scrub backstop.
	sc := scrub.New()

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" {
			return nil
		}
		sep := string(filepath.Separator)
		if !strings.Contains(path, sep+"subagents"+sep) || !strings.Contains(path, sep+"agent-transcripts"+sep) {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return fs.SkipAll
		}
		res.FilesScanned++

		subUUID := strings.TrimSuffix(filepath.Base(path), ".jsonl")
		// path = .../agent-transcripts/<parent_uuid>/subagents/<sub>.jsonl
		// dir(path) = .../subagents
		// dir(dir(path)) = .../<parent_uuid>
		parentUUID := filepath.Base(filepath.Dir(filepath.Dir(path)))

		var projectRoot string
		_ = db.QueryRowContext(ctx, `
			SELECT COALESCE(p.root_path, '')
			  FROM sessions s
			  LEFT JOIN projects p ON p.id = s.project_id
			 WHERE s.id = ?`, parentUUID).Scan(&projectRoot)
		if projectRoot == "" {
			return nil
		}

		info, statErr := os.Stat(path)
		if statErr != nil {
			return nil
		}
		ts := info.ModTime().UTC()

		turns, err := cursor.ParseTranscriptTurns(path)
		if err != nil {
			return nil
		}

		var events []models.ToolEvent
		for i, turn := range turns {
			generationID := fmt.Sprintf("sub:%s:turn%d", subUUID, i)
			if ev, ok := cursor.BuildTranscriptUserPromptEvent(turn, parentUUID, projectRoot, generationID, path, ts, sc); ok {
				ev.IsSidechain = true
				events = append(events, ev)
			}
			toolEvs := cursor.BuildTranscriptToolEvents(turn, parentUUID, projectRoot, generationID, path, ts, sc)
			for _, te := range toolEvs {
				te.IsSidechain = true
				events = append(events, te)
			}
		}
		res.EventsBuilt += len(events)
		if len(events) == 0 {
			return nil
		}
		ingestRes, err := st.Ingest(ctx, events, nil, store.IngestOptions{})
		if err != nil {
			return fmt.Errorf("backfill cursor-subagents: ingest: %w", err)
		}
		res.ActionsInserted += ingestRes.ActionsInserted
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return res, fmt.Errorf("backfill cursor-subagents: walk %s: %w", projectsDir, walkErr)
	}
	return res, nil
}

func backfillCursorTranscriptActions(ctx context.Context, db *sql.DB, projectsDir string, fileLimit int) (MessageIDBackfill, error) {
	res := MessageIDBackfill{}
	st := store.New(db)
	// Backfill reads the same transcripts the live hook path does, so it
	// must scrub the same way: store.Ingest has no scrub backstop.
	sc := scrub.New()

	type turnRef struct {
		MessageID string
		Timestamp string
	}

	walkErr := filepath.WalkDir(projectsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".jsonl" || strings.Contains(path, string(filepath.Separator)+"subagents"+string(filepath.Separator)) {
			return nil
		}
		sessionID := filepath.Base(filepath.Dir(path))
		if strings.TrimSuffix(filepath.Base(path), ".jsonl") != sessionID {
			return nil
		}
		if !strings.Contains(path, string(filepath.Separator)+"agent-transcripts"+string(filepath.Separator)) {
			return nil
		}
		if fileLimit > 0 && res.FilesScanned >= fileLimit {
			return fs.SkipAll
		}
		res.FilesScanned++

		var projectRoot string
		_ = db.QueryRowContext(ctx, `
			SELECT COALESCE(p.root_path, '')
			  FROM sessions s
			  LEFT JOIN projects p ON p.id = s.project_id
			 WHERE s.id = ?`, sessionID).Scan(&projectRoot)
		if projectRoot == "" {
			return nil
		}

		rows, err := db.QueryContext(ctx, `
			SELECT message_id, timestamp
			  FROM token_usage
			 WHERE tool = 'cursor' AND session_id = ? AND message_id IS NOT NULL AND message_id != ''
			 ORDER BY timestamp ASC, id ASC`, sessionID)
		if err != nil {
			return err
		}
		var refs []turnRef
		for rows.Next() {
			var ref turnRef
			if err := rows.Scan(&ref.MessageID, &ref.Timestamp); err != nil {
				rows.Close()
				return err
			}
			refs = append(refs, ref)
		}
		rows.Close()
		if len(refs) == 0 {
			return nil
		}

		turns, err := cursor.ParseTranscriptTurns(path)
		if err != nil {
			return nil
		}
		n := len(turns)
		if len(refs) < n {
			n = len(refs)
		}
		for i := 0; i < n; i++ {
			ts, _ := time.Parse(time.RFC3339Nano, refs[i].Timestamp)
			events := cursor.BuildTranscriptToolEvents(turns[i], sessionID, projectRoot, refs[i].MessageID, path, ts, sc)
			res.LinesExamined += len(events)
			ingestRes, err := st.Ingest(ctx, events, nil, store.IngestOptions{})
			if err != nil {
				return err
			}
			res.ActionsUpdated += ingestRes.ActionsInserted
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return res, fmt.Errorf("backfill cursor transcript actions: walk: %w", walkErr)
	}
	return res, nil
}
