package codex

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/adapter/parseutil"
)

// threadSourceSubagent is the sessionMetaPayload.ThreadSource value
// codex stamps on a subagent-spawned rollout. Normal + user-fork
// sessions carry "user"; the empty string means the field was absent.
const threadSourceSubagent = "subagent"

// forkReplayTracker is the single-pass decision state for detecting
// fork/subagent REPLAY in a codex rollout file.
//
// Codex 0.144+ physically replays the parent rollout's entire event
// stream — including token_count usage telemetry — into a fork or
// subagent's new rollout JSONL, re-stamped to fork-creation time. A
// file-local adapter would re-insert every replayed usage event as a
// fresh token_usage row under the child's session id, double-counting
// the parent's input tokens. This tracker marks those replayed
// token_count lines so emission can be suppressed while cumulative /
// dedup state still advances (so the first LIVE event's delta is
// computed against the replayed cumulative total).
//
// THE DISCRIMINATOR: a replayed task_started keeps its ORIGINAL
// payload.started_at (unix seconds), earlier than the owning session's
// creation time; the first LIVE turn's started_at equals session
// creation to the second (equal ⇒ live). Envelope timestamps are
// re-stamped and useless. The tracker is fail-open: unmarked files and
// events with no governing task_started are treated as live, so
// non-forked files behave byte-identically to before this fix.
type forkReplayTracker struct {
	marked           bool
	ownerLatched     bool
	ownerID          string
	ownerCreatedSec  int64
	haveOwnerCreated bool
	govStartedSec    int64
	haveGov          bool
	lineage          sessionLineage
	// marginSec widens the replay/live boundary for the DESTRUCTIVE
	// determination. isReplayedTokenCount treats a token_count as
	// replayed only when its governing task_started started strictly
	// before ownerCreatedSec-marginSec. Zero (the ingest default) keeps
	// the original strict-< boundary; ReplayedTokenLines (which the
	// backfill --apply DELETE path consumes) sets a small positive
	// margin so second-boundary rounding or a clock regression can never
	// auto-delete a live row. The two paths deliberately diverge: the
	// backfill deletes a slightly conservative subset of what ingest
	// suppresses (documented on ReplayedTokenLines).
	marginSec int64
}

// replayDestructiveMarginSec is the safety margin ReplayedTokenLines
// applies (in seconds) for the backfill --apply delete decision. A
// replayed task_started started_at must be earlier than the owning
// session's creation by MORE than this margin before its token_count
// rows are eligible for deletion, so a one-second boundary rounding or
// a small backwards clock adjustment never destroys a live row. Ingest
// stays at margin 0 (strict <) — it only suppresses emission, which is
// recoverable by a rescan, whereas a delete is not.
const replayDestructiveMarginSec = 2

// sessionLineage is the codex-session lineage captured from the owning
// session_meta. Zero value = a normal (non-fork) session with no
// markers. Mirrored onto models.SessionLineage at the parse boundary.
type sessionLineage struct {
	ForkedFromID   string
	ParentThreadID string
	ThreadSource   string
}

// observeSessionMeta feeds one session_meta record to the tracker. The
// FIRST record latches the file owner (id + creation time + lineage);
// a later record with a DIFFERENT id is a replayed parent session_meta
// and marks the file. createdSec is the owner's payload-level creation
// time in unix seconds; haveCreated is false when it could not be
// resolved (the tracker then fails open).
func (t *forkReplayTracker) observeSessionMeta(id, forkedFromID, parentThreadID, threadSource string, createdSec int64, haveCreated bool) {
	if !t.ownerLatched {
		t.ownerLatched = true
		t.ownerID = id
		t.ownerCreatedSec = createdSec
		t.haveOwnerCreated = haveCreated
		t.lineage = sessionLineage{
			ForkedFromID:   forkedFromID,
			ParentThreadID: parentThreadID,
			ThreadSource:   threadSource,
		}
		if forkedFromID != "" || threadSource == threadSourceSubagent {
			t.marked = true
		}
		return
	}
	if id != "" && id != t.ownerID {
		t.marked = true
	}
}

// observeTaskStarted records the governing turn for the token_count
// events that follow it. startedAtSec is payload.started_at in unix
// seconds; have is false when the field was absent (fail-open live).
func (t *forkReplayTracker) observeTaskStarted(startedAtSec int64, have bool) {
	t.govStartedSec = startedAtSec
	t.haveGov = have
}

// isReplayedTokenCount reports whether the current token_count event is
// replayed parent history (its governing task_started started before the
// owning session was created, by more than marginSec). marginSec is 0 on
// the ingest path (strict <) and positive on the destructive backfill
// path. Fail-open: false for unmarked files, files whose owner creation
// time is unknown, and events with no governing task_started yet.
func (t *forkReplayTracker) isReplayedTokenCount() bool {
	if !t.marked || !t.ownerLatched || !t.haveOwnerCreated {
		return false
	}
	if !t.haveGov {
		return false
	}
	return t.govStartedSec < t.ownerCreatedSec-t.marginSec
}

// lineageMarker returns the captured lineage and whether it carries any
// non-empty field worth persisting.
func (t *forkReplayTracker) lineageMarker() (sessionLineage, bool) {
	if !t.ownerLatched {
		return sessionLineage{}, false
	}
	l := t.lineage
	has := l.ForkedFromID != "" || l.ParentThreadID != "" || l.ThreadSource != ""
	return l, has
}

// replayScanLine is the minimal envelope the backfill scan unmarshals.
type replayScanLine struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

// ReplayedTokenLines scans a codex rollout JSONL stream and returns the
// set of 1-based line numbers whose token_count events are replayed
// fork/subagent parent history — the events whose token_usage rows
// (source_event_id "tk:<basename>:L<line>") are duplicates.
//
// It drives the same forkReplayTracker decision logic ParseSessionFile
// uses, so the fork/replay determination lives in exactly one place: a
// follow-up backfill command computes the rows to delete without
// re-implementing the parse semantics. Returns an empty (non-nil) set
// for a normal, non-forked file.
//
// This is the DESTRUCTIVE path (the backfill --apply DELETE consumes
// its output), so it runs the tracker with a small safety margin
// (replayDestructiveMarginSec): a line is flagged replayed only when its
// governing task_started predates owner creation by MORE than the
// margin. Ingest uses margin 0 (strict <). The divergence is
// deliberate — the backfill deletes a slightly conservative subset of
// what ingest suppresses so a second-boundary or clock-regression edge
// case can never auto-delete a genuinely live row.
func ReplayedTokenLines(r io.Reader) (map[int]bool, error) {
	replayed := map[int]bool{}
	track := forkReplayTracker{marginSec: replayDestructiveMarginSec}
	reader := bufio.NewReaderSize(r, 64*1024)
	lineNum := 0
	for {
		lineStr, consumed, oversized, err := adapter.ReadRecord(reader, maxRecordBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("codex.ReplayedTokenLines: %w", err)
		}
		if consumed == 0 {
			break
		}
		// Unified deferral rule (mirrors ParseSessionFile): an io.EOF from
		// adapter.ReadRecord marks an unterminated final fragment (no '\n'). The
		// ingest parse defers it whole and never assigns it a line, so the
		// destructive backfill must NOT count it either — line-number
		// lockstep with tk:<base>:L<line> ids is a delete invariant.
		if errors.Is(err, io.EOF) {
			break
		}
		lineNum++
		if oversized {
			// Skip the oversized record but keep line numbering in
			// lockstep with ParseSessionFile — the backfill deletes rows
			// keyed tk:<base>:L<line>, so a skip here must consume the
			// same L<line> the ingest parse did. CLEAR governance
			// (fail-open, like a malformed envelope): the skipped record
			// could have been a task_started.
			track.observeTaskStarted(0, false)
			continue
		}
		raw := bytes.TrimRight(lineStr, "\r\n")
		if len(raw) == 0 {
			continue
		}
		var line replayScanLine
		if err := json.Unmarshal(raw, &line); err != nil {
			// A whole malformed envelope CLEARS governance so the
			// token_counts that follow fail open as live (not deleted):
			// were this the replayed task_started, stale governance would
			// flag the following LIVE rows replayed and delete them.
			track.observeTaskStarted(0, false)
			continue
		}
		switch line.Type {
		case "session_meta":
			var meta sessionMetaPayload
			if err := json.Unmarshal(line.Payload, &meta); err != nil {
				continue
			}
			created, have := sessionMetaCreationSec(meta, line.Timestamp)
			track.observeSessionMeta(
				firstNonEmpty(meta.ID, meta.SessionID),
				meta.ForkedFromID, meta.ParentThreadID, meta.ThreadSource,
				created, have,
			)
		case "event_msg":
			switch payloadType(line.Payload) {
			case "task_started":
				var started taskStarted
				if err := json.Unmarshal(line.Payload, &started); err != nil {
					// A malformed task_started must CLEAR governance so
					// the following token_counts fail open as live
					// (marked replayed only by a NEW valid task_started).
					// Leaving stale governance would wrongly classify
					// subsequent live rows as replayed and delete them.
					track.observeTaskStarted(0, false)
					continue
				}
				track.observeTaskStarted(started.StartedAt, started.StartedAt != 0)
			case "token_count":
				if track.isReplayedTokenCount() {
					replayed[lineNum] = true
				}
			}
		case "token_count", "usage":
			// Legacy top-level usage path (dormant for modern rollout
			// files); mark for completeness so the backfill covers both.
			if track.isReplayedTokenCount() {
				replayed[lineNum] = true
			}
		}
	}
	return replayed, nil
}

// ForkLineage is the codex session lineage captured from a rollout's
// OWNING (first) session_meta record. SessionID is the child session
// the markers belong to; the remaining fields mirror
// models.SessionLineage. A backfill uses this to retrofit lineage onto
// sessions ingested before the fork-replay fix persisted it.
type ForkLineage struct {
	SessionID      string
	ForkedFromID   string
	ParentThreadID string
	ThreadSource   string
}

// ScanForkLineage scans a codex rollout JSONL stream and returns the
// lineage carried by its owning (first) session_meta record. It is the
// read-only companion to ReplayedTokenLines — a follow-up backfill can
// retrofit forked_from_id / parent_thread_id / thread_source onto
// pre-fix session rows without re-implementing the meta parsing.
//
// ok is false when the stream carries no session_meta record in its
// leading lines (an empty ForkLineage is returned in that case). A
// separate exported helper keeps ReplayedTokenLines's signature stable
// per the parse-in-one-place contract.
func ScanForkLineage(r io.Reader) (ForkLineage, bool, error) {
	reader := bufio.NewReaderSize(r, 64*1024)
	for {
		lineStr, consumed, oversized, err := adapter.ReadRecord(reader, maxRecordBytes)
		if err != nil && !errors.Is(err, io.EOF) {
			return ForkLineage{}, false, fmt.Errorf("codex.ScanForkLineage: %w", err)
		}
		if consumed == 0 {
			break
		}
		// Unified deferral rule (mirrors ParseSessionFile): an io.EOF from
		// adapter.ReadRecord marks an unterminated final fragment (no '\n'). It is
		// an in-progress append, not a complete record — defer it. The
		// owning session_meta leads the file and is always terminated, so
		// this only guards against classifying a partial trailing record.
		if errors.Is(err, io.EOF) {
			break
		}
		if oversized {
			// The owning session_meta is small and leads the file; an
			// oversized record before it is not lineage — skip it (issue
			// #7 shape: never abort the whole scan on one huge line).
			continue
		}
		raw := bytes.TrimRight(lineStr, "\r\n")
		if len(raw) == 0 {
			continue
		}
		var line replayScanLine
		if err := json.Unmarshal(raw, &line); err != nil {
			continue
		}
		if line.Type != "session_meta" {
			continue
		}
		var meta sessionMetaPayload
		if err := json.Unmarshal(line.Payload, &meta); err != nil {
			continue
		}
		return ForkLineage{
			SessionID:      firstNonEmpty(meta.ID, meta.SessionID),
			ForkedFromID:   meta.ForkedFromID,
			ParentThreadID: meta.ParentThreadID,
			ThreadSource:   meta.ThreadSource,
		}, true, nil
	}
	return ForkLineage{}, false, nil
}

// sessionMetaCreationSec resolves the owning session's creation time in
// unix seconds. It prefers the payload-level timestamp (stable across a
// fork's re-stamping); the envelope timestamp is the fallback. Returns
// have=false when neither parses.
func sessionMetaCreationSec(meta sessionMetaPayload, envelopeTS string) (int64, bool) {
	if t := parseutil.ParseRFC3339(meta.Timestamp); !t.IsZero() {
		return t.Unix(), true
	}
	if t := parseutil.ParseRFC3339(envelopeTS); !t.IsZero() {
		return t.Unix(), true
	}
	return 0, false
}
