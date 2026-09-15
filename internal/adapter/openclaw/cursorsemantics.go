package openclaw

import (
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// CursorSemanticsFor implements adapter.CursorSemantics. OpenClaw
// tracks three differently-shaped stores under one adapter:
//
//   - `runs.sqlite` (+ `-wal`) is scanned by a task watermark.
//   - `agents/<id>/agent/openclaw-agent.sqlite` (+ `-wal`), the
//     OpenClaw 2.0 per-agent store, is scanned by a transcript row
//     watermark (MAX(rowid), or MAX(created_at) where rowid is
//     unavailable) — see agentdb.go.
//   - `sessions.json` is a whole-file map rewritten in place; its
//     cursor is a UnixMilli `updatedAt` watermark compared against
//     entries, not bytes.
//   - `<id>.trajectory.jsonl` is a real byte-offset tail, but its
//     model.completed usage records are suppressed whenever the
//     sibling `<id>.jsonl` message log already covers the call — so a
//     fully-covered trajectory emits nothing at all, by design.
//   - `<id>.jsonl` (the message log) keeps plain byte-offset semantics.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "runs.sqlite" || base == "runs.sqlite-wal":
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorWatermark,
			Detail: "openclaw runs.sqlite is scanned by a task watermark; the cursor is not a byte offset",
		}
	case base == agentDBBase || base == agentDBWAL:
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorWatermark,
			Detail: "openclaw 2.0's per-agent openclaw-agent.sqlite is scanned by a transcript_events row watermark; the cursor is not a byte offset",
		}
	case base == "sessions.json":
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorWatermark,
			Detail: "openclaw sessions.json is a rewritten-in-place index read by a UnixMilli updatedAt watermark; the cursor is not a byte offset",
		}
	case strings.HasSuffix(base, ".trajectory.jsonl"):
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorNoActions,
			Detail: "openclaw trajectory traces carry token usage only, and suppress calls the sibling message log already covers",
		}
	default:
		return adapter.FileCursorSemantics{}
	}
}
