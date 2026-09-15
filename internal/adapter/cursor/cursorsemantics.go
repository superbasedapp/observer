package cursor

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// CursorSemanticsFor implements adapter.CursorSemantics. Cursor's
// per-conversation store.db and agent-transcript JSONL both use a
// genuine byte-offset cursor (the default, so they fall through to
// the zero-value FileCursorSemantics below); state.vscdb does not —
// see stateDBWatermarkSQL's doc comment (statedb.go) for why a
// MAX(rowid) watermark over cursorDiskKV is used instead of a byte
// offset into the shared file.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	if matchesCLIUsageLog(path) {
		return adapter.FileCursorSemantics{Kind: adapter.CursorNoActions, Detail: "Cursor CLI structured log carries reported token usage, not actions"}
	}
	switch filepath.Base(path) {
	case "state.vscdb":
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorWatermark,
			Detail: "cursor state.vscdb is scanned by a MAX(rowid) watermark over cursorDiskKV; the cursor is not a byte offset",
		}
	default:
		return adapter.FileCursorSemantics{}
	}
}
