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
	if matchesHooksLog(path) {
		// The replay emits hook rows under the LIVE hook's source_file
		// ("cursor:hook"), never under this path, so the file-keyed
		// zero-action fingerprint is meaningless here; it seeks to the
		// persisted offset and streams (parseHooksLog), so the oversize
		// guard bounds the unread tail, not the ~30 MB file. Cursor
		// rotates it in place (`.log` -> `.1.log`, same path restarts
		// empty), so the cursor may rewind.
		return adapter.FileCursorSemantics{
			Kind:              adapter.CursorNoActions,
			StreamsFromCursor: true,
			RewindsOnTruncate: true,
			Detail:            "Cursor IDE hooks output log: replayed hook payloads land under the live hook's source identity (cursor:hook), not this file",
		}
	}
	if matchesCLIUsageLog(path) {
		// parseCLIUsageLog seeks to the persisted offset and reads
		// line by line through a bounded reader (cli_usage.go).
		return adapter.FileCursorSemantics{Kind: adapter.CursorNoActions, StreamsFromCursor: true, Detail: "Cursor CLI debug log carries reported token usage and, for turns that never finished, evidence rows only - not activity"}
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
