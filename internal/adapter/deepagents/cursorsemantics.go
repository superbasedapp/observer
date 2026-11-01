package deepagents

import "github.com/marmutapp/superbased-observer/internal/adapter"

// CursorSemanticsFor implements adapter.CursorSemantics. `sessions.db` and its
// `-wal` / `-shm` sidecars are scanned by a checkpoint-clock watermark (Unix
// 100ns ticks decoded from the newest UUIDv6 checkpoint id), so the persisted
// cursor is a clock value rather than a byte offset.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{
		Kind:   adapter.CursorWatermark,
		Detail: "dcode sessions.db is scanned by a checkpoint-id clock watermark; the cursor is not a byte offset",
	}
}
