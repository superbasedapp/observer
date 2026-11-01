package ibmbob

import "github.com/marmutapp/superbased-observer/internal/adapter"

// CursorSemanticsFor implements adapter.CursorSemantics. `bob.db` and its
// `-wal` / `-shm` sidecars are scanned by a tasks.updated_at (epoch ms)
// watermark, so the persisted cursor is a timestamp rather than a byte
// offset.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{
		Kind:   adapter.CursorWatermark,
		Detail: "IBM Bob bob.db is scanned by a tasks.updated_at epoch-ms watermark; the cursor is not a byte offset",
	}
}
