package dimcode

import "github.com/marmutapp/superbased-observer/internal/adapter"

// CursorSemanticsFor implements adapter.CursorSemantics. `dimcode.sqlite`
// and its `-wal`/`-shm` siblings are scanned by a max-updatedAt watermark
// (epoch milliseconds), so the persisted cursor is a timestamp rather than a
// byte offset.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{
		Kind:   adapter.CursorWatermark,
		Detail: "dimcode.sqlite is scanned by a max(updatedAt) epoch-ms watermark; the cursor is not a byte offset",
	}
}
