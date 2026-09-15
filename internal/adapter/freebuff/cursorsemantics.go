package freebuff

import "github.com/marmutapp/superbased-observer/internal/adapter"

// CursorSemanticsFor implements adapter.CursorSemantics.
//
// NEITHER freebuff layout tails bytes, so `file_size - byte_offset` is a
// category error for both:
//
//   - the CLI's `chat-messages.json` is a whole JSON array rewritten in
//     place, and the persisted cursor is a MESSAGE COUNT; and
//   - the Desktop's `desktop-v2.db` is scanned by an epoch-MILLIS
//     high-water mark over threads.updated_at / messages.ts, a number that
//     dwarfs the file size and would read as "permanently at EOF".
//
// Both are therefore CursorWatermark. Table-driven so a third layout is one
// row, not a new branch.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	switch layoutFor(path) {
	case layoutDesktop:
		return adapter.FileCursorSemantics{
			Kind: adapter.CursorWatermark,
			Detail: "freebuff-desktop desktop-v2.db is scanned by an epoch-millis " +
				"threads.updated_at / messages.ts watermark; the cursor is not a byte offset",
		}
	case layoutCLIChats:
		return adapter.FileCursorSemantics{
			Kind: adapter.CursorWatermark,
			Detail: "freebuff chat-messages.json is a whole-file rewrite; the cursor " +
				"is a message COUNT, not a byte offset",
		}
	default:
		return adapter.FileCursorSemantics{}
	}
}
