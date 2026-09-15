package qoder

import (
	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// CursorSemanticsFor implements adapter.CursorSemantics. This adapter
// mixes three cursor shapes across its layouts, so the answer is
// per-PATH:
//
//   - Qoder Work's main.sqlite persists a Unix-MILLISECOND watermark on
//     chat_session_messages.updated_at, not a byte offset — the dashboard
//     would otherwise report a 700 KB file as "1.7 trillion bytes behind".
//   - Run-log segments contribute TokenEvents from
//     model.response.completed records only — and in live capture those
//     records are all-zero and therefore skipped — so a segment file
//     legitimately produces no action rows.
//   - Both transcript layouts (CLI and IDE) keep ordinary byte-offset
//     semantics.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	switch classify(path) {
	case layoutWorkDB:
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorWatermark,
			Detail: "qoder-work main.sqlite cursor is a Unix-millisecond watermark on chat_session_messages.updated_at, not a byte offset",
		}
	case layoutSegment:
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorNoActions,
			Detail: "qoder run-log segments carry token records only; they emit no action rows",
		}
	default:
		return adapter.FileCursorSemantics{}
	}
}
