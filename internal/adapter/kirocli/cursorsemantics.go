package kirocli

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// isFlatStateSidecar reports whether path is the `.json` half of a flat
// session bundle (as opposed to the `.jsonl` stream that owns every
// emitted event).
func isFlatStateSidecar(path string) bool {
	norm := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	return strings.HasSuffix(norm, ".json")
}

// CursorSemanticsFor implements adapter.CursorSemantics. kiro-cli's
// multi-layout store needs three answers:
//
//   - The SQLite layout (`data.sqlite3` + sidecars) is scanned by a
//     conversations_v2 watermark, not a byte offset.
//   - The flat layout fires on BOTH the `.jsonl` stream and the `.json`
//     state sidecar, but parseFlatBundle attributes every emitted event
//     to the canonical `.jsonl` SourceFile. The `.json` cursor row can
//     therefore never accumulate actions, however much content it has.
//   - The Kiro IDE layout's `messages.jsonl` IS a plain append-only
//     byte-offset log parsed by its own path, so the DEFAULT semantics
//     are exactly right — the explicit case exists to say so rather
//     than let it fall through the `default` arm by accident.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	switch classifyLayout(path) {
	case layoutSQLite:
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorWatermark,
			Detail: "kiro-cli data.sqlite3 is scanned by a conversations_v2 watermark; the cursor is not a byte offset",
		}
	case layoutFlat:
		if isFlatStateSidecar(path) {
			return adapter.FileCursorSemantics{
				Kind:   adapter.CursorNoActions,
				Detail: "kiro-cli .json bundle state is a sidecar; its events are emitted under the sibling .jsonl source file",
			}
		}
		return adapter.FileCursorSemantics{}
	case layoutIDE:
		// Plain byte-offset JSONL tailing — the default kind.
		return adapter.FileCursorSemantics{}
	default:
		return adapter.FileCursorSemantics{}
	}
}
