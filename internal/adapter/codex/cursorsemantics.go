package codex

import "github.com/marmutapp/superbased-observer/internal/adapter"

// CursorSemanticsFor implements adapter.CursorSemantics.
//
// A Codex rollout is an append-only JSONL file tailed by byte offset
// (the default Kind), and ParseSessionFile SEEKS to the persisted offset
// (adapter.go:973) before reading records through a bounded
// bufio.Reader — it never slurps the file.
//
// The incremental-resume path additionally re-reads the PREFIX from byte
// 0 (prefetchSessionContext, adapter.go:4107) to rebuild dedup state,
// but that scan is also a 64 KiB streaming reader with a per-record cap
// (maxRecordBytes), so it costs CPU, not heap. The MaxFileBytes guard is
// a heap guard, so gating on the unread tail is correct here.
//
// Without this declaration six rollout transcripts on the 2026-09-16
// audit host sat frozen at ~52 MB while the files grew to 85 MB.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{
		StreamsFromCursor: true,
		Detail:            "append-only JSONL rollout, seek-and-stream from the persisted offset",
	}
}
