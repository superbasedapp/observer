package claudecode

import "github.com/marmutapp/superbased-observer/internal/adapter"

// CursorSemanticsFor implements adapter.CursorSemantics.
//
// A Claude Code transcript is an append-only JSONL file tailed by byte
// offset (the default Kind), and ParseSessionFile SEEKS to the persisted
// offset (adapter.go:354) and streams forward through a 64 KiB
// bufio.Reader (adapter.go:419) — it never slurps the file. So one parse
// allocates on the order of the unread tail, and the watcher's
// MaxFileBytes DoS guard can gate on that tail instead of on the total
// size. Without this declaration a long-running session's transcript was
// skipped on every tick forever the day it crossed the cap, and the
// hook-captured tool calls kept landing while transcript-sourced tokens
// and messages silently stopped.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	return adapter.FileCursorSemantics{
		StreamsFromCursor: true,
		Detail:            "append-only JSONL transcript, seek-and-stream from the persisted offset",
	}
}
