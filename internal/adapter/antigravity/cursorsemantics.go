package antigravity

import "github.com/marmutapp/superbased-observer/internal/adapter"

// CursorSemanticsFor implements adapter.CursorSemantics.
//
// Antigravity `.pb` conversation files (desktop AND the older CLI
// layout) are OSCrypt-encrypted. On a host where the secret cannot be
// retrieved or the cipher mode is unknown (documented for Windows),
// the adapter marks the file unrecoverable and advances the cursor to
// the file size — leaving a cursor-at-EOF row with zero actions
// forever. That is the DESIGNED outcome of an undecodable store, not
// the adapter-misroute fingerprint, so it must not be reported as one.
//
// Byte lag stays meaningful: the cursor really is a file size, and a
// grown `.pb` genuinely awaits another decrypt attempt.
//
// The agy plaintext-protobuf SQLite `.db` stores (CLI tree and desktop
// tree, plus their -wal / -shm sidecars) are WAL-mode databases: a turn
// lands in the -wal without growing the main file, so a size cursor
// would never re-fire. Their cursor is a WATERMARK — the max mtime
// (unix ms) of the .db and its -wal (agyDBWatermark) — like cline-cli's
// sessions.db, and the watcher's size gate does not apply.
//
// The desktop transcript.jsonl is re-read whole on every size change
// and keeps ordinary byte-offset semantics.
func (a *Adapter) CursorSemanticsFor(path string) adapter.FileCursorSemantics {
	if !a.IsSessionFile(path) {
		return adapter.FileCursorSemantics{}
	}
	switch classifyLayout(path) {
	case LayoutDesktop, LayoutCLI:
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorEncrypted,
			Detail: "antigravity .pb conversations are OSCrypt-encrypted; emitting no actions is expected wherever the secret or cipher is unavailable on this host",
		}
	case LayoutCLIDB, LayoutDesktopDB:
		return adapter.FileCursorSemantics{
			Kind:   adapter.CursorWatermark,
			Detail: "agy conversation .db is WAL-mode SQLite scanned on a max-mtime(.db, .db-wal) unix-ms watermark; the cursor is not a byte offset",
		}
	default:
		return adapter.FileCursorSemantics{}
	}
}
