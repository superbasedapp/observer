package adapter

import (
	"path/filepath"
	"sync"
)

// notReadyWarned remembers which (tool, store file) pairs already
// produced a not-ready warning in this process.
var notReadyWarned sync.Map

// NotReadyResult is the ParseResult for a store file that exists but
// does not carry the tables an adapter reads: a database the tool is
// still bootstrapping (the file and its WAL appear before the schema
// does), a storage generation the adapter does not know, or an
// unrelated file that happens to share the store's name. It is not a
// parse error, so the watcher does not log a failure on every scan and
// every -wal event. The cursor stays at fromOffset, no rows are emitted,
// and detail is returned as a warning only the first time this
// (tool, path) pair is seen in that state, so it is logged once per
// file. Call ClearNotReady once the store parses again, so a later
// regression is reported again.
func NotReadyResult(tool, path string, fromOffset int64, detail string) ParseResult {
	res := ParseResult{NewOffset: fromOffset}
	if _, seen := notReadyWarned.LoadOrStore(notReadyKey(tool, path), struct{}{}); !seen {
		res.Warnings = []string{tool + ": " + filepath.Base(path) + ": " + detail}
	}
	return res
}

// ClearNotReady forgets an earlier NotReadyResult warning for
// (tool, path).
func ClearNotReady(tool, path string) {
	notReadyWarned.Delete(notReadyKey(tool, path))
}

func notReadyKey(tool, path string) string { return tool + "|" + path }
