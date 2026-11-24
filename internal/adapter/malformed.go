package adapter

import (
	"fmt"
	"path/filepath"
)

// NoteMalformedRows records, as one warning on res, how many rows an
// SQLite-backed adapter's json_valid guards skipped in this pass because
// their vendor JSON column was malformed (CAPTURE-02).
//
// Without the guard, SQLite's json_extract raises "malformed JSON" on such
// a row, the whole pass fails, the cursor never advances, and every later
// pass fails on the same row, so capture for that store stops for good.
// With the guard the row is skipped and the watermark moves past it; this
// warning is what keeps the skip visible. The watcher logs ParseResult
// warnings (deduplicated per adapter, path and text), so the count is
// logged once per pass that skipped anything. n <= 0 adds nothing.
func NoteMalformedRows(res *ParseResult, tool, path string, n int64) {
	if res == nil || n <= 0 {
		return
	}
	res.Warnings = append(res.Warnings, fmt.Sprintf(
		"%s: %s: skipped %d row(s) whose JSON data is malformed", tool, filepath.Base(path), n))
}
