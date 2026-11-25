package contentcap

import "fmt"

// DefaultMaxBytes is the canonical upper bound for full tool
// input/output capture. Chosen to be ~256× the legacy 4000-byte cap
// while staying well below any practical SQLite row size concern. The
// observed P99 in production AI tool outputs sits around ~50 KB; the
// 1 MB ceiling only clips genuine outliers (large file dumps, full
// directory listings, multi-MB log greps).
const DefaultMaxBytes = 1 << 20 // 1 MiB

// Cap returns s if it fits within max bytes; otherwise returns
// s[:max] with a human-readable marker appended noting the truncation.
//
// max ≤ 0 is treated as DefaultMaxBytes. The marker is always
// counted OUTSIDE max — the returned slice can be at most
// max + len(marker) bytes. This keeps callers' contracts simple
// (max is the cap on the original payload, not the rendered output).
func Cap(s string, max int) string {
	if max <= 0 {
		max = DefaultMaxBytes
	}
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("\n…(content truncated at %d bytes)…", max)
}
