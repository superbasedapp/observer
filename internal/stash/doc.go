// Package stash implements content-addressed on-disk storage for the
// CCR (Compressed Content Retrieval) feature: large tool_result bodies
// are written to a flat directory keyed by their SHA-256 hash, and the
// inline body is replaced with a deterministic marker that names the
// hash. The model can pull the original bytes back via the
// `retrieve_stashed` MCP tool.
//
// See `docs/compression-roadmap.md` (Tier 1, item G31) for the
// strategic context. This package is one of three load-bearing pieces:
//
//	internal/stash/                        — disk read/write/GC
//	internal/compression/conversation/     — pipeline integration + marker
//	internal/mcp/tools_retrieve_stashed.go — retrieve_stashed tool
//
// Layout: flat. Every blob lives directly at `<dir>/<sha>` (no per-
// session subdirs). Per-session aggregation is left for K43 in Tier 3
// once we have signal data showing it pays off — until then the flat
// layout makes GC and dedup-across-sessions trivial: identical bodies
// from two different sessions hash to the same sha and share one disk
// blob.
package stash
