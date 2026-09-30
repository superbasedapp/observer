// Package requestclass is the ONE owner of the client-declared request class
// of a proxy-captured turn (api_turns.request_class: agent migration 144 on
// the node, server migration 188 / PostgreSQL 0054 on the org) and of the
// per-class spend split both dashboards render from it.
//
// The vocabulary is CLOSED - exactly the five classes Claude Code documents
// for its x-claude-code-request-class gateway hint header (main, subagent,
// workflow, compaction, auxiliary). Normalize maps anything else (absent, a
// future class, a different casing, a malformed value) to "", which every
// store writes as NULL: unknown means unknown, never the nearest known class.
// The proxy reads the header through Normalize, the org ingest re-validates
// the wire value through it, and both session details split spend through
// Summarize, so the node and the org cannot disagree about which rows are
// classified or how they add up.
//
// Pure: no database/sql, net/http or fsnotify (pinned by imports_test.go).
// Callers load their own counted proxy rows and pass plain values in.
package requestclass
