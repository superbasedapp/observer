package mcp

// V7-17 (notes-file polish, v1.7.16+): in-band warnings on V7-12 tool
// responses. Closed-set tag strings — agents pattern-match against
// these constants rather than parse free text. Operators can also
// log/alert on the tags directly.
//
// Tags are emitted via the `warnings: [...]` envelope field on every
// V7-12 tool result. Empty slice marshals as omitted (omitempty) so
// pre-v1.7.16 callers see no observable change.
const (
	// WarningIndexUnavailable fires when the codeintel Provider's
	// Available() is false at request time. Paired with degraded: true.
	// The regex fallback in livesym.Parse may produce approximate
	// matches. (Renamed from codegraph_unavailable in Phase 4 when the
	// external codegraph dependency was decommissioned.)
	WarningIndexUnavailable = "index_unavailable"

	// WarningIndexStale fires when the codeintel Provider's
	// Stale(absPath) is true — the file's mtime is meaningfully newer
	// than the index's last pass. Per-match line numbers may be off;
	// drift signal (index_lines + live_lines) fields surface the
	// divergence. (Renamed from codegraph_stale in Phase 4.)
	WarningIndexStale = "index_stale"

	// WarningIndexChangedMidQuery fires when the index DB's mtime
	// changed between observer-serve startup and the current query
	// (V7-13 Gap 5 b). The slog Warn line goes to stderr; this tag
	// mirrors it in-band so the agent can adjust trust on the response
	// without an out-of-band channel.
	WarningIndexChangedMidQuery = "index_changed_mid_query"

	// WarningRegexFallbackLanguageUnsupported fires when the request
	// targeted a file whose extension is outside livesym's supported
	// set AND the codeintel index is unavailable. Matches will be empty.
	WarningRegexFallbackLanguageUnsupported = "regex_fallback_language_unsupported"

	// WarningProjectArchived fires when a symbol tool's answer was empty
	// or degraded AND the project carries a corpus-archival marker — its
	// index was moved to cold storage rather than deleted
	// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md).
	//
	// It is deliberately its own tag rather than a flavour of
	// index_unavailable: "the index is missing" and "the index exists and
	// is one rehydrate away" lead an agent to different next actions, and
	// collapsing them would reproduce the silent-empty the marker exists
	// to prevent. The accompanying `note` carries the date and the two
	// recovery commands.
	WarningProjectArchived = "project_archived"
)

// appendWarning adds tag to dst iff not already present. Cheap
// O(n) dedup — the slice rarely exceeds 3 entries.
func appendWarning(dst []string, tag string) []string {
	for _, t := range dst {
		if t == tag {
			return dst
		}
	}
	return append(dst, tag)
}

// allKnownWarnings lists every tag the V7-12 tools currently emit.
// Pinned by TestKnownWarnings_AreStable so a typo in a tag constant
// trips CI rather than silently shipping a malformed warning to
// agents.
func allKnownWarnings() []string {
	return []string{
		WarningIndexUnavailable,
		WarningIndexStale,
		WarningIndexChangedMidQuery,
		WarningRegexFallbackLanguageUnsupported,
		WarningProjectArchived,
	}
}
