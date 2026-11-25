package orgcontract

// ProjectPatternRow is the W3.3 Discovery/Patterns wire row (see
// docs/plans/org-parity-full-depth-plan-2026-08-24.md §4 "W3.3"): one row per
// (project, pattern kind, value) pair, mirroring the node's `project_patterns`
// table (internal/intelligence/patterns) and the read-side the node's
// Discovery/Patterns dashboard pages + the MCP get_project_patterns tool
// already surface (hot files, repeated commands, and the five other derived-
// pattern kinds the Deriver produces: co-change, edit/test pairing,
// onboarding sequence, cross-tool file, knowledge snippet).
//
// Privacy posture (§0.1 — enterprise-first, admin_managed ships raw by
// default): unlike SessionVerbosityRow (which carries no content to gate),
// this row's Value IS content — a filesystem path or a shell command, and
// for the five composite kinds a small JSON blob (which, for
// knowledge_snippet, itself carries a short reasoning-text excerpt). It
// therefore follows the SAME two-tier convention as SessionRow's
// ProjectRoot/ProjectRootHash: a content-free ProjectRootHash is always
// present, ProjectRoot ships only under shipsRawContent() — and unlike
// SessionRow, Value itself ALSO ships only under that same gate (there is no
// content-free form of Value; a kind/count-only row without a path or
// command is not useful to the fleet/per-dev pattern surfaces this feeds).
// The store seam (internal/store/patternsorgrows.go) is therefore only
// invoked from orgpush.go's existing shipsRawContent() block, exactly like
// SessionVerbositySummaries/SessionCacheSummaries/SessionProcesses.
//
// Value extraction by Kind mirrors internal/mcp/tools_get_project_patterns.go's
// get_project_patterns "derived_patterns" half (which reads project_patterns
// directly, the same source this row reads):
//   - "hot_file"       → pattern_data.file_path (the raw path).
//   - "common_command" → pattern_data.command (the raw shell command).
//   - all other kinds ("co_change", "edit_test_pair",
//     "onboarding_sequence", "cross_tool_file", "knowledge_snippet") → the
//     raw pattern_data JSON blob as-is (multi-field composites not
//     reducible to a single string).
//
// UserEmail attributes the row to the pushing node's operator — the node
// table `project_patterns` is project-scoped, not per-user (patterns are
// derived from the WHOLE project's action history, not one developer's), so
// this row records which developer's node observed/derived it, not that the
// pattern is exclusive to them. The fleet rollup (rollup.PatternsFleet) is
// where cross-developer / cross-tool overlap on the SAME (project, kind,
// value) is aggregated back out.
type ProjectPatternRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping
	// rule as every other wire row — see ingest.go forcePusherOrgID /
	// forcePusherEmail).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// ProjectRootHash is the content-free project identity — always
	// present. ProjectRoot is the raw path, present only under
	// shipsRawContent() (this row is only selected under that gate in the
	// first place, but the field still follows the omitempty convention so
	// a future relaxation of the outer gate doesn't silently leak it).
	ProjectRootHash string `json:"project_root_hash"`
	ProjectRoot     string `json:"project_root,omitempty"`

	// Kind is one of the node's seven pattern_type values (see
	// internal/intelligence/patterns.Type* constants): hot_file,
	// co_change, common_command, edit_test_pair, onboarding_sequence,
	// cross_tool_file, knowledge_snippet.
	Kind string `json:"kind"`

	// Value is the raw path/command/JSON payload — see the Value
	// extraction rule in the type doc comment above. Content-bearing;
	// ships only under shipsRawContent().
	Value string `json:"value,omitempty"`

	// ObservationCount / Confidence mirror project_patterns.observation_count
	// / .confidence — how many times the pattern was observed and the
	// Deriver's confidence score for it.
	ObservationCount int64   `json:"observation_count,omitempty"`
	Confidence       float64 `json:"confidence,omitempty"`

	// SourceTools is the CSV of tools that contributed observations to
	// this pattern (project_patterns.source_tools) — the raw input to the
	// fleet rollup's cross-tool-overlap signal.
	SourceTools string `json:"source_tools,omitempty"`

	// LastSeen is project_patterns.last_reinforced_at (RFC3339, node-local
	// clock) — when the pattern was last reinforced by an observation.
	LastSeen string `json:"last_seen,omitempty"`
}
