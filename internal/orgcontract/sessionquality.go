package orgcontract

// sessionquality.go is the session quality score org wire (post-Agent-Access
// backlog follow-up BL2-ORG, docs/plans/post-agent-access-backlog-tracker-
// 2026-09-27.md). One row per SCORED session, composed node-side by
// internal/store/sessionqualitysummary.go.
//
// WHY A SEPARATE, RE-PUSHABLE ROW. The score is written by the node's
// AutoScorer (internal/intelligence/scoring, the one writer) AFTER a session
// has gone idle - by which time its sessions row has usually already shipped
// on the rowid cursor. A column on SessionRow would therefore almost never
// reach the org. This row is a windowed snapshot wire instead (the SessionLOC
// precedent): its window is on scored_at, so a session scored or re-scored now
// ships on the next push however long ago its sessions row went out.
//
// DEFAULT POSTURE: metadata, unconditional. Every field is a derived number
// computed locally by a rule-based scorer (no model, no content): ratios,
// token counts and a timestamp. It is the same disclosure class as
// SessionRow.TotalActions, so it rides no share tier and no raw-content gate.
//
// HONESTY. Only a session the scorer actually wrote ships a row - an unscored
// session is ABSENT from the wire, never a zero row, and the org surface says
// "not scored yet". The pointer fields are nil exactly where the node's column
// is NULL (the wasteful/necessary split needs cache events; a first-edit turn
// needs an edit), and must stay "not recorded" on the org, never 0.

// SessionQualityRow is one session's persisted spec §15.2 quality score as the
// node's scorer left it.
//
// Natural key on the server is (org_id, pushed_by_user_id, session_id) - the
// OWNER is in the key (unlike the ORG-SCOPE-2 summary tables), because org
// sessions are keyed (id, user_id) and two developers may push the same id.
// The upsert only replaces a stored row with one whose ScoredAt is at least as
// new (see internal/orgserver/ingest/sessionquality.go), so a straggler push
// of an older score never overwrites a newer one.
type SessionQualityRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (the server
	// re-stamps both from the authenticated pusher, like every wire row).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
	SessionID string `json:"session_id"`

	// QualityScore is the blended 0-1 score. Always present on a shipped row.
	QualityScore float64 `json:"quality_score"`
	// The four weighted components (nil = not recorded by the scorer version
	// that wrote the row).
	RedundancyRatio       *float64 `json:"redundancy_ratio,omitempty"`
	ErrorRate             *float64 `json:"error_rate,omitempty"`
	ExplorationEfficiency *float64 `json:"exploration_efficiency,omitempty"`
	ContinuityScore       *float64 `json:"continuity_score,omitempty"`
	// Side metrics the scorer records alongside.
	OnboardingCost          *int64   `json:"onboarding_cost,omitempty"`
	TurnsToFirstEdit        *int64   `json:"turns_to_first_edit,omitempty"`
	RetryCostTokens         *int64   `json:"retry_cost_tokens,omitempty"`
	StaleReadsWasteful      *int64   `json:"stale_reads_wasteful,omitempty"`
	StaleReadsNecessary     *int64   `json:"stale_reads_necessary,omitempty"`
	RedundancyRatioWasteful *float64 `json:"redundancy_ratio_wasteful,omitempty"`

	// ScoredAt is when the node wrote the score, as a FIXED-WIDTH UTC
	// timestamp (2006-01-02T15:04:05.000000000Z) so a plain text comparison
	// orders two stamps correctly on both org engines - the upsert's
	// newest-wins guard depends on that.
	ScoredAt string `json:"scored_at"`
	// ScoredActionCount is how many actions the scorer saw; the org compares
	// it with the session's pushed total_actions to say "scored before N
	// newer actions".
	ScoredActionCount *int64 `json:"scored_action_count,omitempty"`

	// The formula weights of the scorer that composed the row, so the org
	// renders the same formula the node does without a copy of the constants.
	WeightRedundancy  float64 `json:"weight_redundancy"`
	WeightError       float64 `json:"weight_error"`
	WeightExploration float64 `json:"weight_exploration"`
	WeightContinuity  float64 `json:"weight_continuity"`
}
