package store

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// tokenreliability.go owns how InsertTokenEvents' ON CONFLICT reconciles a
// re-parse of the SAME logical token event (same source_file +
// source_event_id) whose `reliability` differs from the stored row's.
//
// WHY. Before this table the upsert never touched `reliability`: a row kept
// the tier of its FIRST emission forever while its counts MAX-upgraded. That
// is wrong exactly when a source changes its mind about whether its counts
// are measured at all. Crush is the grounded case (docs/crush-adapter.md):
// a one-step session's counters ARE the session total (approximate, real
// counts), but once the session grows a second step the counters become a
// last-step context snapshot and the adapter re-emits the row as 0/0 with
// Reliability unknown. Under the old upsert the step-one counts and
// `approximate` stuck until `observer backfill --crush-rescan`.
//
// THE RULE is an ordered table walked top-down, first match wins
// (CLAUDE.md #5). Each row says what happens to `reliability` and whether
// the token-count columns keep their MAX-monotone merge or are REPLACED by
// the incoming emission. Every other column (model, cost, message_id,
// turn_id, generation timing, is_sidechain, web_search_requests) keeps its
// own existing rule in every row.
//
// SAFETY ARGUMENT. Rows 2 and 3 are the only behaviour changes, and both
// require one side to be literally `unknown` - the tier that means "these
// counts are not measured". Every adapter that relies on the MAX merge
// (primeagent's child_usage_attributed fold, openclaw's message-log /
// trajectory overlap, session-cumulative rows from goose / droid /
// mistralcode / copilot session_summary, copilot's snapshot+patches) re-emits
// under ONE constant tier, so row 1 applies to them and nothing changes. Two
// DIFFERENT measured tiers under one key (row 4) keep the old behaviour: the
// table has no evidence to prefer either, so the first-stored tier stands.
//
// A DEMOTION (row 3) is deliberately narrow: the incoming emission must be
// `unknown` AND carry zero in every token dimension. That is an adapter
// restating the row as "not measured", never a partial in-flight parse (a
// partial parse still carries its measured tier and falls to row 1's MAX,
// so it can never lower a count). An `unknown` emission that nevertheless
// carries counts is contradictory and changes nothing (row 4).

// tokenCountAction is what a reconcile row does to the token-count columns.
type tokenCountAction int

const (
	// countsMax keeps the monotone MAX merge (the pre-table behaviour).
	countsMax tokenCountAction = iota
	// countsReplace takes the incoming emission's counts verbatim.
	countsReplace
)

// reliabilityAction is what a reconcile row does to the reliability column.
type reliabilityAction int

const (
	// reliabilityKeep leaves the stored tier.
	reliabilityKeep reliabilityAction = iota
	// reliabilityAdopt takes the incoming tier.
	reliabilityAdopt
)

// measuredReliabilityTiers are the tiers that assert the counts were
// measured (however approximately). `unknown` is the one tier that does not.
var measuredReliabilityTiers = []string{
	models.ReliabilityAccurate,
	models.ReliabilityApproximate,
	models.ReliabilityUnreliable,
}

// tokenCountColumns are the columns a countsReplace row replaces. They are
// the token dimensions InsertTokenEvents otherwise MAX-merges; cost and
// web_search_requests are NOT here (their own rules stand in every row).
var tokenCountColumns = []string{
	"input_tokens",
	"output_tokens",
	"cache_read_tokens",
	"cache_creation_tokens",
	"cache_creation_1h_tokens",
	"reasoning_tokens",
}

// reliabilityRule is one row of the reconcile table. when is a SQL predicate
// over the stored row (token_usage.*) and the incoming one (excluded.*).
type reliabilityRule struct {
	name        string
	when        string
	reliability reliabilityAction
	counts      tokenCountAction
}

// sqlInList renders a quoted SQL IN-list of fixed vocabulary strings.
func sqlInList(vals []string) string {
	q := make([]string, len(vals))
	for i, v := range vals {
		q[i] = "'" + strings.ReplaceAll(v, "'", "''") + "'"
	}
	return "(" + strings.Join(q, ", ") + ")"
}

// incomingCountsAllZero is true when the incoming emission carries no
// token count in any dimension.
func incomingCountsAllZero() string {
	parts := make([]string, len(tokenCountColumns))
	for i, c := range tokenCountColumns {
		parts[i] = "COALESCE(excluded." + c + ", 0) = 0"
	}
	return strings.Join(parts, " AND ")
}

// tokenReliabilityRules is THE reconcile table, walked top-down.
var tokenReliabilityRules = []reliabilityRule{
	{
		// (1) Same tier: the pre-table behaviour, unchanged. Every
		// MAX-reliant adapter lands here.
		name:        "same tier: keep, MAX counts",
		when:        "COALESCE(token_usage.reliability, '') = COALESCE(excluded.reliability, '')",
		reliability: reliabilityKeep,
		counts:      countsMax,
	},
	{
		// (2) A row stored as not-measured is now measured: adopt the
		// measured tier; the MAX merge lifts the stored zeros.
		name: "unknown promoted by a measured tier: adopt, MAX counts",
		when: "token_usage.reliability = '" + models.ReliabilityUnknown + "'" +
			" AND excluded.reliability IN " + sqlInList(measuredReliabilityTiers),
		reliability: reliabilityAdopt,
		counts:      countsMax,
	},
	{
		// (3) The source restates a measured row as not measured (all
		// counts zero, tier unknown): demote and REPLACE the counts, so a
		// stale partial count is not passed off as the total.
		name: "measured demoted by an all-zero unknown restatement: adopt, replace counts",
		when: "excluded.reliability = '" + models.ReliabilityUnknown + "'" +
			" AND token_usage.reliability IN " + sqlInList(measuredReliabilityTiers) +
			" AND " + incomingCountsAllZero(),
		reliability: reliabilityAdopt,
		counts:      countsReplace,
	},
	{
		// (4) Anything else (two different measured tiers, an empty tier
		// on either side, an unknown emission that still carries counts):
		// no evidence to choose, keep the pre-table behaviour.
		name:        "any other change: keep, MAX counts",
		when:        "1",
		reliability: reliabilityKeep,
		counts:      countsMax,
	},
}

// reliabilityReconcileSQL renders the reliability column's SET expression
// from the table.
func reliabilityReconcileSQL() string {
	var b strings.Builder
	b.WriteString("CASE")
	for _, r := range tokenReliabilityRules {
		b.WriteString(" WHEN ")
		b.WriteString(r.when)
		if r.reliability == reliabilityAdopt {
			b.WriteString(" THEN excluded.reliability")
		} else {
			b.WriteString(" THEN token_usage.reliability")
		}
	}
	b.WriteString(" ELSE token_usage.reliability END")
	return b.String()
}

// countsReplacePredicateSQL renders a predicate that is true exactly when the
// FIRST matching table row replaces counts (first-match semantics: an earlier
// countsMax row shadows a later countsReplace one).
func countsReplacePredicateSQL() string {
	var b strings.Builder
	b.WriteString("(CASE")
	for _, r := range tokenReliabilityRules {
		b.WriteString(" WHEN ")
		b.WriteString(r.when)
		if r.counts == countsReplace {
			b.WriteString(" THEN 1")
		} else {
			b.WriteString(" THEN 0")
		}
	}
	b.WriteString(" ELSE 0 END) = 1")
	return b.String()
}

// renderTokenUpsertSQL fills the reconcile placeholders of InsertTokenEvents'
// UPSERT from the table: {{replace_counts}} (true when the first matching row
// replaces the token counts) and {{reliability}} (the reliability column's
// SET expression). The table is the one owner; the statement only names
// where it applies.
func renderTokenUpsertSQL(stmt string) string {
	return strings.NewReplacer(
		"{{replace_counts}}", countsReplacePredicateSQL(),
		"{{reliability}}", reliabilityReconcileSQL(),
	).Replace(stmt)
}
