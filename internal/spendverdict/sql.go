package spendverdict

// The SQL fragments a windowed spend reader applies the stored verdicts with
// - the node twins of the org's rollup countedTokenRow / proxyVerdictJoin /
// countedProxyRow / proxyOutput / proxyReasoning. None binds a value.
//
// A token_usage arm filters with CountedTokenRow. An api_turns arm adds
// ProxyVerdictJoin to its FROM, filters with CountedProxyRow, and reads its
// output through ProxyOutput (and, where the substrate carries them,
// ProxyReasoning / ProxyInheritedFast). Summing what remains the ordinary
// way gives every session exactly its header's figures.

// CountedTokenRow is the WHERE fragment keeping only the token_usage rows
// Derive counts. alias is the token_usage alias in the reader's FROM clause.
func CountedTokenRow(alias string) string {
	return `NOT EXISTS (SELECT 1 FROM spend_verdict_token svt WHERE svt.token_usage_id = ` + alias + `.id)`
}

// UnpairedShadowRow is CountedTokenRow for a TRANSCRIPT-ONLY read (one that
// never reads api_turns, e.g. `observer cost --source jsonl`): it drops only
// a paired output-only shadow row, the one duplicate the transcript makes of
// itself. Every other verdict names a proxy row such a read never counts.
func UnpairedShadowRow(alias string) string {
	return `NOT EXISTS (SELECT 1 FROM spend_verdict_token svt WHERE svt.token_usage_id = ` + alias + `.id AND svt.shadow = 1)`
}

// ProxyVerdictJoin is the LEFT JOIN an api_turns arm adds so the other proxy
// fragments can read the row's stored verdict (aliased svp). alias is the
// api_turns alias.
func ProxyVerdictJoin(alias string) string {
	return ` LEFT JOIN spend_verdict_proxy svp ON svp.api_turn_id = ` + alias + `.id`
}

// CountedProxyRow is the WHERE fragment keeping only the api_turns rows
// Derive counts: every row except one the session-cumulative reconciliation
// dropped.
func CountedProxyRow() string {
	return `COALESCE(svp.counted, 1) = 1`
}

// ProxyOutput is the output an api_turns row contributes: its transcript
// twin's visible output when Derive split it, else its own stored output.
func ProxyOutput(alias string) string {
	return `COALESCE(svp.output_tokens, ` + alias + `.output_tokens, 0)`
}

// ProxyReasoning is the reasoning an api_turns row contributes: its twin's
// reasoning when Derive split it, else 0 (api_turns has no reasoning column).
func ProxyReasoning() string {
	return `COALESCE(svp.reasoning_tokens, 0)`
}

// ProxyInheritedFast is 1 when the row's transcript twin was served in the
// fast tier and the row itself was not: the row bills at the fast tier, and
// its recorded cost (priced at the standard wire tier) no longer stands.
func ProxyInheritedFast() string {
	return `COALESCE(svp.inherited_fast, 0)`
}

// The *Of forms below read the same verdicts through correlated subqueries
// instead of the svp join, for a reader whose FROM clause names api_turns
// without an alias and whose WHERE clause uses bare column names that the
// join would make ambiguous (the guard's budget reads). table is the
// api_turns table name or alias; each subquery is one primary-key seek.

// CountedProxyRowOf is CountedProxyRow without the join.
func CountedProxyRowOf(table string) string {
	return `NOT EXISTS (SELECT 1 FROM spend_verdict_proxy svp WHERE svp.api_turn_id = ` + table + `.id AND svp.counted = 0)`
}

// ProxyOutputOf is ProxyOutput without the join.
func ProxyOutputOf(table string) string {
	return `COALESCE((SELECT svp.output_tokens FROM spend_verdict_proxy svp WHERE svp.api_turn_id = ` + table + `.id), ` + table + `.output_tokens, 0)`
}

// ProxyReasoningOf is ProxyReasoning without the join.
func ProxyReasoningOf(table string) string {
	return `COALESCE((SELECT svp.reasoning_tokens FROM spend_verdict_proxy svp WHERE svp.api_turn_id = ` + table + `.id), 0)`
}

// ProxyInheritedFastOf is ProxyInheritedFast without the join.
func ProxyInheritedFastOf(table string) string {
	return `COALESCE((SELECT svp.inherited_fast FROM spend_verdict_proxy svp WHERE svp.api_turn_id = ` + table + `.id), 0)`
}
