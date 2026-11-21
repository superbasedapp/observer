package spanprice

import "strings"

// kind.go - which spans carry a trace's cost (live findings L-03, L-07). A
// span is priced, counted in a trace's cost provenance and summed into a
// trace's tokens and cost only when its kind is a model call. Agent, chain,
// retriever, tool and the other container kinds may restate their children's
// usage (the Vercel AI SDK's invoke_agent span carries the summed usage of
// every chat call under it), so pricing them counts the same call twice. The
// rule is by KIND, decided on the normalized span-kind vocabulary both the
// machine and the org store, so neither side branches on an instrumentor.
//
// Embedding stays a cost kind here as it was before: whether a trace's TOTAL
// counts embedding spans is ruling E-17's, and is decided where the total is
// summed, not here.

// The span kinds that are model calls (the shared obs_spans.kind vocabulary).
const (
	KindLLM       = "llm"
	KindEmbedding = "embedding"
)

// costKinds is the cost-kind table: the model-call kinds, plus "" (a span
// whose kind a caller did not state keeps the old, kind-blind rule).
var costKinds = []string{"", KindLLM, KindEmbedding}

// CostKind reports whether a span of kind is a model call whose usage and
// cost are priced and counted.
func CostKind(kind string) bool {
	k := strings.ToLower(strings.TrimSpace(kind))
	for _, c := range costKinds {
		if k == c {
			return true
		}
	}
	return false
}

// CostKindSQL is the SQL predicate of CostKind over a kind column (for
// example "sp.kind"): every store that sums or counts span cost filters with
// it, so the SQL and the Go rule cannot drift.
func CostKindSQL(col string) string {
	quoted := make([]string, len(costKinds))
	for i, c := range costKinds {
		quoted[i] = "'" + c + "'"
	}
	return "COALESCE(" + col + ",'') IN (" + strings.Join(quoted, ",") + ")"
}

// CostBearingSQL is the SQL predicate of CostBearing over a span row with
// alias a (for example "sp"): a cost kind with token counts, a cost source or
// a non-zero cost.
func CostBearingSQL(a string) string {
	p := ""
	if a != "" {
		p = a + "."
	}
	return "(" + CostKindSQL(p+"kind") + " AND (COALESCE(" + p + "input_tokens,0) + COALESCE(" + p + "output_tokens,0) > 0" +
		" OR COALESCE(" + p + "total_tokens,0) > 0 OR COALESCE(" + p + "cost_source,'') <> '' OR COALESCE(" + p + "cost_usd,0) <> 0))"
}

// ModelSpanSQL is the SQL predicate of ModelSpan over a span row with alias a.
func ModelSpanSQL(a string) string {
	p := ""
	if a != "" {
		p = a + "."
	}
	return "(" + CostKindSQL(p+"kind") + " AND COALESCE(" + p + "model,'') <> '')"
}

// ModelSpan reports whether a span names a model on a model-call kind: the
// trace made (or tried to make) a model call, whether or not usage was
// reported. A trace with none answers ProvenanceNoModelCalls (L-21).
func ModelSpan(kind, model string) bool {
	return CostKind(kind) && model != ""
}
