// Package costseries is the one owner of the cost engine's bucketed time
// series: spend and tokens per bucket (Cost) and tokens per (bucket, model)
// (TokensByModel). The node dashboard's /api/timeseries/cost and
// /api/timeseries/tokens-by-model handlers and `observer chart` call these
// functions, so a chart in the terminal and a chart in the browser read the
// same substrate (proxy and JSONL, deduped), the same per-row pricing and
// the same bucket keys (internal/timebucket), and their numbers agree.
//
// The package holds no SQL of its own: every row comes from
// cost.Engine.Summary, which owns the queries (the *sql.DB is passed
// through to it). It makes no HTTP, filesystem-watch or subprocess call
// (pinned by imports_test.go). Handler-only logic (the lossy-eviction
// subtraction on the compression-savings fields) stays in the handler.
package costseries
