// Package community is the pure, compiled-in registry of the fixed, versioned
// community metrics and cohorts (divergence remediation plan §3 "W5"; operator
// ruling R3). It is the Go half of the forbidden-metric rule: a metric that is
// not in this registry is un-contributable and un-readable, table-driven, with
// no free-form slicing. It MUST stay in lockstep with the SQL seed in
// migration 0022 (community_metrics) — a store-side test
// (TestMetricRegistryMatchesSeed) pins the two against each other so drift fails
// loudly.
//
// The package is PURE: no database/sql, no net/http, no fsnotify (pinned by
// imports_test.go). Band edges are data-INDEPENDENT constants (a quantile edge
// would shift with one contributor and leak a cohort-minus-one signal), and the
// floor/k thresholds mirror the DB — the DB HARD-floors them at 30/5 regardless,
// so this registry can only ever request EQUAL-OR-STRICTER privacy, never weaker.
package community
