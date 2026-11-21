// Package cloudlane builds the per-project "where it ran" lane of the node
// Projects page (cloud-agents arc, lane CA-B5; plan section 8 of
// docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md).
//
// It buckets a project's sessions, priced turns and provider usage ledger
// figures by sessions.execution_location (local, vendor_cloud,
// customer_worker, and unknown for a NULL column) and says, per figure, how
// complete it is. The rules that matter:
//
//   - A missing figure is never a zero. A lane whose sessions carry no token
//     rows reports Tokens == nil and TokenCoverage "unknown"; a lane with no
//     priced turn reports CostUSD == nil.
//   - Provider units stay native (CA-D11). Ledger figures are grouped by
//     (connector, unit, value type, measurement source, monetary status) and
//     rolled up by a per-value-type rule table, never summed across units or
//     across snapshots of one cumulative counter.
//   - Duplicates across capture rails fold by the CA-D12 token precedence
//     (fold.go, lane CA-C1): on a session that ran off this machine only the
//     best tier present counts (in-sandbox transcript, then provider run
//     total, then OTel, then an org daily report). Local sessions pass
//     through untouched.
//
// The package is pure: no database/sql, net/http, os/exec or fsnotify
// (pinned by imports_test.go). The dashboard handler loads the rows through
// the store seams and hands them in; the cost engine has already priced each
// turn.
package cloudlane
