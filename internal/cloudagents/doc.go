// Package cloudagents is the pure core of the node-side cloud-agent pull
// connectors (Rail P of docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md,
// section 5.1; decisions CA-D5, CA-D11 and CA-D12).
//
// It owns, as data tables walked top-down (CLAUDE.md rule 5):
//
//   - the connector table (Connectors): one row per connector with its
//     provider, the Observer tool id its sessions land under, how it reaches
//     the vendor (a fixed-argv vendor CLI, or exact HTTPS hosts for the API
//     connectors of a later lane), its paging limits and its coverage ceiling
//     per signal;
//   - the coverage vocabulary of the reference's "Show coverage as part of
//     the product" table, the signal vocabulary, and the rule table that turns
//     an error class into a coverage state;
//   - the CA-D12 precedence tables: which token source wins for a session,
//     and how a pulled session finds the row it merges into;
//   - the vendor-status to lifecycle tables and the stderr classification
//     rules of each vendor CLI;
//   - the parsers of each connector's recorded CLI JSON, the discovery
//     overlap and gap planner, and the mapping of a pulled task to
//     models.ToolEvent / models.TokenEvent / ledger entries.
//
// It performs no I/O: no database/sql, no net/http, no os/exec, no fsnotify
// (pinned by imports_test.go). The one egress package is
// internal/cloudagentsnet, which runs the argv this package builds; the
// service internal/cloudagentssvc composes the two with the store.
//
// Honesty rules that hold everywhere here: a figure a vendor does not report
// is absent, never zero; a task that carries no repository is filed under a
// placeholder project, never a guessed one unless the connector row declares
// the inference; vendor error text never leaves the egress package, only a
// closed ErrorClass token does.
package cloudagents
