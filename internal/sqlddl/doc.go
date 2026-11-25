// Package sqlddl holds the small, quote-aware text helpers that the
// repository's hand-rolled SQL DDL readers share: the structural checker
// (tools/structcheck/check, which replays both org migration lineages) and
// the tenancy manifest's lineage test (internal/orgserver/tenancy).
//
// Both used to carry byte-identical copies of these functions. They are
// deliberately simple: they read migration text the repository wrote, track
// single and double quotes and parenthesis depth, and are not a SQL parser.
// internal/migcheck is the full tokenizing migration analyzer; this package
// is only the four helpers those two DDL replays need.
//
// The package is pure: no database, network, file system or watcher import
// (imports_test.go).
package sqlddl
