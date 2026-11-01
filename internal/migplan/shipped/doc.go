// Package shipped holds the released-step rule for every migration lineage
// (D-880, T-982): once a step has shipped, no new step in that lineage may be
// numbered at or below the shipped head, and a shipped step's file never
// changes or disappears.
//
// "Shipped" means the step is in a public release tag, or it runs on a hosted
// production database we cannot rebuild (the Cloud Intelligence service at
// cloud.superbased.app). The committed record of what shipped lives at
// RecordPath; tools/shippedmiggen writes it from a git ref and
// tests/invariant/shipped_migrations_test.go holds the working tree to it.
//
// With the rule in force every release only appends steps after the previous
// release's last step, so no install ever receives a late lower-numbered step
// and the update path's snapshot rule (snapshot when the manifest
// schema_version rises) is always enough. The per-step ledger
// (internal/migplan) stays as the backstop for unreleased builds.
//
// The package is pure: it decides, the caller reads the tree (the invariant
// test reads files, the generator reads git). See docs/migration-numbering.md,
// "The released-step rule".
package shipped
