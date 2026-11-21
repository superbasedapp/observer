// Package personalmig is the pure core of `observer-cloud migrate-personal`,
// the cloud half of stage E3 (managed SaaS plan 06 section 9.4; plan 07
// M9.3; docs/plans/managed-saas/individuals/inventory.md D-IND-4, D-IND-5,
// D-IND-6).
//
// The control plane holds no credential to tenant data (plan 06 5.4), so the
// cloud half moves each personal-plane account onto its personal org (the
// org of one) and writes per-org bundles (internal/cloudcontract
// personalimport.go) the operator carries to the tenant host, where
// `observer-org tenant import-intel` imports them and writes a receipt.
//
// Everything here is decided by ordered tables walked top-down, one test case
// per row:
//
//   - scopeRules: which accounts are in scope (any personal-plane footprint:
//     an analysis result, an account-scoped Paddle subscription, a device
//     registration, or an account plan above the free floor);
//   - skipRules: which in-scope accounts are skipped, with the reason;
//   - needRules: what an account needs (ensure its personal org, re-key its
//     live plus_beta subscription onto the org, export its results);
//   - stageMoves: the ledger's stage machine
//     (planned -> org_ready -> rekeyed -> exported -> verified, plus skipped);
//   - resultRules: which analysis results are exported, and the effective
//     result of each (the AI original with every user correction folded in,
//     revision by revision, the latest present field winning).
//
// The package imports no database/sql, net, os or pgx (imports_test.go): the
// store reads the facts and the command does the I/O.
package personalmig
