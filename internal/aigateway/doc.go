// Package aigateway is the pure-logic core of the org AI Gateway — the
// inference data plane described in the Plane B dual-mode design
// (docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §2).
//
// The gateway is the org's single governed inference egress: coding-agent
// traffic, org-intelligence jobs, and judge/eval calls all pass through one
// registry, one budget ledger, and one metadata-only audit stream, against
// the org's OWN provider credentials (custody: a node never sees a provider
// key — §2.3).
//
// # Module discipline
//
// This root package is PURE (CLAUDE.md module rule #1, design §2.2): it
// imports no database/sql, no net/http, no fsnotify, and no internal/proxy
// or internal/orgserver package. All I/O — the virtual-key store, the
// budget/reservation ledger, the audit sink, the sealed-secret resolver,
// and the upstream HTTP dialer — is injected as interfaces defined here and
// implemented in the sibling subpackages (gwstore for SQLite-backed state,
// gwhttp for the listener + provider dispatch). imports_test.go pins that
// purity; tests/invariant/aigateway_boundary_test.go pins the reverse rule
// (internal/proxy never imports this package or orgserver).
//
// Keeping the core pure is what makes the v1.5 standalone-binary split
// (cmd/observer-aigateway) mechanical rather than a rewrite: the org-server
// identity/budget state is already behind interfaces here.
//
// # What lives here
//
//   - keys.go     — virtual-key format, mint/hash, member+machine binding,
//     TTL/rotation/revocation, the Sol S9 revocation-watermark auth cache.
//   - budget.go   — hierarchical caps and the worst-case reservation →
//     settle/refund math (Sol S1); the durable BudgetStore seam.
//   - policy.go   — model allow-lists + per-role/team tiers; max_tokens caps
//     that feed reservations.
//   - ratecard.go — the versioned rate card (Sol S12): tokens authoritative,
//     dollars estimated and labeled as such everywhere.
//   - provider.go — lane→kind parser binding, credential modes, data-control
//     annotations, pseudonymous member-identity stamping.
//   - stream.go   — the §2.7 streaming rules as pure decision types:
//     pre-first-byte verdicts, pass-through, abort-on-detect.
//   - audit.go    — the metadata-ONLY audit event and the economic-owner
//     category (developer / org_intelligence / judge).
//   - store.go    — the injected store interfaces.
package aigateway
