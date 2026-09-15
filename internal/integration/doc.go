// Package integration is the adapter Integration Capability Registry —
// the single, table-driven source of truth for what each AI-tool adapter
// can integrate with: a proxy route, a hook-registration mechanism, an
// MCP config target, vendor native-console rails, and its token/cost
// capture tier.
//
// It exists to kill a recurring anti-pattern. Before it, `observer init`
// (cmd/observer/init.go::wireAIClients), internal/hook/register.go, and
// the MCP-config writer each carried their OWN hardcoded 3-adapter switch
// (claude-code / codex / cursor), so every cross-cutting capability was a
// "two-or-three-tool club" and adding an adapter meant editing five files.
// That violates the project's anti-spaghetti rules #3 (branch on
// capabilities, never on source identity) and #5 (decision logic is
// table-driven). This package is the capability table; the writers at the
// boundary (cmd/observer, internal/hook, internal/diag) iterate it and
// dispatch on capability SHAPE, not on tool name.
//
// Design rules (CLAUDE.md module boundaries):
//   - Pure data + lookups. NO database/sql, net/http, or fsnotify — the
//     consumers own all I/O.
//   - Additive (rule #6): new capability fields must not force changes in
//     unrelated consumers; For returns a zero-value-safe Capability.
//   - One owner: this is THE registry. It subsumes the former
//     internal/diag.routableTools proxy-route table; nothing else should
//     re-declare per-tool integration capabilities.
//
// # What a row is keyed on
//
// A registry row is keyed on ADAPTER IDENTITY — one row per entry in
// internal/adapter/defaults.Adapters(), pinned in both directions by
// registry_coverage_test.go (TestRegistryCoversEveryRegisteredAdapter /
// TestRegistryHasNoOrphanRows) and a third time by
// tests/invariant/adapter_registry_sync_test.go.
//
// That is deliberately NOT the same key space as the `sessions.tool`
// column, because an adapter may re-tag its events per-file: the cline
// adapter watches both the Cline and the Roo Code VS Code task dirs and
// picks the emitted Tool from the enclosing extension directory, so
// "roo-code" is a real tool VALUE with no adapter of its own (as is
// "zoo-code", the ZooCode community continuation of Roo Code added
// 2026-09-03 via the same table). Such a tool gets tooltax vocabulary
// rows (tooltax is keyed on the emitted column, which is what Resolve
// is handed at read time) but NO capability row —
// every cell would be either zero or copied from the host adapter, and
// copying would break the registry's honesty rule that a zero value means
// "no grounded capability", never an inferred one. Contrast kilo-code,
// which DOES get a row: kilocode.NewLegacy() is a registered adapter with
// its own Name() and watch roots, even though it wraps the same parser.
//
// The gap between the two key spaces is enumerated and reasoned in
// registry_coverage_test.go::registryRowlessTaxonomyTools, so a future
// re-tagged tool that silently lacks a row fails loudly.
//
// The registry is filled incrementally across the adapter-coverage-parity
// phases (docs/plans/adapter-coverage-parity-plan-2026-06-26.md): Phase 0
// seeds the proxy-route capability (migrated from routableTools); later
// phases populate Hook, MCP, Native, and TokenTier.
package integration
