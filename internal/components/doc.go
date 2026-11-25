// Package components is the modular-packaging component catalog
// (docs/plans/modular-packaging-plan-2026-10-07.md, phase P0, lane MP-CAT).
//
// It is pure DATA plus pure functions over that data: one Component row per
// named, catalogued slice of the product (a node feature, an adapter, an
// integration writer, an org server module), one ArtifactComponent row per
// thing installed outside the Observer binary (the browser extension and the
// separately packaged helpers), the four node distros, and the dependency
// resolver that every later phase builds on. No SQL, no HTTP, no fsnotify,
// no os/exec (pinned by imports_test.go): consumers own the I/O.
//
// What the catalog is and is not. The catalog DESCRIBES the product; nothing
// in this package switches a goroutine, a listener, a route or a verb on or
// off. The gates that do live elsewhere: build-tag wiring pairs (L1, an
// `sbo_omit_*` tag compiles a component out; a plain `go build` remains the
// full product), the runtime gate internal/componentstate (L2, resolved from
// the [components] block and, on a managed node, governance), and config
// toggles (L3). Levels.Implemented records which of those levels a
// component's code delivers today (most node rows include L1), while
// Levels.Target records where the plan takes each component.
//
// Truth is enforced by tests rather than care (plan section 3.2): the
// invariant suite in tests/invariant/components_*_test.go checks the catalog
// against the real tree (go list -deps module closures, an AST package
// fence with a ratcheted boundary-debt baseline, adapter rows against the
// integration registry and the adapter fan-in, declared listeners and
// egress hosts against the config defaults, declared tables against the
// migrations, declared verbs against the CLI). docs/components.md is
// generated from this package by cmd/sbo-components and drift-gated.
//
// The integration registry (internal/integration) stays the one owner of
// adapter integration facts; adapter rows here reference it and derive
// their Stability from its lifecycle, never a second copy.
package components
