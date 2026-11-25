// Package defaults exposes the canonical set of session-file adapters
// the observer registers in production. Pulling this out of
// cmd/observer/main.go lets tests in internal/adapter/ and
// internal/watcher/ assemble the same adapter set the production
// binary uses — needed for the all-adapters IsSessionFile invariant
// test and the multi-adapter watcher regression test that pins the
// poller's dispatch rule.
//
// The sub-package shape is intentional: putting this list in
// internal/adapter directly would create an import cycle (each
// adapter package imports internal/adapter for the Adapter
// interface).
//
// Registration (modular packaging P5, lanes MP-ADP and MP-L1D, T-598):
// every adapter registers itself from one file per adapter package,
// adapter_<pkg>.go, built unless the package's catalog omit tag is set
// (`-tags sbo_omit_adapter_zed`). Its pair, adapter_<pkg>_omit.go, is built
// only with that tag and marks the component compiled out, so the binary
// reports its own compiled set. Nothing else in the node binary imports
// those packages (cmd/observer reaches an adapter's hook receiver, backfill
// passes and watcher wiring through its own build-tagged files, the same
// way), which is what the package-absence invariant (tests/invariant)
// proves per tag. Every adapter keeps one slot in the canonical order, so a
// full build's list is exactly the pre-P5 list (pinned by
// TestAdaptersCanonicalOrder).
package defaults
