// Package isolation is the isolation engine's one small API for callers
// outside the sandbox module (sandbox plan v2 section 11.1, joint roadmap
// F0-11, component `isolation`): a one-shot isolated run of a single
// program with no network. It adapts the pure one-shot planner
// (internal/sandbox.BuildOneShot) to the shared runner's
// extrun.IsolationProvider seam, so internal/extrun wraps a checked plan in
// bwrap without knowing the planner.
//
// The package is pure: it composes argv and never executes anything (the
// runner's executor in internal/extrun/host starts bwrap). The host facts
// (the resolved bwrap path, the home, ~/.observer, the host socket masks)
// are injected by the cmd layer (cmd/observer/isolation_wire.go), which
// hands a consumer an extrun.IsolationFactory only while this component is
// compiled in and active. The security module never imports this package.
package isolation
