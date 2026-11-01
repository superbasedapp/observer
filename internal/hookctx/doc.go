// Package hookctx is the hook context seam (joint security and sandbox
// roadmap docs/plans/security-and-sandbox-joint-roadmap-2026-10-20.md,
// piece F0-3; security pillar plan sections 4.7 item 2 and 4.8; sandbox
// plan section 5.2, the hook-context inventory).
//
// One function, (*Context).Fill, fills the context a hook event is judged
// in: the process facts (parent process id, ancestry, environment), the
// files a payload names, Event.Security, the dirty-marker raise and the
// quick-scan request. It has two entry points, one per caller:
//
//   - Host is the hook process on the developer's machine (the direct
//     `observer hook` path). Process facts and files come from the
//     operating system. Event.Security comes from the signed posture
//     sidecar, the dirty marker is a file the hook raises, and the quick
//     scan is a request to the daemon over loopback.
//   - Daemon is the sandbox capture relay's handler, running inside the
//     daemon for an event relayed out of a sandbox. Process facts and files
//     come from the run's channel, never from the daemon's own process or
//     filesystem. Event.Security comes from the daemon's in-memory posture
//     (no sidecar is read), the dirty marker is raised in the daemon before
//     it replies, and the quick scan runs in process.
//
// Every security and sandbox extension point is an injected provider whose
// nil value does nothing, so today's hook path pays for none of them: with
// nil providers Fill does no I/O and starts no goroutine (pinned by the
// tests). A provider that fails, panics or overruns its time limit never
// blocks the hook: Fill records an Issue and degrades the fact to its
// honest unknown value. Only internal/guard's deny and ask path turns a
// fact into a block.
//
// The package is a neutral core leaf on the internal/hook side: neither the
// security module nor the sandbox module owns it, so both can import it
// (tests/invariant/components_fence_test.go). It imports no database, HTTP
// or fsnotify package and none of either module's packages
// (TestNoForbiddenImports in hookctx_test.go pins that); the only
// operating-system access is the host Source, which
// the Host entry point and the HostSource helper name.
package hookctx
