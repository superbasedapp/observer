// Package execevidence is the shared execution evidence envelope (joint
// roadmap F0-13; sandbox plan v2 section 8.4; security plan sections 7.4
// and 7.10): one closed, versioned record of who ran what, how isolated,
// and what Observer could capture of it, with a digest over its canonical
// form so a later record (a security change record, an org row) can name it
// and detect a change.
//
// Its first consumer is the sandbox module's G19 evidence: the isolation
// facts of a terminal run (class, stack, egress tier, computed capture
// level and origin, native-sandbox state, verification, key custody) on the
// node's terminal_run row and the org wire's TerminalRunRow. The security
// plan's change records reference a run's envelope by digest when one
// exists and stay valid when the sandbox module is absent.
//
// The package is pure and in core (no component owns it), so both optional
// modules can use it without importing each other: it imports only the
// neutral vocabulary leaf internal/sandboxvocab and the standard library.
package execevidence
