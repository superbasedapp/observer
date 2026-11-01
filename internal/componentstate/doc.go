// Package componentstate is the ONE owner of the node's component
// selection and effective set (modular packaging plan section 6.1, phase
// P1, lane MP-GATE).
//
// It turns the operator's [components] config block (config.ComponentsConfig)
// and the binary's own compiled set (components.Compiled) into a Snapshot
// through the catalog's single resolver (components.Resolve). Every wiring
// site that starts a goroutine, binds a listener, makes an outbound call or
// writes a file on behalf of an optional component asks the same question,
// Snapshot.Active(id), so the L2 "installed but inert" guarantee has one
// seam (plan section 4). An optional module (security, terminals.sandbox)
// asks Snapshot.ModuleActive(id) instead, which treats an id the catalog does
// not know as off ("fail invisible"); module.go says when to use which, and
// registers the resolver config.Load uses to skip validating a section whose
// component is not active.
//
// The zero [components] block is today's behaviour: every compiled
// component is active and each feature's own config switch still decides
// whether it runs. Nothing in this package can make an existing install
// without the block behave differently.
//
// Pure (CLAUDE.md module rule 1): no SQL, HTTP, fsnotify or os/exec. The
// writer of the block is internal/componentsvc. Managed-node policy rows
// (plan 6.2) are added later as resolver input (lane MP-GOVF), never as a
// second resolver here.
package componentstate
