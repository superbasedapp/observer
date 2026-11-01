// Package securityscanning is the `security.scanning` policy FAMILY body
// (security pillar plan 4.9, lane SEC-E milestone 1): the org's scanner
// floors for the security module. A body raises the node's own settings,
// never lowers them, on the axes listed in Axes; each `sections.<child>`
// entry carries the capability token `security.<child>.v1` so the org
// server and the node agree on which child components a body needs.
//
// The package holds the whole family as data and pure functions:
//
//   - the JSON wire body (Body), its strict decoder (DecodeBody: unknown
//     fields refused, a size cap, trailing data refused, every enum value
//     checked against its axis through postureop.ReviewEnums) and the
//     compiler (CompileBody) that returns the canonical bytes the org
//     server signs;
//   - the vocabularies (children, drivers, scanner sources) and the axis
//     table, weaker to stronger, so a value added without a direction
//     review fails the tests;
//   - the node-side evaluation (Evaluate, CheckPosture, LiveCapabilities)
//     over a NodeFacts value the cmd layer supplies through SetNodeFacts.
//     Nothing here reads config.toml, the store or the network: the cmd
//     layer binds one provider (cmd/observer/security_scanning_wire.go).
//
// Floors only raise. On an individual node a floor whose child component
// is absent, or a key that only a managed node honours, is reported
// not_applicable with a named reason, never forced and never silently
// dropped; a key that has no setting built on this node yet is reported
// not_applicable: not_built. On a managed node a section whose child
// component is not active refuses the body at the capability gate, because
// the node does not advertise that section's token.
//
// Pure package: no SQL, HTTP, fsnotify, config or store (imports_test.go).
package securityscanning
