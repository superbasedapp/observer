// Package postureop holds the core merge operators and the result-based
// posture comparison shared by every module that lets an organization move a
// node's settings (roadmap piece F0-8, lane SHR-KIT; design of record
// docs/plans/spikes/JSP-1-governance-and-wire-2026-10.md).
//
// It is a pure leaf: standard library only (pinned by imports_test.go), so
// both the policy layer (internal/policyfam/nodegov, whose Direction aliases
// this package's) and internal/config (which may not import the policy layer)
// apply the SAME operator for a direction. Before this package the config
// overlay kept a mirror of the operators, and both it and govern.LowerInt
// read 0 as "unset", which turned a local "keep forever" retention into a
// finite one.
//
// Three things live here:
//
//   - the direction table (Rules): what an org value may be for a key with a
//     given direction, and how it merges with the node's own value;
//   - Compare over axes supplied as data: each module (security, sandbox)
//     names its posture axes and their order, and Compare reports the first
//     axis an update would loosen;
//   - ReviewEnums: a setting whose enum carries a value its axis does not
//     order fails, so a new value cannot ship without a direction review.
//
// Retention is a semantic number: 0 means forever, which is the maximum.
// On an individual node retention is raise-only (an org may lengthen it,
// never shorten it); shortening is possible only through a managed pull on a
// managed node, never through this package's merge.
package postureop
