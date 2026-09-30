// Package mcpschema canonicalizes, hashes and diffs the FULL MCP tool
// descriptors an upstream server advertises through tools/list (Agent Access
// implementation plan section 11.4 W2a, rulings R8.10 and R9.8).
//
// It EXTENDS internal/guard/mcpsec, which pins only a tool's name,
// description and depth-1 parameter docs for the node-side guard: here the
// whole JSON Schema 2020-12 inputSchema / outputSchema and the tool
// annotations are part of the pinned surface, because a rug-pull that keeps
// the description and changes a nested property, a default, an enum or a
// destructiveHint must read as drift. mcpsec is neither reused nor modified.
//
// Canonical form (the one owner of what schema_hash covers):
//
//   - JSON objects are serialized with keys in byte order, no insignificant
//     whitespace, strings escaped minimally (no HTML escaping), numbers in a
//     normalized text form (integers verbatim, floats via the shortest
//     round-trip representation);
//   - LOCAL $ref pointers ("#/$defs/x", "#/definitions/x", any "#/..." JSON
//     pointer) are resolved by inline substitution, BOUNDED by a maximum
//     resolution depth and a maximum total number of expansions, and a
//     reference cycle is an error rather than an infinite expansion. A
//     sibling keyword beside $ref is merged over the resolved target (the
//     2020-12 "siblings apply too" reading; on a key conflict the sibling
//     wins). A NON-local $ref (a URL) is left verbatim: the canonical form
//     never fetches anything;
//   - tools are ordered by name; a duplicate tool name is an error.
//
// SchemaHash is SHA-256 over a versioned preamble and the canonical
// descriptors; CfgHash covers the launch/config SHAPE only (transport, URL,
// command, args, env KEY names, header NAMES - never a value). Diff produces
// the drift artifact: added / removed / changed tool names with the changed
// fields, plus the subset of touched tools whose effective destructiveHint is
// true (feeding the annotation override of R9.8/R12.11).
//
// NameMap is the explicit native<->exposed tool-name mapping (R8.10): every
// native key must exist in the snapshot, every exposed name must be a valid
// tool name and unique across the exposed set, and the reverse lookup is
// what the data plane uses to route an exposed name back to the upstream.
//
// The package is PURE (CLAUDE.md module rule 1): encoding/json and the
// standard library only - no database/sql, net/http or fsnotify
// (imports_test.go pins it).
package mcpschema
