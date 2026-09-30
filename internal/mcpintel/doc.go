// Package mcpintel is the root of the Agent Access P11 SuperBased-native
// MCP intelligence packages (doc3 §11.12b, R9.12 / R10.12 package map).
//
// Every package under internal/mcpintel is PURE decision/derivation logic:
// no database/sql, no net/http, no fsnotify, and no store or org-server
// import. Callers load their own rows through a store seam on each side
// (internal/store on the node, internal/orgserver/... on the org) and pass
// plain values in; the packages return plain results. The subpackages are:
//
//   - correlate: P11(a) MCP call <-> coding-session correlation with an
//     honest confidence (exact | inferred | none), R10.7 / R11.8.
//   - cost: P11(b) per-server/tool ESTIMATED cost attribution, R10.8 / R11.9.
//   - discover: P11(c) shadow-MCP discovery diff, R10.10 / R12.10.
//
// Later v1.x subpackages (grantrec, simulate, risk, anomaly, roi) join the
// same map. This package deliberately does NOT reuse
// internal/intelligence/discover, which imports SQL (R10.12).
//
// imports_test.go walks this directory recursively and pins the purity
// rule for every subpackage, so a new subpackage needs no allow-list edit.
package mcpintel
