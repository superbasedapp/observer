// Package policyfam is the umbrella for the PURE per-family policy
// compilers behind the unified org policy resource
// (docs/plane-a/unified-policy-resource.md §3;
// docs/plans/plane-a-p0-5-unified-policy-resource-v1-plan.md Phase F).
//
// "Family" is the unified-resource concept: one closed enum value selects
// exactly one existing enforcement engine and its compiled spec type — no
// family is a new engine (unified-policy-resource.md §3). Each subpackage
// here (internal/policyfam/admission, internal/policyfam/egress) is the
// extracted, engine-specific COMPILER for one family: it owns the plain
// PolicyInput, the compiled PolicySpec, the enums Compile resolves, Lint,
// and the versioned wire boundary (BodyV1 + DecodeBody + CompileBody) that
// turns a signed org resource's Body into a ready spec.
//
// Every family subpackage is pure — no database/sql, net/http, fsnotify, or
// internal/obs — pinned by its own imports_test.go, so internal/orgserver
// (compiling a published body before signing) and internal/orgclient
// (compiling a fetched, verified body before installing it) can depend on
// policyfam directly without pulling in internal/obs's evaluation engines,
// judge client, or store. Three packages in this tree are not family
// compilers and carry no such pin: nodefeatures/lkgsidecar is the node-local
// I/O half that reads and writes the node.features last-known-good file (it
// imports os), nodegov/rc11compat holds only a test fixture, and
// nodegov/navtabsrc (with its gen command) generates nodegov's tab table.
//
// internal/obs/admission and internal/obs/egress import their matching
// policyfam subpackage and RE-EXPORT every moved type/const/func via a
// type alias or a package-level var (CLAUDE.md #6 — additive, not
// invasive): existing evaluation code (pipeline/judge/prefilter/evaluate)
// and every external call site (internal/obs/httpapi, cmd/observer, …)
// keep compiling unchanged. Evaluation itself — RUNNING a compiled
// PolicySpec against one request — stays in internal/obs/{admission,egress}
// because it is the boundary-owned engine, not the family compiler.
package policyfam
