package codeintel

// This file defines the plain-data types that cross the [Provider]
// seam. They are deliberately free of behaviour and of any subsystem
// dependency so every consumer (MCP tools, the compression pipeline,
// CLI surfaces) can depend on them without importing internals. The
// native engine translates its internal rows into these shapes at the
// boundary.

// Symbol is a code symbol defined in a file: its name, kind, and span.
// Returned by [Provider.SymbolsInFile]. The span ([StartLine] +
// [EndLine]) is 1-based and inclusive. A zero [EndLine] means the
// backend did not record an end (an approximate/heuristic span); the
// aggressive compressor treats that as non-collapsible (ADR-0005).
type Symbol struct {
	Name      string
	Kind      string // function | method | class | interface | type
	StartLine int
	EndLine   int
	// Exact reports whether the span came from an exact-span backend
	// (go/ast, tree-sitter) rather than the heuristic fallback. ADR-0005:
	// ONLY an Exact span may drive aggressive body-collapse. The zero
	// value (false) is the safe default — a consumer that ignores this
	// field never collapses.
	Exact bool
}

// SymbolMatch is the richer per-symbol shape returned by
// [Provider.FindSymbols]. It carries enough metadata for the MCP
// retrieval tools to render a match (and follow up via relations)
// without a second query round-trip.
type SymbolMatch struct {
	ID        int64
	Name      string
	FQN       string
	Kind      string
	File      string
	Language  string
	StartLine int
	EndLine   int
}

// Ref is one symbol reached via an edge traversal: a caller, a callee,
// or a node reached by [Provider.Reachable]. It unifies the
// Caller and Reachable shapes — [Depth] and [ViaEdge] are populated
// only by reachability traversals (zero/empty for direct
// caller/callee lists).
type Ref struct {
	ID        int64
	Name      string
	FQN       string
	Kind      string
	File      string
	Language  string
	StartLine int
	EndLine   int
	// Depth is the number of hops from the anchor (>= 1). Populated by
	// [Provider.Reachable]; zero for direct caller/callee lists.
	Depth int
	// ViaEdge is the edge kind that brought this ref in (e.g. "CALLS").
	// Populated by [Provider.Reachable].
	ViaEdge string
}

// GraphNode is one symbol in a project's loaded graph — the in-memory
// input the pure analyze/ and query/ engines run over (Phase 6). It is a
// flattened SymbolMatch (no behaviour).
type GraphNode struct {
	ID        int64
	Name      string
	FQN       string
	Kind      string
	File      string
	Language  string
	StartLine int
	EndLine   int
}

// GraphEdge is one RESOLVED relationship (dst != 0) in the loaded graph.
type GraphEdge struct {
	Src        int64
	Dst        int64
	Kind       string
	Confidence float64
}

// ResultSet is the tabular output of a Cypher-subset query
// ([Provider.Query]). Columns names the projected return items; Rows are
// stringified cells (the engine renders ints/identifiers to strings so
// the surface is JSON/CLI-stable without per-cell type negotiation).
type ResultSet struct {
	Columns []string
	Rows    [][]string
}

// Graph is a whole-project node+edge snapshot. The store loads it once
// (CodeIntelLoadGraph) and the pure analyze/query engines compute over it
// in memory — keeping those packages free of SQL (imports_test boundary).
type Graph struct {
	Project string
	Nodes   []GraphNode
	Edges   []GraphEdge
}

// RelationDirection selects which edge kind to traverse and which side
// of the edge the anchor sits on, for [Provider.Reachable].
type RelationDirection int

const (
	// RelationCallers traverses CALLS edges from the anchor as the
	// target back to the source. Answers "who calls X?".
	RelationCallers RelationDirection = iota
	// RelationCallees traverses CALLS edges from the anchor as the
	// source forward to the target. Answers "what does X call?".
	RelationCallees
	// RelationContains traverses CONTAINS edges from the anchor as the
	// source forward to the target (parent -> child). May be empty
	// when a backend does not populate CONTAINS edges.
	RelationContains
)

// String renders a RelationDirection for logs and diagnostics.
func (d RelationDirection) String() string {
	switch d {
	case RelationCallers:
		return "callers"
	case RelationCallees:
		return "callees"
	case RelationContains:
		return "contains"
	default:
		return "unknown"
	}
}
