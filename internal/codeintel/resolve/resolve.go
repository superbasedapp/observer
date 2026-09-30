package resolve

// This package holds the PURE name-matched resolution logic: given the
// set of defined symbols and a callee name, pick the target node. It
// imports no database/sql/http/fsnotify — the store seam feeds it plain
// data and persists the result. Type-resolved (Hybrid-LSP) resolution is
// a future additive backend (Tier D); see docs/codeintel/resolution.md.

// NodeRef is a defined symbol the resolver can target: its id, name, and
// the file it lives in (for same-file preference).
type NodeRef struct {
	ID     int64
	Name   string
	FileID int64
}

// NameIndex maps a symbol name to the node ids that define it, plus a
// per-id file lookup for same-file preference. Built once per project.
type NameIndex struct {
	byName map[string][]int64
	fileOf map[int64]int64
}

// BuildNameIndex indexes nodes by name. Deterministic: ids within a name
// bucket preserve input order.
func BuildNameIndex(nodes []NodeRef) *NameIndex {
	idx := &NameIndex{
		byName: make(map[string][]int64, len(nodes)),
		fileOf: make(map[int64]int64, len(nodes)),
	}
	for _, n := range nodes {
		if n.Name == "" {
			continue
		}
		idx.byName[n.Name] = append(idx.byName[n.Name], n.ID)
		idx.fileOf[n.ID] = n.FileID
	}
	return idx
}

// Resolve picks the target node id for a callee name observed in
// callerFile. Resolution policy (name-matched):
//
//   - no node with that name      -> (0, false)  [unresolved/external]
//   - exactly one                 -> that id
//   - several, one in callerFile  -> the same-file one (locality wins)
//   - several, none in callerFile -> the first (deterministic by input
//     order); the call is name-ambiguous (a documented fidelity bound —
//     type resolution is the future upgrade, Tier D)
//
// Returns (id, true) on a match.
func (idx *NameIndex) Resolve(callee string, callerFile int64) (int64, bool) {
	ids := idx.byName[callee]
	switch len(ids) {
	case 0:
		return 0, false
	case 1:
		return ids[0], true
	}
	for _, id := range ids {
		if idx.fileOf[id] == callerFile {
			return id, true
		}
	}
	return ids[0], true
}

// Ambiguous reports whether callee resolves to more than one candidate
// (used to lower an edge's confidence).
func (idx *NameIndex) Ambiguous(callee string) bool {
	return len(idx.byName[callee]) > 1
}
