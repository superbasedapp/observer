package mcpaccess

import "sort"

// NodeRow is one row of the node decision table.
type NodeRow struct {
	Grant Grant `json:"grant"`
}

// NodeDecisionTable is the ordered table the P4 node relay walks TOP-DOWN,
// FIRST MATCH WINS. Rows are ordered by effect precedence (deny, ask,
// allow), then hierarchy level, then ord, then id, so first-match-wins
// reproduces "deny > ask > allow, shallowest level attributed". A request
// that matches no row is denied.
type NodeDecisionTable struct {
	Registry Registry  `json:"registry"`
	Rows     []NodeRow `json:"rows"`
}

// CompileNodeTable compiles spec into the ordered table.
func CompileNodeTable(spec Spec, now int64) (NodeDecisionTable, error) {
	n, err := Normalize(spec, now)
	if err != nil {
		return NodeDecisionTable{}, err
	}
	rows := make([]NodeRow, 0, len(n.Grants))
	for _, g := range n.Grants {
		rows = append(rows, NodeRow{Grant: g})
	}
	sort.SliceStable(rows, func(i, j int) bool { return precedenceLess(rows[i].Grant, rows[j].Grant) })
	return NodeDecisionTable{Registry: n.Registry, Rows: rows}, nil
}

// Evaluate walks the table top-down and returns the first matching row's
// effect, or default-deny.
func (t NodeDecisionTable) Evaluate(in EvalInput) Decision {
	if ok, why := requireInvariantsHold(t.Registry, in); !ok {
		return denyDecision(in, "invariant: "+why)
	}
	for _, row := range t.Rows {
		if grantMatches(row.Grant, t.Registry, in) {
			return decisionFor(row.Grant, "node table: first matching row")
		}
	}
	return denyDecision(in, "node table: no row matched (default-deny)")
}
