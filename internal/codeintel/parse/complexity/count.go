package complexity

import (
	"slices"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
)

// counted reports whether a node of kind k gets a figure.
func counted(k string) bool { return slices.Contains(Kinds, k) }

// Count sets Complexity on every function and method in nodes with an
// exact byte span (EndByte > StartByte) to 1 + the decision positions
// (byte offsets) whose innermost enclosing function or method it is.
// Nodes of other kinds, and nodes without an exact span, are left
// untouched (0, not counted). Offsets may be unsorted and repeated; a
// repeated offset counts once. A decision outside every function (a
// top-level statement, a class body) counts toward none.
//
// The sweep relies on a parse tree's spans being nested or disjoint; it
// never reads a node out of range on input that is not.
func Count(nodes []codeintel.Node, offsets []int) {
	var cands []int
	for i, n := range nodes {
		if counted(n.Kind) && n.EndByte > n.StartByte && n.StartByte >= 0 {
			cands = append(cands, i)
		}
	}
	if len(cands) == 0 {
		return
	}
	sort.SliceStable(cands, func(a, b int) bool {
		na, nb := nodes[cands[a]], nodes[cands[b]]
		if na.StartByte != nb.StartByte {
			return na.StartByte < nb.StartByte
		}
		return na.EndByte > nb.EndByte // the outer of two same-start spans first
	})
	offs := append([]int(nil), offsets...)
	sort.Ints(offs)
	offs = slices.Compact(offs)

	decisions := make([]int, len(nodes))
	var stack []int
	j := 0
	for _, off := range offs {
		for j < len(cands) && nodes[cands[j]].StartByte <= off {
			c := cands[j]
			for len(stack) > 0 && nodes[stack[len(stack)-1]].EndByte <= nodes[c].StartByte {
				stack = stack[:len(stack)-1]
			}
			stack = append(stack, c)
			j++
		}
		for len(stack) > 0 && nodes[stack[len(stack)-1]].EndByte <= off {
			stack = stack[:len(stack)-1]
		}
		if len(stack) > 0 {
			decisions[stack[len(stack)-1]]++
		}
	}
	for _, c := range cands {
		nodes[c].Complexity = 1 + decisions[c]
	}
}
