package secassess

import (
	"sort"
	"strconv"
	"strings"
)

// The data-flow diagram of a threat model, as Mermaid flowchart source
// (plan W6a: "source plus tables"; the page shows the source beside the flow
// table, copyable, and draws nothing from agent strings).
//
// The source is built so that no agent text can change what the diagram says
// beyond its own labels. Node and subgraph ids come from positions in the
// model, never from the agent's ids (an id such as `end` or `a"];click` is a
// Mermaid reserved word or an injection). Every label is wrapped in double
// quotes and reduced to the characters [A-Za-z0-9 .,:/_()-]; anything else
// (quotes, brackets, pipes, backticks, a percent sign, a newline, any
// non-ASCII character) becomes a space. Observer's own words on an edge ("no
// authentication", "not encrypted") are fixed text added after the agent's
// protocol.

// The node cap of a diagram. The setting diagram_max_nodes accepts 10 to 300;
// an unset or non-positive request reads as DefaultMermaidNodes and a larger
// one as MaxMermaidNodes.
const (
	DefaultMermaidNodes = 60
	MaxMermaidNodes     = 300
)

// The label length of a diagram: the most runes of agent text a label may
// hold. The setting diagram_label_chars accepts 10 to 120; an unset or
// non-positive request reads as DefaultMermaidLabelChars and a larger one as
// MaxMermaidLabelChars.
const (
	DefaultMermaidLabelChars = 40
	MaxMermaidLabelChars     = 120
	minMermaidLabelChars     = 10
)

// MermaidOptions are the two limits of a diagram. A zero value reads as the
// defaults.
type MermaidOptions struct {
	// MaxNodes is the most nodes drawn (see RenderMermaid).
	MaxNodes int
	// LabelChars is the most runes of agent text a label keeps.
	LabelChars int
}

// mermaidWeakStyle is the style of a crossing flow that is unauthenticated or
// not encrypted. It carries no agent text.
const mermaidWeakStyle = "stroke:#d33,stroke-width:2px"

// MermaidDiagram is the rendered diagram and what it leaves out.
type MermaidDiagram struct {
	// Source is the Mermaid flowchart source.
	Source string `json:"source"`
	// Nodes is how many nodes are drawn.
	Nodes int `json:"nodes"`
	// TotalNodes is every component and every actor that takes part in a flow.
	TotalNodes int `json:"total_nodes"`
	// OmittedNodes is the nodes past the cap.
	OmittedNodes int `json:"omitted_nodes"`
	// Edges is how many flows are drawn.
	Edges int `json:"edges"`
	// OmittedEdges is the flows not drawn: those with an endpoint past the cap
	// and those whose endpoint is not in the model.
	OmittedEdges int `json:"omitted_edges"`
	// MaxNodes is the cap in force.
	MaxNodes int `json:"max_nodes"`
	// LabelChars is the label length in force.
	LabelChars int `json:"label_chars"`
	// LabelsCut is how many drawn labels (a node, a zone or a flow's protocol)
	// were cut to LabelChars; the diagram is the one view that shortens agent
	// text, so it counts what it shortened.
	LabelsCut int `json:"labels_cut"`
}

// mmShape is the Mermaid shape of a node.
type mmShape struct{ open, close string }

// The node shapes: a data store is a cylinder, an external entity a subroutine
// box, an actor a stadium and anything else a rectangle.
var (
	mmShapeStore    = mmShape{`[("`, `")]`}
	mmShapeExternal = mmShape{`[["`, `"]]`}
	mmShapeActor    = mmShape{`(["`, `"])`}
	mmShapePlain    = mmShape{`["`, `"]`}
)

// mmShapeOfClass maps the DFD class of a component type to its shape; a class
// not in the table (and an unknown type) is drawn plain.
var mmShapeOfClass = map[DFDClass]mmShape{
	ClassDataStore:      mmShapeStore,
	ClassExternalEntity: mmShapeExternal,
}

// mmNode is one node of the diagram: a component or an actor taking part in a
// flow.
type mmNode struct {
	id     string
	label  string
	cut    bool // the label was cut to the label length
	shape  mmShape
	zone   int  // 1-based position of the component's known zone, 0 for none
	comp   bool // a component, not an actor
	degree int  // flows the node takes part in
	kept   bool
}

// mmEdge is one flow between two nodes of the model, by index into the nodes.
type mmEdge struct {
	from, to int
	flow     *Flow
}

// RenderMermaid renders the model's system as Mermaid flowchart source with
// the default label length. maxNodes <= 0 reads as DefaultMermaidNodes; above
// MaxMermaidNodes it is MaxMermaidNodes. See RenderMermaidWith.
func RenderMermaid(m *ThreatModelDoc, maxNodes int) MermaidDiagram {
	return RenderMermaidWith(m, MermaidOptions{MaxNodes: maxNodes})
}

// RenderMermaidWith renders the model's system as Mermaid flowchart source.
// Options outside their range read as the nearest bound (a zero or negative
// one as the default).
//
// Trust zones are subgraph blocks holding their components; a component with
// no zone, or one the model does not list, and every actor sit outside any
// block. A flow is an edge, dashed when it crosses a trust zone (its crosses
// list is not empty, or its endpoints are components in two different known
// zones); a crossing flow with no authentication or no encryption is also
// listed on one linkStyle line so it draws highlighted. A model with more
// nodes than the cap keeps the nodes that take part in the most flows (ties in
// model order), draws only the flows between kept nodes and says how many it
// left out. A nil model, or one with no component, renders as an empty
// flowchart.
func RenderMermaidWith(m *ThreatModelDoc, o MermaidOptions) MermaidDiagram {
	limit, chars := mmBounds(o)
	out := MermaidDiagram{Source: "flowchart LR", MaxNodes: limit, LabelChars: chars}
	if m == nil {
		return out
	}
	if len(m.System.Components) == 0 {
		// Nothing can be drawn, and every flow is a flow not drawn.
		out.OmittedEdges = len(m.System.Flows)
		return out
	}
	sys := &m.System
	lab := mmLabeler{max: chars}
	zoneNo := mmZoneNumbers(sys)

	nodes, compAt, actAt := mmNodes(sys, zoneNo, lab)
	edges := mmEdges(sys, nodes, compAt, actAt)
	out.TotalNodes = len(nodes)
	mmKeep(nodes, limit)

	lines, weak := mmEdgeLines(edges, nodes, lab, &out)
	out.Edges = len(lines)
	out.OmittedEdges = len(sys.Flows) - len(lines)

	var b strings.Builder
	b.WriteString("flowchart LR")
	mmWriteZones(&b, sys, zoneNo, nodes, lab, &out)
	for j := range nodes {
		if n := &nodes[j]; n.kept && !(n.comp && n.zone > 0) {
			b.WriteString("\n  " + mmNodeLine(n))
		}
	}
	for _, l := range lines {
		b.WriteString("\n" + l)
	}
	if len(weak) > 0 {
		b.WriteString("\n  linkStyle " + strings.Join(weak, ",") + " " + mermaidWeakStyle)
	}
	for j := range nodes {
		if nodes[j].kept {
			out.Nodes++
			if nodes[j].cut {
				out.LabelsCut++
			}
		}
	}
	out.OmittedNodes = out.TotalNodes - out.Nodes
	if out.OmittedNodes > 0 || out.OmittedEdges > 0 {
		b.WriteString("\n  %% " + strconv.Itoa(out.OmittedNodes) + " nodes and " + strconv.Itoa(out.OmittedEdges) +
			" flows are not drawn (cap " + strconv.Itoa(limit) + ")")
	}
	out.Source = b.String()
	return out
}

// mmBounds clamps the options to their range: a zero or negative value reads
// as the default, one above its maximum (or below the label minimum) as the
// nearest bound.
func mmBounds(o MermaidOptions) (limit, chars int) {
	limit = o.MaxNodes
	switch {
	case limit <= 0:
		limit = DefaultMermaidNodes
	case limit > MaxMermaidNodes:
		limit = MaxMermaidNodes
	}
	chars = o.LabelChars
	switch {
	case chars <= 0:
		chars = DefaultMermaidLabelChars
	case chars < minMermaidLabelChars:
		chars = minMermaidLabelChars
	case chars > MaxMermaidLabelChars:
		chars = MaxMermaidLabelChars
	}
	return limit, chars
}

// mmZoneNumbers maps each zone id of the model to its 1-based position; a
// blank id or a repeated one keeps the first position (or none for blank).
func mmZoneNumbers(sys *System) map[string]int {
	zoneNo := map[string]int{}
	for i, z := range sys.Zones {
		if _, dup := zoneNo[z.ID]; z.ID != "" && !dup {
			zoneNo[z.ID] = i + 1
		}
	}
	return zoneNo
}

// mmEdgeLines renders the flows between kept nodes, in model order, as edge
// lines; weak lists the indexes of the lines that cross a trust zone with no
// authentication or no encryption. Labels cut to the label length are counted
// on out.
func mmEdgeLines(edges []mmEdge, nodes []mmNode, lab mmLabeler, out *MermaidDiagram) (lines, weak []string) {
	for _, e := range edges {
		if !nodes[e.from].kept || !nodes[e.to].kept {
			continue
		}
		crosses := mmCrosses(e.flow, &nodes[e.from], &nodes[e.to])
		if crosses && (e.flow.Authn == "none" || e.flow.Encrypted == "no") {
			weak = append(weak, strconv.Itoa(len(lines)))
		}
		edge, cut := mmEdgeLabel(e.flow, lab)
		if cut {
			out.LabelsCut++
		}
		lines = append(lines, "  "+nodes[e.from].id+" "+mmArrow(crosses)+edge+" "+nodes[e.to].id)
	}
	return lines, weak
}

// mmWriteZones writes one subgraph block per known zone that holds a kept
// component, in zone order. Labels cut to the label length are counted on out.
func mmWriteZones(b *strings.Builder, sys *System, zoneNo map[string]int, nodes []mmNode, lab mmLabeler, out *MermaidDiagram) {
	for i, z := range sys.Zones {
		if zoneNo[z.ID] != i+1 {
			continue
		}
		var inside []*mmNode
		for j := range nodes {
			if nodes[j].kept && nodes[j].comp && nodes[j].zone == i+1 {
				inside = append(inside, &nodes[j])
			}
		}
		if len(inside) == 0 {
			continue
		}
		zl, zcut := lab.label(z.Name, "z"+strconv.Itoa(i+1))
		if zcut {
			out.LabelsCut++
		}
		b.WriteString("\n  subgraph z" + strconv.Itoa(i+1) + "[\"" + zl + "\"]")
		for _, n := range inside {
			b.WriteString("\n    " + mmNodeLine(n))
		}
		b.WriteString("\n  end")
	}
}

// mmNodes lists the nodes of the model: every component, in model order, then
// every actor that is an endpoint of a flow, in model order. compAt and actAt
// map an id of the model to the node (the first one wins on a repeated id).
func mmNodes(sys *System, zoneNo map[string]int, lab mmLabeler) (nodes []mmNode, compAt, actAt map[string]int) {
	compAt, actAt = map[string]int{}, map[string]int{}
	for i := range sys.Components {
		c := &sys.Components[i]
		id := "c" + strconv.Itoa(i+1)
		shape := mmShapePlain
		if t, ok := ComponentTypeByID(c.Type); ok {
			if s, ok := mmShapeOfClass[t.Class]; ok {
				shape = s
			}
		}
		if _, dup := compAt[c.ID]; !dup {
			compAt[c.ID] = len(nodes)
		}
		label, cut := lab.label(c.Name, id)
		nodes = append(nodes, mmNode{id: id, label: label, cut: cut, shape: shape, zone: zoneNo[c.Zone], comp: true})
	}
	// An actor takes part when some flow starts or ends at it.
	named := map[string]bool{}
	for _, f := range sys.Flows {
		named[f.From], named[f.To] = true, true
	}
	for i := range sys.Actors {
		a := &sys.Actors[i]
		if !named[a.ID] {
			continue
		}
		if _, isComp := compAt[a.ID]; isComp {
			continue
		}
		if _, dup := actAt[a.ID]; dup {
			continue
		}
		id := "a" + strconv.Itoa(i+1)
		actAt[a.ID] = len(nodes)
		label, cut := lab.label(a.Name, id)
		nodes = append(nodes, mmNode{id: id, label: label, cut: cut, shape: mmShapeActor})
	}
	return nodes, compAt, actAt
}

// mmEdges resolves the flows to node indexes and counts each node's flows. A
// flow whose endpoint is not in the model is left out (the caller counts it
// among the flows not drawn). An endpoint that is both a component and an
// actor reads as the component.
func mmEdges(sys *System, nodes []mmNode, compAt, actAt map[string]int) []mmEdge {
	var edges []mmEdge
	find := func(id string) (int, bool) {
		if i, ok := compAt[id]; ok {
			return i, true
		}
		i, ok := actAt[id]
		return i, ok
	}
	for i := range sys.Flows {
		f := &sys.Flows[i]
		from, ok1 := find(f.From)
		to, ok2 := find(f.To)
		if !ok1 || !ok2 {
			continue
		}
		edges = append(edges, mmEdge{from: from, to: to, flow: f})
		nodes[from].degree++
		if to != from {
			nodes[to].degree++
		}
	}
	return edges
}

// mmKeep marks the nodes to draw: all of them when they fit under limit, else
// the limit nodes that take part in the most flows, ties in model order.
func mmKeep(nodes []mmNode, limit int) {
	if len(nodes) <= limit {
		for i := range nodes {
			nodes[i].kept = true
		}
		return
	}
	order := make([]int, len(nodes))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return nodes[order[a]].degree > nodes[order[b]].degree })
	for _, i := range order[:limit] {
		nodes[i].kept = true
	}
}

// mmCrosses reports whether a flow crosses a trust zone: it says so itself, or
// its endpoints are components in two different known zones.
func mmCrosses(f *Flow, from, to *mmNode) bool {
	if len(f.Crosses) > 0 {
		return true
	}
	return from.comp && to.comp && from.zone > 0 && to.zone > 0 && from.zone != to.zone
}

// mmArrow is the arrow of an edge: dashed when it crosses a zone.
func mmArrow(crosses bool) string {
	if crosses {
		return "-.->"
	}
	return "-->"
}

// mmEdgeLabel is the edge's label with its leading bar syntax, or "" when the
// edge has nothing to say: the agent's protocol (cleaned and cut to the label
// length, as every piece of agent text is), then Observer's own words for a
// missing authentication or encryption, which are added after the cut so they
// are never lost to it. The second result says the protocol was cut.
func mmEdgeLabel(f *Flow, lab mmLabeler) (string, bool) {
	var parts []string
	p, cut := lab.clean(f.Protocol)
	if p != "" {
		parts = append(parts, p)
	}
	if f.Authn == "none" {
		parts = append(parts, "no authentication")
	}
	if f.Encrypted == "no" {
		parts = append(parts, "not encrypted")
	}
	if len(parts) == 0 {
		return "", false
	}
	return `|"` + strings.Join(parts, ", ") + `"|`, cut
}

// mmNodeLine is the line that declares a node, without indentation.
func mmNodeLine(n *mmNode) string { return n.id + n.shape.open + n.label + n.shape.close }

// mmLabeler cleans the agent's text into labels of at most max runes.
type mmLabeler struct{ max int }

// label is a label for a node or a subgraph: the cleaned text, or the fallback
// (the node's own index id) when nothing is left of it. The second result says
// the text was cut to the label length.
func (l mmLabeler) label(s, fallback string) (string, bool) {
	if c, cut := l.clean(s); c != "" {
		return c, cut
	}
	return fallback, false
}

// clean reduces agent text to the characters a quoted Mermaid label may hold
// safely: [A-Za-z0-9 .,:/_()-]. Any other rune becomes a space, runs of spaces
// collapse, the ends are trimmed and the result is cut to the label length.
// The second result is true when allowed text was left off because of that
// cut (not because it was spaces or characters a label cannot hold).
func (l mmLabeler) clean(s string) (string, bool) {
	var b strings.Builder
	n, space := 0, false
	for _, r := range s {
		if !mmAllowed(r) || r == ' ' {
			space = n > 0
			continue
		}
		if n >= l.max {
			return strings.TrimRight(b.String(), " "), true
		}
		if space {
			b.WriteByte(' ')
			n++
			space = false
			if n >= l.max {
				return strings.TrimRight(b.String(), " "), true
			}
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimRight(b.String(), " "), false
}

// mmAllowed reports whether r may appear in a label.
func mmAllowed(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune(" .,:/_()-", r)
}
