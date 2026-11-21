package secassess

import (
	"fmt"
	"sort"
	"strings"
)

// The threat model half of the Markdown export: the summary and its numbers,
// the scope, the system as tables, every threat, the considered-and-waived
// pairs, the attack trees, the open questions and the data-flow diagram.

// mdThreatModel writes every section of a threat model.
func mdThreatModel(w *mdWriter, m ExportMeta, res Result) {
	tm := res.TM
	names := newMDNames(tm.System)
	mdTMSummary(w, res)
	mdTMScope(w, tm.Scope)
	mdTMSystem(w, tm.System, names)
	mdTMThreats(w, tm.Threats, names)
	mdTMNoThreat(w, tm.NoThreat, names)
	mdTMTrees(w, tm.AttackTrees)
	mdAgentSection(w, "Open questions and the agent's own limits", tm.OpenQuestions, tm.Limits)
	mdTMDiagram(w, m, tm)
}

// mdTMSummary writes the agent's summary, the count of threats by band and the
// coverage Observer counted.
func mdTMSummary(w *mdWriter, res Result) {
	tm := res.TM
	w.heading(2, "Summary")
	if s := mdText(tm.Summary); s != "" {
		w.para("The agent says: " + s)
	}
	mdGenerator(w, tm.Generator, tm.PromptVersion)
	bands := make([]Band, len(tm.Threats))
	for i, t := range tm.Threats {
		bands[i] = mdBandOf(t.Band, t.Rating)
	}
	w.para(counted(len(tm.Threats), "threat", "threats") + " in the model, all listed below: " + mdBandCounts(bands) + ". " + mdBandNote)
	if cov := res.Report.TM; cov != nil {
		mdTMCoverage(w, cov)
	}
}

// mdFrameworkNames are the plain names of the two base frameworks; the AI
// frameworks are named by their own table (AIFrameworks).
var mdFrameworkNames = map[string]string{
	FrameworkSTRIDE:  "STRIDE",
	FrameworkLINDDUN: "LINDDUN",
}

// mdFramework is a framework's name from Observer's tables, or the id as
// written (escaped) when no table knows it.
func mdFramework(id string) string {
	if n, ok := mdFrameworkNames[id]; ok {
		return n
	}
	if f, ok := AIFrameworkByID(id); ok {
		return f.Name
	}
	return mdWords(id)
}

// mdCategory is a threat's category by its name in Observer's tables (STRIDE
// and LINDDUN carry names; the AI frameworks' ids are their names), or the id
// as written (escaped). A framework of "" looks the id up among the base
// frameworks' categories, which is what a waived pair needs (it names no
// framework).
func mdCategory(framework, id string) string {
	if framework == "" || framework == FrameworkSTRIDE {
		if c, ok := StrideCategoryByID(id); ok {
			return c.Name
		}
	}
	if framework == "" || framework == FrameworkLINDDUN {
		if c, ok := LinddunCategoryByID(id); ok {
			return c.Name
		}
	}
	return mdText(id)
}

// mdTMCoverage writes the cells Observer counted (V11) and the same by
// framework.
func mdTMCoverage(w *mdWriter, cov *TMCoverage) {
	w.para("Coverage as Observer counted it, by element and category: " + pairs(cov.Analysed) + " with a threat, " +
		pairs(cov.Waived) + " waived with a reason, and " + pairs(cov.Empty) + " with neither.")
	if len(cov.ByFramework) > 0 {
		rows := make([][]string, 0, len(cov.ByFramework))
		for _, f := range cov.ByFramework {
			rows = append(rows, []string{mdFramework(f.Framework), mdInt(f.Analysed), mdInt(f.Waived), mdInt(f.Empty)})
		}
		w.table([]string{"Framework", "With a threat", "Waived with a reason", "With neither"}, rows)
	}
	if len(cov.AIThreats) > 0 {
		keys := make([]string, 0, len(cov.AIThreats))
		for k := range cov.AIThreats {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		w.para("Threats written under the AI frameworks, whose pairs are not counted above:")
		for _, k := range keys {
			w.bullet(0, mdFramework(k)+": "+mdInt(cov.AIThreats[k]))
		}
		w.blank()
	}
}

// mdTMScope writes what the agent says the model covers.
func mdTMScope(w *mdWriter, s Scope) {
	if len(s.InScope)+len(s.OutOfScope)+len(s.Assumptions) == 0 {
		return
	}
	w.heading(2, "Scope")
	mdAgentList(w, "In scope, as the agent wrote it:", s.InScope)
	mdAgentList(w, "Out of scope, as the agent wrote it:", s.OutOfScope)
	mdAgentList(w, "Assumptions, as the agent wrote them:", s.Assumptions)
}

// mdTMThreats writes every threat, highest score first, then by id.
func mdTMThreats(w *mdWriter, ts []Threat, n *mdNames) {
	w.heading(2, "Threats")
	if len(ts) == 0 {
		w.para("No threat is listed in this copy of the model. The reading at the top says what that does and does not mean.")
		return
	}
	w.para("Every threat in the model, highest score first and then by id. Everything under \"The agent says\" is the agent's claim.")
	order := mdByScore(len(ts), func(i int) int { return mdScoreOf(ts[i].Score, ts[i].Rating) }, func(i int) string { return ts[i].ID })
	for _, i := range order {
		mdTMThreat(w, ts[i], n)
	}
}

// mdItemHeading is a threat's heading text: the id and the title.
func mdItemHeading(id, title string) string {
	switch {
	case id == "" && title == "":
		return "(no id)"
	case title == "":
		return mdText(id)
	case id == "":
		return mdText(title)
	}
	return mdText(id) + ": " + mdText(title)
}

// mdTMThreat writes one threat.
func mdTMThreat(w *mdWriter, t Threat, n *mdNames) {
	w.heading(3, mdItemHeading(t.ID, t.Title))
	w.bullet(0, "Framework: "+mdFramework(t.Framework)+"; category: "+mdCategory(t.Framework, t.Category))
	w.bullet(0, "Element: "+n.elementMD(t.Element))
	if t.Actor != "" {
		w.bullet(0, "Actor: "+n.label(mdKindActor, t.Actor))
	}
	w.bullet(0, "Rating: "+mdRating(t.Rating, t.Band, t.Score))
	if t.Status != "" {
		w.bullet(0, "Status, as the agent says: "+mdWords(t.Status))
	}
	mdTMIDs(w, t)
	w.blank()
	if d := mdText(t.Description); d != "" {
		w.para("The agent says: " + d)
	}
	mdTMExisting(w, t.Existing)
	mdTMMissing(w, t.Missing)
	mdTMAbuse(w, t.AbuseCase)
}

// mdTMIDs writes the weakness, attack-pattern and verification ids the agent
// attached to a threat.
func mdTMIDs(w *mdWriter, t Threat) {
	for _, l := range []struct {
		name string
		ids  []string
	}{{"CWE", t.CWE}, {"CAPEC", t.CAPEC}, {"ASVS", t.ASVS}} {
		if len(l.ids) > 0 {
			w.bullet(0, l.name+", as the agent lists them: "+mdText(strings.Join(l.ids, ", ")))
		}
	}
}

// mdTMExisting writes the controls the agent says are already in the code.
func mdTMExisting(w *mdWriter, ms []Mitigation) {
	if len(ms) == 0 {
		return
	}
	w.para("Existing mitigations, as the agent says:")
	for _, m := range ms {
		w.bullet(0, mdText(m.Text)+" Cited: "+mdRefs(m.Refs)+".")
	}
	w.blank()
}

// mdTMMissing writes the controls the agent says are missing.
func mdTMMissing(w *mdWriter, ms []Missing) {
	if len(ms) == 0 {
		return
	}
	w.para("Missing mitigations, as the agent says:")
	for _, m := range ms {
		s := mdText(m.Text)
		var extra []string
		if m.Control != "" {
			extra = append(extra, "control: "+mdWords(m.Control))
		}
		if m.Effort != "" {
			extra = append(extra, "effort: "+mdText(m.Effort))
		}
		if len(extra) > 0 {
			s += " (" + strings.Join(extra, "; ") + ")"
		}
		if len(m.Refs) > 0 {
			s += " Cited: " + mdRefs(m.Refs) + "."
		}
		w.bullet(0, s)
	}
	w.blank()
}

// mdTMAbuse writes a threat's abuse case.
func mdTMAbuse(w *mdWriter, a *AbuseCase) {
	if a == nil {
		return
	}
	w.para("Abuse case, as the agent says:")
	if s := mdText(a.Actor); s != "" {
		w.bullet(0, "Actor: "+s)
	}
	if s := mdText(a.Goal); s != "" {
		w.bullet(0, "Goal: "+s)
	}
	for i, st := range a.Steps {
		if s := mdText(st); s != "" {
			w.bullet(0, "Step "+mdInt(i+1)+": "+s)
		}
	}
	w.blank()
}

// mdTMNoThreat writes the pairs the agent says it considered and wrote no
// threat for. Observer counts them as waived, not analysed.
func mdTMNoThreat(w *mdWriter, ns []NoThreat, n *mdNames) {
	w.heading(2, "Considered, no threat found")
	if len(ns) == 0 {
		w.para("The agent listed no waived pair.")
		return
	}
	w.para("Each row is an element and category pair the agent says it considered and wrote no threat for, with its reason. Observer counts these pairs as waived, not as analysed, and did not check the reasons.")
	rows := make([][]string, 0, len(ns))
	for _, x := range ns {
		rows = append(rows, []string{n.elementMD(x.Element), mdCategory("", x.Category), mdText(x.Reason)})
	}
	w.table([]string{"Element", "Category", "Reason, as the agent says"}, rows)
}

// mdTMTrees writes each attack tree as a nested list built from the nodes'
// parent links.
func mdTMTrees(w *mdWriter, ts []Tree) {
	if len(ts) == 0 {
		return
	}
	w.heading(2, "Attack trees")
	w.para("Each tree is the agent's: a goal and the steps that lead to it.")
	for _, t := range ts {
		w.heading(3, "Goal, as the agent wrote it: "+mdText(t.Root))
		mdTMTree(w, t)
		w.blank()
	}
}

// mdTreeNode writes one node: its label, and how its children combine or that
// it is a leaf.
func mdTreeNode(nd TreeNode, hasChildren bool) string {
	s := mdText(nd.Label)
	var tags []string
	switch {
	case nd.Op != "" && hasChildren:
		tags = append(tags, "children: "+mdWords(nd.Op))
	case nd.Op != "":
		tags = append(tags, "op: "+mdWords(nd.Op))
	}
	if nd.Leaf {
		tags = append(tags, "leaf")
	}
	if len(tags) > 0 {
		s += " (" + strings.Join(tags, "; ") + ")"
	}
	return s
}

// mdTMTree writes a tree's nodes. A node whose parent is empty, or is not a
// node of the tree, starts at the top level; a node that no walk from a top
// level node reaches (a loop of parent links) is listed at the top level too,
// so every node appears once.
func mdTMTree(w *mdWriter, t Tree) {
	ids := map[string]bool{}
	children := map[string][]int{}
	for i, nd := range t.Nodes {
		ids[nd.ID] = true
		children[nd.Parent] = append(children[nd.Parent], i)
	}
	seen := make([]bool, len(t.Nodes))
	var walk func(i, depth int)
	walk = func(i, depth int) {
		if seen[i] {
			return
		}
		seen[i] = true
		nd := t.Nodes[i]
		kids := children[nd.ID]
		w.bullet(depth, mdTreeNode(nd, len(kids) > 0))
		for _, k := range kids {
			walk(k, depth+1)
		}
	}
	for i, nd := range t.Nodes {
		if nd.Parent == "" || !ids[nd.Parent] {
			walk(i, 0)
		}
	}
	for i := range t.Nodes {
		walk(i, 0)
	}
}

// mdTMDiagram writes the data-flow diagram as Mermaid source in a fenced
// block, and what the diagram left out.
func mdTMDiagram(w *mdWriter, m ExportMeta, tm *ThreatModelDoc) {
	d := RenderMermaidWith(tm, MermaidOptions{MaxNodes: m.DiagramMaxNodes, LabelChars: m.DiagramLabelChars})
	w.heading(2, "Data-flow diagram")
	if d.TotalNodes == 0 {
		w.para("The model has no component and no flow, so there is nothing to draw.")
		return
	}
	w.para("Mermaid source drawn by Observer from the flows above, to paste into any Mermaid viewer. Its labels hold at most " +
		mdInt(d.LabelChars) + " characters of the agent's text, only plain letters, digits and a few marks.")
	w.line("```mermaid")
	// The source holds no backtick (its labels are restricted); the replace is
	// the guarantee that nothing in it can close this fence.
	w.line(strings.ReplaceAll(strings.TrimRight(d.Source, "\n"), "`", "'"))
	w.line("```")
	w.blank()
	if d.OmittedNodes > 0 || d.OmittedEdges > 0 {
		w.para(fmt.Sprintf("%d of %d nodes are drawn and %d %s not drawn: the cap is the diagram size setting (%d nodes).",
			d.Nodes, d.TotalNodes, d.OmittedEdges, mdPlural(d.OmittedEdges, "flow is", "flows are"), d.MaxNodes))
	}
	if d.LabelsCut > 0 {
		w.para(counted(d.LabelsCut, "label was", "labels were") + " shortened to " + mdInt(d.LabelChars) + " characters; the full names are in the tables above.")
	}
}
