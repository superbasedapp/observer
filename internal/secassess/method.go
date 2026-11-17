package secassess

import (
	"fmt"
	"strings"
)

// The threat-model method as data (depth plan W3.1). Each step is a row; the
// prompt walks the rows whose condition holds on the sets in force. The words
// are Observer's own; the schema words (field names, closed lists) come from
// the vocabulary tables so the steps cannot drift from what the validator
// reads. SchemaBlock says what SHAPE the result has; these steps say what WORK
// to do before writing it.

// MethodStep is one step of the threat-model method, as data. When gates the
// step on the sets in force: "" always, "linddun" when LINDDUN is in force,
// "ai" when an AI framework is in force and the project is an AI application,
// "abuse_cases" and "attack_trees" when that method extra is in force,
// "scoped" when the run has scope paths.
type MethodStep struct {
	ID   string
	When string
	Text string
}

// The conditions a step can carry.
const (
	tmWhenAlways      = ""
	tmWhenLinddun     = "linddun"
	tmWhenAI          = "ai"
	tmWhenAbuseCases  = "abuse_cases"
	tmWhenAttackTrees = "attack_trees"
	tmWhenScoped      = "scoped"
)

// tmMethodConditions is the table of conditions: one predicate per When value.
// A step whose When is not in the table never shows (fail closed); a test pins
// that every row of tmMethod uses a known condition.
var tmMethodConditions = map[string]func(TMMethodInput) bool{
	tmWhenAlways:      func(TMMethodInput) bool { return true },
	tmWhenLinddun:     func(in TMMethodInput) bool { return has(in.frameworksInForce(), FrameworkLINDDUN) },
	tmWhenAI:          func(in TMMethodInput) bool { return in.AIApp && tmAnyAIFramework(in.frameworksInForce()) },
	tmWhenAbuseCases:  func(in TMMethodInput) bool { return has(in.MethodExtras, ExtraAbuseCases) },
	tmWhenAttackTrees: func(in TMMethodInput) bool { return has(in.MethodExtras, ExtraAttackTrees) },
	tmWhenScoped:      func(in TMMethodInput) bool { return in.Scoped },
}

// tmAnyAIFramework reports whether one of the AI-application frameworks is in
// the set.
func tmAnyAIFramework(fws []string) bool {
	for _, f := range AIFrameworks {
		if has(fws, f.ID) {
			return true
		}
	}
	return false
}

// strideApplies is the words for the STRIDE categories that apply to a class
// of element, read from the same chart the coverage rule (V11) uses.
func strideApplies(c DFDClass, holdsLogs bool) string {
	ids := ApplicableStride(c, holdsLogs)
	if len(ids) == len(StrideCategories) {
		return "all six"
	}
	return strings.Join(ids, ", ")
}

// strideLogStoreExtra is what a log or audit store adds to a plain data store.
func strideLogStoreExtra() string {
	plain := map[string]bool{}
	for _, id := range ApplicableStride(ClassDataStore, false) {
		plain[id] = true
	}
	var extra []string
	for _, id := range ApplicableStride(ClassDataStore, true) {
		if !plain[id] {
			extra = append(extra, id)
		}
	}
	return strings.Join(extra, ", ")
}

// aiCategoryRanges is "owasp_llm (LLM01 to LLM10) or owasp_agentic (ASI01 to
// ASI10)", read from the AI framework table.
func aiCategoryRanges() string {
	var parts []string
	for _, f := range AIFrameworks {
		parts = append(parts, fmt.Sprintf("%s (%s01 to %s10)", f.ID, f.IDPrefix, f.IDPrefix))
	}
	return strings.Join(parts, " or ")
}

// tmMethod is the threat-model method table, in the order the work is done.
var tmMethod = []MethodStep{
	{ID: "scope", When: tmWhenScoped, Text: "Scope: this run covers only the paths the developer chose. Model those paths (list them in scope.in_scope); read the rest of the repository only for callers, callees and configuration; list everything else in scope.out_of_scope and note in scope.assumptions what you assumed about it."},
	{ID: "decompose", When: tmWhenAlways, Text: "Decompose first: the components (one per deployable unit or library boundary, with the paths that hold it), trust zones, actors, assets (sensitivity, where stored), entry points, and the data flows between them (what moves, protocol, zones crossed, authenticated, encrypted, personal data or not). Write what the repository shows; put what you could not tell in open_questions."},
	{ID: "enumerate", When: tmWhenAlways, Text: fmt.Sprintf("Enumerate per element: for every component, actor and flow, take each STRIDE category that applies and write a threat or a no_threat entry with a one-line reason; do not skip a cell. Applies to an actor or external component: %s; a service, interface, job, gateway or other process: %s; a data store or queue: %s (and %s for a log or audit store); a flow: %s. Put each threat on the component, actor or flow it is about, which is where Observer counts what was considered.",
		strideApplies(ClassExternalEntity, false), strideApplies(ClassProcess, false), strideApplies(ClassDataStore, false), strideLogStoreExtra(), strideApplies(ClassDataFlow, false))},
	{ID: "linddun", When: tmWhenLinddun, Text: "Privacy (LINDDUN): for every flow with personal_data true, go through all seven LINDDUN categories and write a threat (framework linddun) or a no_threat with a reason for each. Mark a flow personal_data true when it moves data about a person: identifiers, contact or payment details, health, location, behaviour."},
	{ID: "ai", When: tmWhenAI, Text: "AI application: this project calls a model or gives one tools, so also examine the model, tool, memory and prompt boundaries against the OWASP LLM and agentic categories: text the model reads that an outsider can write (documents, web pages, tool results), what a tool call can reach with the agent's own credentials, model output reaching a shell, query, file or template unchecked, who can write to memory or retrieval stores, one agent's output feeding another. Use framework " + aiCategoryRanges() + "."},
	{ID: "rate", When: tmWhenAlways, Text: "Rate every threat: likelihood and impact, whole numbers 1 to 5 each, judged from what the code and configuration show. Observer computes the band from your two numbers."},
	{ID: "abuse_cases", When: tmWhenAbuseCases, Text: "Abuse cases: for the five highest-rated threats, and for every threat rated high or critical, write an abuse_case: the attacker, the goal and the steps they would take, using only what the code and configuration show."},
	{ID: "attack_trees", When: tmWhenAttackTrees, Text: "Attack trees: when three or more threats rate high or critical, write at least one attack tree for the most serious goal: a root, then nodes joined by and or or down to leaf actions (give a node a parent to nest it)."},
	{ID: "mitigations", When: tmWhenAlways, Text: "Cite mitigations: list what the code already does (existing) and what is missing (missing, with a control name and an effort of s, m or l). Give each a reference: path, line and a needle copied exactly from that code line (8 or more characters with a name from the code). A control described only in a comment or a document is not a mitigation. For a missing control, cite the file and line where it belongs: that location becomes a finding."},
	{ID: "report", When: tmWhenAlways, Text: "Write report.md last, from the same analysis, under the headings listed with the result files. It is read as your own words and Observer does not check it. Put no credential or secret value in it."},
}

// TMMethodInput is what the method steps depend on.
type TMMethodInput struct {
	// Frameworks and MethodExtras are the sets in force (resolved presets).
	// A nil Frameworks takes every framework and a nil MethodExtras takes no
	// extra, the same defaults SchemaInput uses, so the method and the result
	// model block agree on what is asked for. STRIDE is always asked for.
	Frameworks   []string
	MethodExtras []string
	// AIApp: the project is an AI application: it calls a model or gives one
	// tools (ProjectFacts.AIApp).
	AIApp bool
	// Scoped: the run has scope paths.
	Scoped bool
}

// frameworksInForce is the framework set with the nil default applied.
func (in TMMethodInput) frameworksInForce() []string {
	if in.Frameworks == nil {
		all, _ := ResolvePreset(FrameworkPresets, "all")
		return all
	}
	return in.Frameworks
}

// TMMethodLines returns the text of the steps that apply, in order, without
// numbers. A step with an unknown condition is left out.
func TMMethodLines(in TMMethodInput) []string {
	var out []string
	for _, s := range tmMethod {
		if cond, ok := tmMethodConditions[s.When]; ok && cond(in) {
			out = append(out, s.Text)
		}
	}
	return out
}

// riskBandEdge is one row of the band table the rating words are written from: a
// band and the inclusive range of likelihood-times-impact products it covers.
type riskBandEdge struct {
	Band     Band
	Min, Max int
}

// riskBandEdges are the band ranges in the order of Bands. A test holds them to
// BandOf at every band edge (the products a 1-to-5 by 1-to-5 rating can reach)
// and to the contiguity of the ranges, so the words cannot drift from the
// computation.
var riskBandEdges = []riskBandEdge{
	{BandLow, 1, 6},
	{BandMedium, 7, 12},
	{BandHigh, 13, 19},
	{BandCritical, 20, 25},
}

// renderBandMethod writes the band method from riskBandEdges. BandMethodText is
// its output as a constant (a constant is part of the frozen contract); a test
// asserts the two are equal.
func renderBandMethod() string {
	parts := make([]string, len(riskBandEdges))
	for i, e := range riskBandEdges {
		parts[i] = fmt.Sprintf("%s %d-%d", e.Band, e.Min, e.Max)
	}
	return "Risk is rated as likelihood times impact, each a whole number 1 to 5: " + strings.Join(parts, ", ") +
		". This is an ordinal heuristic, not a probability and not a loss figure. No residual score is computed: credited mitigations are shown beside the band, never subtracted from it. Observer computes the band; write only the two numbers."
}

// BandMethodText is the sentence block that states how risk is rated.
const BandMethodText = "Risk is rated as likelihood times impact, each a whole number 1 to 5: low 1-6, medium 7-12, high 13-19, critical 20-25. This is an ordinal heuristic, not a probability and not a loss figure. No residual score is computed: credited mitigations are shown beside the band, never subtracted from it. Observer computes the band; write only the two numbers."
