package secframework

import (
	"sort"
	"strings"
)

// Framework is one framework family the report can pick.
type Framework string

// The frameworks of section 7.8.
const (
	OWASPAgentic Framework = "owasp-agentic-2026"
	OWASPLLM     Framework = "owasp-llm-2026"
	ATLAS        Framework = "mitre-atlas-2026.09"
)

// Frameworks returns the framework picker's values in report order.
func Frameworks() []Framework { return []Framework{OWASPAgentic, OWASPLLM, ATLAS} }

// Status is one id's coverage status.
type Status string

// The statuses.
const (
	// StatusCovered: every requirement group has a selected control.
	StatusCovered Status = "covered"
	// StatusPartial: some groups have a selected control, others do not.
	StatusPartial Status = "partial"
	// StatusNotSelected: the controls are in this build but none is
	// selected.
	StatusNotSelected Status = "not_selected"
	// StatusNotBuilt: no control for the id is in this build.
	StatusNotBuilt Status = "not_built"
)

// Group is one requirement: met by any one of its components.
type Group struct {
	// What says, in Observer's words, what the group contributes.
	What string
	// AnyOf lists the catalog component ids that meet the group.
	AnyOf []string
}

// Entry is one framework id and Observer's controls for it.
type Entry struct {
	Framework Framework
	ID        string
	// Scope says, in Observer's words, what Observer checks under this id
	// (not the framework's title or text).
	Scope  string
	Groups []Group
}

// Mapping is the closed mapping table, in report order. One test case per
// row (secframework_test.go); every component id must be in the catalog.
var Mapping = []Entry{
	{
		Framework: OWASPAgentic, ID: "ASI02",
		Scope: "An agent using the tools it was given in ways that hurt the project: dangerous commands, hook bypasses and unscanned commits.",
		Groups: []Group{
			{What: "guard rules on every gated tool call and the commit gate", AnyOf: []string{"security"}},
			{What: "secret checks on what the agent writes and commits", AnyOf: []string{"security.secrets"}},
		},
	},
	{
		Framework: OWASPAgentic, ID: "ASI04",
		Scope: "What an agent brings into the project from outside: packages it installs, dependencies it adds and repository configuration it trusts.",
		Groups: []Group{
			{What: "install-time package checks", AnyOf: []string{"security.deps"}},
			{What: "a dependency scanner over the lockfiles", AnyOf: []string{"security.scan.scalibr", "security.scan.osv"}},
			{What: "repository trust before an agent starts", AnyOf: []string{"security.trust"}},
		},
	},
	{
		Framework: OWASPAgentic, ID: "ASI05",
		Scope: "Code an agent writes that runs later: CI workflows, weakened tests and secrets left in files.",
		Groups: []Group{
			{What: "native diff rules on agent changes", AnyOf: []string{"security.code"}},
			{What: "secret checks on written files and commits", AnyOf: []string{"security.secrets"}},
		},
	},
	{
		Framework: OWASPLLM, ID: "LLM03",
		Scope: "Third-party components a model-driven change pulls in.",
		Groups: []Group{
			{What: "install-time package checks", AnyOf: []string{"security.deps"}},
			{What: "a dependency scanner over the lockfiles", AnyOf: []string{"security.scan.scalibr", "security.scan.osv"}},
		},
	},
	{
		Framework: ATLAS, ID: "AML.T0081",
		Scope: "Changes to an agent's own configuration or instructions inside the repository.",
		Groups: []Group{
			{What: "the agent configuration baseline and repository trust", AnyOf: []string{"security.trust"}},
		},
	},
	{
		Framework: ATLAS, ID: "AML.T0083",
		Scope: "Credentials an agent can reach and write out.",
		Groups: []Group{
			{What: "secret checks on what the agent writes and commits", AnyOf: []string{"security.secrets"}},
		},
	},
	{
		Framework: ATLAS, ID: "AML.M0029",
		Scope: "A person in the loop for risky agent actions.",
		Groups: []Group{
			{What: "the commit gate's ask and exceptions only a person grants", AnyOf: []string{"security"}},
			{What: "templated feedback to the agent after a finding", AnyOf: []string{"security.feedback"}},
		},
	},
	{
		Framework: ATLAS, ID: "AML.M0030",
		Scope: "Limiting what an agent does with untrusted repository content.",
		Groups: []Group{
			{What: "repository trust before an agent starts", AnyOf: []string{"security.trust"}},
			{What: "findings text kept out of agent instructions (templated lines only)", AnyOf: []string{"security"}},
		},
	},
}

// Facts are the injected predicates.
type Facts struct {
	// Built reports whether a component is compiled into this binary.
	Built func(id string) bool
	// Selected reports whether it is selected (the opt-in rule applied).
	Selected func(id string) bool
}

// GroupResult is one group's outcome.
type GroupResult struct {
	What     string   `json:"what"`
	Built    []string `json:"built,omitempty"`
	Selected []string `json:"selected,omitempty"`
}

// Row is one id's outcome.
type Row struct {
	Framework Framework     `json:"framework"`
	ID        string        `json:"id"`
	Scope     string        `json:"scope"`
	Status    Status        `json:"status"`
	Groups    []GroupResult `json:"groups"`
}

// statusRule is one row of the status table, walked top to bottom.
type statusRule struct {
	when   func(groups, built, selected int) bool
	status Status
}

// statusRules is the decision table: groups is the number of requirement
// groups, built how many have a control in this build, selected how many
// have a selected control.
var statusRules = []statusRule{
	{func(g, _, s int) bool { return g > 0 && s == g }, StatusCovered},
	{func(_, _, s int) bool { return s > 0 }, StatusPartial},
	{func(_, b, _ int) bool { return b > 0 }, StatusNotSelected},
	{func(int, int, int) bool { return true }, StatusNotBuilt},
}

// Report evaluates the ids of the picked frameworks (none: every one).
func Report(f Facts, pick ...Framework) []Row {
	want := map[Framework]bool{}
	for _, p := range pick {
		want[p] = true
	}
	var out []Row
	for _, e := range Mapping {
		if len(want) > 0 && !want[e.Framework] {
			continue
		}
		row := Row{Framework: e.Framework, ID: e.ID, Scope: e.Scope}
		built, selected := 0, 0
		for _, g := range e.Groups {
			gr := GroupResult{What: g.What}
			for _, id := range g.AnyOf {
				if f.Built != nil && f.Built(id) {
					gr.Built = append(gr.Built, id)
					if f.Selected != nil && f.Selected(id) {
						gr.Selected = append(gr.Selected, id)
					}
				}
			}
			if len(gr.Built) > 0 {
				built++
			}
			if len(gr.Selected) > 0 {
				selected++
			}
			row.Groups = append(row.Groups, gr)
		}
		for _, r := range statusRules {
			if r.when(len(e.Groups), built, selected) {
				row.Status = r.status
				break
			}
		}
		out = append(out, row)
	}
	return out
}

// ParseFramework maps the picker's value ("all" or "" picks every one).
func ParseFramework(s string) ([]Framework, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "all" {
		return nil, true
	}
	for _, f := range Frameworks() {
		if string(f) == s {
			return []Framework{f}, true
		}
	}
	return nil, false
}

// ComponentIDs returns every component id the mapping names, sorted.
func ComponentIDs() []string {
	seen := map[string]bool{}
	for _, e := range Mapping {
		for _, g := range e.Groups {
			for _, id := range g.AnyOf {
				seen[id] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
