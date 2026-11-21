package secassess

import (
	"reflect"
	"testing"
)

// pjSignalFacts builds facts that show exactly one signal of the AppFacts
// table, plus a manifest so they do not read as "unknown".
func pjSignalFacts(s projSignal) ProjectFacts {
	f := ProjectFacts{Manifests: []string{"package.json"}}
	switch s.kind {
	case "role":
		f.Deps = []DepRole{{Role: s.value, Names: []string{"x"}}}
	case "framework":
		f.Frameworks = []string{s.value}
	case "dir":
		f.Dirs = []string{s.value}
	case "spec":
		f.SpecPath = "openapi.json"
	case "spec_auth":
		f.SpecPath = "openapi.json"
		f.Spec = &SpecSummary{Path: "openapi.json", AuthSchemes: []string{"bearerAuth"}}
	case "start":
		f.src = []ProjectFile{pjFile("package.json", `{"scripts":{"dev":"vite"}}`)}
	}
	return f
}

// TestProjectFactRules is one case per signal of the AppFacts table: a project
// showing only that signal has the row's fact.
func TestProjectFactRules(t *testing.T) {
	facts := projSet(GroundingFacts)
	for _, r := range projFactRules {
		if !facts[r.fact] || r.fact == FactAlways {
			t.Errorf("rule for %q: not a conditional grounding fact", r.fact)
		}
		for _, s := range r.signals {
			got := pjSignalFacts(s).AppFacts()
			if !strSliceHas(got, r.fact) {
				t.Errorf("%s via %s %q: AppFacts = %v", r.fact, s.kind, s.value, got)
			}
			if got[0] != FactAlways {
				t.Errorf("FactAlways is not first: %v", got)
			}
		}
	}
}

func TestAppFacts(t *testing.T) {
	all := []string{FactAlways, FactLogin, FactSessions, FactBrowserClient, FactHTTPAPI}
	for _, c := range []struct {
		name  string
		facts ProjectFacts
		want  []string
	}{
		// Unknown is not "not applicable": nothing was seen, so everything holds.
		{"unknown: empty", ProjectFacts{}, all},
		{"unknown: only listings", ProjectFacts{Dirs: []string{"src"}, Infra: []string{"dockerfile"}}, all},
		{"unknown: analysed README folder", AnalyzeProject(SurveyInput{Names: []string{"README.md"}}), all},
		// An agent configuration file says the project was written with an AI
		// tool, not what it is: it does not make an unknown folder known.
		{"unknown: only an agent file", AnalyzeProject(SurveyInput{Names: []string{"README.md", "CLAUDE.md"}}), all},
		{"known: a tool-server config", AnalyzeProject(SurveyInput{Names: []string{".mcp.json"}}), []string{FactAlways}},
		{"unknown: nothing at all", AnalyzeProject(SurveyInput{}), all},
		// A Go library: known (go.mod), no web signal.
		{"library", AnalyzeProject(SurveyInput{Names: []string{"go.mod"}, Files: []ProjectFile{pjFile("go.mod", "module x\n\nrequire github.com/pkg/errors v1\n")}}), []string{FactAlways}},
		// An API-only service: a framework and a spec, no template or client.
		{
			"api only", AnalyzeProject(SurveyInput{Names: []string{"requirements.txt", "openapi.json"}, Files: []ProjectFile{pjFile("requirements.txt", "fastapi\n")}}),
			[]string{FactAlways, FactLogin, FactHTTPAPI},
		},
		// A server-rendered Django app has all four.
		{"django", AnalyzeProject(SurveyInput{Names: []string{"requirements.txt"}, Files: []ProjectFile{pjFile("requirements.txt", "django\n")}}), all},
		// A static front end: a client, no server.
		{
			"front end only", AnalyzeProject(SurveyInput{Names: []string{"package.json"}, Files: []ProjectFile{pjFile("package.json", `{"dependencies":{"react":"18"}}`)}}),
			[]string{FactAlways, FactBrowserClient},
		},
		// Express with a login library has login, sessions and an API, and a
		// public folder gives it a client.
		{"express with auth", AnalyzeProject(SurveyInput{Names: []string{"package.json"}, Dirs: []string{"public"}, Files: []ProjectFile{pjFile("package.json", `{"dependencies":{"express":"4","passport":"1"}}`)}}), all},
		// A hand-rolled login: a web framework and no auth library still holds login.
		{
			"express without auth library", AnalyzeProject(SurveyInput{Names: []string{"package.json"}, Files: []ProjectFile{pjFile("package.json", `{"dependencies":{"express":"4"}}`)}}),
			[]string{FactAlways, FactLogin, FactHTTPAPI},
		},
	} {
		if got := c.facts.AppFacts(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: AppFacts = %v, want %v", c.name, got, c.want)
		}
	}
}
