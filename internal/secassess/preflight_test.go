package secassess

import (
	"strings"
	"testing"
)

// pfNote finds a note by id.
func pfNote(notes []Note, id string) (Note, bool) {
	for _, n := range notes {
		if n.ID == id {
			return n, true
		}
	}
	return Note{}, false
}

func pfNodeFacts(extraNames []string, present []string, extraFiles ...ProjectFile) ProjectFacts {
	files := append([]ProjectFile{pjFile("package.json", `{"scripts":{"dev":"vite"},"dependencies":{"express":"4"}}`)}, extraFiles...)
	return AnalyzeProject(SurveyInput{Names: append([]string{"package.json"}, extraNames...), Files: files, Present: present})
}

// TestPreflightRules is one case per rule of the table.
func TestPreflightRules(t *testing.T) {
	for _, c := range []struct {
		name  string
		facts ProjectFacts
		in    PreflightInput
		id    string
		level NoteLevel // "" means the note must be absent
		text  []string
	}{
		{
			"deps missing, proxy_only", pfNodeFacts(nil, nil),
			PreflightInput{Tier: "proxy_only"},
			"deps_not_installed", NoteLikelyFails,
			[]string{"no node_modules", "The box cannot install packages while its network is limited to the model proxy: run the installer outside first"},
		},
		{"deps missing, no tier", pfNodeFacts(nil, nil), PreflightInput{}, "deps_not_installed", NoteLikelyFails, []string{"cannot install packages while its network is limited to the model proxy"}},
		{"deps missing, internet", pfNodeFacts(nil, nil), PreflightInput{Tier: "internet"}, "deps_not_installed", NoteWarn, []string{"can reach the internet"}},
		{"deps installed", pfNodeFacts(nil, []string{"node_modules"}), PreflightInput{}, "deps_not_installed", "", nil},
		{
			"python venv missing", AnalyzeProject(SurveyInput{Names: []string{"requirements.txt"}, Files: []ProjectFile{pjFile("requirements.txt", "flask\n")}}),
			PreflightInput{},
			"deps_not_installed", NoteLikelyFails,
			[]string{"no a venv or .venv folder"},
		},
		{
			"python venv present", AnalyzeProject(SurveyInput{Names: []string{"requirements.txt"}, Dirs: []string{".venv"}, Present: []string{".venv"}, Files: []ProjectFile{pjFile("requirements.txt", "flask\n")}}),
			PreflightInput{},
			"deps_not_installed", "", nil,
		},
		{
			"no manifest dependencies", AnalyzeProject(SurveyInput{Names: []string{"package.json"}, Files: []ProjectFile{pjFile("package.json", `{"scripts":{}}`)}}),
			PreflightInput{},
			"deps_not_installed", "", nil,
		},
		{
			"go needs no folder", AnalyzeProject(SurveyInput{Names: []string{"go.mod"}, Files: []ProjectFile{pjFile("go.mod", "require github.com/gin-gonic/gin v1\n")}}),
			PreflightInput{},
			"deps_not_installed", "", nil,
		},

		{
			"service from compose", AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("compose.yml", "services:\n  db:\n    image: postgres\n  c:\n    image: redis\n")}}),
			PreflightInput{},
			"service_needed", NoteWarn,
			[]string{"postgres and redis", "The box has no route to one (Observer cannot see a container engine there either)", "start it yourself and tell the agent"},
		},
		{
			"service from compose, proxy_only", AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("compose.yml", "services:\n  db:\n    image: postgres\n")}}),
			PreflightInput{Tier: "proxy_only"},
			"service_needed", NoteWarn,
			[]string{"The box has no route to one (Observer cannot see a container engine there either)"},
		},
		{
			"service from compose, internet", AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("compose.yml", "services:\n  db:\n    image: postgres\n")}}),
			PreflightInput{Tier: "internet"},
			"service_needed", NoteWarn,
			[]string{"The box can reach the internet, so a remote one may answer", "Observer cannot see a container engine in the box, so do not count on a local one", "start it yourself and tell the agent"},
		},
		{
			"service from compose, a tier that is not known reads as the narrowest", AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("compose.yml", "services:\n  db:\n    image: postgres\n")}}),
			PreflightInput{Tier: "somethingelse"},
			"service_needed", NoteWarn,
			[]string{"The box has no route to one"},
		},
		{
			"service from env example", AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile(".env.example", "DATABASE_URL=mysql://x\nOTHER_URL=mysql://y\n")}}),
			PreflightInput{},
			"service_needed", NoteWarn,
			[]string{"names mysql as a service"},
		},
		{"no services", pfNodeFacts(nil, nil), PreflightInput{}, "service_needed", "", nil},

		{
			"no start command", AnalyzeProject(SurveyInput{Names: []string{"go.mod"}}),
			PreflightInput{},
			"no_start_command", NoteWarn,
			[]string{"No start command could be read from the project's files", "you can type it"},
		},
		{
			"entries that cannot be a plain command", AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("Procfile", "web: gunicorn app:app -b 0.0.0.0:$PORT\n")}}),
			PreflightInput{},
			"no_start_command", NoteWarn,
			[]string{"The project's files name 1 start command, but none that can be written as a plain command", "no quotes, pipes, variables or shell", "you can type it"},
		},
		{
			"two entries that cannot be a plain command", AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile(".claude/launch.json", `{"configurations":[{"runtimeExecutable":"sh","runtimeArgs":["-c","a && b"]},{"runtimeExecutable":"bash","runtimeArgs":["-c","c d"]}]}`)}}),
			PreflightInput{},
			"no_start_command", NoteWarn,
			[]string{"name 2 start commands, but none that can be written as a plain command"},
		},
		{"a reserved word is an entry that cannot be a command", AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("Procfile", "web: none\n")}}), PreflightInput{}, "no_start_command", NoteWarn, []string{"name 1 start command, but none that"}},
		{"entries dropped but a plan exists", AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("Procfile", "web: gunicorn app:app -b 0.0.0.0:$PORT\n"), pjFile("package.json", `{"scripts":{"dev":"vite"}}`)}}), PreflightInput{}, "no_start_command", "", nil},
		{"entries dropped but a start was chosen", AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("Procfile", "web: gunicorn app:app -b 0.0.0.0:$PORT\n")}}), PreflightInput{Start: &StartPlan{Argv: []string{"make", "run"}}}, "no_start_command", "", nil},
		{"start plans exist", pfNodeFacts(nil, nil), PreflightInput{}, "no_start_command", "", nil},
		{"a start was chosen", AnalyzeProject(SurveyInput{}), PreflightInput{Start: &StartPlan{Argv: []string{"make", "run"}}}, "no_start_command", "", nil},

		{
			"env files named", pfNodeFacts([]string{".env", ".env.example", ".env.local"}, nil),
			PreflightInput{},
			"env_files", NoteWarn,
			[]string{"2 environment files (.env, .env.local) are in this folder", "can read them: the agent is told not to."},
		},
		{"one env file", pfNodeFacts([]string{".env"}, nil), PreflightInput{}, "env_files", NoteWarn, []string{"1 environment file (.env) is in this folder and the box can read it:"}},
		{"many env files", pfNodeFacts([]string{".env", ".env.a", ".env.b", ".env.c", ".env.d", ".env.e", ".env.f"}, nil), PreflightInput{}, "env_files", NoteWarn, []string{"7 environment files", "and 2 more"}},
		{"examples only", pfNodeFacts([]string{".env.example"}, nil), PreflightInput{}, "env_files", "", nil},

		{"no lock file", pfNodeFacts(nil, nil), PreflightInput{}, "no_lockfile", NoteInfo, []string{"for the node packages"}},
		{"lock file there", pfNodeFacts([]string{"yarn.lock"}, nil), PreflightInput{}, "no_lockfile", "", nil},
		{"no dependencies, no lock needed", AnalyzeProject(SurveyInput{Names: []string{"package.json"}}), PreflightInput{}, "no_lockfile", "", nil},
		{"python has no lock rule", AnalyzeProject(SurveyInput{Names: []string{"requirements.txt"}, Files: []ProjectFile{pjFile("requirements.txt", "flask\n")}}), PreflightInput{}, "no_lockfile", "", nil},

		{
			"prepare step", pfNodeFacts(nil, nil),
			PreflightInput{Start: &StartPlan{Argv: []string{"python", "manage.py", "runserver"}, Prepare: [][]string{{"python", "manage.py", "migrate"}, {"python", "manage.py", "loaddata", "seed"}}}},
			"start_prepare", NoteInfo,
			[]string{"The project's files suggest preparation steps (python manage.py migrate; python manage.py loaddata seed). They will not run unless you tick Run the preparation steps first; without them the app may not start."},
		},
		{
			"prepare step, chosen", pfNodeFacts(nil, nil),
			PreflightInput{PrepareChosen: true, Start: &StartPlan{Argv: []string{"python", "manage.py", "runserver"}, Prepare: [][]string{{"python", "manage.py", "migrate"}, {"python", "manage.py", "loaddata", "seed"}}}},
			"start_prepare", NoteWarn,
			[]string{"These steps run first and can change local data in the project, for example its database file: python manage.py migrate; python manage.py loaddata seed."},
		},
		{
			"prepare step, a step the placement refuses", pfNodeFacts(nil, nil),
			PreflightInput{PrepareChosen: true, Start: &StartPlan{Argv: []string{"x"}, Prepare: [][]string{{"a`b"}, {"go", "generate"}}}},
			"start_prepare", NoteWarn,
			[]string{"database file: a step that cannot be shown here; go generate."},
		},
		{
			"prepare step, chosen but the plan has none", pfNodeFacts(nil, nil),
			PreflightInput{PrepareChosen: true, Start: &StartPlan{Argv: []string{"npm", "run", "dev"}}},
			"start_prepare", "", nil,
		},
		{"no prepare step", pfNodeFacts(nil, nil), PreflightInput{Start: &StartPlan{Argv: []string{"npm", "run", "dev"}}}, "start_prepare", "", nil},
		{"no chosen start", pfNodeFacts(nil, nil), PreflightInput{}, "start_prepare", "", nil},
		{"no chosen start, prepare ticked", pfNodeFacts(nil, nil), PreflightInput{PrepareChosen: true}, "start_prepare", "", nil},

		{
			"start port differs from the target", pfNodeFacts(nil, nil),
			PreflightInput{TargetPort: 3000, Start: &StartPlan{Argv: []string{"npm", "run", "dev"}, Port: 5173}},
			"start_port", NoteWarn,
			[]string{"expected to listen on port 5173, but the target you chose is on port 3000", "skipped (not started)", "choose the target on port 5173", "listens on port 3000"},
		},
		{"start port equals the target's", pfNodeFacts(nil, nil), PreflightInput{TargetPort: 3000, Start: &StartPlan{Argv: []string{"npm", "run", "dev"}, Port: 3000}}, "start_port", "", nil},
		{"start port unknown", pfNodeFacts(nil, nil), PreflightInput{TargetPort: 3000, Start: &StartPlan{Argv: []string{"make", "dev"}}}, "start_port", "", nil},
		{"target port unknown", pfNodeFacts(nil, nil), PreflightInput{Start: &StartPlan{Argv: []string{"npm", "run", "dev"}, Port: 5173}}, "start_port", "", nil},
		{"no start chosen", pfNodeFacts(nil, nil), PreflightInput{TargetPort: 3000}, "start_port", "", nil},

		{
			"openapi json", AnalyzeProject(SurveyInput{Names: []string{"openapi.json"}, Files: []ProjectFile{pjFile("openapi.json", `{"openapi":"3","paths":{"/a":{"get":{},"post":{}}}}`)}}),
			PreflightInput{},
			"api_spec", NoteInfo,
			[]string{"(openapi.json, 2 operations)"},
		},
		{
			"openapi one operation", AnalyzeProject(SurveyInput{Names: []string{"openapi.json"}, Files: []ProjectFile{pjFile("openapi.json", `{"openapi":"3","paths":{"/a":{"get":{}}}}`)}}),
			PreflightInput{},
			"api_spec", NoteInfo,
			[]string{"1 operation)"},
		},
		{"openapi yaml", AnalyzeProject(SurveyInput{Names: []string{"openapi.yaml"}}), PreflightInput{}, "api_spec", NoteInfo, []string{"(openapi.yaml)"}},
		{"no spec", pfNodeFacts(nil, nil), PreflightInput{}, "api_spec", "", nil},

		{"survey truncated", AnalyzeProject(SurveyInput{Truncated: true}), PreflightInput{}, "survey_truncated", NoteInfo, []string{"size or time limit"}},
		{"survey complete", AnalyzeProject(SurveyInput{}), PreflightInput{}, "survey_truncated", "", nil},
	} {
		notes := Preflight(c.facts, c.in)
		n, ok := pfNote(notes, c.id)
		if c.level == "" {
			if ok {
				t.Errorf("%s: unexpected note %+v", c.name, n)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: no %s note in %+v", c.name, c.id, notes)
			continue
		}
		if n.Level != c.level {
			t.Errorf("%s: level %s, want %s", c.name, n.Level, c.level)
		}
		for _, want := range c.text {
			if !strings.Contains(n.Text, want) {
				t.Errorf("%s: text %q does not contain %q", c.name, n.Text, want)
			}
		}
	}
}

// TestPreflightTableCoverage: every rule id has a case above that produces its
// note, and the ids are the closed list.
func TestPreflightTableCoverage(t *testing.T) {
	want := []string{"deps_not_installed", "service_needed", "no_start_command", "start_port", "env_files", "no_lockfile", "start_prepare", "api_spec", "survey_truncated"}
	if len(pflRules) != len(want) {
		t.Fatalf("%d rules, want %d", len(pflRules), len(want))
	}
	for i, r := range pflRules {
		if r.id != want[i] {
			t.Errorf("rule %d is %q, want %q", i, r.id, want[i])
		}
	}
}

// TestPreflightOrder: most severe first, rule order within a level.
func TestPreflightOrder(t *testing.T) {
	f := AnalyzeProject(SurveyInput{
		Names: []string{"package.json", ".env", "openapi.yaml"}, Truncated: true,
		Files: []ProjectFile{
			pjFile("package.json", `{"dependencies":{"express":"4"}}`),
			pjFile("compose.yml", "services:\n  db:\n    image: postgres\n"),
		},
	})
	notes := Preflight(f, PreflightInput{Tier: "proxy_only", Start: &StartPlan{Argv: []string{"x"}, Prepare: [][]string{{"y"}}}})
	var ids []string
	for _, n := range notes {
		ids = append(ids, string(n.Level)+":"+n.ID)
	}
	want := "likely_fails:deps_not_installed warn:service_needed warn:env_files info:no_lockfile info:start_prepare info:api_spec info:survey_truncated"
	if got := strings.Join(ids, " "); got != want {
		t.Errorf("order\n got %s\nwant %s", got, want)
	}
	// Under the wider tier the same note drops to a warning and sorts with them.
	notes = Preflight(f, PreflightInput{Tier: "internet", Start: &StartPlan{Argv: []string{"x"}}})
	if notes[0].ID != "deps_not_installed" || notes[0].Level != NoteWarn {
		t.Errorf("internet tier: %+v", notes[0])
	}
}

func TestPreflightNeverRefusesAndIsSafe(t *testing.T) {
	// An empty value, and facts from an empty survey, give notes and no panic.
	_ = Preflight(ProjectFacts{}, PreflightInput{})
	notes := Preflight(AnalyzeProject(SurveyInput{}), PreflightInput{})
	if n, ok := pfNote(notes, "no_start_command"); !ok || n.Level != NoteWarn {
		t.Errorf("an empty project: %+v", notes)
	}
	for _, n := range notes {
		if n.ID == "" || n.Text == "" || pflRank[n.Level] > 2 {
			t.Errorf("malformed note %+v", n)
		}
	}
}

func TestPreflightListWords(t *testing.T) {
	for in, want := range map[string]string{"": "", "a": "a", "a,b": "a and b", "a,b,c": "a, b and c"} {
		var words []string
		if in != "" {
			words = strings.Split(in, ",")
		}
		if got := pflList(words); got != want {
			t.Errorf("pflList(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestPreflightFactsWithoutAnalysis: a ProjectFacts value built by hand (no
// per-language counts) still gets the install rule from its totals.
func TestPreflightFactsWithoutAnalysis(t *testing.T) {
	f := ProjectFacts{Languages: []string{"node"}, DepCount: 3}
	n, ok := pfNote(Preflight(f, PreflightInput{}), "deps_not_installed")
	if !ok || n.Level != NoteLikelyFails {
		t.Errorf("deps_not_installed = %+v %v", n, ok)
	}
}

// TestPreflightNoteWords: no note claims more than Observer knows (the banned
// claim words of the method texts), whichever rule or tier produced it.
func TestPreflightNoteWords(t *testing.T) {
	f := AnalyzeProject(SurveyInput{
		Names: []string{"package.json", ".env", "openapi.yaml"}, Truncated: true,
		Files: []ProjectFile{
			pjFile("package.json", `{"dependencies":{"express":"4"}}`),
			pjFile("compose.yml", "services:\n  db:\n    image: postgres\n"),
			pjFile("Procfile", "web: gunicorn app:app -b 0.0.0.0:$PORT\n"),
		},
	})
	plan := &StartPlan{Argv: []string{"python", "manage.py", "runserver"}, Port: 8000, Prepare: [][]string{{"python", "manage.py", "migrate"}}}
	seen := map[string]bool{}
	for _, in := range []PreflightInput{
		{Tier: "proxy_only"},
		{Tier: "internet"},
		{},
		{Tier: "proxy_only", Start: plan, TargetPort: 3000},
		{Tier: "internet", Start: plan, TargetPort: 3000, PrepareChosen: true},
	} {
		for _, n := range Preflight(f, in) {
			seen[n.ID] = true
			mCheckWords(t, "preflight note "+n.ID, n.Text)
			if strings.ContainsAny(n.Text, "\r\n") || clean(n.Text, 1000) != n.Text {
				t.Errorf("note %s has a break or is changed by clean: %q", n.ID, n.Text)
			}
		}
	}
	for _, r := range pflRules {
		if !seen[r.id] {
			t.Errorf("rule %s produced no note in this test", r.id)
		}
	}
}
