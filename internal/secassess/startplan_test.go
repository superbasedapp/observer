package secassess

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// pjScriptCases is one case per scriptRules row plus the explicit-port forms
// and the negatives. The drift test in secassesssvc feeds the same commands to
// secdast.ScriptPort.
var pjScriptCases = []struct {
	cmd  string
	port int
	rule string
}{
	{"next dev", 3000, "next"},
	{"nuxi dev", 3000, "nuxt"},
	{"remix vite:dev", 3000, "remix"},
	{"react-scripts start", 3000, "react-scripts"},
	{"astro dev", 4321, "astro"},
	{"ng serve", 4200, "angular"},
	{"svelte-kit dev", 5173, "sveltekit"},
	{"vite", 5173, "vite"},
	{"vite dev --host", 5173, "vite"},
	{"gatsby develop", 8000, "gatsby"},
	{"vue-cli-service serve", 8080, "vue-cli"},
	{"webpack serve --mode development", 8080, "webpack"},
	{"parcel src/index.html", 1234, "parcel"},
	{"storybook dev", 6006, "storybook"},
	{"expo start", 8081, "expo"},
	{"python manage.py runserver", 8000, "django"},
	{"flask run", 5000, "flask"},
	{"bin/rails server", 3000, "rails"},
	{"hugo server -D", 1313, "hugo"},
	{"bundle exec jekyll serve", 4000, "jekyll"},
	{"nodemon src/server.js", 3000, "express"},
	// Explicit ports win over the row's default.
	{"next dev -p 4000", 4000, "next"},
	{"vite --port=5555", 5555, "vite"},
	{"PORT=3100 react-scripts start", 3100, "react-scripts"},
	{"python manage.py runserver 0.0.0.0:8100", 8100, "django"},
	{"flask run --port 5100", 5100, "flask"},
	{"astro dev --listen 4400", 4400, "astro"},
}

var pjScriptNegatives = []string{"tsc -p tsconfig.json", "eslint .", "vitest run", "jest", "", "node build.js", "npm test"}

func TestScriptPortTable(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range pjScriptCases {
		p, rule, ok := ScriptPort(c.cmd)
		if !ok || p != c.port || rule != c.rule {
			t.Errorf("ScriptPort(%q) = %d %q %v, want %d %q", c.cmd, p, rule, ok, c.port, c.rule)
		}
		covered[c.rule] = true
	}
	for _, r := range scriptRules {
		if !covered[r.name] {
			t.Errorf("scriptRules row %q has no case", r.name)
		}
	}
	for _, cmd := range pjScriptNegatives {
		if _, _, ok := ScriptPort(cmd); ok {
			t.Errorf("ScriptPort(%q) matched a dev server", cmd)
		}
	}
}

func TestDevServerFilesAreRead(t *testing.T) {
	for _, p := range DevServerFiles {
		rel := strings.TrimSuffix(p, "*")
		if p == "vite.config*" {
			rel = "vite.config.ts"
		}
		if !splReads(rel) {
			t.Errorf("%q is in DevServerFiles but the start table does not read it", p)
		}
	}
	for _, rel := range []string{"Procfile", "Makefile", "vite.config.mjs"} {
		if !splReads(rel) {
			t.Errorf("%q is not read", rel)
		}
	}
	for _, rel := range []string{".env", "README.md", "src/package.json", "procfile", ".env.example", "docker-compose.yml"} {
		if splReads(rel) {
			t.Errorf("%q must not be read by the start table", rel)
		}
	}
}

// TestPlanCandidates walks the candidate file table: one case per row, dedup by
// URL, first source wins (the same expectation as secdast's own test).
func TestPlanCandidates(t *testing.T) {
	f := AnalyzeProject(SurveyInput{Files: []ProjectFile{
		pjFile(".claude/launch.json", `{"configurations":[{"name":"web","port":5173}]}`),
		pjFile("package.json", `{"scripts":{"dev":"vite","storybook":"storybook dev -p 6007","lint":"eslint ."}}`),
		pjFile("vite.config.ts", `export default { server: { host: true, port: 5180 } }`),
		pjFile("manage.py", `os.environ.setdefault("DJANGO_SETTINGS_MODULE", "x")  # django`),
		pjFile(".flaskenv", "FLASK_APP=app\nFLASK_RUN_PORT=5050\n"),
		pjFile("bin/rails", "#!/usr/bin/env ruby\n"),
		pjFile("config/puma.rb", `port ENV.fetch("PORT") { 3030 }`),
		pjFile("hugo.toml", "baseURL = 'x'\n"),
		pjFile("_config.yml", "theme: minima\nport: 4001\n"),
		pjFile("README.md", "next dev"),
	}})
	want := []Candidate{
		{URL: "http://localhost:5173/", Name: "web", Source: StartSourceLaunchJSON},
		{URL: "http://localhost:6007/", Name: "npm run storybook (storybook)", Source: StartSourcePackageJSON},
		{URL: "http://localhost:5180/", Name: "vite", Source: StartSourceViteConfig},
		{URL: "http://localhost:8000/", Name: "django", Source: StartSourceDjango},
		{URL: "http://localhost:5050/", Name: "flask", Source: StartSourceFlask},
		{URL: "http://localhost:3000/", Name: "rails", Source: StartSourceRails},
		{URL: "http://localhost:3030/", Name: "rails", Source: StartSourceRails},
		{URL: "http://localhost:1313/", Name: "hugo", Source: StartSourceHugo},
		{URL: "http://localhost:4001/", Name: "jekyll", Source: StartSourceJekyll},
	}
	got := PlanCandidates(f)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PlanCandidates =\n%+v\nwant\n%+v", got, want)
	}
	for _, c := range got {
		if _, err := ParseTarget(c.URL); err != nil {
			t.Errorf("%s: %v", c.URL, err)
		}
	}
	for name, files := range map[string][]ProjectFile{
		"over the cap":      {{Rel: "package.json", Data: make([]byte, MaxProjectFile+1)}},
		"jekyll no signal":  {pjFile("_config.yml", "title: docs\n")},
		"manage.py no name": {pjFile("manage.py", "import os\n")},
		"vite no port":      {pjFile("vite.config.ts", "export default {}")},
		"empty":             {pjFile("package.json", "")},
		"no files":          nil,
	} {
		if c := PlanCandidates(AnalyzeProject(SurveyInput{Files: files})); len(c) != 0 {
			t.Errorf("%s produced %v", name, c)
		}
	}
	// A facts value that did not come from AnalyzeProject plans nothing.
	if PlanCandidates(ProjectFacts{}) != nil || PlanStarts(ProjectFacts{}) != nil {
		t.Error("an empty ProjectFacts planned something")
	}
}

func pjPlans(files ...ProjectFile) []StartPlan {
	return PlanStarts(AnalyzeProject(SurveyInput{Files: files}))
}

// TestPlanStartsRows is one case per row of the start table.
func TestPlanStartsRows(t *testing.T) {
	for _, c := range []struct {
		name  string
		files []ProjectFile
		want  []StartPlan
	}{
		{
			"launch.json: executable, args and port",
			[]ProjectFile{pjFile(".claude/launch.json",
				`{"configurations":[{"name":"web","runtimeExecutable":"npm","runtimeArgs":["run","dev"],"port":5173},{"name":"api","runtimeExecutable":"node","runtimeArgs":["server.js"]},{"name":"portonly","port":3000}]}`)},
			[]StartPlan{
				{Argv: []string{"npm", "run", "dev"}, Port: 5173, Source: "launch.json"},
				{Argv: []string{"node", "server.js"}, Port: 3000, Source: "launch.json", Rule: "express"},
			},
		},
		{
			"launch.json: url port, numeric arg, cwd",
			[]ProjectFile{pjFile(".claude/launch.json",
				`{"configurations":[{"runtimeExecutable":"python","runtimeArgs":["-m","http.server",8080],"url":"http://127.0.0.1:8080/","cwd":"./site"}]}`)},
			[]StartPlan{{Argv: []string{"python", "-m", "http.server", "8080"}, Cwd: "site", Port: 8080, Source: "launch.json"}},
		},
		{
			"launch.json: port from the command",
			[]ProjectFile{pjFile(".claude/launch.json",
				`{"configurations":[{"runtimeExecutable":"next","runtimeArgs":["dev","-p","4000"]}]}`)},
			[]StartPlan{{Argv: []string{"next", "dev", "-p", "4000"}, Port: 4000, Source: "launch.json", Rule: "next"}},
		},
		{
			"package.json: dev start serve",
			[]ProjectFile{pjFile("package.json",
				`{"scripts":{"serve":"vue-cli-service serve","start":"node server.js","dev":"next dev -p 4000","build":"next build","lint":"eslint ."}}`)},
			[]StartPlan{
				{Argv: []string{"npm", "run", "dev"}, Port: 4000, Source: "package.json", Rule: "next"},
				{Argv: []string{"npm", "run", "start"}, Port: 3000, Source: "package.json", Rule: "express"},
				{Argv: []string{"npm", "run", "serve"}, Port: 8080, Source: "package.json", Rule: "vue-cli"},
			},
		},
		{
			"package.json: no port known",
			[]ProjectFile{pjFile("package.json", `{"scripts":{"dev":"node build.js && node watch.js"}}`)},
			[]StartPlan{{Argv: []string{"npm", "run", "dev"}, Source: "package.json"}},
		},
		{
			"package.json: vite takes the config port",
			[]ProjectFile{
				pjFile("package.json", `{"scripts":{"dev":"vite","start":"vite --port 4444"}}`),
				pjFile("vite.config.ts", `export default { server: { port: 5180 } }`),
			},
			[]StartPlan{
				{Argv: []string{"npm", "run", "dev"}, Port: 5180, Source: "package.json", Rule: "vite"},
				{Argv: []string{"npm", "run", "start"}, Port: 4444, Source: "package.json", Rule: "vite"},
			},
		},
		{
			"package.json: the script body is never in the argv",
			[]ProjectFile{pjFile("package.json", `{"scripts":{"dev":"rm -rf / ; vite"}}`)},
			[]StartPlan{{Argv: []string{"npm", "run", "dev"}, Port: 5173, Source: "package.json", Rule: "vite"}},
		},
		{
			"Procfile",
			[]ProjectFile{pjFile("Procfile", "release: python migrate.py\nweb: gunicorn app:app --port 8100\nworker: python w.py\n")},
			[]StartPlan{{Argv: []string{"gunicorn", "app:app", "--port", "8100"}, Port: 8100, Source: "procfile"}},
		},
		{
			"Procfile: express",
			[]ProjectFile{pjFile("Procfile", "web: node server.js\n")},
			[]StartPlan{{Argv: []string{"node", "server.js"}, Port: 3000, Source: "procfile", Rule: "express"}},
		},
		{
			"manage.py",
			[]ProjectFile{pjFile("manage.py", "os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'x')  # django\n")},
			[]StartPlan{{
				Argv: []string{"python", "manage.py", "runserver", "127.0.0.1:8000"}, Port: 8000, Source: "manage.py", Rule: "django",
				Prepare: [][]string{{"python", "manage.py", "migrate"}},
			}},
		},
		{
			".flaskenv",
			[]ProjectFile{pjFile(".flaskenv", "FLASK_APP=app\nFLASK_RUN_PORT=5050\n")},
			[]StartPlan{{Argv: []string{"flask", "run", "--host", "127.0.0.1", "--port", "5050"}, Port: 5050, Source: "flask", Rule: "flask"}},
		},
		{
			".flaskenv default",
			[]ProjectFile{pjFile(".flaskenv", "FLASK_APP=app\n")},
			[]StartPlan{{Argv: []string{"flask", "run", "--host", "127.0.0.1", "--port", "5000"}, Port: 5000, Source: "flask", Rule: "flask"}},
		},
		{
			"bin/rails",
			[]ProjectFile{pjFile("bin/rails", "#!/usr/bin/env ruby\n")},
			[]StartPlan{{
				Argv: []string{"bin/rails", "server", "-b", "127.0.0.1", "-p", "3000"}, Port: 3000, Source: "rails", Rule: "rails",
				Prepare: [][]string{{"bin/rails", "db:prepare"}},
			}},
		},
		{
			"bin/rails with puma port",
			[]ProjectFile{pjFile("bin/rails", "#!/usr/bin/env ruby\n"), pjFile("config/puma.rb", `port ENV.fetch("PORT") { 3030 }`)},
			[]StartPlan{{
				Argv: []string{"bin/rails", "server", "-b", "127.0.0.1", "-p", "3030"}, Port: 3030, Source: "rails", Rule: "rails",
				Prepare: [][]string{{"bin/rails", "db:prepare"}},
			}},
		},
		{"puma.rb alone has no executable to run", []ProjectFile{pjFile("config/puma.rb", `port 3030`)}, nil},
		{
			"hugo",
			[]ProjectFile{pjFile("hugo.toml", "baseURL = 'x'\nport = 1400\n")},
			[]StartPlan{{Argv: []string{"hugo", "server", "--bind", "127.0.0.1", "--port", "1400"}, Port: 1400, Source: "hugo", Rule: "hugo"}},
		},
		{
			"hugo yaml default",
			[]ProjectFile{pjFile("hugo.yaml", "baseURL: x\n")},
			[]StartPlan{{Argv: []string{"hugo", "server", "--bind", "127.0.0.1", "--port", "1313"}, Port: 1313, Source: "hugo", Rule: "hugo"}},
		},
		{
			"jekyll",
			[]ProjectFile{pjFile("_config.yml", "theme: minima\nport: 4001\n")},
			[]StartPlan{{Argv: []string{"bundle", "exec", "jekyll", "serve", "--host", "127.0.0.1", "--port", "4001"}, Port: 4001, Source: "jekyll", Rule: "jekyll"}},
		},
		{"_config.yml without Jekyll signals", []ProjectFile{pjFile("_config.yml", "title: docs\n")}, nil},
		{
			"Makefile targets",
			[]ProjectFile{pjFile("Makefile", ".PHONY: run dev\nVAR := 1\nbuild:\n\tgo build ./...\n\nrun: build\n\t@python manage.py runserver 0.0.0.0:8200\n\ndev:\n\t./watch.sh\nserve::\n\thugo server -D\ntest:\n\tgo test\n")},
			[]StartPlan{
				{Argv: []string{"make", "run"}, Port: 8200, Source: "makefile", Rule: "django", Prepare: [][]string{{"python", "manage.py", "migrate"}}},
				{Argv: []string{"make", "dev"}, Source: "makefile"},
				{Argv: []string{"make", "serve"}, Port: 1313, Source: "makefile", Rule: "hugo"},
			},
		},
		{"Makefile assignment is not a target", []ProjectFile{pjFile("Makefile", "run := 1\n\techo hi\n")}, nil},
	} {
		got := pjPlans(c.files...)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\ngot  %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

// TestPlanStartsOrderAndDedup: launch.json, package.json scripts, Procfile,
// framework files, Makefile; one plan per argv, the first source wins.
func TestPlanStartsOrderAndDedup(t *testing.T) {
	got := pjPlans(
		pjFile("Makefile", "dev:\n\tnpm run dev\n"),
		pjFile("hugo.toml", "x = 1\n"),
		pjFile("Procfile", "web: npm run dev\n"),
		pjFile("package.json", `{"scripts":{"dev":"vite"}}`),
		pjFile(".claude/launch.json", `{"configurations":[{"runtimeExecutable":"npm","runtimeArgs":["run","dev"],"port":5999}]}`),
	)
	var sources []string
	for _, p := range got {
		sources = append(sources, p.Source+":"+p.Command())
	}
	want := []string{"launch.json:npm run dev", "hugo:hugo server --bind 127.0.0.1 --port 1313", "makefile:make dev"}
	if !reflect.DeepEqual(sources, want) {
		t.Errorf("plans = %v, want %v", sources, want)
	}
	if got[0].Port != 5999 {
		t.Errorf("the first source did not win: port %d", got[0].Port)
	}
}

// TestPlanStartsNeeds: compose service names ride on every plan; a database
// named only by an example env file has no service name and is not listed.
func TestPlanStartsNeeds(t *testing.T) {
	f := AnalyzeProject(SurveyInput{Files: []ProjectFile{
		pjFile("package.json", `{"scripts":{"dev":"vite"}}`),
		pjFile("compose.yml", "services:\n  db:\n    image: postgres:16\n  cache:\n    image: redis\n  web:\n    build: .\n"),
		pjFile(".env.example", "MONGO_URL=mongodb://x\n"),
	}})
	plans := PlanStarts(f)
	if len(plans) != 1 || !reflect.DeepEqual(plans[0].Needs, []string{"db", "cache"}) {
		t.Fatalf("plans = %+v", plans)
	}
	if len(f.Needs) != 3 {
		t.Errorf("Needs = %+v", f.Needs)
	}
	// The slice is the plan's own.
	plans[0].Needs[0] = "changed"
	if again := PlanStarts(f); again[0].Needs[0] != "db" {
		t.Error("a plan's Needs aliases the facts")
	}
}

// TestPlanStartsSkipsWhatCannotBeAnArgv: an entry whose command needs a shell
// is skipped and counted, never rewritten.
func TestPlanStartsSkipsWhatCannotBeAnArgv(t *testing.T) {
	f := AnalyzeProject(SurveyInput{Files: []ProjectFile{
		pjFile(".claude/launch.json", `{"configurations":[
			{"runtimeExecutable":"sh","runtimeArgs":["-c","vite && echo done"],"port":3000},
			{"runtimeExecutable":"bash","runtimeArgs":["-c","a b"]},
			{"runtimeExecutable":"node","runtimeArgs":["--inspect=${PORT}"]},
			{"runtimeExecutable":"node","runtimeArgs":[true]},
			{"runtimeExecutable":"npm","runtimeArgs":["run","dev"],"cwd":"/etc"},
			{"runtimeExecutable":"npm","runtimeArgs":["run","dev"],"cwd":"../x"},
			{"runtimeExecutable":"a","runtimeArgs":["1","2","3","4","5","6","7","8"]},
			{"runtimeExecutable":"yarn","runtimeArgs":["dev"],"port":3001},
			{"port":3002}
		]}`),
		pjFile("Procfile", "web: gunicorn app:app --bind 0.0.0.0:$PORT\n"),
	}})
	plans := PlanStarts(f)
	if len(plans) != 1 || plans[0].Command() != "yarn dev" || plans[0].Port != 3001 {
		t.Fatalf("plans = %+v", plans)
	}
	if f.Dropped != 8 {
		t.Errorf("Dropped = %d, want 8", f.Dropped)
	}
	// Whatever a plan holds is a valid argv.
	for _, p := range plans {
		if err := ValidStartArgv(p.Argv); err != nil {
			t.Errorf("%v: %v", p.Argv, err)
		}
	}
}

func TestSplCwd(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"", "", true},
		{".", "", true},
		{"./web", "web", true},
		{"apps/web", "apps/web", true},
		{"/etc", "", false},
		{"../x", "", false},
		{"a/../b", "", false},
		{"a b", "", false},
		{"${workspaceFolder}", "", false},
		{"./", "", true},
		{"web/", "web", true},
		{"/", "", false},
		{"a//b", "", false},
		{"a/./b", "", false},
		{strings.Repeat("d", maxStartCwdBytes), strings.Repeat("d", maxStartCwdBytes), true},
		{strings.Repeat("d", maxStartCwdBytes+1), "", false},
	} {
		if got, ok := splCwd(c.in); got != c.want || ok != c.ok {
			t.Errorf("splCwd(%q) = %q %v, want %q %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestStartPlanCommand(t *testing.T) {
	if got := (StartPlan{Argv: []string{"npm", "run", "dev"}}).Command(); got != "npm run dev" {
		t.Errorf("Command = %q", got)
	}
	if got := (StartPlan{}).Command(); got != "" {
		t.Errorf("empty Command = %q", got)
	}
}

func TestValidStartArgv(t *testing.T) {
	long := strings.Repeat("a", maxStartArgBytes+1)
	for _, c := range []struct {
		name string
		argv []string
		ok   bool
		msg  string
	}{
		{"npm run dev", []string{"npm", "run", "dev"}, true, ""},
		{"every charset class", []string{"A-z_0.9/x:y=z@v+1,2"}, true, ""},
		{"eight words", []string{"a", "b", "c", "d", "e", "f", "g", "h"}, true, ""},
		{"the longest word", []string{strings.Repeat("a", maxStartArgBytes)}, true, ""},
		{"the longest command", []string{strings.Repeat("a", 79), strings.Repeat("b", maxStartCommandBytes-maxStartArgBytes)}, true, ""},
		{"none with an argument is a command", []string{"none", "--x"}, true, ""},
		{"no words", nil, false, "no start command"},
		{"empty list", []string{}, false, "no start command"},
		{"nine words", []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}, false, "at most 8"},
		{"empty word", []string{"npm", ""}, false, "Word 2"},
		{"81 bytes", []string{long}, false, "over 80"},
		{"a command over its total", []string{strings.Repeat("a", 80), strings.Repeat("b", 80)}, false, "at most " + strconv.Itoa(maxStartCommandBytes)},
		{"none", []string{"none"}, false, "reserved"},
		{"None", []string{"None"}, false, "reserved"},
		{"NONE", []string{"NONE"}, false, "reserved"},
		{"space inside", []string{"npm run"}, false, "' '"},
		{"double quote", []string{`"a"`}, false, `'"'`},
		{"single quote", []string{"it's"}, false, `'\''`},
		{"dollar", []string{"$HOME"}, false, "'$'"},
		{"semicolon", []string{"a;b"}, false, "';'"},
		{"pipe", []string{"a|b"}, false, "'|'"},
		{"ampersand", []string{"a&b"}, false, "'&'"},
		{"backtick", []string{"`id`"}, false, "'`'"},
		{"less than", []string{"<f"}, false, "'<'"},
		{"greater than", []string{">f"}, false, "'>'"},
		{"parenthesis", []string{"(a)"}, false, "'('"},
		{"closing parenthesis", []string{"a)"}, false, "')'"},
		{"brace", []string{"{a}"}, false, "'{'"},
		{"closing brace", []string{"a}"}, false, "'}'"},
		{"star", []string{"*.js"}, false, "'*'"},
		{"question", []string{"a?"}, false, "'?'"},
		{"bang", []string{"!a"}, false, "'!'"},
		{"tilde", []string{"~/a"}, false, "'~'"},
		{"hash", []string{"#a"}, false, "'#'"},
		{"newline", []string{"a\nb"}, false, `'\n'`},
		{"tab", []string{"a\tb"}, false, `'\t'`},
		{"backslash", []string{`a\b`}, false, `'\\'`},
		{"bracket", []string{"a[0]"}, false, "'['"},
		{"non ascii", []string{"é"}, false, "'é'"},
		{"invalid utf-8", []string{"a\xffb"}, false, "not allowed"},
	} {
		err := ValidStartArgv(c.argv)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
			continue
		}
		if err != nil && !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.msg)
		}
	}
}

func TestParseStartEdit(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
		msg  string
	}{
		{"npm run dev", []string{"npm", "run", "dev"}, ""},
		{"  npm   run  dev  ", []string{"npm", "run", "dev"}, ""},
		{"npm run dev\n", []string{"npm", "run", "dev"}, ""},
		{"python manage.py runserver 127.0.0.1:8000", []string{"python", "manage.py", "runserver", "127.0.0.1:8000"}, ""},
		{"", nil, "no start command"},
		{"   ", nil, "no start command"},
		{`sh -c "npm run dev"`, nil, "start it yourself and tell the agent"},
		{"npm run dev && echo hi", nil, "start it yourself and tell the agent"},
		{"PORT=$PORT npm start", nil, "start it yourself and tell the agent"},
		{"npm run dev\nrm -rf x", nil, "not allowed"},
		{"a\tb", nil, "not allowed"},
		{"a b c d e f g h i", nil, "at most 8"},
		{strings.Repeat("a ", 600), nil, "too long"},
		{strings.Repeat("a", 80) + " " + strings.Repeat("b", 80), nil, "at most " + strconv.Itoa(maxStartCommandBytes)},
		{"none", nil, "reserved"},
		{"None", nil, "reserved"},
		{" NONE ", nil, "reserved"},
		{"npm run dev (in web)", nil, "not allowed"},
	} {
		got, err := ParseStartEdit(c.in)
		if c.msg == "" {
			if err != nil || !reflect.DeepEqual(got, c.want) {
				t.Errorf("ParseStartEdit(%q) = %v, %v, want %v", c.in, got, err, c.want)
			}
			continue
		}
		if err == nil || got != nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("ParseStartEdit(%q) = %v, %v, want an error mentioning %q", c.in, got, err, c.msg)
		}
	}
}

func TestStartConstantsMatchSecdastSpelling(t *testing.T) {
	// The first eight sources are secdast's Candidate.Source values; the drift
	// test in secassesssvc pins them against the real constants.
	for _, s := range []string{StartSourceLaunchJSON, StartSourcePackageJSON, StartSourceViteConfig, StartSourceDjango, StartSourceFlask, StartSourceRails, StartSourceHugo, StartSourceJekyll, StartSourceProcfile, StartSourceMakefile} {
		if !projStrict(s) {
			t.Errorf("source %q is not a strict id", s)
		}
	}
}

// TestStartPlanChoice: the choice of a plan is its command, framed with its
// folder when it has one, and no typed command can spell a folder frame.
func TestStartPlanChoice(t *testing.T) {
	for _, c := range []struct {
		plan StartPlan
		want string
	}{
		{StartPlan{Argv: []string{"npm", "run", "dev"}}, "npm run dev"},
		{StartPlan{Argv: []string{"npm", "run", "dev"}, Cwd: "web"}, "npm run dev (in web)"},
		{StartPlan{Argv: []string{"make", "run"}, Cwd: "apps/api"}, "make run (in apps/api)"},
		{StartPlan{}, ""},
	} {
		if got := c.plan.Choice(); got != c.want {
			t.Errorf("Choice(%+v) = %q, want %q", c.plan, got, c.want)
		}
		if c.plan.Cwd != "" {
			if _, err := ParseStartEdit(c.want); err == nil {
				t.Errorf("%q can be typed as a start command", c.want)
			}
		}
	}
	if (StartPlan{Argv: []string{"a"}, Cwd: "x"}).Choice() == (StartPlan{Argv: []string{"a"}, Cwd: "y"}).Choice() {
		t.Error("two folders share a choice")
	}
}

// TestMaxStartChoice: the longest valid choice is at most MaxStartChoice (and is
// exactly it), every one-byte-longer command or folder is refused, and the
// prompt's text bounds are derived from the same constants.
func TestMaxStartChoice(t *testing.T) {
	// The longest command: words of the longest length that keep the whole at the
	// total bound.
	words := []string{strings.Repeat("a", maxStartArgBytes), strings.Repeat("b", maxStartCommandBytes-maxStartArgBytes-1)}
	if err := ValidStartArgv(words); err != nil {
		t.Fatalf("the longest command is refused: %v", err)
	}
	cwd := strings.Repeat("d", maxStartCwdBytes)
	if got, ok := splCwd(cwd); !ok || got != cwd {
		t.Fatalf("the longest folder is refused: %q %v", got, ok)
	}
	plan := StartPlan{Argv: words, Cwd: cwd, Source: StartSourceLaunchJSON}
	if got := len(plan.Choice()); got != MaxStartChoice {
		t.Errorf("the longest choice is %d bytes, MaxStartChoice is %d", got, MaxStartChoice)
	}
	// The same choice goes through SelectStart whole.
	if got := SelectStart([]StartPlan{plan}, plan.Choice()); got.Choice != plan.Choice() || got.Plan == nil || got.Cwd != cwd {
		t.Errorf("the longest choice does not select its plan: %+v", got)
	}
	// One byte more is refused.
	if ValidStartArgv([]string{words[0], words[1] + "b"}) == nil {
		t.Error("a command over the total bound is valid")
	}
	if _, ok := splCwd(cwd + "d"); ok {
		t.Error("a folder over the bound is valid")
	}
	// Every plan the project's own files produce fits.
	for _, p := range pjPlans(pjFile(".claude/launch.json", `{"configurations":[{"runtimeExecutable":"npm","runtimeArgs":["run","dev"],"cwd":"`+cwd+`"}]}`)) {
		if len(p.Choice()) > MaxStartChoice {
			t.Errorf("%q is over MaxStartChoice", p.Choice())
		}
	}
	// The prompt's bound for a start command is the validator's.
	if maxStartText != maxStartCommandBytes {
		t.Errorf("maxStartText %d, maxStartCommandBytes %d", maxStartText, maxStartCommandBytes)
	}
	if MaxStartChoice != maxStartCommandBytes+len(" (in ")+maxStartCwdBytes+len(")") {
		t.Errorf("MaxStartChoice = %d", MaxStartChoice)
	}
}

// TestPlanStartsKeepFolders: a launch.json that runs one command in two folders
// gives two plans (they differ only by folder), one command in the same folder
// twice gives one, and the folder is part of what a plan says it is.
func TestPlanStartsKeepFolders(t *testing.T) {
	got := pjPlans(
		pjFile(".claude/launch.json", `{"configurations":[
			{"name":"web","runtimeExecutable":"npm","runtimeArgs":["run","dev"],"cwd":"web","port":5173},
			{"name":"api","runtimeExecutable":"npm","runtimeArgs":["run","dev"],"cwd":"./api/","port":3000},
			{"name":"web again","runtimeExecutable":"npm","runtimeArgs":["run","dev"],"cwd":"web","port":5199},
			{"name":"root","runtimeExecutable":"npm","runtimeArgs":["run","dev"]}
		]}`),
		pjFile("package.json", `{"scripts":{"dev":"vite"}}`),
	)
	var choices []string
	for _, p := range got {
		choices = append(choices, p.Source+":"+p.Choice()+":"+strconv.Itoa(p.Port))
	}
	want := []string{
		"launch.json:npm run dev (in web):5173",
		"launch.json:npm run dev (in api):3000",
		"launch.json:npm run dev:0", // the first source wins the plan: the project root, no port named
	}
	if !reflect.DeepEqual(choices, want) {
		t.Errorf("plans = %v, want %v", choices, want)
	}
}

// TestPlanStartsNoneIsReserved: a command called none, in any case, cannot be a
// plan (the dialog's radio would send it back as the declared-none choice); the
// entry is skipped and counted, never rewritten.
func TestPlanStartsNoneIsReserved(t *testing.T) {
	for _, c := range []struct {
		name  string
		files []ProjectFile
	}{
		{"Procfile web: none", []ProjectFile{pjFile("Procfile", "web: none\n")}},
		{"Procfile web: None", []ProjectFile{pjFile("Procfile", "web: None\n")}},
		{"Procfile web: NONE", []ProjectFile{pjFile("Procfile", "web: NONE\n")}},
		{"launch.json executable none", []ProjectFile{pjFile(".claude/launch.json", `{"configurations":[{"runtimeExecutable":"none"}]}`)}},
		{"launch.json executable None", []ProjectFile{pjFile(".claude/launch.json", `{"configurations":[{"runtimeExecutable":"None"}]}`)}},
	} {
		f := AnalyzeProject(SurveyInput{Files: c.files})
		if plans := PlanStarts(f); len(plans) != 0 {
			t.Errorf("%s: plans = %+v", c.name, plans)
		}
		if f.Dropped != 1 {
			t.Errorf("%s: Dropped = %d, want 1", c.name, f.Dropped)
		}
		if sel := SelectStart(PlanStarts(f), ""); sel.Command != "" || sel.Plan != nil {
			t.Errorf("%s: selection = %+v", c.name, sel)
		}
	}
	// A command that merely starts with the word is still a command.
	if plans := pjPlans(pjFile("Procfile", "web: none-such serve\n")); len(plans) != 1 {
		t.Errorf("none-such: plans = %+v", plans)
	}
}
