package secassesssvc

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secdast"
)

// secassess keeps standard-library COPIES of secdast's dev-server file list,
// package.json script table, explicit-port forms and per-file port rows
// (importing secdast from a pure package that stays in the omit build would
// break the component fence). These tests, which are not linked into any
// binary, hold the copies to the originals on one shared case table, the
// ParseTarget precedent (depth plan W4.1). The table has files and ports and
// rule names and NO commands: the start commands are secassess's own.

func driftDastFiles(files []secassess.ProjectFile) []secdast.ProjectFile {
	out := make([]secdast.ProjectFile, len(files))
	for i, f := range files {
		out[i] = secdast.ProjectFile{Rel: f.Rel, Data: f.Data}
	}
	return out
}

func driftPF(rel, data string) secassess.ProjectFile {
	return secassess.ProjectFile{Rel: rel, Data: []byte(data)}
}

// driftScriptCommands is one command per row of the script table (all 20), the
// explicit-port forms and the negatives.
var driftScriptCommands = []string{
	"next dev", "next start", "nuxi dev", "nuxt dev", "remix vite:dev", "remix dev", "react-scripts start", "astro dev", "ng serve",
	"svelte-kit dev", "vite", "vite dev --host", "vite serve", "gatsby develop", "vue-cli-service serve",
	"webpack serve --mode development", "webpack-dev-server", "parcel src/index.html", "parcel serve index.html",
	"storybook dev", "start-storybook", "expo start", "python manage.py runserver", "flask run", "bin/rails server", "rails s",
	"hugo server -D", "bundle exec jekyll serve", "nodemon src/server.js", "node app.mjs", "node index.ts",
	// explicit ports win
	"next dev -p 4000", "vite --port=5555", "PORT=3100 react-scripts start", "python manage.py runserver 0.0.0.0:8100",
	"python manage.py runserver 8101", "flask run --port 5100", "astro dev --listen 4400", "vite -l 4401", "next dev -p 70000",
	"next dev --port 1", "next dev -p 9",
	// not dev servers
	"tsc -p tsconfig.json", "eslint .", "vitest run", "jest", "", "node build.js", "npm test", "vite-node x.ts", "next build",
	"echo next dev",
}

// driftScriptRuleCount is how many rows the script table has: adding a row to
// both tables means adding its command above and raising this.
const driftScriptRuleCount = 20

func TestScriptPortAgreesWithSecdast(t *testing.T) {
	rules := map[string]bool{}
	for _, cmd := range driftScriptCommands {
		ap, ar, aok := secassess.ScriptPort(cmd)
		dp, dr, dok := secdast.ScriptPort(cmd)
		if ap != dp || ar != dr || aok != dok {
			t.Errorf("%q: secassess %d %q %v, secdast %d %q %v", cmd, ap, ar, aok, dp, dr, dok)
		}
		if aok {
			rules[ar] = true
		}
	}
	if len(rules) != driftScriptRuleCount {
		t.Errorf("the case table covers %d of the %d script rows: %v", len(rules), driftScriptRuleCount, rules)
	}
}

func TestDevServerFilesAgreeWithSecdast(t *testing.T) {
	if !reflect.DeepEqual(secassess.DevServerFiles, secdast.DevServerFiles) {
		t.Errorf("secassess.DevServerFiles = %v, secdast.DevServerFiles = %v", secassess.DevServerFiles, secdast.DevServerFiles)
	}
	if secassess.MaxProjectFile != secdast.MaxProjectFile {
		t.Errorf("project file caps differ: %d vs %d", secassess.MaxProjectFile, secdast.MaxProjectFile)
	}
	for _, c := range [][2]string{
		{secassess.StartSourceLaunchJSON, secdast.SourceLaunchJSON},
		{secassess.StartSourcePackageJSON, secdast.SourcePackageJSON},
		{secassess.StartSourceViteConfig, secdast.SourceViteConfig},
		{secassess.StartSourceDjango, secdast.SourceDjango},
		{secassess.StartSourceFlask, secdast.SourceFlask},
		{secassess.StartSourceRails, secdast.SourceRails},
		{secassess.StartSourceHugo, secdast.SourceHugo},
		{secassess.StartSourceJekyll, secdast.SourceJekyll},
	} {
		if c[0] != c[1] {
			t.Errorf("candidate source %q differs from secdast's %q", c[0], c[1])
		}
	}
}

// driftProjects is the shared case table of project files: one case per row of
// the per-file table and per branch of each row.
func driftProjects() map[string][]secassess.ProjectFile {
	cases := map[string][]secassess.ProjectFile{
		"launch.json: port, string port, url, remote url, bad": {driftPF(".claude/launch.json",
			`{"configurations":[{"name":"web","port":3000},{"name":"api","port":"8080"},{"name":"u","url":"http://127.0.0.1:5173/x"},{"name":"r","url":"http://example.com:80/"},{"port":0},{"port":70000},{"port":"x"},{"name":"ok","port":4000}]}`)},
		"launch.json: duplicate":    {driftPF(".claude/launch.json", `{"configurations":[{"port":3000},{"url":"http://localhost:3000"}]}`)},
		"launch.json: garbage":      {driftPF(".claude/launch.json", `{nope`)},
		"launch.json: not a list":   {driftPF(".claude/launch.json", `{"configurations":"x"}`)},
		"launch.json: executable":   {driftPF(".claude/launch.json", `{"configurations":[{"name":"w","runtimeExecutable":"npm","runtimeArgs":["run","dev"],"port":5173}]}`)},
		"launch.json: over the cap": {{Rel: ".claude/launch.json", Data: make([]byte, secdast.MaxProjectFile+1)}},
		"package.json: stable name order": {driftPF("package.json",
			`{"scripts":{"dev":"vite","storybook":"storybook dev -p 6007","lint":"eslint .","a":"next dev","z":"flask run"}}`)},
		"package.json: scripts not strings": {driftPF("package.json", `{"scripts":{"dev":["vite"]}}`)},
		"package.json: garbage":             {driftPF("package.json", `[`)},
		"package.json: no scripts":          {driftPF("package.json", `{"name":"x"}`)},
		"vite.config: port":                 {driftPF("vite.config.ts", `export default { server: { host: true, port: 5180 } }`)},
		"vite.config: other extension":      {driftPF("vite.config.mjs", `export default defineConfig({ server: { port: 5190 } })`)},
		"vite.config: no port":              {driftPF("vite.config.ts", `export default {}`)},
		"vite.config: port outside server":  {driftPF("vite.config.ts", `export default { preview: { port: 4173 } }`)},
		"manage.py: django":                 {driftPF("manage.py", `os.environ.setdefault("DJANGO_SETTINGS_MODULE", "x")  # django`)},
		"manage.py: not django":             {driftPF("manage.py", `import os`)},
		".flaskenv: port":                   {driftPF(".flaskenv", "FLASK_APP=app\nFLASK_RUN_PORT=5050\n")},
		".flaskenv: default":                {driftPF(".flaskenv", "FLASK_APP=app\n")},
		"puma.rb: ENV.fetch block":          {driftPF("config/puma.rb", `port ENV.fetch("PORT") { 3030 }`)},
		"puma.rb: ENV.fetch default arg":    {driftPF("config/puma.rb", `port ENV.fetch("PORT", 3040)`)},
		"puma.rb: literal":                  {driftPF("config/puma.rb", "workers 2\nport 3050\n")},
		"puma.rb: none":                     {driftPF("config/puma.rb", "workers 2\n")},
		"bin/rails: default":                {driftPF("bin/rails", "#!/usr/bin/env ruby\n")},
		"bin/rails: port line":              {driftPF("bin/rails", "port 3060\n")},
		"hugo.toml: port":                   {driftPF("hugo.toml", "baseURL = 'x'\nport = 1400\n")},
		"hugo.toml: default":                {driftPF("hugo.toml", "baseURL = 'x'\n")},
		"hugo.yaml: port":                   {driftPF("hugo.yaml", "baseURL: x\nport: 1500\n")},
		"_config.yml: jekyll":               {driftPF("_config.yml", "jekyll: 1\nport: 4002\n")},
		"_config.yml: theme default":        {driftPF("_config.yml", "theme: minima\n")},
		"_config.yml: permalink":            {driftPF("_config.yml", "permalink: pretty\nport: 4003\n")},
		"_config.yml: no signal":            {driftPF("_config.yml", "title: docs\nport: 4004\n")},
		"empty file":                        {driftPF("package.json", "")},
		"over the cap":                      {{Rel: "package.json", Data: make([]byte, secdast.MaxProjectFile+1)}},
		"unrelated files":                   {driftPF("README.md", "next dev"), driftPF("Makefile", "run:\n\tnext dev\n"), driftPF("Procfile", "web: next dev\n")},
		"mixed project, first source wins": {
			driftPF(".claude/launch.json", `{"configurations":[{"name":"web","port":5173}]}`),
			driftPF("package.json", `{"scripts":{"dev":"vite","storybook":"storybook dev -p 6007","lint":"eslint ."}}`),
			driftPF("vite.config.ts", `export default { server: { host: true, port: 5180 } }`),
			driftPF("manage.py", `# django`),
			driftPF(".flaskenv", "FLASK_RUN_PORT=5050\n"),
			driftPF("config/puma.rb", `port ENV.fetch("PORT") { 3030 }`),
			driftPF("hugo.toml", "baseURL = 'x'\n"),
			driftPF("_config.yml", "theme: minima\nport: 4001\n"),
			driftPF("README.md", "next dev"),
		},
		"order of files decides": {
			driftPF("_config.yml", "theme: minima\nport: 5173\n"),
			driftPF(".claude/launch.json", `{"configurations":[{"name":"web","port":5173}]}`),
		},
		"no files": nil,
	}
	// One package.json per script command: the rows' ports and rule names.
	for i, cmd := range driftScriptCommands {
		raw := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(cmd)
		cases[fmt.Sprintf("script %02d: %s", i, cmd)] = []secassess.ProjectFile{driftPF("package.json", `{"scripts":{"dev":"`+raw+`"}}`)}
	}
	return cases
}

func TestPlanCandidatesAgreeWithSecdast(t *testing.T) {
	for name, files := range driftProjects() {
		var a, d []string
		for _, c := range secassess.PlanCandidates(secassess.AnalyzeProject(secassess.SurveyInput{Files: files})) {
			a = append(a, c.URL+"|"+c.Name+"|"+c.Source)
		}
		for _, c := range secdast.ProjectCandidates(driftDastFiles(files)) {
			d = append(d, c.URL+"|"+c.Name+"|"+c.Source)
		}
		if !reflect.DeepEqual(a, d) {
			t.Errorf("%s:\nsecassess %v\nsecdast   %v", name, a, d)
		}
	}
}

// TestPlanPortsAgreeWithSecdast: the port of every candidate agrees, and so does
// the port a start plan from the same files carries wherever both name one for
// the same source (a plan is built from the same rows; the commands differ).
func TestPlanPortsAgreeWithSecdast(t *testing.T) {
	for name, files := range driftProjects() {
		f := secassess.AnalyzeProject(secassess.SurveyInput{Files: files})
		cands := secassess.PlanCandidates(f)
		for _, c := range cands {
			tg, err := secassess.ParseTarget(c.URL)
			if err != nil {
				t.Errorf("%s: %s is not a target: %v", name, c.URL, err)
				continue
			}
			if tg.PortNumber() != secdast.CandidatePort(c.URL) {
				t.Errorf("%s: %s: port %d, secdast %d", name, c.URL, tg.PortNumber(), secdast.CandidatePort(c.URL))
			}
		}
		// Plans whose source is a framework file or the launch.json port rows
		// use the very same port rows, so every such plan's port is a candidate
		// of its own source (or the file's candidate could not be read).
		for _, p := range secassess.PlanStarts(f) {
			if p.Port == 0 || p.Source == secassess.StartSourcePackageJSON || p.Source == secassess.StartSourceLaunchJSON ||
				p.Source == secassess.StartSourceProcfile || p.Source == secassess.StartSourceMakefile {
				continue
			}
			found := false
			for _, c := range cands {
				found = found || (c.Source == p.Source && strings.HasSuffix(strings.TrimSuffix(c.URL, "/"), fmt.Sprintf(":%d", p.Port)))
			}
			if !found {
				t.Errorf("%s: plan %q has port %d that no %s candidate carries (%v)", name, p.Command(), p.Port, p.Source, cands)
			}
		}
	}
}
