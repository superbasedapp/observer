package secassess

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// pjFile builds a surveyed file.
func pjFile(rel, data string) ProjectFile { return ProjectFile{Rel: rel, Data: []byte(data)} }

func TestProjectStrict(t *testing.T) {
	long := strings.Repeat("a", 81)
	for _, c := range []struct {
		s    string
		want bool
	}{
		{"package.json", true},
		{"@anthropic-ai/sdk", true},
		{"a_b+c/d@1.0-x", true},
		{strings.Repeat("a", 80), true},
		{"", false},
		{long, false},
		{"a b", false},
		{"a`b", false},
		{"a\nb", false},
		{"a;b", false},
		{"a$b", false},
		{"a:b", false},
		{"é", false},
		{"a\"b", false},
		{"a'b", false},
		{"a|b", false},
		{"a=b", false},
	} {
		if got := projStrict(c.s); got != c.want {
			t.Errorf("projStrict(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// TestProjectDepRoleTable is one case per table row: the row's own name
// resolves to the row's role and framework in the row's ecosystem.
func TestProjectDepRoleTable(t *testing.T) {
	langs := map[string]bool{"node": true, "python": true, "ruby": true, "php": true, "go": true, "rust": true, "java": true}
	roles := projSet(DepRoleIDs)
	seen := map[depRoleRule]bool{}
	for _, r := range depRoleRules {
		if !langs[r.lang] {
			t.Errorf("row %+v: unknown ecosystem", r)
		}
		if r.role != "" && !roles[r.role] {
			t.Errorf("row %+v: role is not in DepRoleIDs", r)
		}
		if r.role == "" && r.framework == "" {
			t.Errorf("row %+v: neither a role nor a framework", r)
		}
		if seen[r] {
			t.Errorf("row %+v is listed twice", r)
		}
		seen[r] = true
		name := r.match
		if strings.HasSuffix(name, "*") {
			name = strings.TrimSuffix(name, "*") + "x"
		}
		gotRoles, gotFws := depRolesOf(r.lang, depNormalize(r.lang, name))
		if r.role != "" && !strSliceHas(gotRoles, r.role) {
			t.Errorf("%s %q: roles %v, want %q", r.lang, name, gotRoles, r.role)
		}
		if r.framework != "" && !strSliceHas(gotFws, r.framework) {
			t.Errorf("%s %q: frameworks %v, want %q", r.lang, name, gotFws, r.framework)
		}
	}
	ids := ProjectFrameworkIDs()
	if len(ids) < 20 || len(projSet(ids)) != len(ids) {
		t.Errorf("framework ids: %v", ids)
	}
	for _, want := range []string{"express", "django", "flask", "fastapi", "rails", "nextjs", "react", "vue", "svelte", "angular", "gin", "echo", "spring", "laravel"} {
		if !strSliceHas(ids, want) {
			t.Errorf("framework id %q is missing", want)
		}
	}
}

func TestProjectDepRoleNegatives(t *testing.T) {
	for _, c := range []struct{ lang, name string }{
		{"node", "django"},
		{"python", "ai"},
		{"python", "express"},
		{"node", "left-pad"},
		{"go", "github.com/pkg/errors"},
		{"ruby", "rails-i18n"},
		{"node", "pass"},
		{"php", "monolog/monolog"},
		{"java", "junit"},
		{"rust", "serde"},
	} {
		if r, f := depRolesOf(c.lang, depNormalize(c.lang, c.name)); len(r) != 0 || len(f) != 0 {
			t.Errorf("%s %q matched roles %v frameworks %v", c.lang, c.name, r, f)
		}
	}
	// A package can have more than one role.
	r, _ := depRolesOf("python", "aiohttp")
	if !reflect.DeepEqual(r, []string{DepRoleWebFramework, DepRoleHTTPClient}) {
		t.Errorf("aiohttp roles = %v", r)
	}
}

func TestProjectDepNormalize(t *testing.T) {
	for _, c := range []struct{ lang, in, want string }{
		{"python", "Flask_Login", "flask-login"},
		{"python", "zope.interface", "zope-interface"},
		{"python", "A--B__C", "a-b-c"},
		{"go", "github.com/labstack/echo/v4", "github.com/labstack/echo"},
		{"go", "github.com/x/vim", "github.com/x/vim"},
		{"go", "github.com/x/v2x", "github.com/x/v2x"},
		{"rust", "Serde_Json", "serde-json"},
		{"node", " Express ", "express"},
		{"ruby", "Devise", "devise"},
	} {
		if got := depNormalize(c.lang, c.in); got != c.want {
			t.Errorf("depNormalize(%s, %q) = %q, want %q", c.lang, c.in, got, c.want)
		}
	}
}

const pjNodeManifest = `{
  "name": "shop",
  "scripts": {"dev": "next dev", "start": "node server.js"},
  "dependencies": {"express": "^4", "passport": "1", "passport-local": "1", "jsonwebtoken": "9", "bcrypt": "5", "prisma": "5", "ejs": "3", "axios": "1", "bullmq": "5", "openai": "4", "@modelcontextprotocol/sdk": "1", "react": "18", "left-pad": "1"},
  "devDependencies": {"typescript": "5", "@anthropic-ai/sdk": "1"}
}`

func TestAnalyzeProjectNodeApp(t *testing.T) {
	in := SurveyInput{
		Dirs:    []string{".git", ".github", "api", "build", "node_modules", "public", "src"},
		Names:   []string{".env", ".env.example", ".env.local", ".gitlab-ci.yml", "AGENTS.md", "Dockerfile", "README.md", "docker-compose.yml", "openapi.yaml", "package-lock.json", "package.json"},
		Files:   []ProjectFile{pjFile("package.json", pjNodeManifest)},
		Present: []string{"node_modules", ".github/workflows"},
	}
	f := AnalyzeProject(in)
	if !reflect.DeepEqual(f.Dirs, []string{".github", "api", "public", "src"}) {
		t.Errorf("Dirs = %v", f.Dirs)
	}
	if !reflect.DeepEqual(f.Languages, []string{"node"}) || !reflect.DeepEqual(f.Manifests, []string{"package.json"}) {
		t.Errorf("languages %v manifests %v", f.Languages, f.Manifests)
	}
	if !reflect.DeepEqual(f.Frameworks, []string{"express", "react"}) {
		t.Errorf("Frameworks = %v", f.Frameworks)
	}
	wantDeps := []DepRole{
		{DepRoleAuth, []string{"jsonwebtoken", "passport", "passport-local"}},
		{DepRoleCrypto, []string{"bcrypt"}},
		{DepRoleORM, []string{"prisma"}},
		{DepRoleTemplate, []string{"ejs"}},
		{DepRoleHTTPClient, []string{"axios"}},
		{DepRoleQueue, []string{"bullmq"}},
		{DepRoleLLMSDK, []string{"@anthropic-ai/sdk", "openai"}},
		{DepRoleMCPSDK, []string{"@modelcontextprotocol/sdk"}},
		{DepRoleWebFramework, []string{"express"}},
	}
	if !reflect.DeepEqual(f.Deps, wantDeps) {
		t.Errorf("Deps =\n%+v\nwant\n%+v", f.Deps, wantDeps)
	}
	if f.DepCount != 15 {
		t.Errorf("DepCount = %d, want 15", f.DepCount)
	}
	if !f.AIApp || !reflect.DeepEqual(f.AISignals, []string{"llm_sdk", "mcp_sdk", "agent_file"}) {
		t.Errorf("AI = %v %v", f.AIApp, f.AISignals)
	}
	if !reflect.DeepEqual(f.Infra, []string{"dockerfile", "compose", "github_actions", "gitlab_ci"}) {
		t.Errorf("Infra = %v", f.Infra)
	}
	if !reflect.DeepEqual(f.Installed, []string{"node_modules"}) || !reflect.DeepEqual(f.Lockfiles, []string{"package-lock.json"}) {
		t.Errorf("Installed %v Lockfiles %v", f.Installed, f.Lockfiles)
	}
	if !reflect.DeepEqual(f.EnvFiles, []string{".env", ".env.local"}) || !reflect.DeepEqual(f.EnvExamples, []string{".env.example"}) {
		t.Errorf("env files %v examples %v", f.EnvFiles, f.EnvExamples)
	}
	if f.SpecPath != "openapi.yaml" || f.Spec != nil {
		t.Errorf("SpecPath %q Spec %+v", f.SpecPath, f.Spec)
	}
	if f.Dropped != 0 || f.Truncated {
		t.Errorf("Dropped %d Truncated %v", f.Dropped, f.Truncated)
	}
	if got := len(PlanStarts(f)); got != 2 {
		t.Errorf("PlanStarts = %d plans, want 2 (dev, start)", got)
	}
}

func TestAnalyzeProjectLanguages(t *testing.T) {
	for _, c := range []struct {
		name  string
		names []string
		want  []string
	}{
		{
			"all",
			[]string{"Cargo.toml", "Gemfile", "MyApp.csproj", "build.gradle", "composer.json", "go.mod", "package.json", "requirements-dev.txt"},
			[]string{"go", "node", "python", "ruby", "php", "java", "rust", "dotnet"},
		},
		{"solution", []string{"App.sln"}, []string{"dotnet"}},
		{"maven", []string{"pom.xml"}, []string{"java"}},
		{"python setup", []string{"setup.py"}, []string{"python"}},
		{"none", []string{"README.md", "main.c"}, nil},
	} {
		if got := AnalyzeProject(SurveyInput{Names: c.names}).Languages; !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Languages = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAnalyzeProjectRejectsUnsafeStrings(t *testing.T) {
	in := SurveyInput{
		Dirs:  []string{"good", "bad dir", "bad`tick", "new\nline", strings.Repeat("d", 81)},
		Names: []string{"package.json", "Evil `touch x`.csproj", "line\nbreak.sln", ".env.example", ".env.bad name", "yarn.lock"},
		Files: []ProjectFile{pjFile("package.json", `{"dependencies":{"passport-evil name":"1","passport-ok":"1"}}`)},
	}
	f := AnalyzeProject(in)
	if !reflect.DeepEqual(f.Dirs, []string{"good"}) {
		t.Errorf("Dirs = %v", f.Dirs)
	}
	if !reflect.DeepEqual(f.Manifests, []string{"package.json"}) {
		t.Errorf("Manifests = %v", f.Manifests)
	}
	// The language is a closed id: an unlistable file name still shows it.
	if !reflect.DeepEqual(f.Languages, []string{"node", "dotnet"}) {
		t.Errorf("Languages = %v", f.Languages)
	}
	if !reflect.DeepEqual(f.Deps, []DepRole{{DepRoleAuth, []string{"passport-ok"}}}) {
		t.Errorf("Deps = %+v", f.Deps)
	}
	// 4 dirs + 2 manifest names + 1 dependency name + 1 env name.
	if f.Dropped != 8 {
		t.Errorf("Dropped = %d, want 8", f.Dropped)
	}
	b, _ := json.Marshal(f)
	for _, bad := range []string{"touch", "bad dir", "line\\nbreak", "`"} {
		if strings.Contains(string(b), bad) {
			t.Errorf("the facts carry %q: %s", bad, b)
		}
	}
}

// TestAnalyzeProjectNeverReadsEnvFiles: a real environment file handed to the
// analysis is ignored, and an example file gives only the scheme word of the
// URL values, never a host, credential or any other value.
func TestAnalyzeProjectNeverReadsEnvFiles(t *testing.T) {
	const canary = "CANARY-9f2c1d"
	real := "DATABASE_URL=postgres://admin:" + canary + "@secret-host.internal:5432/prod\nREDIS_URL=redis://:" + canary + "@cache.internal:6379\nAPI_KEY=" + canary + "\n"
	example := "# example\nDATABASE_URL=postgresql+asyncpg://user:" + canary + "@db.example.internal:5432/app\n" +
		"export REDIS_URL=\"rediss://cache.example.internal\"\nMONGO_URI=mongodb+srv://u:" + canary + "@m.example.internal/x\n" +
		"BROKER_URL=amqps://b\nJDBC_DSN=jdbc:mysql://h/db\nAPI_KEY=" + canary + "\nSTRIPE_URL=https://api.stripe.com\nLOG_URL=${LOG_URL}\n"
	in := SurveyInput{
		Names: []string{".env", ".env.example", "package.json"},
		Files: []ProjectFile{
			pjFile(".env", real), pjFile(".env.local", real), pjFile(".envrc", real), pjFile("prod.env", real),
			pjFile(".env.example", example),
		},
	}
	f := AnalyzeProject(in)
	want := []Need{
		{Kind: "postgres", From: "env_example"},
		{Kind: "redis", From: "env_example"},
		{Kind: "mongodb", From: "env_example"},
		{Kind: "rabbitmq", From: "env_example"},
		{Kind: "mysql", From: "env_example"},
	}
	if !reflect.DeepEqual(f.Needs, want) {
		t.Errorf("Needs = %+v, want %+v", f.Needs, want)
	}
	b, _ := json.Marshal(f)
	for _, leak := range []string{canary, "internal", "secret-host", "stripe", "admin"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("the facts carry %q: %s", leak, b)
		}
	}
	// The only thing a real env file ever contributes is its name.
	if !reflect.DeepEqual(f.EnvFiles, []string{".env"}) || !reflect.DeepEqual(f.EnvExamples, []string{".env.example"}) {
		t.Errorf("EnvFiles %v EnvExamples %v", f.EnvFiles, f.EnvExamples)
	}
}

func TestProjectIsEnvName(t *testing.T) {
	for _, c := range []struct {
		name         string
		env, example bool
	}{
		{".env", true, false},
		{".envrc", true, false},
		{".env.local", true, false},
		{".env.production", true, false},
		{"prod.env", true, false},
		{".env.example", false, true},
		{".env.sample", false, true},
		{".env.template", false, true},
		{".env.dist", false, true},
		{"example.env", false, true},
		{".env.local.example", false, true},
		{"environment.ts", false, false},
		{"env.go", false, false},
		{".gitignore", false, false},
	} {
		env, ex := projIsEnvName(c.name)
		if env != c.env || ex != c.example {
			t.Errorf("projIsEnvName(%q) = %v,%v, want %v,%v", c.name, env, ex, c.env, c.example)
		}
	}
}

func TestProjectInfraRules(t *testing.T) {
	for _, c := range []struct {
		name    string
		names   []string
		dirs    []string
		present []string
		want    string
	}{
		{"dockerfile", []string{"Dockerfile"}, nil, nil, "dockerfile"},
		{"dockerfile suffix", []string{"api.dockerfile"}, nil, nil, "dockerfile"},
		{"dockerfile prefix", []string{"Dockerfile.dev"}, nil, nil, "dockerfile"},
		{"compose yml", []string{"docker-compose.yml"}, nil, nil, "compose"},
		{"compose override", []string{"docker-compose.override.yml"}, nil, nil, "compose"},
		{"compose v2", []string{"compose.yaml"}, nil, nil, "compose"},
		{"terraform file", []string{"main.tf"}, nil, nil, "terraform"},
		{"terraform dir", nil, []string{"terraform"}, nil, "terraform"},
		{"kubernetes dir", nil, []string{"k8s"}, nil, "kubernetes"},
		{"helm dir", nil, []string{"helm"}, nil, "kubernetes"},
		{"charts dir", nil, []string{"charts"}, nil, "kubernetes"},
		{"kubernetes dir 2", nil, []string{"kubernetes"}, nil, "kubernetes"},
		{"chart file", []string{"Chart.yaml"}, nil, nil, "kubernetes"},
		{"github actions", nil, nil, []string{".github/workflows"}, "github_actions"},
		{"gitlab", []string{".gitlab-ci.yml"}, nil, nil, "gitlab_ci"},
		{"circleci", nil, []string{".circleci"}, nil, "circleci"},
		{"bicep", []string{"main.bicep"}, nil, nil, "bicep"},
	} {
		got := projInfra(projSet(c.names), projSet(c.dirs), projSet(c.present))
		if !reflect.DeepEqual(got, []string{c.want}) {
			t.Errorf("%s: infra = %v, want [%s]", c.name, got, c.want)
		}
	}
	if got := projInfra(projSet([]string{"README.md"}), nil, nil); got != nil {
		t.Errorf("a README alone shows infra %v", got)
	}
}

func TestProjectInstalledAndLockfiles(t *testing.T) {
	f := AnalyzeProject(SurveyInput{
		Dirs:    []string{"vendor", "venv"},
		Names:   []string{"Cargo.lock", "Gemfile.lock", "go.sum", "poetry.lock", "uv.lock", "composer.lock", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock", "other.lock"},
		Present: []string{".venv", "target", "node_modules"},
	})
	if !reflect.DeepEqual(f.Installed, []string{"node_modules", "venv", "vendor", "target"}) {
		t.Errorf("Installed = %v", f.Installed)
	}
	want := []string{"yarn.lock", "pnpm-lock.yaml", "go.sum", "poetry.lock", "Pipfile.lock", "Gemfile.lock", "Cargo.lock", "composer.lock", "uv.lock"}
	if !reflect.DeepEqual(f.Lockfiles, want) {
		t.Errorf("Lockfiles = %v, want %v", f.Lockfiles, want)
	}
}

func TestProjectAISignals(t *testing.T) {
	for _, c := range []struct {
		name  string
		names []string
		dirs  []string
		files []ProjectFile
		want  []string
		ai    bool
	}{
		{"nothing", []string{"README.md"}, nil, nil, nil, false},
		{"llm dependency", []string{"requirements.txt"}, nil, []ProjectFile{pjFile("requirements.txt", "openai==1.0\n")}, []string{"llm_sdk"}, true},
		{"mcp dependency", []string{"package.json"}, nil, []ProjectFile{pjFile("package.json", `{"dependencies":{"@modelcontextprotocol/sdk":"1"}}`)}, []string{"mcp_sdk"}, true},
		// An agent configuration file is a listed signal; it does not make the
		// project an AI application (review W3-8).
		{"AGENTS.md", []string{"AGENTS.md"}, nil, nil, []string{"agent_file"}, false},
		{"CLAUDE.md", []string{"CLAUDE.md"}, nil, nil, []string{"agent_file"}, false},
		{"GEMINI.md", []string{"GEMINI.md"}, nil, nil, []string{"agent_file"}, false},
		{"cursor dir", nil, []string{".cursor"}, nil, []string{"agent_file"}, false},
		{"cursorrules", []string{".cursorrules"}, nil, nil, []string{"agent_file"}, false},
		{"windsurfrules", []string{".windsurfrules"}, nil, nil, []string{"agent_file"}, false},
		{"a plain service with CLAUDE.md and a web dependency", []string{"package.json", "CLAUDE.md"}, nil, []ProjectFile{pjFile("package.json", `{"dependencies":{"express":"4"}}`)}, []string{"agent_file"}, false},
		{"an agent file beside a model dependency", []string{"requirements.txt", "CLAUDE.md"}, nil, []ProjectFile{pjFile("requirements.txt", "openai==1.0\n")}, []string{"llm_sdk", "agent_file"}, true},
		{"prompts dir", nil, []string{"prompts"}, nil, []string{"prompt_files"}, true},
		{"prompt file", []string{"summarise.prompt.md"}, nil, nil, []string{"prompt_files"}, true},
		{"mcp config", []string{".mcp.json"}, nil, nil, []string{"mcp_config"}, true},
		{
			"all in order",
			[]string{".mcp.json", "AGENTS.md", "go.mod"},
			[]string{"prompts"},
			[]ProjectFile{pjFile("go.mod", "module x\n\nrequire (\n\tgithub.com/mark3labs/mcp-go v0.1.0\n\tgithub.com/sashabaranov/go-openai v1.0.0\n)\n")},
			[]string{"llm_sdk", "mcp_sdk", "agent_file", "prompt_files", "mcp_config"},
			true,
		},
	} {
		f := AnalyzeProject(SurveyInput{Names: c.names, Dirs: c.dirs, Files: c.files})
		if !reflect.DeepEqual(f.AISignals, c.want) || f.AIApp != c.ai {
			t.Errorf("%s: signals %v app %v, want %v %v", c.name, f.AISignals, f.AIApp, c.want, c.ai)
		}
	}
}

// TestProjectAIAppTable (review W3-8) holds the table that says which AI
// signals make a project an AI application: every id the analysis can list is in
// it, each row says what the method step "this project calls a model or gives
// one tools" needs, and an id outside it never does.
func TestProjectAIAppTable(t *testing.T) {
	// Every signal id, shown alone by a project that carries nothing else.
	alone := map[string]SurveyInput{
		"llm_sdk":      {Names: []string{"requirements.txt"}, Files: []ProjectFile{pjFile("requirements.txt", "anthropic\n")}},
		"mcp_sdk":      {Names: []string{"package.json"}, Files: []ProjectFile{pjFile("package.json", `{"dependencies":{"@modelcontextprotocol/sdk":"1"}}`)}},
		"agent_file":   {Names: []string{"CLAUDE.md"}},
		"prompt_files": {Dirs: []string{"prompts"}},
		"mcp_config":   {Names: []string{".mcp.json"}},
	}
	if len(alone) != len(projAISignalSetsApp) {
		t.Fatalf("%d fixtures for %d table rows", len(alone), len(projAISignalSetsApp))
	}
	for _, row := range projAISignalSetsApp {
		t.Run(row.id, func(t *testing.T) {
			in, ok := alone[row.id]
			if !ok {
				t.Fatalf("no fixture for the signal %q", row.id)
			}
			f := AnalyzeProject(in)
			if !reflect.DeepEqual(f.AISignals, []string{row.id}) {
				t.Fatalf("signals %v, want only %q", f.AISignals, row.id)
			}
			if f.AIApp != row.app {
				t.Errorf("AIApp = %v for %q, want %v", f.AIApp, row.id, row.app)
			}
			if projAIApp([]string{row.id}) != row.app {
				t.Errorf("projAIApp(%q) = %v, want %v", row.id, !row.app, row.app)
			}
		})
	}
	// Only the agent configuration signal is a listed signal that is not an AI
	// application, and the other four are.
	want := map[string]bool{"llm_sdk": true, "mcp_sdk": true, "agent_file": false, "prompt_files": true, "mcp_config": true}
	for _, row := range projAISignalSetsApp {
		if row.app != want[row.id] {
			t.Errorf("row %q: app = %v, want %v", row.id, row.app, want[row.id])
		}
	}
	if projAIApp(nil) || projAIApp([]string{"agent_file"}) || projAIApp([]string{"made_up"}) {
		t.Error("no signal, an agent file alone or an unknown id must not read as an AI application")
	}
	if !projAIApp([]string{"agent_file", "mcp_config"}) {
		t.Error("an agent file beside a tool-server config is an AI application")
	}
	// The ids the rule table and the dependency roles can list are all in the
	// closed table.
	in := map[string]bool{}
	for _, row := range projAISignalSetsApp {
		in[row.id] = true
	}
	for _, r := range projAISignalRules {
		if !in[r.id] {
			t.Errorf("the rule %q is not in the AI application table", r.id)
		}
	}
}

func TestProjectSpec(t *testing.T) {
	openapi3 := `{"openapi":"3.0.1","servers":[{"url":"x"},{"url":"y"}],"paths":{"/a":{"get":{},"post":{},"parameters":[]},"/b":{"delete":{}}},
		"components":{"securitySchemes":{"bearerAuth":{},"api key":{},"basic":{}}}}`
	swagger2 := `{"swagger":"2.0","host":"api.local","paths":{"/a":{"get":{},"put":{}}},"securityDefinitions":{"oauth":{}}}`
	for _, c := range []struct {
		name  string
		names []string
		files []ProjectFile
		path  string
		spec  *SpecSummary
		drop  int
	}{
		{
			"openapi 3",
			[]string{"openapi.json"},
			[]ProjectFile{pjFile("openapi.json", openapi3)},
			"openapi.json",
			&SpecSummary{Path: "openapi.json", Operations: 3, AuthSchemes: []string{"basic", "bearerAuth"}, Servers: 2}, 1,
		},
		{
			"swagger 2", nil,
			[]ProjectFile{pjFile("docs/openapi.json", swagger2)},
			"docs/openapi.json",
			&SpecSummary{Path: "docs/openapi.json", Operations: 2, AuthSchemes: []string{"oauth"}, Servers: 1}, 0,
		},
		{"not a spec", []string{"openapi.json"}, []ProjectFile{pjFile("openapi.json", `{"a":1}`)}, "openapi.json", nil, 0},
		{"garbage", []string{"swagger.json"}, []ProjectFile{pjFile("swagger.json", `{nope`)}, "swagger.json", nil, 0},
		{"yaml", []string{"openapi.yaml"}, nil, "openapi.yaml", nil, 0},
		{"graphql", []string{"schema.graphql", "z.graphql"}, nil, "schema.graphql", nil, 0},
		{"other graphql", []string{"api.graphql"}, nil, "api.graphql", nil, 0},
		{"none", []string{"README.md"}, nil, "", nil, 0},
	} {
		f := AnalyzeProject(SurveyInput{Names: c.names, Files: c.files})
		if f.SpecPath != c.path || !reflect.DeepEqual(f.Spec, c.spec) || f.Dropped != c.drop {
			t.Errorf("%s: path %q spec %+v dropped %d, want %q %+v %d", c.name, f.SpecPath, f.Spec, f.Dropped, c.path, c.spec, c.drop)
		}
	}
}

func TestProjectNeedsFromCompose(t *testing.T) {
	compose := `version: "3.9"
x-common: &common
  restart: always
services:
  web:
    build: .
    ports: ["3000:3000"]
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_PASSWORD: secretvalue
  cache:
    image: "docker.io/library/redis:7"
  search:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
  mongo:
    build: ./mongo
  pgweb:
    image: sosedoff/pgweb
  exporter:
    image: prom/postgres-exporter
  sql:
    image: mcr.microsoft.com/mssql/server:2022
  queue:
    image: bitnami/kafka@sha256:abc
  kafka-ui:
    image: provectuslabs/kafka-ui
  odd$svc:
    image: mysql:8
volumes:
  data: {}
`
	f := AnalyzeProject(SurveyInput{Names: []string{"docker-compose.yml"}, Files: []ProjectFile{pjFile("docker-compose.yml", compose)}})
	want := []Need{
		{"postgres", "compose", "db"},
		{"redis", "compose", "cache"},
		{"elasticsearch", "compose", "search"},
		{"mongodb", "compose", "mongo"},
		{"sqlserver", "compose", "sql"},
		{"kafka", "compose", "queue"},
		{"mysql", "compose", ""},
	}
	if !reflect.DeepEqual(f.Needs, want) {
		t.Errorf("Needs =\n%+v\nwant\n%+v", f.Needs, want)
	}
	if f.Dropped != 1 {
		t.Errorf("Dropped = %d (the unsafe service name)", f.Dropped)
	}
	b, _ := json.Marshal(f)
	if strings.Contains(string(b), "secretvalue") {
		t.Errorf("a value leaked: %s", b)
	}
	// A compose file with no services key, and the empty file.
	for _, d := range []string{"", "version: 3\nvolumes:\n  a: {}\n", "services: {}\n", "services:\n  # nothing\n"} {
		if got := projComposeNeeds(&projCollector{}, []byte(d)); len(got) != 0 {
			t.Errorf("compose %q: needs %v", d, got)
		}
	}
	// Needs are capped.
	var many strings.Builder
	many.WriteString("services:\n")
	for i := 0; i < 40; i++ {
		many.WriteString("  redis" + strings.Repeat("x", i) + ":\n    image: redis\n")
	}
	if got := AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("compose.yml", many.String())}}).Needs; len(got) != projMaxNeeds {
		t.Errorf("%d needs, want the cap %d", len(got), projMaxNeeds)
	}
}

func TestProjectDirsCapAndTruncation(t *testing.T) {
	var dirs []string
	for i := 0; i < projMaxDirs+5; i++ {
		dirs = append(dirs, "d"+strings.Repeat("a", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	f := AnalyzeProject(SurveyInput{Dirs: dirs})
	if len(f.Dirs) != projMaxDirs || !f.Truncated {
		t.Errorf("%d dirs, truncated %v", len(f.Dirs), f.Truncated)
	}
	if f := AnalyzeProject(SurveyInput{Truncated: true}); !f.Truncated {
		t.Error("the survey's Truncated is not carried")
	}
}

func TestAnalyzeProjectTolerantOfGarbage(t *testing.T) {
	var files []ProjectFile
	for _, rel := range []string{"package.json", "go.mod", "requirements.txt", "pyproject.toml", "Pipfile", "Gemfile", "composer.json", "Cargo.toml", "pom.xml", "build.gradle", "docker-compose.yml", ".env.example", "openapi.json", ".claude/launch.json", "Procfile", "Makefile", "manage.py"} {
		files = append(files, pjFile(rel, "\x00\xff\xfe{[(((\n\"\"'\n"+strings.Repeat("x", 5000)), ProjectFile{Rel: rel}, ProjectFile{Rel: rel, Data: make([]byte, MaxProjectFile+1)})
	}
	f := AnalyzeProject(SurveyInput{Files: files})
	if len(f.Deps) != 0 || f.DepCount != 0 || len(f.Needs) != 0 || f.Spec != nil {
		t.Errorf("garbage produced %+v", f)
	}
	if got := f.AppFacts(); len(got) != len(GroundingFacts) {
		t.Errorf("a folder with nothing readable is unknown: AppFacts = %v", got)
	}
}

func TestProjectManifestParsers(t *testing.T) {
	for _, c := range []struct {
		name  string
		parse func([]byte) []string
		in    string
		want  []string
	}{
		{"package.json", projParsePackageJSON, `{"dependencies":{"b":"1","a":"1"},"devDependencies":{"c":"1"},"peerDependencies":{"p":"1"}}`, []string{"a", "b", "c"}},
		{"package.json garbage", projParsePackageJSON, `[1,2]`, nil},
		{"composer", projParseComposer, `{"require":{"php":">=8","ext-json":"*","laravel/framework":"11"},"require-dev":{"phpunit/phpunit":"1"}}`, []string{"laravel/framework", "phpunit/phpunit"}},
		{"go.mod", projParseGoMod, "module x\n\ngo 1.22\n\nrequire github.com/a/one v1.0.0\n\nrequire (\n\tgithub.com/b/two v1.2.3\n\tgithub.com/c/three v0.1.0 // indirect\n\t// github.com/d/four v1\n)\n\nreplace (\n\tgithub.com/e/five => ../five\n)\n", []string{"github.com/a/one", "github.com/b/two"}},
		{"go.mod indirect single", projParseGoMod, "require github.com/z/z v1.0.0 // indirect\n", nil},
		{"requirements", projParseRequirements, "# c\nFlask==2.0\nrequests[security]>=2 ; python_version>'3'\n-r other.txt\n-e .\ngit+https://x/y.git#egg=z\nhttps://x/y.whl\nDjango_Rest # trailing\n\n", []string{"Flask", "requests", "Django_Rest"}},
		{"pyproject pep621", projParsePyproject, "[project]\nname = \"x\"\ndependencies = [\n  \"flask>=2\",\n  'sqlalchemy',\n]\n\n[project.optional-dependencies]\ndev = [\"pytest\"]\n", []string{"flask", "sqlalchemy"}},
		{"pyproject inline", projParsePyproject, "[project]\ndependencies = [\"fastapi\", \"uvicorn[standard]>=1\"]\n", []string{"fastapi", "uvicorn"}},
		{"pyproject poetry", projParsePyproject, "[tool.poetry.dependencies]\npython = \"^3.11\"\ndjango = \"^5\"\nrequests = {version = \"2\"}\n[tool.poetry.group.dev.dependencies]\npytest = \"8\"\n[tool.other]\nnot = \"a dep\"\n", []string{"django", "requests", "pytest"}},
		{"pipfile", projParsePipfile, "[[source]]\nname = \"pypi\"\n\n[packages]\nflask = \"*\"\n\"requests\" = {version = \"2\"}\n\n[dev-packages]\npytest = \"*\"\n\n[requires]\npython_version = \"3.11\"\n", []string{"flask", "requests", "pytest"}},
		{"gemfile", projParseGemfile, "source 'https://rubygems.org'\ngem 'rails', '~> 7'\n  gem \"devise\"\n# gem 'old'\ngroup :test do\n  gem 'rspec'\nend\n", []string{"rails", "devise", "rspec"}},
		{"cargo", projParseCargo, "[package]\nname = \"x\"\n\n[dependencies]\naxum = \"0.7\"\nserde = { version = \"1\" }\ntokio.workspace = true\n\n[dev-dependencies]\ntower = \"0.4\"\n\n[dependencies.reqwest]\nversion = \"0.12\"\nfeatures = [\"json\"]\n\n[features]\ndefault = []\n", []string{"axum", "serde", "tokio", "tower", "reqwest"}},
		{"pom", projParsePom, "<project><artifactId>mine</artifactId><parent><artifactId>spring-boot-starter-parent</artifactId></parent>\n<dependencyManagement><dependencies><dependency><artifactId>managed</artifactId></dependency></dependencies></dependencyManagement>\n<dependencies><dependency><groupId>g</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>\n<dependency><artifactId> junit </artifactId></dependency></dependencies>\n<!-- <dependency><artifactId>commented</artifactId></dependency> -->\n<build><plugins><plugin><dependencies><dependency><artifactId>plugindep</artifactId></dependency></dependencies></plugin></plugins></build></project>", []string{"spring-boot-starter-web", "junit"}},
		{"gradle", projParseGradle, "dependencies {\n  implementation 'org.springframework.boot:spring-boot-starter-web'\n  implementation(\"org.springframework.boot:spring-boot-starter-security:3.2.0\")\n  testImplementation platform(\"org.x:bom:1\")\n  runtimeOnly \"com.h2database:h2\"\n  // implementation 'a:b'\n}\n", []string{"spring-boot-starter-web", "spring-boot-starter-security", "h2"}},
	} {
		if got := c.parse([]byte(c.in)); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	// A line that is not UTF-8 or is over 4 KiB is skipped, the rest is read.
	long := "Z" + strings.Repeat("a", projMaxLineBytes)
	got := projParseRequirements([]byte("good1\n" + long + "\nbad\xff\ngood2\n"))
	if !reflect.DeepEqual(got, []string{"good1", "good2"}) {
		t.Errorf("hostile lines: %v", got)
	}
}

// TestAnalyzeProjectManifestsPerLanguage checks that each ecosystem's own role
// rows apply and the count and per-language count follow the manifest.
func TestAnalyzeProjectManifestsPerLanguage(t *testing.T) {
	f := AnalyzeProject(SurveyInput{
		Names: []string{"requirements.txt", "go.mod", "Gemfile", "composer.json", "Cargo.toml", "pom.xml"},
		Files: []ProjectFile{
			pjFile("requirements.txt", "Flask==2\nflask-login\nSQLAlchemy\nrequests\nlangchain-openai\nmcp\n"),
			pjFile("go.mod", "module m\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgorm.io/gorm v1.25.0\n\tgithub.com/labstack/echo/v4 v4.1.0\n\tgolang.org/x/crypto v0.1.0\n)\n"),
			pjFile("Gemfile", "gem 'rails'\ngem 'devise'\ngem 'sidekiq'\n"),
			pjFile("composer.json", `{"require":{"laravel/framework":"11","guzzlehttp/guzzle":"7"}}`),
			pjFile("Cargo.toml", "[dependencies]\naxum = \"1\"\nreqwest = \"1\"\n"),
			pjFile("pom.xml", "<dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency><dependency><artifactId>hibernate-core</artifactId></dependency></dependencies>"),
		},
	})
	// Closed order is the table's: node, python, ruby, php, go, rust, java.
	wantFw := []string{"flask", "rails", "laravel", "gin", "echo", "axum", "spring"}
	if !reflect.DeepEqual(f.Frameworks, wantFw) {
		t.Errorf("Frameworks = %v, want %v", f.Frameworks, wantFw)
	}
	if f.DepCount != 19 {
		t.Errorf("DepCount = %d", f.DepCount)
	}
	for lang, n := range map[string]int{"python": 6, "go": 4, "ruby": 3, "php": 2, "rust": 2, "java": 2} {
		if f.depsByLang[lang] != n {
			t.Errorf("depsByLang[%s] = %d, want %d", lang, f.depsByLang[lang], n)
		}
	}
	roles := map[string][]string{}
	for _, d := range f.Deps {
		roles[d.Role] = d.Names
	}
	if !reflect.DeepEqual(roles[DepRoleLLMSDK], []string{"langchain-openai"}) || !reflect.DeepEqual(roles[DepRoleMCPSDK], []string{"mcp"}) {
		t.Errorf("AI roles: %v %v", roles[DepRoleLLMSDK], roles[DepRoleMCPSDK])
	}
	if !reflect.DeepEqual(roles[DepRoleQueue], []string{"sidekiq"}) || !reflect.DeepEqual(roles[DepRoleCrypto], []string{"golang.org/x/crypto"}) {
		t.Errorf("roles: queue %v crypto %v", roles[DepRoleQueue], roles[DepRoleCrypto])
	}
}

// TestProjectNamesCapPerRole: an enormous manifest cannot grow the facts.
func TestProjectNamesCapPerRole(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"dependencies":{`)
	for i := 0; i < 60; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"passport-` + strings.Repeat("a", i/3) + string(rune('a'+i%3)) + `":"1"`)
	}
	b.WriteString(`}}`)
	f := AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("package.json", b.String())}})
	if len(f.Deps) != 1 || len(f.Deps[0].Names) != projMaxNamesPerRole {
		t.Fatalf("Deps = %+v", f.Deps)
	}
	if f.Dropped != 60-projMaxNamesPerRole {
		t.Errorf("Dropped = %d, want %d", f.Dropped, 60-projMaxNamesPerRole)
	}
}

func TestAnalyzeProjectStartCommandsCountedAsDropped(t *testing.T) {
	f := AnalyzeProject(SurveyInput{
		Names: []string{"Procfile"},
		Files: []ProjectFile{
			pjFile("Procfile", "web: gunicorn app:app --bind 0.0.0.0:$PORT\n"),
			pjFile(".claude/launch.json", `{"configurations":[{"runtimeExecutable":"sh","runtimeArgs":["-c","a && b"],"port":3000},{"runtimeExecutable":"npm","runtimeArgs":["run","dev"],"port":5173}]}`),
		},
	})
	if f.Dropped != 2 {
		t.Errorf("Dropped = %d, want 2 (a Procfile line and a launch entry)", f.Dropped)
	}
}

// TestProjectNeedTables is one case per row of the service tables.
func TestProjectNeedTables(t *testing.T) {
	for _, r := range projNeedImages {
		for _, seg := range r.segments {
			for _, image := range []string{seg, seg + ":1.2", "docker.io/library/" + seg + ":latest", "vendor/" + seg + "@sha256:abc"} {
				if seg == "mssql/server" {
					image = "mcr.microsoft.com/" + seg + ":2022"
				}
				if got := projNeedFromImage(image); got != r.kind {
					t.Errorf("image %q = %q, want %q", image, got, r.kind)
				}
			}
		}
	}
	for name, kind := range projNeedServiceNames {
		if got := projComposeNeeds(&projCollector{}, []byte("services:\n  "+name+":\n    build: .\n")); len(got) != 1 || got[0].Kind != kind || got[0].Service != name {
			t.Errorf("service %q = %+v, want kind %q", name, got, kind)
		}
	}
	for scheme, kind := range projNeedSchemes {
		got := projEnvExampleNeeds([]byte("X_URL=" + scheme + "://h/db\n"))
		if len(got) != 1 || got[0].Kind != kind || got[0].From != "env_example" {
			t.Errorf("scheme %q = %+v, want kind %q", scheme, got, kind)
		}
	}
	for _, image := range []string{"prom/postgres-exporter", "sosedoff/pgweb", "provectuslabs/kafka-ui", "rediscommander/redis-commander", "mongo-express", "nginx", "", "postgres-backup", "app/db"} {
		if got := projNeedFromImage(image); got != "" {
			t.Errorf("image %q = %q, want none", image, got)
		}
	}
	for _, name := range []string{"db", "cache", "database", "broker", "app", "postgres-exporter"} {
		if got := projComposeNeeds(&projCollector{}, []byte("services:\n  "+name+":\n    build: .\n")); len(got) != 0 {
			t.Errorf("service %q read as %+v", name, got)
		}
	}
}

// TestProjectFactsJSONHasNoHiddenState: the exported shape is all that
// serialises, so the start files the facts keep never leave the process.
func TestProjectFactsJSONHasNoHiddenState(t *testing.T) {
	f := AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("Makefile", "run:\n\tCANARY-start-file\n"), pjFile("package.json", `{"dependencies":{"express":"4"}}`)}})
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "CANARY") || strings.Contains(string(b), "express\":") {
		t.Errorf("hidden state serialised: %s", b)
	}
	var back ProjectFacts
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if len(PlanStarts(back)) != 0 {
		t.Error("a decoded ProjectFacts planned a start command")
	}
	if !reflect.DeepEqual(back.Deps, f.Deps) || back.DepCount != f.DepCount {
		t.Errorf("round trip lost data: %+v", back)
	}
}
