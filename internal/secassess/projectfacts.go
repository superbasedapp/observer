package secassess

import (
	"sort"
	"strings"
)

// Project facts (depth plan W3.2, data side): the pure analysis of a bounded
// look at a project's folder. secassesssvc.Survey reads names and a fixed
// allow-list of files; AnalyzeProject turns them into closed ids and
// strict-charset names, never into repository prose.
//
// What is read and what is not (the privacy rules of the module):
//   - Environment files are known by NAME only. Their contents are never read
//     here, and AnalyzeProject refuses to parse one even when a caller passes
//     it in: only an EXAMPLE file (.env.example, .env.sample, .env.template)
//     is read, and from it only the URL scheme word of a value whose key ends
//     in _URL, _URI or _DSN, from a closed list (postgres, redis, ...). No
//     value, host, user, password or any other part of a URL is ever kept.
//   - Every string that lands in a ProjectFacts field is a closed id or passes
//     the strict charset [A-Za-z0-9._/@+-], at most 80 characters, so
//     repository-authored text is safe to put inside a prompt fence later; a
//     string that does not is left out and counted in Dropped.
//   - A manifest line that is not UTF-8 or is longer than 4 KiB is skipped.
//   - Only the top level of the project is looked at: a manifest in a
//     sub-folder of a monorepo is not seen, and the facts say nothing about it.

// ProjectFile is one project file the service's survey read: Rel is
// project-relative with forward slashes, Data at most MaxProjectFile bytes.
type ProjectFile struct {
	Rel  string
	Data []byte
}

// MaxProjectFile is the most bytes of one project file the analysis reads.
const MaxProjectFile = 256 << 10

// SurveyInput is what secassesssvc.Survey hands the pure analysis: names and
// bytes, nothing interpreted.
type SurveyInput struct {
	// Dirs are the top-level directory names, sorted.
	Dirs []string
	// Names are the top-level file names, hidden ones included, sorted.
	Names []string
	// Files are the files read, from the fixed allow-list (SurveyFiles).
	Files []ProjectFile
	// Present are the existence probes that held (directories such as
	// node_modules or .venv, by closed id).
	Present []string
	// Truncated: a cap was hit (a listing or a file); the notes say so.
	Truncated bool
}

// DepRole is the direct dependencies of one role (auth, crypto, orm, template,
// http_client, queue, llm_sdk, mcp_sdk, web_framework), by name.
type DepRole struct {
	Role  string   `json:"role"`
	Names []string `json:"names"`
}

// Need is a service the application needs that the box cannot give it: a
// database or cache named by a compose file or an example env file.
type Need struct {
	// Kind is a closed id (postgres, mysql, redis, mongodb, ...).
	Kind string `json:"kind"`
	// From is "compose" or "env_example".
	From string `json:"from"`
	// Service is the compose service's name (strict charset) when From is
	// "compose" and the name passed it; an example env file names no service.
	Service string `json:"service,omitempty"`
}

// SpecSummary is a one-line account of an OpenAPI JSON spec the project holds
// (a YAML spec is left to the agent: the standard library has no YAML).
type SpecSummary struct {
	Path        string   `json:"path"`
	Operations  int      `json:"operations"`
	AuthSchemes []string `json:"auth_schemes,omitempty"`
	Servers     int      `json:"servers"`
}

// ProjectFacts is the pure analysis of a SurveyInput: plain data every consumer
// (the grounding digest, the start plan, the preflight notes, the method
// tables) reads. Every string is a closed id or has passed the strict charset
// [A-Za-z0-9._/@+-] (at most 80 characters); one that did not is dropped and
// counted in Dropped.
//
// Facts also carry, unexported and unserialised, the few project files the
// start table reads (PlanStarts, PlanCandidates): a ProjectFacts decoded from
// JSON plans no start command; one made by AnalyzeProject does.
type ProjectFacts struct {
	// Dirs are the top-level directories the scope picker offers.
	Dirs []string `json:"dirs,omitempty"`
	// Languages are closed ids (go, node, python, ruby, php, java, rust, dotnet).
	Languages []string `json:"languages,omitempty"`
	// Manifests are the manifest file names found (package.json, go.mod, ...).
	Manifests []string `json:"manifests,omitempty"`
	// Frameworks are closed framework ids derived from the dependencies.
	Frameworks []string `json:"frameworks,omitempty"`
	// Infra are closed ids: dockerfile, compose, terraform, kubernetes,
	// github_actions, gitlab_ci, circleci, bicep.
	Infra []string `json:"infra,omitempty"`
	// SpecPath is the project-relative path of an OpenAPI or GraphQL spec file
	// ("" none); Spec summarises an OpenAPI JSON one.
	SpecPath string       `json:"spec_path,omitempty"`
	Spec     *SpecSummary `json:"spec,omitempty"`
	// Deps are the direct dependencies by role; DepCount is how many direct
	// dependencies the manifests list.
	Deps     []DepRole `json:"deps,omitempty"`
	DepCount int       `json:"dep_count,omitempty"`
	// AISignals are the closed ids of the AI signals the project shows (llm_sdk,
	// mcp_sdk, agent_file, prompt_files, mcp_config). AIApp says the project is
	// an AI application, one that calls a model or gives one tools: only
	// llm_sdk, mcp_sdk, prompt_files and mcp_config say so. An agent
	// configuration file (agent_file) is a signal that the project was written
	// with an AI tool, and does not (projAISignalSetsApp).
	AIApp     bool     `json:"ai_app,omitempty"`
	AISignals []string `json:"ai_signals,omitempty"`
	// Installed are the closed ids of dependency folders present
	// (node_modules, venv, vendor, target); Lockfiles the lock file names.
	Installed []string `json:"installed,omitempty"`
	Lockfiles []string `json:"lockfiles,omitempty"`
	// Needs are the services the application needs.
	Needs []Need `json:"needs,omitempty"`
	// EnvFiles are the names of the environment files that may hold real
	// values (.env, .env.local, .env.production, .envrc); EnvExamples the
	// example ones (.env.example, .env.sample). Their contents are never read
	// except an example's URL schemes.
	EnvFiles    []string `json:"env_files,omitempty"`
	EnvExamples []string `json:"env_examples,omitempty"`
	// Dropped counts strings left out for failing the strict charset (a start
	// command from a project file that cannot be written as an argv counts
	// here too).
	Dropped int `json:"dropped,omitempty"`
	// Truncated: the survey hit a cap.
	Truncated bool `json:"truncated,omitempty"`

	// src are the files the start table reads, in survey order.
	src []ProjectFile
	// depsByLang counts the direct dependencies each language's manifests
	// list (the preflight "installed" and "lock file" rules need them).
	depsByLang map[string]int
}

// projStrict reports whether s passes the strict charset [A-Za-z0-9._/@+-],
// one to 80 characters.
func projStrict(s string) bool {
	if s == "" || len(s) > 80 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		case b == '.', b == '_', b == '/', b == '@', b == '+', b == '-':
		default:
			return false
		}
	}
	return true
}

// projCollector counts the strings the strict charset refused.
type projCollector struct{ dropped int }

// keep reports whether s passes the strict charset, counting it when it does
// not.
func (c *projCollector) keep(s string) bool {
	if projStrict(s) {
		return true
	}
	c.dropped++
	return false
}

// projSet is a set of names.
func projSet(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// Caps on what one analysis keeps, so a hostile folder cannot grow the facts.
const (
	projMaxDirs         = 100
	projMaxListed       = 20
	projMaxDepsPerFile  = 5000
	projMaxNamesPerRole = 24
	projMaxLineBytes    = 4 << 10
	projMaxNeeds        = 16
)

// projScopeSkipDirs are top-level folders the scope picker never offers:
// installed dependencies and build output (every dot-folder except .github is
// skipped as well: version control and tool state).
var projScopeSkipDirs = map[string]bool{
	"node_modules": true, "__pycache__": true, "venv": true, "vendor": true, "target": true,
	"dist": true, "build": true, "coverage": true,
}

// AnalyzeProject parses a survey into facts. It is pure and tolerant: a file
// that does not parse contributes nothing, and no input makes it fail.
func AnalyzeProject(in SurveyInput) ProjectFacts {
	var c projCollector
	f := ProjectFacts{Truncated: in.Truncated, depsByLang: map[string]int{}}
	names, dirs := projSet(in.Names), projSet(in.Dirs)
	present := projSet(in.Present)

	f.Dirs = projScopeDirs(&c, in.Dirs, &f.Truncated)
	projFindManifests(&c, in.Names, &f)

	deps := projReadManifests(in.Files)
	projApplyDeps(&c, deps, &f)

	f.AISignals = projAISignals(&f, names, dirs)
	f.AIApp = projAIApp(f.AISignals)
	f.Infra = projInfra(names, dirs, present)
	projSpec(&c, in, names, &f)
	f.Installed = projInstalled(present, dirs)
	f.Lockfiles = projLockfiles(&c, in.Names)
	projEnvNames(&c, in.Names, &f)
	f.Needs = projNeeds(&c, in.Files)
	f.src = projStartFiles(in.Files)
	// A start command that cannot be written as an argv is a string left out
	// for failing the strict charset: count it with the others.
	if _, skipped := splPlan(f); skipped > 0 {
		c.dropped += skipped
	}
	f.Dropped = c.dropped
	return f
}

// projScopeDirs returns the top-level directories the scope picker offers:
// sorted, strict charset, none of the tool or build folders, at most
// projMaxDirs.
func projScopeDirs(c *projCollector, dirs []string, truncated *bool) []string {
	var out []string
	for _, d := range dirs {
		if (strings.HasPrefix(d, ".") && d != ".github") || projScopeSkipDirs[d] {
			continue
		}
		if !c.keep(d) {
			continue
		}
		if len(out) == projMaxDirs {
			*truncated = true
			break
		}
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// projFactRule is one row of the AppFacts table: the fact holds when any of
// its signals does.
type projFactRule struct {
	fact    string
	signals []projSignal
}

// projSignal is one thing the project can show: a dependency role, a
// framework id, a top-level directory name, an API description (with or
// without a security scheme) or a start command.
type projSignal struct {
	kind  string // role, framework, dir, spec, spec_auth, start
	value string
}

// projFactRules is THE AppFacts table (one test row per row). The asymmetry
// is on purpose: a category wrongly read as "not applicable" is a test that
// never happens, a category wrongly read as applicable is a test the agent
// marks skipped, so every row leans toward holding.
//
//   - login holds for any web application: a hand-rolled login uses no
//     library, so the absence of an authentication dependency proves nothing;
//   - sessions needs an authentication library, a framework that sets session
//     cookies itself, server-rendered templates or a security scheme in the
//     API description;
//   - browser_client holds for a front-end framework, a template engine, a
//     framework that renders pages itself or a folder of pages and assets;
//   - http_api holds for a web framework, an API description, a start command
//     or an API folder.
var projFactRules = []projFactRule{
	{FactLogin, []projSignal{
		{"role", "auth"},
		{"role", "web_framework"},
		{"spec_auth", ""},
		{"start", ""},
		{"dir", "auth"},
		{"dir", "login"},
		{"dir", "accounts"},
		{"dir", "users"},
	}},
	{FactSessions, []projSignal{
		{"role", "auth"},
		{"role", "template"},
		{"spec_auth", ""},
		{"framework", "django"},
		{"framework", "rails"},
		{"framework", "laravel"},
		{"framework", "flask"},
		{"framework", "symfony"},
		{"framework", "spring"},
		{"framework", "sinatra"},
		{"framework", "nextjs"},
		{"framework", "nuxt"},
		{"framework", "sveltekit"},
		{"framework", "remix"},
	}},
	{FactBrowserClient, []projSignal{
		{"role", "template"},
		{"framework", "react"},
		{"framework", "vue"},
		{"framework", "svelte"},
		{"framework", "angular"},
		{"framework", "nextjs"},
		{"framework", "nuxt"},
		{"framework", "sveltekit"},
		{"framework", "remix"},
		{"framework", "astro"},
		{"framework", "gatsby"},
		{"framework", "streamlit"},
		{"framework", "gradio"},
		{"framework", "django"},
		{"framework", "rails"},
		{"framework", "laravel"},
		{"framework", "symfony"},
		{"framework", "cakephp"},
		{"framework", "yii"},
		{"framework", "codeigniter"},
		{"dir", "public"},
		{"dir", "static"},
		{"dir", "templates"},
		{"dir", "views"},
		{"dir", "frontend"},
		{"dir", "client"},
		{"dir", "web"},
		{"dir", "www"},
		{"dir", "pages"},
		{"dir", "assets"},
	}},
	{FactHTTPAPI, []projSignal{
		{"role", "web_framework"},
		{"spec", ""},
		{"start", ""},
		{"framework", "nextjs"},
		{"framework", "nuxt"},
		{"framework", "sveltekit"},
		{"framework", "remix"},
		{"dir", "api"},
		{"dir", "server"},
		{"dir", "routes"},
		{"dir", "controllers"},
		{"dir", "handlers"},
	}},
}

// AppFacts returns the closed grounding facts (the Fact* constants) that hold
// for the project, FactAlways first.
//
// When the survey could not tell what the project is (no manifest, no
// framework, no dependency of interest, no API description and no AI
// application signal: a folder the survey saw nothing in, or only a README or an
// agent configuration file), every fact reads as holding: unknown is not "not
// applicable".
func (f ProjectFacts) AppFacts() []string {
	out := []string{FactAlways}
	unknown := len(f.Manifests) == 0 && len(f.Frameworks) == 0 && len(f.Deps) == 0 && f.SpecPath == "" && !f.AIApp
	if unknown {
		for _, fact := range GroundingFacts {
			if fact != FactAlways {
				out = append(out, fact)
			}
		}
		return out
	}
	roles := map[string]bool{}
	for _, d := range f.Deps {
		roles[d.Role] = true
	}
	fws, dirs := projSet(f.Frameworks), projSet(f.Dirs)
	hasStart := len(PlanStarts(f)) > 0
	specAuth := f.Spec != nil && len(f.Spec.AuthSchemes) > 0
	for _, r := range projFactRules {
		for _, s := range r.signals {
			var hit bool
			switch s.kind {
			case "role":
				hit = roles[s.value]
			case "framework":
				hit = fws[s.value]
			case "dir":
				hit = dirs[s.value]
			case "spec":
				hit = f.SpecPath != ""
			case "spec_auth":
				hit = specAuth
			case "start":
				hit = hasStart
			}
			if hit {
				out = append(out, r.fact)
				break
			}
		}
	}
	return out
}
