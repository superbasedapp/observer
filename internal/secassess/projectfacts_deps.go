package secassess

import (
	"encoding/json"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

// The languages, in the order the facts list them.
var projLanguages = []string{"go", "node", "python", "ruby", "php", "java", "rust", "dotnet"}

// projManifestNames maps a top-level file name to its language: the manifests
// the facts name. Only some are READ (projParsers); the rest are presence.
var projManifestNames = map[string]string{
	"go.mod": "go", "package.json": "node",
	"requirements.txt": "python", "pyproject.toml": "python", "Pipfile": "python", "setup.py": "python", "setup.cfg": "python",
	"Gemfile": "ruby", "composer.json": "php",
	"pom.xml": "java", "build.gradle": "java", "build.gradle.kts": "java",
	"Cargo.toml": "rust",
}

// projManifestSuffixes are file name endings that name a manifest: the .NET
// project and solution files.
var projManifestSuffixes = []struct{ suffix, lang string }{
	{".csproj", "dotnet"}, {".fsproj", "dotnet"}, {".vbproj", "dotnet"}, {".sln", "dotnet"}, {".slnx", "dotnet"},
}

// projManifestLang returns the language a top-level file name is the manifest
// of ("" when it is none).
func projManifestLang(name string) string {
	if l, ok := projManifestNames[name]; ok {
		return l
	}
	if strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt") {
		return "python"
	}
	for _, s := range projManifestSuffixes {
		if strings.HasSuffix(name, s.suffix) {
			return s.lang
		}
	}
	return ""
}

// projFindManifests fills Manifests and Languages from the top-level names.
func projFindManifests(c *projCollector, names []string, f *ProjectFacts) {
	langs := map[string]bool{}
	for _, n := range names {
		l := projManifestLang(n)
		if l == "" {
			continue
		}
		// The language is a closed id and holds whatever the file is called; only
		// the name itself needs the strict charset to be listed.
		langs[l] = true
		if !c.keep(n) {
			continue
		}
		if len(f.Manifests) < projMaxListed {
			f.Manifests = append(f.Manifests, n)
		}
	}
	sort.Strings(f.Manifests)
	for _, l := range projLanguages {
		if langs[l] {
			f.Languages = append(f.Languages, l)
		}
	}
}

// projDeps are the direct dependency names one manifest lists.
type projDeps struct {
	lang  string
	names []string
}

// projParsers is THE table of manifests the analysis reads: the project
// relative path, the ecosystem and the reader. Each reader is tolerant (a
// file it cannot read lists nothing) and bounded.
var projParsers = []struct {
	rel   string
	lang  string
	parse func(data []byte) []string
}{
	{"package.json", "node", projParsePackageJSON},
	{"go.mod", "go", projParseGoMod},
	{"requirements.txt", "python", projParseRequirements},
	{"pyproject.toml", "python", projParsePyproject},
	{"Pipfile", "python", projParsePipfile},
	{"Gemfile", "ruby", projParseGemfile},
	{"composer.json", "php", projParseComposer},
	{"Cargo.toml", "rust", projParseCargo},
	{"pom.xml", "java", projParsePom},
	{"build.gradle", "java", projParseGradle},
	{"build.gradle.kts", "java", projParseGradle},
}

// projReadManifests parses every manifest among files.
func projReadManifests(files []ProjectFile) []projDeps {
	var out []projDeps
	for _, file := range files {
		if len(file.Data) == 0 || len(file.Data) > MaxProjectFile {
			continue
		}
		for _, p := range projParsers {
			if p.rel != file.Rel {
				continue
			}
			names := p.parse(file.Data)
			if len(names) > projMaxDepsPerFile {
				names = names[:projMaxDepsPerFile]
			}
			out = append(out, projDeps{lang: p.lang, names: names})
			break
		}
	}
	return out
}

// projApplyDeps counts the direct dependencies, matches them against the role
// table and fills Deps, DepCount, Frameworks and depsByLang.
func projApplyDeps(c *projCollector, deps []projDeps, f *ProjectFacts) {
	type langName struct{ lang, name string }
	counted := map[langName]bool{}
	roleNames := map[string]map[string]bool{}
	fws := map[string]bool{}
	for _, d := range deps {
		for _, raw := range d.names {
			name := depNormalize(d.lang, raw)
			if name == "" || counted[langName{d.lang, name}] {
				continue
			}
			counted[langName{d.lang, name}] = true
			f.depsByLang[d.lang]++
			roles, frameworks := depRolesOf(d.lang, name)
			for _, fw := range frameworks {
				fws[fw] = true
			}
			if len(roles) == 0 {
				continue
			}
			if !c.keep(name) {
				continue
			}
			for _, r := range roles {
				if roleNames[r] == nil {
					roleNames[r] = map[string]bool{}
				}
				roleNames[r][name] = true
			}
		}
	}
	f.DepCount = len(counted)
	for _, role := range DepRoleIDs {
		set := roleNames[role]
		if len(set) == 0 {
			continue
		}
		names := make([]string, 0, len(set))
		for n := range set {
			names = append(names, n)
		}
		sort.Strings(names)
		if len(names) > projMaxNamesPerRole {
			c.dropped += len(names) - projMaxNamesPerRole
			names = names[:projMaxNamesPerRole]
		}
		f.Deps = append(f.Deps, DepRole{Role: role, Names: names})
	}
	for _, id := range projFrameworkIDs {
		if fws[id] {
			f.Frameworks = append(f.Frameworks, id)
		}
	}
}

// projLines splits data into lines, skipping the ones that are not UTF-8 or are
// over 4 KiB (a manifest line that is neither is skipped, never an error).
func projLines(data []byte) []string {
	var out []string
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimRight(ln, "\r")
		if len(ln) > projMaxLineBytes || !utf8.ValidString(ln) {
			continue
		}
		out = append(out, ln)
	}
	return out
}

// projSortedKeys returns the keys of m in sorted order.
func projSortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func projParsePackageJSON(data []byte) []string {
	var pj struct {
		Dependencies    map[string]json.RawMessage `json:"dependencies"`
		DevDependencies map[string]json.RawMessage `json:"devDependencies"`
	}
	if json.Unmarshal(data, &pj) != nil {
		return nil
	}
	return append(projSortedKeys(pj.Dependencies), projSortedKeys(pj.DevDependencies)...)
}

func projParseComposer(data []byte) []string {
	var cj struct {
		Require    map[string]json.RawMessage `json:"require"`
		RequireDev map[string]json.RawMessage `json:"require-dev"`
	}
	if json.Unmarshal(data, &cj) != nil {
		return nil
	}
	var out []string
	for _, n := range append(projSortedKeys(cj.Require), projSortedKeys(cj.RequireDev)...) {
		if n == "php" || strings.HasPrefix(n, "ext-") || strings.HasPrefix(n, "lib-") {
			continue
		}
		out = append(out, n)
	}
	return out
}

// goModSingle matches a one-line require directive.
var goModSingle = regexp.MustCompile(`^\s*require\s+(\S+)\s+\S+`)

// projParseGoMod lists the modules go.mod requires directly (a requirement
// marked "// indirect" is not direct).
func projParseGoMod(data []byte) []string {
	var out []string
	inBlock := false
	for _, ln := range projLines(data) {
		t := strings.TrimSpace(ln)
		switch {
		case inBlock && strings.HasPrefix(t, ")"):
			inBlock = false
		case inBlock:
			if strings.Contains(t, "// indirect") || t == "" || strings.HasPrefix(t, "//") {
				continue
			}
			if f := strings.Fields(t); len(f) >= 2 {
				out = append(out, f[0])
			}
		case strings.HasPrefix(t, "require") && strings.HasSuffix(strings.TrimSpace(strings.SplitN(t, "//", 2)[0]), "("):
			inBlock = true
		default:
			if m := goModSingle.FindStringSubmatch(t); m != nil && !strings.Contains(t, "// indirect") {
				out = append(out, m[1])
			}
		}
	}
	return out
}

// reqName is the leading package name of a requirements line.
var reqName = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)

func projParseRequirements(data []byte) []string {
	var out []string
	for _, ln := range projLines(data) {
		t := strings.TrimSpace(ln)
		if i := strings.Index(t, " #"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") || strings.Contains(t, "://") {
			continue
		}
		if m := reqName.FindStringSubmatch(t); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// pyQuoted matches one quoted dependency string of a TOML array.
var pyQuoted = regexp.MustCompile(`["']([^"']+)["']`)

// projTOMLSection returns the section name of a "[name]" header line ("" when
// the line is not a header; "[[x]]" arrays of tables read as "x").
func projTOMLSection(t string) (string, bool) {
	if !strings.HasPrefix(t, "[") {
		return "", false
	}
	t = strings.TrimSpace(strings.SplitN(t, "#", 2)[0])
	t = strings.Trim(t, "[]")
	return strings.TrimSpace(t), true
}

// projParsePyproject reads the dependencies of a pyproject.toml: PEP 621's
// project.dependencies array and the Poetry tables.
func projParsePyproject(data []byte) []string {
	var out []string
	section, inArray := "", false
	for _, ln := range projLines(data) {
		t := strings.TrimSpace(ln)
		if s, ok := projTOMLSection(t); ok && !inArray {
			section = s
			continue
		}
		if inArray {
			for _, m := range pyQuoted.FindAllStringSubmatch(t, -1) {
				if r := reqName.FindStringSubmatch(m[1]); r != nil {
					out = append(out, r[1])
				}
			}
			if strings.Contains(t, "]") {
				inArray = false
			}
			continue
		}
		switch {
		case section == "project" && strings.HasPrefix(t, "dependencies"):
			if _, rest, ok := strings.Cut(t, "="); ok {
				rest = strings.TrimSpace(rest)
				for _, m := range pyQuoted.FindAllStringSubmatch(rest, -1) {
					if r := reqName.FindStringSubmatch(m[1]); r != nil {
						out = append(out, r[1])
					}
				}
				inArray = strings.HasPrefix(rest, "[") && !strings.Contains(rest, "]")
			}
		case projPoetryDeps(section):
			if name, _, ok := strings.Cut(t, "="); ok {
				name = strings.TrimSpace(name)
				if name != "" && !strings.HasPrefix(name, "#") && name != "python" && reqName.MatchString(name) {
					out = append(out, name)
				}
			}
		}
	}
	return out
}

// projPoetryDeps reports whether a pyproject section is a Poetry dependency
// table.
func projPoetryDeps(section string) bool {
	if section == "tool.poetry.dependencies" || section == "tool.poetry.dev-dependencies" {
		return true
	}
	return strings.HasPrefix(section, "tool.poetry.group.") && strings.HasSuffix(section, ".dependencies")
}

func projParsePipfile(data []byte) []string {
	var out []string
	section := ""
	for _, ln := range projLines(data) {
		t := strings.TrimSpace(ln)
		if s, ok := projTOMLSection(t); ok {
			section = s
			continue
		}
		if section != "packages" && section != "dev-packages" {
			continue
		}
		if name, _, ok := strings.Cut(t, "="); ok {
			name = strings.Trim(strings.TrimSpace(name), `"'`)
			if reqName.MatchString(name) {
				out = append(out, name)
			}
		}
	}
	return out
}

var gemLine = regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"]`)

func projParseGemfile(data []byte) []string {
	var out []string
	for _, ln := range projLines(data) {
		if m := gemLine.FindStringSubmatch(ln); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

var (
	cargoKey     = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*[.=]`)
	cargoTableOf = regexp.MustCompile(`^(?:workspace\.)?(?:dev-|build-)?dependencies\.([A-Za-z0-9_-]+)$`)
)

// projCargoSection reports whether a Cargo.toml section is a dependency table.
func projCargoSection(s string) bool {
	switch s {
	case "dependencies", "dev-dependencies", "build-dependencies", "workspace.dependencies":
		return true
	}
	return false
}

func projParseCargo(data []byte) []string {
	var out []string
	section := ""
	for _, ln := range projLines(data) {
		t := strings.TrimSpace(ln)
		if s, ok := projTOMLSection(t); ok {
			section = s
			if m := cargoTableOf.FindStringSubmatch(s); m != nil {
				out = append(out, m[1])
				section = ""
			}
			continue
		}
		if !projCargoSection(section) {
			continue
		}
		if m := cargoKey.FindStringSubmatch(t); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

var (
	pomStrip    = regexp.MustCompile(`(?s)<!--.*?-->|<dependencyManagement>.*?</dependencyManagement>|<pluginManagement>.*?</pluginManagement>|<build>.*?</build>`)
	pomDep      = regexp.MustCompile(`(?s)<dependency>(.*?)</dependency>`)
	pomArtifact = regexp.MustCompile(`<artifactId>\s*([^<\s]+)\s*</artifactId>`)
)

// projParsePom lists the artifact ids of a pom.xml's own dependencies (managed
// versions and build plugins are not direct dependencies and are left out).
func projParsePom(data []byte) []string {
	if !utf8.Valid(data) {
		return nil
	}
	body := pomStrip.ReplaceAllString(string(data), "")
	var out []string
	for _, d := range pomDep.FindAllStringSubmatch(body, -1) {
		if m := pomArtifact.FindStringSubmatch(d[1]); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

var gradleDep = regexp.MustCompile(`(?m)^\s*(?:api|implementation|compileOnly|runtimeOnly|compile|annotationProcessor|kapt|developmentOnly|testImplementation|testRuntimeOnly|testCompileOnly)\s*\(?\s*['"][^'":\s]+:([^'":\s]+)(?::[^'"]*)?['"]`)

// projParseGradle lists the artifact ids of a Gradle build's dependencies.
func projParseGradle(data []byte) []string {
	if !utf8.Valid(data) {
		return nil
	}
	var out []string
	for _, m := range gradleDep.FindAllStringSubmatch(string(data), -1) {
		out = append(out, m[1])
	}
	return out
}

// projAISignalRules is the closed list of AI signals other than the two
// dependency roles, by top-level name.
var projAISignalRules = []struct {
	id    string
	names []string // top-level file names
	dirs  []string // top-level directory names
	glob  []string // file name suffixes
}{
	{"agent_file", []string{"AGENTS.md", "CLAUDE.md", "GEMINI.md", ".cursorrules", ".windsurfrules"}, []string{".cursor"}, nil},
	{"prompt_files", nil, []string{"prompts", "prompt"}, []string{".prompt.md", ".prompty"}}, //nolint:misspell // .prompty is the Prompty file format (Microsoft), not "promptly"
	{"mcp_config", []string{".mcp.json", "mcp.json"}, nil, nil},
}

// projAISignalSetsApp is the closed table of every AI signal id and whether it
// makes the project an AI APPLICATION (ProjectFacts.AIApp): one that calls a
// model, gives one tools, or holds the prompts or the tool-server configuration
// of one. A signal that says only that the project was written WITH an AI tool
// (an agent configuration file: CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules,
// .windsurfrules, .cursor/) is still listed, because the agent may use it, but
// does not set AIApp: nearly every repository a developer uses an assistant on
// holds one, and the method step "this project calls a model or gives one
// tools" would then be said of a plain web service. The order is the order the
// ids are listed in.
var projAISignalSetsApp = []struct {
	id  string
	app bool
}{
	{"llm_sdk", true},
	{"mcp_sdk", true},
	{"agent_file", false},
	{"prompt_files", true},
	{"mcp_config", true},
}

// projAIApp reports whether any of the listed signals makes the project an AI
// application. A signal not in projAISignalSetsApp does not (fail closed).
func projAIApp(signals []string) bool {
	for _, row := range projAISignalSetsApp {
		if row.app && slices.Contains(signals, row.id) {
			return true
		}
	}
	return false
}

// projAISignals returns the closed ids of the AI signals the project shows,
// in the order llm_sdk, mcp_sdk, agent_file, prompt_files, mcp_config.
func projAISignals(f *ProjectFacts, names, dirs map[string]bool) []string {
	var out []string
	for _, d := range f.Deps {
		if d.Role == DepRoleLLMSDK {
			out = append(out, "llm_sdk")
		}
	}
	for _, d := range f.Deps {
		if d.Role == DepRoleMCPSDK {
			out = append(out, "mcp_sdk")
		}
	}
	for _, r := range projAISignalRules {
		hit := false
		for _, n := range r.names {
			hit = hit || names[n]
		}
		for _, d := range r.dirs {
			hit = hit || dirs[d]
		}
		for n := range names {
			for _, s := range r.glob {
				hit = hit || strings.HasSuffix(n, s)
			}
		}
		if hit {
			out = append(out, r.id)
		}
	}
	return out
}

// projLockfileNames is the closed list of lock file names.
var projLockfileNames = []string{
	"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "poetry.lock", "Pipfile.lock",
	"Gemfile.lock", "Cargo.lock", "composer.lock", "uv.lock",
}

// projLockfiles returns the lock files among the top-level names.
func projLockfiles(c *projCollector, names []string) []string {
	set := projSet(names)
	var out []string
	for _, l := range projLockfileNames {
		if set[l] && c.keep(l) {
			out = append(out, l)
		}
	}
	return out
}

// projInstalled returns the closed ids of the dependency folders present
// (node_modules, venv, vendor, target), from the existence probes and the
// top-level listing.
func projInstalled(present, dirs map[string]bool) []string {
	var out []string
	for _, id := range []struct {
		id    string
		names []string
	}{
		{"node_modules", []string{"node_modules"}},
		{"venv", []string{".venv", "venv"}},
		{"vendor", []string{"vendor"}},
		{"target", []string{"target"}},
	} {
		for _, n := range id.names {
			if present[n] || dirs[n] {
				out = append(out, id.id)
				break
			}
		}
	}
	return out
}
