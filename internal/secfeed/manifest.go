package secfeed

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

// manifest.go reads the dependencies a manifest edit adds (S-747, security
// plan section 5.4: "manifest edits that add a dependency are checked after
// the write"). It reads the text an edit adds, line by line, against the
// manifest's own shape; a whole package.json or composer.json is parsed as
// JSON. It is a best-effort reader, not a resolver: what it misses is still
// seen by the commit gate, the dependency scan and CI.

// manifestReader is one row of the manifest table.
type manifestReader struct {
	match func(base string) bool
	eco   Ecosystem
	read  func(text string) []string
}

var (
	jsonDepLine  = regexp.MustCompile(`^\s*"(@?[A-Za-z0-9][A-Za-z0-9._~/-]*)"\s*:\s*"([^"]*)"`)
	tomlDepLine  = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)\s*=\s*(?:"([^"]*)"|\{)`)
	pyQuotedDep  = regexp.MustCompile(`^\s*"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;][^"]*)?",?\s*$`)
	goModLine    = regexp.MustCompile(`^\s*(?:require\s+)?([a-zA-Z0-9][a-zA-Z0-9._~-]*\.[a-zA-Z0-9._~/-]+)\s+(v[0-9][^\s]*)`)
	gemLine      = regexp.MustCompile(`^\s*gem\s+["']([A-Za-z0-9][A-Za-z0-9._-]*)["']`)
	csprojLine   = regexp.MustCompile(`<PackageReference\s+[^>]*Include\s*=\s*"([A-Za-z0-9_][A-Za-z0-9_.-]*)"`)
	versionShape = regexp.MustCompile(`^(?:[\^~<>=*]|[0-9]|v[0-9]|latest$|next$|npm:|workspace:|x$)`)
)

// jsonTopLevelKeys are package.json and composer.json fields that look like
// a dependency line but are not one.
var jsonTopLevelKeys = set("name", "version", "description", "main", "module", "types", "typings", "license", "type",
	"author", "homepage", "private", "packageManager", "node", "npm", "pnpm", "yarn", "minimum-stability", "php")

// tomlNonDeps are Cargo and Poetry keys that are not dependencies.
var tomlNonDeps = set("name", "version", "edition", "description", "license", "authors", "readme", "repository",
	"homepage", "documentation", "rust-version", "python", "requires-python", "build-backend", "resolver", "publish",
	"keywords", "categories", "include", "exclude", "workspace", "default-run", "autobins", "links", "requires")

var manifestTable = []manifestReader{
	{match: eq("package.json"), eco: EcoNpm, read: jsonDeps([]string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"})},
	{match: eq("composer.json"), eco: EcoPackagist, read: jsonDeps([]string{"require", "require-dev"})},
	{match: func(b string) bool {
		return strings.HasSuffix(b, ".txt") && (strings.HasPrefix(b, "requirements") || strings.HasPrefix(b, "constraints"))
	}, eco: EcoPyPI, read: requirementsDeps},
	{match: eq("pyproject.toml"), eco: EcoPyPI, read: pyprojectDeps},
	{match: eq("Pipfile"), eco: EcoPyPI, read: tomlDeps},
	{match: eq("Cargo.toml"), eco: EcoCargo, read: tomlDeps},
	{match: eq("go.mod"), eco: EcoGo, read: lineDeps(goModLine)},
	{match: eq("Gemfile"), eco: EcoRubyGems, read: lineDeps(gemLine)},
	{match: func(b string) bool { return strings.HasSuffix(b, ".csproj") || b == "Directory.Packages.props" }, eco: EcoNuGet, read: lineDeps(csprojLine)},
}

func eq(name string) func(string) bool { return func(b string) bool { return b == name } }

// IsManifest reports whether a path is a manifest the reader knows, and its
// ecosystem.
func IsManifest(p string) (Ecosystem, bool) {
	base := path.Base(strings.ReplaceAll(p, "\\", "/"))
	for _, r := range manifestTable {
		if r.match(base) {
			return r.eco, true
		}
	}
	return "", false
}

// ManifestAdditions returns the dependencies newText names that oldText
// does not, for a manifest at p (nil for any other file).
func ManifestAdditions(p, oldText, newText string) []InstallSpec {
	base := path.Base(strings.ReplaceAll(p, "\\", "/"))
	for _, r := range manifestTable {
		if !r.match(base) {
			continue
		}
		before := map[string]bool{}
		for _, n := range r.read(oldText) {
			before[Normalize(r.eco, ParseSpec(r.eco, n).Name)] = true
		}
		var out []InstallSpec
		seen := map[string]bool{}
		for _, n := range r.read(newText) {
			s := ParseSpec(r.eco, n)
			k := Normalize(r.eco, s.Name)
			if s.Invalid || before[k] || seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, s)
			if len(out) >= MaxParsedInstallSpecs {
				break
			}
		}
		return out
	}
	return nil
}

// jsonDeps reads a whole JSON document's dependency objects, or falls back
// to dependency-shaped lines for a fragment.
func jsonDeps(sections []string) func(string) []string {
	return func(text string) []string {
		var doc map[string]json.RawMessage
		if json.Unmarshal([]byte(text), &doc) == nil {
			var out []string
			for _, s := range sections {
				var deps map[string]any
				if raw, ok := doc[s]; ok && json.Unmarshal(raw, &deps) == nil {
					for n := range deps {
						out = append(out, n)
					}
				}
			}
			return out
		}
		var out []string
		for _, line := range strings.Split(text, "\n") {
			m := jsonDepLine.FindStringSubmatch(line)
			if m == nil || jsonTopLevelKeys[m[1]] || !versionShape.MatchString(m[2]) {
				continue
			}
			out = append(out, m[1])
		}
		return out
	}
}

func requirementsDeps(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if i := strings.Index(t, " #"); i >= 0 {
			t = strings.TrimSpace(t[:i])
		}
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") {
			continue
		}
		out = append(out, t)
	}
	return out
}

func pyprojectDeps(text string) []string {
	out := tomlDeps(text)
	for _, line := range strings.Split(text, "\n") {
		if m := pyQuotedDep.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

func tomlDeps(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		m := tomlDepLine.FindStringSubmatch(line)
		if m == nil || tomlNonDeps[m[1]] {
			continue
		}
		if !strings.Contains(line, "{") && !versionShape.MatchString(m[2]) {
			continue
		}
		out = append(out, m[1])
	}
	return out
}

func lineDeps(re *regexp.Regexp) func(string) []string {
	return func(text string) []string {
		var out []string
		for _, line := range strings.Split(text, "\n") {
			if m := re.FindStringSubmatch(line); m != nil {
				out = append(out, m[1])
			}
		}
		return out
	}
}
