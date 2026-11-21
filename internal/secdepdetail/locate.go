package secdepdetail

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Location reasons (Location.Reason): "" when found.
const (
	ReasonNotFound          = "not_found"
	ReasonFileTooLarge      = "file_too_large"
	ReasonUnsupportedFormat = "unsupported_format"
	ReasonUnreadable        = "unreadable"
	ReasonOutsideProject    = "outside_project"
)

// Context window caps.
const (
	// ContextLines is how many lines either side of the entry are shown.
	ContextLines = 3
	// MaxEntryLines caps the entry's own lines shown (a Cargo.lock package
	// with a long dependency list, a composer.lock object).
	MaxEntryLines = 20
	// MaxShownEntryLines caps the entry's lines the drawer shows (the
	// start of a package-lock block names the key, version, resolved URL
	// and integrity; the rest is its dependency list).
	MaxShownEntryLines = 8
	// MaxLineBytes caps one shown line.
	MaxLineBytes = 300
)

// Line is one shown lockfile line (1-based Number); Match marks the
// entry's own lines.
type Line struct {
	Number int
	Text   string
	Match  bool
}

// Location is where the lockfile holds the package.
type Location struct {
	RelPath   string
	Found     bool
	Reason    string
	StartLine int
	EndLine   int
	Context   []Line
}

// span is a located entry: 0-based first and last line.
type span struct{ start, end int }

// locateFunc finds the package's entry in a lockfile's lines.
type locateFunc func(lines []string, pkg Package) (span, bool)

// relateFunc reads what the lockfile says about the entry's relationship.
type relateFunc func(data []byte, lines []string, pkg Package, at span) Relationship

// Relationship is what a lockfile states about a package: direct or
// transitive, runtime or dev, and which entries depend on it. Empty
// fields mean the file does not say.
type Relationship struct {
	Relationship string
	Scope        string
	IntroducedBy []string
}

// Relationship and scope values.
const (
	RelDirect     = "direct"
	RelTransitive = "transitive"
	ScopeRuntime  = "runtime"
	ScopeDev      = "dev"
)

// MaxIntroducedBy caps the dependents listed.
const MaxIntroducedBy = 5

// locatorRow is one lockfile format: the file names it covers and how to
// find (and relate) an entry.
type locatorRow struct {
	format string
	match  func(base string) bool
	locate locateFunc
	relate relateFunc
}

func named(names ...string) func(string) bool {
	return func(base string) bool {
		for _, n := range names {
			if strings.EqualFold(base, n) {
				return true
			}
		}
		return false
	}
}

// locatorRows is the lockfile table, walked top-down by the file's base
// name (case-insensitive); the first match decides. A file no row names
// is unsupported_format: nothing is guessed.
var locatorRows = []locatorRow{
	{"npm", named("package-lock.json", "npm-shrinkwrap.json"), locateNPMLock, relateNPMLock},
	{"yarn", named("yarn.lock"), locateYarnLock, nil},
	{"pnpm", named("pnpm-lock.yaml"), locatePNPMLock, nil},
	{"bun", named("bun.lock"), locateBunLock, nil},
	{"go.mod", named("go.mod"), locateGoMod, relateGoMod},
	{"go.sum", named("go.sum"), locateGoSum, nil},
	{"cargo", named("Cargo.lock"), locateTOMLPackage, nil},
	{"gemfile", named("Gemfile.lock", "gems.locked"), locateGemfileLock, nil},
	{"composer", named("composer.lock"), locateComposerLock, nil},
	{"requirements", func(b string) bool {
		l := strings.ToLower(b)
		return strings.HasPrefix(l, "requirements") && strings.HasSuffix(l, ".txt")
	}, locateRequirements, nil},
	{"poetry", named("poetry.lock"), locateTOMLPackage, nil},
	{"uv", named("uv.lock"), locateTOMLPackage, nil},
	{"pipfile", named("Pipfile.lock"), locatePipfileLock, nil},
	{"pdm", named("pdm.lock"), locateTOMLPackage, nil},
	{"nuget-lock", named("packages.lock.json"), locateNuGetLock, relateNuGetLock},
	{"csproj", func(b string) bool { return strings.HasSuffix(strings.ToLower(b), ".csproj") }, locateCsproj, nil},
	{"packages.config", named("packages.config"), locatePackagesConfig, nil},
	{"maven", named("pom.xml"), locatePom, nil},
	{"gradle", named("gradle.lockfile"), locateGradleLock, nil},
}

// rowFor returns the locator row of a lockfile path.
func rowFor(rel string) (locatorRow, bool) {
	base := path.Base(strings.ReplaceAll(rel, `\`, "/"))
	for _, r := range locatorRows {
		if r.match(base) {
			return r, true
		}
	}
	return locatorRow{}, false
}

// Supported reports whether a lockfile path has a locator row.
func Supported(rel string) bool {
	_, ok := rowFor(rel)
	return ok
}

// splitLines splits file bytes into lines without their "\n" or "\r\n".
func splitLines(data []byte) []string {
	lines := strings.Split(string(data), "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// Locate finds pkg's entry in the lockfile data and returns the location
// (line numbers 1-based, the context window cleaned and capped, each line
// passed through clean when it is not nil) and what the file says about
// the relationship. rel names the format (locatorRows).
func Locate(rel string, data []byte, pkg Package, clean func(string) string) (Location, Relationship) {
	loc := Location{RelPath: rel}
	row, ok := rowFor(rel)
	if !ok {
		loc.Reason = ReasonUnsupportedFormat
		return loc, Relationship{}
	}
	lines := splitLines(data)
	at, ok := row.locate(lines, pkg)
	if !ok {
		loc.Reason = ReasonNotFound
		return loc, Relationship{}
	}
	loc.Found, loc.StartLine, loc.EndLine = true, at.start+1, at.end+1
	shownEnd := at.end
	if shownEnd > at.start+MaxShownEntryLines-1 {
		shownEnd = at.start + MaxShownEntryLines - 1
	}
	from := at.start - ContextLines
	if from < 0 {
		from = 0
	}
	to := shownEnd + ContextLines
	if to > len(lines)-1 {
		to = len(lines) - 1
	}
	for i := from; i <= to; i++ {
		text, _ := capBytes(cleanText(lines[i], false), MaxLineBytes)
		if clean != nil {
			text = clean(text)
		}
		loc.Context = append(loc.Context, Line{Number: i + 1, Text: text, Match: i >= at.start && i <= at.end})
	}
	var rel2 Relationship
	if row.relate != nil {
		rel2 = row.relate(data, lines, pkg, at)
	}
	return loc, rel2
}

// ---- JSON-shaped lockfiles (line-oriented, string-aware brace depth) ----

// depths returns, for each line, the bracket depth before it and after
// it, counting '{' and '[' outside JSON strings (a JSON string never spans
// lines).
func depths(lines []string) (before, after []int) {
	before, after = make([]int, len(lines)), make([]int, len(lines))
	d := 0
	for i, l := range lines {
		before[i] = d
		in, esc := false, false
		for j := 0; j < len(l); j++ {
			c := l[j]
			switch {
			case esc:
				esc = false
			case in && c == '\\':
				esc = true
			case c == '"':
				in = !in
			case in:
			case c == '{' || c == '[':
				d++
			case c == '}' || c == ']':
				d--
			}
		}
		after[i] = d
	}
	return before, after
}

// blockEnd is the last line of the value that opens on line i: the first
// line at or after i whose depth drops back to the depth before i.
func blockEnd(before, after []int, i int) int {
	for k := i; k < len(after); k++ {
		if after[k] <= before[i] {
			return k
		}
	}
	return len(after) - 1
}

// enclosingObject is the object holding line i: the nearest line before i
// that opens to i's depth, through the line that closes it.
func enclosingObject(before, after []int, i int) (span, bool) {
	d := before[i]
	if d <= 0 {
		return span{}, false
	}
	for j := i - 1; j >= 0; j-- {
		if before[j] < d && after[j] >= d {
			for k := i; k < len(after); k++ {
				if after[k] < d {
					return span{j, k}, true
				}
			}
			return span{j, len(after) - 1}, true
		}
	}
	return span{}, false
}

// jsonKey reads a line that starts with a JSON object key: the decoded key
// and the text after the colon.
func jsonKey(line string) (string, string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, `"`) {
		return "", "", false
	}
	esc := false
	for j := 1; j < len(t); j++ {
		switch {
		case esc:
			esc = false
		case t[j] == '\\':
			esc = true
		case t[j] == '"':
			var key string
			if json.Unmarshal([]byte(t[:j+1]), &key) != nil {
				return "", "", false
			}
			rest := strings.TrimSpace(t[j+1:])
			if !strings.HasPrefix(rest, ":") {
				return "", "", false
			}
			return key, strings.TrimSpace(rest[1:]), true
		}
	}
	return "", "", false
}

// jsonStringValue decodes a JSON string value written after a key
// (trailing comma allowed).
func jsonStringValue(rest string) (string, bool) {
	rest = strings.TrimSuffix(strings.TrimSpace(rest), ",")
	var s string
	if json.Unmarshal([]byte(rest), &s) != nil {
		return "", false
	}
	return s, true
}

// keyValueIn reports whether some line in [from, to] at depth d is
// `"key": "<value>"` with accept(value) true.
func keyValueIn(lines []string, before []int, from, to, d int, key string, accept func(string) bool) bool {
	for k := from; k <= to && k < len(lines); k++ {
		if before[k] != d {
			continue
		}
		if kk, rest, ok := jsonKey(lines[k]); ok && kk == key {
			if v, ok := jsonStringValue(rest); ok && accept(v) {
				return true
			}
		}
	}
	return false
}

// jsonKeyedObject finds an object-valued key accepted by keyOK whose
// object holds `"<field>": "<value>"` accepted by valueOK (at the
// object's own depth).
func jsonKeyedObject(lines []string, keyOK func(string) bool, field string, valueOK func(string) bool) (span, bool) {
	before, after := depths(lines)
	for i, l := range lines {
		key, rest, ok := jsonKey(l)
		if !ok || !strings.HasPrefix(rest, "{") || !keyOK(key) {
			continue
		}
		end := blockEnd(before, after, i)
		if end == i {
			// A one-line object: decode it whole.
			var obj map[string]any
			if json.Unmarshal([]byte(strings.TrimSuffix(strings.TrimSpace(rest), ",")), &obj) == nil {
				if v, ok := obj[field].(string); ok && valueOK(v) {
					return span{i, i}, true
				}
			}
			continue
		}
		if keyValueIn(lines, before, i+1, end, before[i]+1, field, valueOK) {
			return span{i, end}, true
		}
	}
	return span{}, false
}

// locateNPMLock finds a package-lock.json / npm-shrinkwrap.json entry: the
// "node_modules/<name>" key (nested "…/node_modules/<name>" too) whose
// block has "version": "<v>" (lockfile v2/v3), else a v1 "<name>" key
// under dependencies with that version.
func locateNPMLock(lines []string, pkg Package) (span, bool) {
	want := func(v string) bool { return v == pkg.Version }
	nm := "node_modules/" + pkg.Name
	if at, ok := jsonKeyedObject(lines, func(k string) bool {
		return k == nm || strings.HasSuffix(k, "/"+nm)
	}, "version", want); ok {
		return at, true
	}
	return jsonKeyedObject(lines, func(k string) bool { return k == pkg.Name }, "version", want)
}

// npmLockfile is the part of a v2/v3 package-lock.json the relationship
// reads.
type npmLockfile struct {
	LockfileVersion int                 `json:"lockfileVersion"`
	Packages        map[string]npmEntry `json:"packages"`
}

type npmEntry struct {
	Version              string            `json:"version"`
	Dev                  bool              `json:"dev"`
	DevOptional          bool              `json:"devOptional"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// npmEntryName is the package name of a packages key
// ("node_modules/a/node_modules/@s/b" -> "@s/b").
func npmEntryName(key string) string {
	if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
		return key[i+len("node_modules/"):]
	}
	return ""
}

// relateNPMLock reads a v2/v3 lockfile's statement about the located
// entry: scope dev when it is "dev" (or "devOptional"), else runtime;
// direct when the root package (packages[""]) declares it, else
// transitive; and the entries whose dependencies name it. A v1 lockfile
// (no packages map) says nothing here.
func relateNPMLock(data []byte, lines []string, pkg Package, at span) Relationship {
	key, _, ok := jsonKey(lines[at.start])
	if !ok || npmEntryName(key) == "" {
		return Relationship{}
	}
	var lf npmLockfile
	if json.Unmarshal(data, &lf) != nil || lf.LockfileVersion < 2 || len(lf.Packages) == 0 {
		return Relationship{}
	}
	e, ok := lf.Packages[key]
	if !ok {
		return Relationship{}
	}
	r := Relationship{Scope: ScopeRuntime, Relationship: RelTransitive}
	if e.Dev || e.DevOptional {
		r.Scope = ScopeDev
	}
	if root, ok := lf.Packages[""]; ok {
		for _, m := range []map[string]string{root.Dependencies, root.DevDependencies, root.OptionalDependencies, root.PeerDependencies} {
			if _, has := m[pkg.Name]; has {
				r.Relationship = RelDirect
			}
		}
	}
	var by []string
	seen := map[string]bool{}
	for k, other := range lf.Packages {
		if k == "" || k == key {
			continue
		}
		if _, has := other.Dependencies[pkg.Name]; !has {
			continue
		}
		name := npmEntryName(k)
		if name == "" || other.Version == "" {
			continue
		}
		id := cleanShort(name+"@"+other.Version, 214)
		if !seen[id] {
			seen[id] = true
			by = append(by, id)
		}
	}
	sort.Strings(by)
	if len(by) > MaxIntroducedBy {
		by = by[:MaxIntroducedBy]
	}
	r.IntroducedBy = by
	return r
}

// locateBunLock finds a bun.lock entry: `["<name>@<version>", …]`.
func locateBunLock(lines []string, pkg Package) (span, bool) {
	needle := `"` + pkg.Name + "@" + pkg.Version + `"`
	before, after := depths(lines)
	for i, l := range lines {
		j := strings.Index(l, needle)
		if j < 0 {
			continue
		}
		if !strings.HasSuffix(strings.TrimSpace(l[:j]), "[") {
			continue
		}
		if after[i] > before[i] {
			return span{i, blockEnd(before, after, i)}, true
		}
		return span{i, i}, true
	}
	return span{}, false
}

// locateComposerLock finds a composer.lock package object: "name" equal
// (case-insensitive) and "version" the version (a "v" prefix allowed).
func locateComposerLock(lines []string, pkg Package) (span, bool) {
	before, after := depths(lines)
	for i, l := range lines {
		key, rest, ok := jsonKey(l)
		if !ok || key != "name" {
			continue
		}
		v, ok := jsonStringValue(rest)
		if !ok || !strings.EqualFold(v, pkg.Name) {
			continue
		}
		obj, ok := enclosingObject(before, after, i)
		if !ok {
			continue
		}
		if keyValueIn(lines, before, obj.start+1, obj.end, before[i], "version", func(s string) bool { return sameVersion(s, pkg.Version) }) {
			return obj, true
		}
	}
	return span{}, false
}

// locatePipfileLock finds a Pipfile.lock entry: the "<name>" key (PEP 503
// normalised) whose object has "version": "==<v>".
func locatePipfileLock(lines []string, pkg Package) (span, bool) {
	want := normalizePEP503(pkg.Name)
	return jsonKeyedObject(lines, func(k string) bool { return normalizePEP503(k) == want }, "version",
		func(v string) bool { return v == "=="+pkg.Version || v == "==="+pkg.Version })
}

// locateNuGetLock finds a packages.lock.json entry: the "<name>" key
// (case-insensitive) whose object has "resolved": "<v>".
func locateNuGetLock(lines []string, pkg Package) (span, bool) {
	return jsonKeyedObject(lines, func(k string) bool { return strings.EqualFold(k, pkg.Name) }, "resolved",
		func(v string) bool { return v == pkg.Version })
}

// relateNuGetLock reads the entry's "type": Direct is direct, Transitive
// and CentralTransitive are transitive; the file states no scope.
func relateNuGetLock(_ []byte, lines []string, _ Package, at span) Relationship {
	before, _ := depths(lines)
	d := before[at.start] + 1
	for k := at.start + 1; k <= at.end && k < len(lines); k++ {
		if before[k] != d {
			continue
		}
		if key, rest, ok := jsonKey(lines[k]); ok && key == "type" {
			v, _ := jsonStringValue(rest)
			switch strings.ToLower(v) {
			case "direct":
				return Relationship{Relationship: RelDirect}
			case "transitive", "centraltransitive":
				return Relationship{Relationship: RelTransitive}
			}
		}
	}
	return Relationship{}
}

// ---- indentation-shaped lockfiles ----

func indentOf(l string) int { return len(l) - len(strings.TrimLeft(l, " \t")) }

// indentedBlockEnd is the last line after i indented deeper than minIndent
// (blank lines inside are kept, trailing ones trimmed).
func indentedBlockEnd(lines []string, i, minIndent int) int {
	end := i
	for k := i + 1; k < len(lines); k++ {
		if strings.TrimSpace(lines[k]) == "" {
			continue
		}
		if indentOf(lines[k]) <= minIndent {
			break
		}
		end = k
	}
	return end
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// yarnSpecName is the package name of a yarn.lock specifier
// ("@s/p@^1", "p@npm:^1" -> "@s/p", "p").
func yarnSpecName(spec string) string {
	spec = strings.Trim(spec, " \"'")
	from := 0
	if strings.HasPrefix(spec, "@") {
		from = 1
	}
	if i := strings.Index(spec[from:], "@"); i >= 0 {
		return spec[:from+i]
	}
	return spec
}

// locateYarnLock finds a yarn.lock entry (classic v1 and berry): an
// unindented header naming the package, whose block's version line is the
// version.
func locateYarnLock(lines []string, pkg Package) (span, bool) {
	for i, l := range lines {
		if l == "" || indentOf(l) > 0 || strings.HasPrefix(l, "#") || !strings.HasSuffix(strings.TrimSpace(l), ":") {
			continue
		}
		header := strings.TrimSuffix(strings.TrimSpace(l), ":")
		hit := false
		for _, spec := range strings.Split(header, ",") {
			if yarnSpecName(spec) == pkg.Name {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		end := indentedBlockEnd(lines, i, 0)
		for k := i + 1; k <= end; k++ {
			t := strings.TrimSpace(lines[k])
			var v string
			switch {
			case strings.HasPrefix(t, "version:"):
				v = unquote(strings.TrimPrefix(t, "version:"))
			case strings.HasPrefix(t, "version "):
				v = unquote(strings.TrimPrefix(t, "version "))
			default:
				continue
			}
			if v == pkg.Version {
				return span{i, end}, true
			}
		}
	}
	return span{}, false
}

// locatePNPMLock finds a pnpm-lock.yaml package key ("/name@v:",
// "name@v:", v5's "/name/v:", a peer suffix "(…)" or "_…" ignored).
func locatePNPMLock(lines []string, pkg Package) (span, bool) {
	at := pkg.Name + "@" + pkg.Version
	slash := pkg.Name + "/" + pkg.Version
	for i, l := range lines {
		if indentOf(l) != 2 || !strings.HasSuffix(strings.TrimSpace(l), ":") {
			continue
		}
		key := unquote(strings.TrimSuffix(strings.TrimSpace(l), ":"))
		key = strings.TrimPrefix(key, "/")
		if j := strings.Index(key, "("); j > 0 {
			key = key[:j]
		}
		if key == at || key == slash || strings.HasPrefix(key, slash+"_") {
			return span{i, indentedBlockEnd(lines, i, 2)}, true
		}
	}
	return span{}, false
}

// locateGemfileLock finds a Gemfile.lock spec line ("    name (v)" or with
// a platform suffix "(v-x86_64-linux)") and its dependency lines.
func locateGemfileLock(lines []string, pkg Package) (span, bool) {
	for i, l := range lines {
		if indentOf(l) != 4 {
			continue
		}
		name, rest, ok := strings.Cut(strings.TrimSpace(l), " (")
		if !ok || name != pkg.Name || !strings.HasSuffix(rest, ")") {
			continue
		}
		v := strings.TrimSuffix(rest, ")")
		if v == pkg.Version || strings.HasPrefix(v, pkg.Version+"-") {
			return span{i, indentedBlockEnd(lines, i, 4)}, true
		}
	}
	return span{}, false
}

// ---- TOML [[package]] lockfiles (Cargo.lock, poetry.lock, uv.lock, pdm.lock) ----

// tomlString reads `key = "value"` (basic or literal string).
func tomlString(line, key string) (string, bool) {
	k, v, ok := strings.Cut(line, "=")
	if !ok || strings.TrimSpace(k) != key {
		return "", false
	}
	v = strings.TrimSpace(v)
	if len(v) < 2 || !(v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		return "", false
	}
	return v[1 : len(v)-1], true
}

// locateTOMLPackage finds a [[package]] table with name (normalised per
// ecosystem) and version: the block runs to the next [[package]] or a
// header that is not one of the package's own sub-tables.
func locateTOMLPackage(lines []string, pkg Package) (span, bool) {
	want := NormalizeName(pkg.Ecosystem, pkg.Name)
	for i, l := range lines {
		if strings.TrimSpace(l) != "[[package]]" {
			continue
		}
		end := i
		var name, ver string
		own := true // still in the table's own keys (before a sub-table)
		for k := i + 1; k < len(lines); k++ {
			t := strings.TrimSpace(lines[k])
			if strings.HasPrefix(t, "[") {
				if t == "[[package]]" || !(strings.HasPrefix(t, "[package.") || strings.HasPrefix(t, "[[package.")) {
					break
				}
				own = false
			}
			if t != "" {
				end = k
			}
			if !own {
				continue
			}
			if v, ok := tomlString(t, "name"); ok {
				name = v
			}
			if v, ok := tomlString(t, "version"); ok {
				ver = v
			}
		}
		if name != "" && NormalizeName(pkg.Ecosystem, name) == want && ver == pkg.Version {
			return span{i, end}, true
		}
	}
	return span{}, false
}

// ---- line-per-entry files ----

// locateGoMod finds the require line of the module at the version.
func locateGoMod(lines []string, pkg Package) (span, bool) {
	inBlock := false
	for i, l := range lines {
		code, _, _ := strings.Cut(l, "//")
		f := strings.Fields(code)
		switch {
		case len(f) >= 2 && f[0] == "require" && f[1] == "(":
			inBlock = true
			continue
		case inBlock && len(f) >= 1 && f[0] == ")":
			inBlock = false
			continue
		case len(f) >= 1 && f[0] == "require":
			f = f[1:]
		case !inBlock:
			continue
		}
		if len(f) >= 2 && f[0] == pkg.Name && sameVersion(f[1], pkg.Version) {
			return span{i, i}, true
		}
	}
	return span{}, false
}

// relateGoMod: a require line marked "// indirect" is transitive, any
// other direct; go.mod states no scope.
func relateGoMod(_ []byte, lines []string, _ Package, at span) Relationship {
	_, comment, _ := strings.Cut(lines[at.start], "//")
	if strings.Contains(comment, "indirect") {
		return Relationship{Relationship: RelTransitive}
	}
	return Relationship{Relationship: RelDirect}
}

// locateGoSum finds the go.sum lines of the module at the version (the
// module hash and its go.mod hash).
func locateGoSum(lines []string, pkg Package) (span, bool) {
	first, last := -1, -1
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] != pkg.Name {
			continue
		}
		v := strings.TrimSuffix(f[1], "/go.mod")
		if !sameVersion(v, pkg.Version) {
			continue
		}
		if first < 0 {
			first = i
		}
		last = i
	}
	if first < 0 {
		return span{}, false
	}
	return span{first, last}, true
}

// requirementName is the distribution name at the start of a
// requirements line.
var requirementName = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$`)

// locateRequirements finds a requirements*.txt pin "name==v" (PEP 503
// name, extras and markers allowed) and its "\" continuation lines (the
// hashes).
func locateRequirements(lines []string, pkg Package) (span, bool) {
	want := normalizePEP503(pkg.Name)
	for i, l := range lines {
		code := l
		if j := strings.Index(code, " #"); j >= 0 {
			code = code[:j]
		}
		t := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(code), `\`))
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "-") {
			continue
		}
		m := requirementName.FindStringSubmatch(t)
		if m == nil || normalizePEP503(m[1]) != want {
			continue
		}
		spec, _, _ := strings.Cut(m[3], ";")
		hit := false
		for _, part := range strings.Split(spec, ",") {
			part = strings.TrimSpace(part)
			// "===" before "==": the first matching operator decides.
			for _, op := range []string{"===", "=="} {
				if v, ok := strings.CutPrefix(part, op); ok {
					hit = hit || strings.TrimSpace(v) == pkg.Version
					break
				}
			}
		}
		if !hit {
			continue
		}
		end := i
		for end < len(lines)-1 && strings.HasSuffix(strings.TrimSpace(lines[end]), `\`) {
			end++
		}
		return span{i, end}, true
	}
	return span{}, false
}

// xmlAttr reads attribute name="value" (case-insensitive name).
var xmlAttr = regexp.MustCompile(`([A-Za-z_:][A-Za-z0-9_.:-]*)\s*=\s*"([^"]*)"`)

func attrs(l string) map[string]string {
	out := map[string]string{}
	for _, m := range xmlAttr.FindAllStringSubmatch(l, -1) {
		out[strings.ToLower(m[1])] = m[2]
	}
	return out
}

// xmlElem reads <tag>text</tag> on one line.
func xmlElem(l, tag string) (string, bool) {
	open, closing := "<"+tag+">", "</"+tag+">"
	i := strings.Index(l, open)
	if i < 0 {
		return "", false
	}
	rest := l[i+len(open):]
	j := strings.Index(rest, closing)
	if j < 0 {
		return "", false
	}
	return strings.TrimSpace(rest[:j]), true
}

// csprojVersionOK accepts a PackageReference version equal to the
// version, or the exact-pin range "[v]".
func csprojVersionOK(v, version string) bool {
	return v == version || v == "["+version+"]"
}

// locateCsproj finds a <PackageReference Include="name"> (or Update=) with
// the version as an attribute or a <Version> child; a reference with no
// version at all (central package management) names the package too.
func locateCsproj(lines []string, pkg Package) (span, bool) {
	for i, l := range lines {
		if !strings.Contains(l, "<PackageReference") {
			continue
		}
		a := attrs(l)
		name := a["include"]
		if name == "" {
			name = a["update"]
		}
		if !strings.EqualFold(name, pkg.Name) {
			continue
		}
		if v, ok := a["version"]; ok {
			if csprojVersionOK(v, pkg.Version) {
				return span{i, i}, true
			}
			continue
		}
		if strings.Contains(l, "/>") {
			return span{i, i}, true
		}
		for k := i + 1; k < len(lines) && k <= i+MaxEntryLines; k++ {
			if v, ok := xmlElem(lines[k], "Version"); ok {
				if csprojVersionOK(v, pkg.Version) {
					return span{i, closingLine(lines, k, "</PackageReference>")}, true
				}
				break
			}
			if strings.Contains(lines[k], "</PackageReference>") {
				return span{i, k}, true
			}
		}
	}
	return span{}, false
}

func closingLine(lines []string, from int, tag string) int {
	for k := from; k < len(lines) && k <= from+MaxEntryLines; k++ {
		if strings.Contains(lines[k], tag) {
			return k
		}
	}
	return from
}

// locatePackagesConfig finds <package id="name" version="v" />.
func locatePackagesConfig(lines []string, pkg Package) (span, bool) {
	for i, l := range lines {
		if !strings.Contains(l, "<package ") {
			continue
		}
		a := attrs(l)
		if strings.EqualFold(a["id"], pkg.Name) && a["version"] == pkg.Version {
			return span{i, i}, true
		}
	}
	return span{}, false
}

// locatePom finds a <dependency> whose groupId:artifactId is the package
// and whose version is the version, a ${property} reference, or absent
// (managed elsewhere).
func locatePom(lines []string, pkg Package) (span, bool) {
	group, artifact, ok := strings.Cut(pkg.Name, ":")
	if !ok {
		return span{}, false
	}
	for i := 0; i < len(lines); i++ {
		if !strings.Contains(lines[i], "<dependency>") {
			continue
		}
		var g, a, v string
		end := -1
		for k := i; k < len(lines) && k <= i+40; k++ {
			if s, ok := xmlElem(lines[k], "groupId"); ok {
				g = s
			}
			if s, ok := xmlElem(lines[k], "artifactId"); ok {
				a = s
			}
			if s, ok := xmlElem(lines[k], "version"); ok {
				v = s
			}
			if strings.Contains(lines[k], "</dependency>") {
				end = k
				break
			}
		}
		if end < 0 {
			continue
		}
		if g == group && a == artifact && (v == "" || v == pkg.Version || strings.HasPrefix(v, "${")) {
			return span{i, end}, true
		}
		i = end
	}
	return span{}, false
}

// locateGradleLock finds "group:artifact:version=configurations".
func locateGradleLock(lines []string, pkg Package) (span, bool) {
	prefix := pkg.Name + ":" + pkg.Version + "="
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), prefix) {
			return span{i, i}, true
		}
	}
	return span{}, false
}
