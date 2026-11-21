package secreach

import "strings"

// keyRule is one row of a language's import-specifier table: the first row
// whose When holds decides the specifier (Key returns the import key, ok
// false for a specifier that names no package: a relative path, a
// builtin, a local module).
type keyRule struct {
	Name string
	When func(spec string) bool
	Key  func(spec string) (string, bool)
}

func skipSpec(string) (string, bool) { return "", false }

// jsKeyRules maps a JavaScript or TypeScript import specifier (an ESM
// import, a require() argument, a dynamic import() where the index records
// it) to its npm package name, walked top-down (one test case per row).
var jsKeyRules = []keyRule{
	{Name: "empty or a loader chain", When: func(s string) bool { return s == "" || strings.Contains(s, "!") }, Key: skipSpec},
	{Name: "relative path", When: func(s string) bool {
		return s == "." || s == ".." || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../")
	}, Key: skipSpec},
	{Name: "absolute path", When: func(s string) bool { return strings.HasPrefix(s, "/") || strings.HasPrefix(s, `\`) }, Key: skipSpec},
	{Name: "package.json subpath import", When: func(s string) bool { return strings.HasPrefix(s, "#") }, Key: skipSpec},
	{Name: "npm: specifier", When: func(s string) bool { return strings.HasPrefix(s, "npm:") }, Key: func(s string) (string, bool) {
		return npmPackageOf(stripNPMVersion(strings.TrimPrefix(s, "npm:")))
	}},
	{Name: "node: builtin or another scheme", When: hasScheme, Key: skipSpec},
	{Name: "scoped or bare package", When: func(string) bool { return true }, Key: npmPackageOf},
}

// hasScheme reports a "scheme:" prefix (node:, http:, file:, data:, jsr:, a
// Windows drive letter).
func hasScheme(s string) bool {
	i := strings.IndexByte(s, ':')
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := s[j]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// stripNPMVersion drops the "@range" of an "npm:name@range/sub" specifier.
func stripNPMVersion(s string) string {
	start := 0
	if strings.HasPrefix(s, "@") {
		start = 1
	}
	at := strings.IndexByte(s[start:], '@')
	if at < 0 {
		return s
	}
	at += start
	rest := s[at:]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		return s[:at] + rest[slash:]
	}
	return s[:at]
}

// npmPackageOf returns the package of a bare specifier: "@scope/name" of
// "@scope/name/sub", "name" of "name/sub"; a query ("?raw") is dropped.
func npmPackageOf(s string) (string, bool) {
	if i := strings.IndexByte(s, '?'); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, "/")
	if strings.HasPrefix(s, "@") {
		if len(parts) < 2 || !npmNamePart(parts[0][1:]) || !npmNamePart(parts[1]) {
			return "", false
		}
		return parts[0] + "/" + parts[1], true
	}
	if !npmNamePart(parts[0]) {
		return "", false
	}
	return parts[0], true
}

// npmNamePart reports a valid npm name or scope: URL-safe characters
// (letters, digits, '-', '.', '_', '~'), not starting with '.', '_' or
// '~', at most 214 bytes. Upper case is kept (legacy names have it).
func npmNamePart(s string) bool {
	if s == "" || len(s) > 214 || s[0] == '.' || s[0] == '_' || s[0] == '~' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	return true
}

// pythonKeyRules maps a Python import (the module of "import a.b" or
// "from a.b import c", as the index records it) to its dotted module path.
var pythonKeyRules = []keyRule{
	{Name: "relative import", When: func(s string) bool { return strings.HasPrefix(s, ".") }, Key: skipSpec},
	{Name: "__future__", When: func(s string) bool { return s == "__future__" }, Key: skipSpec},
	{Name: "dotted module path", When: func(string) bool { return true }, Key: func(s string) (string, bool) {
		for _, seg := range strings.Split(s, ".") {
			if !identifier(seg) {
				return "", false
			}
		}
		return s, true
	}},
}

// rustLocalRoots are the path roots of a use declaration that name no
// crate of the dependency graph (the crate itself, its modules, and the
// sysroot crates).
var rustLocalRoots = map[string]bool{
	"crate": true, "self": true, "super": true, "Self": true,
	"std": true, "core": true, "alloc": true, "proc_macro": true, "test": true,
}

// rustKeyRules maps a Rust use path ("serde::Deserialize", "::tokio::io",
// a bare "tokio", an extern crate name) to its crate key.
var rustKeyRules = []keyRule{
	{Name: "empty", When: func(s string) bool { return strings.TrimLeft(s, ":") == "" }, Key: skipSpec},
	{Name: "crate root", When: func(string) bool { return true }, Key: func(s string) (string, bool) {
		first, _, _ := strings.Cut(strings.TrimPrefix(s, "::"), "::")
		first = strings.TrimPrefix(strings.TrimSpace(first), "r#")
		if !identifier(first) || rustLocalRoots[first] {
			return "", false
		}
		return CrateKey(first), true
	}},
}

// goKeyRules keeps a Go import path as written.
var goKeyRules = []keyRule{
	{Name: "import path", When: func(string) bool { return true }, Key: func(s string) (string, bool) { return s, s != "" }},
}

// keyRulesByLang is the specifier table of each language.
var keyRulesByLang = map[string][]keyRule{
	LangGo:     goKeyRules,
	LangJS:     jsKeyRules,
	LangPython: pythonKeyRules,
	LangRust:   rustKeyRules,
}

// ImportKey is the import key a specifier of lang contributes to an
// ImportSet (an npm package, a Python module path, a Rust crate), ok false
// when it names no dependency or lang has no table.
func ImportKey(lang, spec string) (string, bool) {
	for _, r := range keyRulesByLang[lang] {
		if r.When(spec) {
			return r.Key(spec)
		}
	}
	return "", false
}

// CrateKey is a crate name's comparable form: lower case, '-' as '_'
// (Cargo maps a package's dashes to underscores in code).
func CrateKey(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "-", "_")
}

// identifier reports an ASCII identifier ([A-Za-z_][A-Za-z0-9_]*).
func identifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// testFileRow says which project files of a language are test files: a
// base name with one of Suffixes, Prefixes or Infixes, a base name in
// Bases, or a directory element in Dirs.
type testFileRow struct {
	Lang     string
	Suffixes []string
	Prefixes []string
	Infixes  []string
	Bases    []string
	Dirs     []string
}

// testFileRows is the test-file table (one test case per row). A "tests
// only" label rests on it; it is a naming convention, not a build fact.
var testFileRows = []testFileRow{
	{Lang: LangGo, Suffixes: []string{"_test.go"}},
	{Lang: LangJS, Infixes: []string{".test.", ".spec."}, Dirs: []string{"__tests__", "__mocks__", "test", "tests"}},
	{Lang: LangPython, Prefixes: []string{"test_"}, Suffixes: []string{"_test.py"}, Bases: []string{"conftest.py"}, Dirs: []string{"test", "tests"}},
	{Lang: LangRust, Bases: []string{"tests.rs"}, Dirs: []string{"tests", "benches"}},
}

// IsTestFile reports whether a project-relative file (slash form) of lang
// is a test file by testFileRows.
func IsTestFile(lang, rel string) bool {
	dir, base := "", rel
	if i := strings.LastIndexByte(rel, '/'); i >= 0 {
		dir, base = rel[:i], rel[i+1:]
	}
	for _, row := range testFileRows {
		if row.Lang != lang {
			continue
		}
		for _, s := range row.Suffixes {
			if strings.HasSuffix(base, s) {
				return true
			}
		}
		for _, p := range row.Prefixes {
			if strings.HasPrefix(base, p) {
				return true
			}
		}
		for _, in := range row.Infixes {
			if strings.Contains(base, in) {
				return true
			}
		}
		for _, b := range row.Bases {
			if base == b {
				return true
			}
		}
		if dir != "" {
			for _, seg := range strings.Split(dir, "/") {
				for _, d := range row.Dirs {
					if seg == d {
						return true
					}
				}
			}
		}
	}
	return false
}
