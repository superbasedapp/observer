package seclang

import "strings"

// Row is one language or file format: its id (the filter value), the
// label the page shows, and what names it, all lower case. A suffix holds
// exactly one dot, its first character (".go", never ".d.ts"); a name is a
// whole base name ("dockerfile", "cmakelists.txt").
type Row struct {
	ID       string
	Label    string
	Suffixes []string
	Names    []string
}

// rows is the language table, in display order. Its two rules (no suffix
// is the tail of another row's suffix, no name ends with another row's
// suffix) keep the SQL filter exact; TestRowsDoNotOverlap holds them.
var rows = []Row{
	// Code.
	{ID: "go", Label: "Go", Suffixes: []string{".go"}, Names: []string{"go.mod", "go.sum", "go.work"}},
	{ID: "typescript", Label: "TypeScript", Suffixes: []string{".ts", ".tsx", ".mts", ".cts"}},
	{ID: "javascript", Label: "JavaScript", Suffixes: []string{".js", ".jsx", ".mjs", ".cjs"}},
	{ID: "python", Label: "Python", Suffixes: []string{".py", ".pyi", ".pyw"}},
	{ID: "jupyter", Label: "Jupyter notebook", Suffixes: []string{".ipynb"}},
	{ID: "java", Label: "Java", Suffixes: []string{".java"}},
	{ID: "kotlin", Label: "Kotlin", Suffixes: []string{".kt", ".kts"}},
	{ID: "scala", Label: "Scala", Suffixes: []string{".scala", ".sc"}},
	{ID: "groovy", Label: "Groovy", Suffixes: []string{".groovy", ".gradle"}, Names: []string{"jenkinsfile"}},
	{ID: "csharp", Label: "C#", Suffixes: []string{".cs", ".csx"}},
	{ID: "fsharp", Label: "F#", Suffixes: []string{".fs", ".fsi", ".fsx"}},
	{ID: "visualbasic", Label: "Visual Basic", Suffixes: []string{".vb"}},
	{ID: "c", Label: "C", Suffixes: []string{".c", ".h"}},
	{ID: "cpp", Label: "C++", Suffixes: []string{".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}},
	{ID: "objectivec", Label: "Objective-C", Suffixes: []string{".m", ".mm"}},
	{ID: "swift", Label: "Swift", Suffixes: []string{".swift"}},
	{ID: "rust", Label: "Rust", Suffixes: []string{".rs"}},
	{ID: "ruby", Label: "Ruby", Suffixes: []string{".rb", ".rake", ".gemspec"}, Names: []string{"gemfile", "rakefile", "podfile", "vagrantfile"}},
	{ID: "php", Label: "PHP", Suffixes: []string{".php", ".phtml"}},
	{ID: "dart", Label: "Dart", Suffixes: []string{".dart"}},
	{ID: "elixir", Label: "Elixir", Suffixes: []string{".ex", ".exs"}},
	{ID: "erlang", Label: "Erlang", Suffixes: []string{".erl", ".hrl"}},
	{ID: "haskell", Label: "Haskell", Suffixes: []string{".hs", ".lhs"}},
	{ID: "ocaml", Label: "OCaml", Suffixes: []string{".ml", ".mli"}},
	{ID: "clojure", Label: "Clojure", Suffixes: []string{".clj", ".cljs", ".cljc"}},
	{ID: "lua", Label: "Lua", Suffixes: []string{".lua"}},
	{ID: "perl", Label: "Perl", Suffixes: []string{".pl", ".pm"}},
	{ID: "r", Label: "R", Suffixes: []string{".r"}},
	{ID: "julia", Label: "Julia", Suffixes: []string{".jl"}},
	{ID: "zig", Label: "Zig", Suffixes: []string{".zig"}},
	{ID: "solidity", Label: "Solidity", Suffixes: []string{".sol"}},
	{ID: "sql", Label: "SQL", Suffixes: []string{".sql"}},
	{ID: "html", Label: "HTML", Suffixes: []string{".html", ".htm"}},
	{ID: "css", Label: "CSS", Suffixes: []string{".css", ".scss", ".sass", ".less"}},
	{ID: "vue", Label: "Vue", Suffixes: []string{".vue"}},
	{ID: "svelte", Label: "Svelte", Suffixes: []string{".svelte"}},
	// Scripts.
	{ID: "shell", Label: "Shell", Suffixes: []string{".sh", ".bash", ".zsh", ".ksh", ".fish"}, Names: []string{".bashrc", ".zshrc", ".profile", ".bash_profile"}},
	{ID: "powershell", Label: "PowerShell", Suffixes: []string{".ps1", ".psm1", ".psd1"}},
	{ID: "batch", Label: "Batch", Suffixes: []string{".bat", ".cmd"}},
	// Config and infrastructure formats.
	{ID: "yaml", Label: "YAML", Suffixes: []string{".yml", ".yaml"}},
	{ID: "json", Label: "JSON", Suffixes: []string{".json", ".jsonc", ".json5"}},
	{ID: "toml", Label: "TOML", Suffixes: []string{".toml"}},
	{ID: "xml", Label: "XML", Suffixes: []string{".xml", ".xsd", ".xsl", ".xslt", ".csproj", ".fsproj", ".vbproj", ".props", ".targets", ".plist"}},
	{ID: "ini", Label: "INI", Suffixes: []string{".ini", ".cfg"}},
	{ID: "properties", Label: "Java properties", Suffixes: []string{".properties"}},
	{ID: "dotenv", Label: "Environment file", Suffixes: []string{".env"}, Names: []string{".env.local", ".env.development", ".env.production", ".env.test", ".env.example"}},
	{ID: "terraform", Label: "Terraform / HCL", Suffixes: []string{".tf", ".tfvars", ".hcl"}},
	{ID: "bicep", Label: "Bicep", Suffixes: []string{".bicep"}},
	{ID: "dockerfile", Label: "Dockerfile", Suffixes: []string{".dockerfile"}, Names: []string{"dockerfile", "containerfile"}},
	{ID: "makefile", Label: "Makefile", Suffixes: []string{".mk"}, Names: []string{"makefile", "gnumakefile"}},
	{ID: "cmake", Label: "CMake", Suffixes: []string{".cmake"}, Names: []string{"cmakelists.txt"}},
	{ID: "starlark", Label: "Starlark (Bazel)", Suffixes: []string{".bzl", ".bazel", ".star"}},
	{ID: "nix", Label: "Nix", Suffixes: []string{".nix"}},
	{ID: "protobuf", Label: "Protocol Buffers", Suffixes: []string{".proto"}},
	{ID: "graphql", Label: "GraphQL", Suffixes: []string{".graphql", ".gql"}},
	// Docs.
	{ID: "markdown", Label: "Markdown", Suffixes: []string{".md", ".markdown", ".mdx"}},
}

// The lookups Language reads, built once from rows.
var (
	bySuffix = map[string]string{}
	byName   = map[string]string{}
	byID     = map[string]int{}
)

func init() {
	for i, r := range rows {
		byID[r.ID] = i
		for _, s := range r.Suffixes {
			bySuffix[s] = r.ID
		}
		for _, n := range r.Names {
			byName[n] = r.ID
		}
	}
}

// Fold lower-cases the ASCII letters of s and leaves every other byte as
// it is: the folding SQLite's lower() applies, so a match made in Go and
// one made in SQL agree on every path.
func Fold(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if b[j] >= 'A' && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// Language returns the language id of a file, "" when no row names it. The
// path may use either separator; the base name decides, by exact name
// first, then by its last suffix (case-insensitive, ASCII only).
func Language(relPath string) string {
	p := Fold(relPath)
	base := p[strings.LastIndexAny(p, `/\`)+1:]
	if base == "" {
		return ""
	}
	if id, ok := byName[base]; ok {
		return id
	}
	if dot := strings.LastIndexByte(base, '.'); dot >= 0 {
		return bySuffix[base[dot:]]
	}
	return ""
}

// Label returns a language id's label, "" for an unknown id.
func Label(id string) string {
	if i, ok := byID[id]; ok {
		return rows[i].Label
	}
	return ""
}

// Patterns returns what names a language id: its suffixes and base names,
// lower case (the SQL filter's patterns); ok is false for an unknown id.
func Patterns(id string) (suffixes, names []string, ok bool) {
	i, ok := byID[id]
	if !ok {
		return nil, nil, false
	}
	return append([]string(nil), rows[i].Suffixes...), append([]string(nil), rows[i].Names...), true
}

// Rows returns the table, in display order (copies: a caller cannot edit
// the table).
func Rows() []Row {
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		out = append(out, Row{ID: r.ID, Label: r.Label, Suffixes: append([]string(nil), r.Suffixes...), Names: append([]string(nil), r.Names...)})
	}
	return out
}
