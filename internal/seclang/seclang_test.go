package seclang

import (
	"strings"
	"testing"
)

// TestLanguage is one case per table row (by suffix, and by name where the
// row has names), plus the unknown and edge cases.
func TestLanguage(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"cmd/main.go", "go"},
		{"go.mod", "go"},
		{"web/src/App.tsx", "typescript"},
		{"src/index.mjs", "javascript"},
		{"tools/run.py", "python"},
		{"notebooks/a.ipynb", "jupyter"},
		{"src/Main.java", "java"},
		{"build.gradle.kts", "kotlin"},
		{"src/App.scala", "scala"},
		{"build.gradle", "groovy"},
		{"ci/Jenkinsfile", "groovy"},
		{"src/Program.cs", "csharp"},
		{"src/Lib.fs", "fsharp"},
		{"src/Module.vb", "visualbasic"},
		{"src/util.h", "c"},
		{"src/util.cpp", "cpp"},
		{"src/View.mm", "objectivec"},
		{"Sources/App.swift", "swift"},
		{"src/lib.rs", "rust"},
		{"Gemfile", "ruby"},
		{"lib/task.rake", "ruby"},
		{"public/index.php", "php"},
		{"lib/main.dart", "dart"},
		{"lib/app.ex", "elixir"},
		{"src/app.erl", "erlang"},
		{"src/Main.hs", "haskell"},
		{"bin/main.ml", "ocaml"},
		{"src/core.clj", "clojure"},
		{"init.lua", "lua"},
		{"script.pl", "perl"},
		{"R/analysis.R", "r"},
		{"src/Pkg.jl", "julia"},
		{"src/main.zig", "zig"},
		{"contracts/Token.sol", "solidity"},
		{"db/schema.sql", "sql"},
		{"site/index.html", "html"},
		{"styles/app.scss", "css"},
		{"src/App.vue", "vue"},
		{"src/App.svelte", "svelte"},
		{"scripts/deploy.sh", "shell"},
		{"home/.bashrc", "shell"},
		{"scripts/setup.ps1", "powershell"},
		{"build.cmd", "batch"},
		{".github/workflows/ci.yml", "yaml"},
		{"package.json", "json"},
		{"Cargo.toml", "toml"},
		{"src/App.csproj", "xml"},
		{"setup.cfg", "ini"},
		{"src/main/resources/app.properties", "properties"},
		{".env", "dotenv"},
		{"config/prod.env", "dotenv"},
		{".env.local", "dotenv"},
		{"infra/main.tf", "terraform"},
		{"infra/main.bicep", "bicep"},
		{"Dockerfile", "dockerfile"},
		{"deploy/app.Dockerfile", "dockerfile"},
		{"Containerfile", "dockerfile"},
		{"Makefile", "makefile"},
		{"rules.mk", "makefile"},
		{"CMakeLists.txt", "cmake"},
		{"BUILD.bazel", "starlark"},
		{"flake.nix", "nix"},
		{"api/service.proto", "protobuf"},
		{"schema.graphql", "graphql"},
		{"README.md", "markdown"},
		// Separators, case and the unknown.
		{`src\win\Main.GO`, "go"},
		{`deploy\Dockerfile`, "dockerfile"},
		{"MAKEFILE", "makefile"},
		{"notes.txt", ""},
		{"LICENSE", ""},
		{"", ""},
		{"dir/", ""},
		{"archive.tar.gz", ""},
		// A name only matches the whole base name.
		{"mydockerfile", ""},
		{"Dockerfile.dev", ""},
	}
	for _, c := range cases {
		if got := Language(c.path); got != c.want {
			t.Errorf("Language(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// TestEveryRowIsReachable: every suffix and name of every row reads as
// that row (a row nothing can name is a dead row), and every row has its
// label.
func TestEveryRowIsReachable(t *testing.T) {
	for _, r := range Rows() {
		if len(r.Suffixes) == 0 && len(r.Names) == 0 {
			t.Errorf("row %s names nothing", r.ID)
			continue
		}
		for _, s := range r.Suffixes {
			if got := Language("x" + s); got != r.ID {
				t.Errorf("suffix %s of %s reads %q", s, r.ID, got)
			}
		}
		for _, n := range r.Names {
			if got := Language("dir/" + n); got != r.ID {
				t.Errorf("name %s of %s reads %q", n, r.ID, got)
			}
		}
		if Label(r.ID) == "" || Label(r.ID) != r.Label {
			t.Errorf("label of %s: %q", r.ID, Label(r.ID))
		}
	}
	if Label("nope") != "" {
		t.Fatal("an unknown id has a label")
	}
	if _, _, ok := Patterns("nope"); ok {
		t.Fatal("an unknown id has patterns")
	}
}

// TestRowsDoNotOverlap holds the two table rules that make the SQL filter
// (each row's own patterns, OR'd) select exactly the paths Language names
// that row: every pattern is lower case, a suffix is one leading dot and no
// other, no suffix or name is listed twice, and no name ends with another
// row's suffix.
func TestRowsDoNotOverlap(t *testing.T) {
	seenID := map[string]bool{}
	suffixOf := map[string]string{}
	nameOf := map[string]string{}
	for _, r := range Rows() {
		if r.ID == "" || r.ID != Fold(r.ID) || seenID[r.ID] {
			t.Errorf("bad or repeated id %q", r.ID)
		}
		seenID[r.ID] = true
		for _, s := range r.Suffixes {
			if s != Fold(s) || !strings.HasPrefix(s, ".") || strings.Count(s, ".") != 1 || len(s) < 2 || strings.ContainsAny(s, `/\%_`) {
				t.Errorf("suffix %q of %s: one leading dot, lower case, no separator or LIKE wildcard", s, r.ID)
			}
			if prev, ok := suffixOf[s]; ok {
				t.Errorf("suffix %q in %s and %s", s, prev, r.ID)
			}
			suffixOf[s] = r.ID
		}
		for _, n := range r.Names {
			if n != Fold(n) || n == "" || strings.ContainsAny(n, `/\%`) {
				t.Errorf("name %q of %s: lower case, no separator, no %%", n, r.ID)
			}
			if prev, ok := nameOf[n]; ok {
				t.Errorf("name %q in %s and %s", n, prev, r.ID)
			}
			nameOf[n] = r.ID
		}
	}
	for n, nid := range nameOf {
		for s, sid := range suffixOf {
			if sid != nid && strings.HasSuffix(n, s) {
				t.Errorf("name %q (%s) ends with suffix %q (%s): the SQL filter of %s would select it", n, nid, s, sid, sid)
			}
		}
	}
}

// TestFoldIsASCIIOnly: Fold is SQLite's lower(): ASCII letters only, so
// the Go label and the SQL filter fold the same bytes.
func TestFoldIsASCIIOnly(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ABC.Go", "abc.go"},
		{"already", "already"},
		{"ÄÖ.GO", "ÄÖ.go"},
		{"K", "K"}, // the Kelvin sign: strings.ToLower would fold it to "k"
		{"", ""},
	}
	for _, c := range cases {
		if got := Fold(c.in); got != c.want {
			t.Errorf("Fold(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRowsAreCopies: a caller editing Rows() or Patterns() cannot change
// the table.
func TestRowsAreCopies(t *testing.T) {
	r := Rows()
	r[0].Suffixes[0] = ".changed"
	s, _, _ := Patterns(r[0].ID)
	s[0] = ".changed"
	if Language("x.go") != "go" {
		t.Fatal("the table was edited through a copy")
	}
	if again, _, _ := Patterns("go"); again[0] != ".go" {
		t.Fatalf("patterns: %v", again)
	}
}
