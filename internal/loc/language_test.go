package loc

import "testing"

// TestLanguage is the row-per-case table for the extension and basename
// tables (CLAUDE.md rule #5).
func TestLanguage(t *testing.T) {
	cases := []struct {
		name string
		path string
		lang Lang
		cat  Category
	}{
		// --- separators ---------------------------------------------
		{"posix path", "/home/u/proj/main.go", LangGo, CategoryCode},
		{"windows path", `C:\programsx\proj\main.go`, LangGo, CategoryCode},
		{"windows path mixed", `C:\programsx\proj/sub\a.py`, LangPython, CategoryCode},
		{"bare basename", "main.go", LangGo, CategoryCode},
		{"empty path", "", LangUnknown, CategoryUnknown},
		{"uppercase extension", "SRC/Main.GO", LangGo, CategoryCode},

		// --- code extensions ----------------------------------------
		{"c source", "a/b.c", LangC, CategoryCode},
		{"c header", "a/b.h", LangC, CategoryCode},
		{"cpp cc", "a/b.cc", LangCPP, CategoryCode},
		{"cpp cpp", "a/b.cpp", LangCPP, CategoryCode},
		{"cpp cxx", "a/b.cxx", LangCPP, CategoryCode},
		{"cpp hpp", "a/b.hpp", LangCPP, CategoryCode},
		{"cpp hh", "a/b.hh", LangCPP, CategoryCode},
		{"csharp", "a/b.cs", LangCSharp, CategoryCode},
		{"java", "a/b.java", LangJava, CategoryCode},
		{"kotlin kt", "a/b.kt", LangKotlin, CategoryCode},
		{"kotlin kts", "a/b.kts", LangKotlin, CategoryCode},
		{"swift", "a/b.swift", LangSwift, CategoryCode},
		{"rust", "a/b.rs", LangRust, CategoryCode},
		{"js", "a/b.js", LangJavaScript, CategoryCode},
		{"mjs", "a/b.mjs", LangJavaScript, CategoryCode},
		{"cjs", "a/b.cjs", LangJavaScript, CategoryCode},
		{"ts", "a/b.ts", LangTypeScript, CategoryCode},
		{"mts", "a/b.mts", LangTypeScript, CategoryCode},
		{"cts", "a/b.cts", LangTypeScript, CategoryCode},
		{"jsx", "a/b.jsx", LangJSX, CategoryCode},
		{"tsx", "a/b.tsx", LangTSX, CategoryCode},
		{"python", "a/b.py", LangPython, CategoryCode},
		{"python stub", "a/b.pyi", LangPython, CategoryCode},
		{"ruby", "a/b.rb", LangRuby, CategoryCode},
		{"php", "a/b.php", LangPHP, CategoryCode},
		{"perl pl", "a/b.pl", LangPerl, CategoryCode},
		{"perl pm", "a/b.pm", LangPerl, CategoryCode},
		{"shell sh", "a/b.sh", LangShell, CategoryCode},
		{"shell bash", "a/b.bash", LangShell, CategoryCode},
		{"shell zsh", "a/b.zsh", LangShell, CategoryCode},
		{"shell ksh", "a/b.ksh", LangShell, CategoryCode},
		{"powershell ps1", "a/b.ps1", LangPowerShell, CategoryCode},
		{"powershell psm1", "a/b.psm1", LangPowerShell, CategoryCode},
		{"lua", "a/b.lua", LangLua, CategoryCode},
		{"sql", "a/b.sql", LangSQL, CategoryCode},
		{"html", "a/b.html", LangHTML, CategoryCode},
		{"htm", "a/b.htm", LangHTML, CategoryCode},
		{"xml", "a/b.xml", LangXML, CategoryCode},
		{"xsd", "a/b.xsd", LangXML, CategoryCode},
		{"xsl", "a/b.xsl", LangXML, CategoryCode},
		{"css", "a/b.css", LangCSS, CategoryCode},
		{"scss", "a/b.scss", LangSCSS, CategoryCode},
		{"sass", "a/b.sass", LangSCSS, CategoryCode},
		{"less maps to scss", "a/b.less", LangSCSS, CategoryCode},
		{"proto", "a/b.proto", LangProto, CategoryCode},
		{"graphql", "a/b.graphql", LangGraphQL, CategoryCode},
		{"gql", "a/b.gql", LangGraphQL, CategoryCode},
		{"vue", "a/b.vue", LangVue, CategoryCode},
		{"svelte", "a/b.svelte", LangSvelte, CategoryCode},
		{"dart", "a/b.dart", LangDart, CategoryCode},
		{"scala", "a/b.scala", LangScala, CategoryCode},
		{"sbt", "a/b.sbt", LangScala, CategoryCode},
		{"elixir ex", "a/b.ex", LangElixir, CategoryCode},
		{"elixir exs", "a/b.exs", LangElixir, CategoryCode},
		{"haskell", "a/b.hs", LangHaskell, CategoryCode},
		{"r", "a/b.r", LangR, CategoryCode},
		{"terraform tf", "a/b.tf", LangTerraform, CategoryCode},
		{"terraform tfvars", "a/b.tfvars", LangTerraform, CategoryCode},
		{"zig", "a/b.zig", LangZig, CategoryCode},
		{"nim", "a/b.nim", LangNim, CategoryCode},
		{"julia", "a/b.jl", LangJulia, CategoryCode},
		{"clojure clj", "a/b.clj", LangClojure, CategoryCode},
		{"clojure cljs", "a/b.cljs", LangClojure, CategoryCode},
		{"clojure cljc", "a/b.cljc", LangClojure, CategoryCode},
		{"clojure edn", "a/b.edn", LangClojure, CategoryCode},
		{"lisp", "a/b.lisp", LangLisp, CategoryCode},
		{"emacs lisp", "a/b.el", LangLisp, CategoryCode},
		{"scheme", "a/b.scm", LangLisp, CategoryCode},
		{"erlang erl", "a/b.erl", LangErlang, CategoryCode},
		{"erlang hrl", "a/b.hrl", LangErlang, CategoryCode},
		{"ocaml ml", "a/b.ml", LangOCaml, CategoryCode},
		{"ocaml mli", "a/b.mli", LangOCaml, CategoryCode},
		{"fsharp fs", "a/b.fs", LangFSharp, CategoryCode},
		{"fsharp fsx", "a/b.fsx", LangFSharp, CategoryCode},
		{"vb", "a/b.vb", LangVB, CategoryCode},
		{"groovy", "a/b.groovy", LangGroovy, CategoryCode},
		{"gradle", "a/b.gradle", LangGroovy, CategoryCode},
		{"notebook", "a/b.ipynb", LangNotebook, CategoryCode},
		// The documented ambiguity: .m is MATLAB or Objective-C and the
		// two disagree about the comment character.
		{"dot m is ambiguous", "a/b.m", LangUnknown, CategoryCode},

		// --- docs ----------------------------------------------------
		{"markdown", "a/b.md", LangMarkdown, CategoryDocs},
		{"markdown long", "a/b.markdown", LangMarkdown, CategoryDocs},
		{"mdx", "a/b.mdx", LangMarkdown, CategoryDocs},
		{"text", "a/b.txt", LangText, CategoryDocs},
		{"rst", "a/b.rst", LangText, CategoryDocs},
		{"readme no ext", "proj/README", LangText, CategoryDocs},
		{"license", "proj/LICENSE", LangText, CategoryDocs},

		// --- config --------------------------------------------------
		{"yaml", "a/b.yaml", LangYAML, CategoryConfig},
		{"yml", "a/b.yml", LangYAML, CategoryConfig},
		{"json", "a/b.json", LangJSON, CategoryConfig},
		{"jsonc", "a/b.jsonc", LangJSON, CategoryConfig},
		{"package.json is extension based", "web/package.json", LangJSON, CategoryConfig},
		{"toml", "a/b.toml", LangTOML, CategoryConfig},
		{"ini", "a/b.ini", LangINI, CategoryConfig},
		{"cfg", "a/b.cfg", LangINI, CategoryConfig},
		{"conf", "a/b.conf", LangINI, CategoryConfig},
		{"properties", "a/b.properties", LangINI, CategoryConfig},
		{"dotenv", "proj/.env", LangText, CategoryConfig},
		{"gitignore", "proj/.gitignore", LangText, CategoryConfig},
		{"go.mod is not a .mod file", "proj/go.mod", LangText, CategoryConfig},

		// --- extension-less basenames --------------------------------
		{"makefile", "proj/Makefile", LangMakefile, CategoryCode},
		{"dockerfile", "proj/Dockerfile", LangDockerfile, CategoryCode},
		{"rakefile", "proj/Rakefile", LangRuby, CategoryCode},
		{"gemfile", "proj/Gemfile", LangRuby, CategoryCode},
		{"vagrantfile", "proj/Vagrantfile", LangRuby, CategoryCode},
		{"cmakelists keeps code category", "proj/CMakeLists.txt", LangUnknown, CategoryCode},
		{"bashrc", "home/.bashrc", LangShell, CategoryCode},
		{"zshrc", "home/.zshrc", LangShell, CategoryCode},

		// --- unknown -------------------------------------------------
		{"unrecognised extension", "a/b.qqq", LangUnknown, CategoryUnknown},
		{"no extension no basename row", "a/somefile", LangUnknown, CategoryUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lang, cat := Language(tc.path)
			if lang != tc.lang || cat != tc.cat {
				t.Errorf("Language(%q) = (%q, %q), want (%q, %q)",
					tc.path, lang, cat, tc.lang, tc.cat)
			}
		})
	}
}

// TestLanguageDenylistVendored pins the path-segment vendored rule.
func TestLanguageDenylistVendored(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"node_modules", "web/node_modules/react/index.js"},
		{"vendor", "proj/vendor/github.com/x/y.go"},
		{"dot venv", "proj/.venv/lib/x.py"},
		{"venv", "proj/venv/lib/x.py"},
		{"site-packages", "usr/lib/python3/site-packages/x.py"},
		{"third_party", "proj/third_party/lib.c"},
		{"thirdparty", "proj/thirdparty/lib.c"},
		{"bower_components", "web/bower_components/x/y.js"},
		{"Pods", "ios/Pods/AFNetworking/A.m"},
		{"dot yarn", "web/.yarn/cache/x.js"},
		{"pnpm store", "web/.pnpm-store/v3/x.js"},
		{"dot git", "proj/.git/hooks/pre-commit.sh"},
		{"windows separator", `C:\proj\node_modules\x\y.js`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lang, cat := Language(tc.path)
			if cat != CategoryVendored {
				t.Errorf("Language(%q) category = %q, want %q", tc.path, cat, CategoryVendored)
			}
			if lang != LangUnknown {
				t.Errorf("Language(%q) lang = %q, want LangUnknown for a denylisted path", tc.path, lang)
			}
		})
	}
}

// TestLanguageDenylistGenerated pins the generated-directory, lockfile,
// generated-basename and binary-extension rules.
func TestLanguageDenylistGenerated(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		// path segments
		{"dist", "web/dist/assets/app.js"},
		{"next", "web/.next/server/page.js"},
		{"nuxt", "web/.nuxt/dist/x.js"},
		{"out", "web/out/index.html"},
		{"coverage", "proj/coverage/lcov-report/x.js"},
		{"pycache", "proj/pkg/__pycache__/mod.py"},
		{"terraform", "infra/.terraform/modules/x.tf"},
		{"gradle", "app/.gradle/caches/x.java"},
		{"svelte-kit", "web/.svelte-kit/output/x.js"},
		// generated basenames / suffixes
		{"protobuf go", "api/types.pb.go"},
		{"protobuf python", "api/types_pb2.py"},
		{"protobuf cc", "api/types.pb.cc"},
		{"protobuf h", "api/types.pb.h"},
		{"underscore generated", "api/model_generated.go"},
		{"dot generated", "api/model.generated.ts"},
		{"dart generated", "lib/model.g.dart"},
		{"dart freezed", "lib/model.freezed.dart"},
		{"minified js", "web/assets/app.min.js"},
		{"minified css", "web/assets/app.min.css"},
		{"source map", "web/assets/app.js.map"},
		// lockfiles
		{"package-lock", "web/package-lock.json"},
		{"yarn.lock", "web/yarn.lock"},
		{"pnpm-lock", "web/pnpm-lock.yaml"},
		{"bun.lockb", "web/bun.lockb"},
		{"Cargo.lock", "rs/Cargo.lock"},
		{"go.sum", "proj/go.sum"},
		{"poetry.lock", "py/poetry.lock"},
		{"Pipfile.lock", "py/Pipfile.lock"},
		{"composer.lock", "php/composer.lock"},
		{"Gemfile.lock", "rb/Gemfile.lock"},
		{"mix.lock", "ex/mix.lock"},
		{"flake.lock", "nix/flake.lock"},
		{"packages.lock.json", "cs/packages.lock.json"},
		// binary / asset extensions
		{"svg", "web/logo.svg"},
		{"png", "web/logo.png"},
		{"jpg", "web/photo.jpg"},
		{"gif", "web/anim.gif"},
		{"ico", "web/favicon.ico"},
		{"woff", "web/font.woff"},
		{"woff2", "web/font.woff2"},
		{"ttf", "web/font.ttf"},
		{"eot", "web/font.eot"},
		{"pdf", "docs/spec.pdf"},
		{"zip", "rel/bundle.zip"},
		{"gz", "rel/bundle.gz"},
		{"tar", "rel/bundle.tar"},
		{"wasm", "web/mod.wasm"},
		{"exe", "bin/observer.exe"},
		{"dll", "bin/observer.dll"},
		{"so", "lib/observer.so"},
		{"dylib", "lib/observer.dylib"},
		{"class", "target/Main.class"},
		{"jar", "libs/app.jar"},
		{"bin", "data/blob.bin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lang, cat := Language(tc.path)
			if cat != CategoryGenerated {
				t.Errorf("Language(%q) category = %q, want %q", tc.path, cat, CategoryGenerated)
			}
			if lang != LangUnknown {
				t.Errorf("Language(%q) lang = %q, want LangUnknown for a denylisted path", tc.path, lang)
			}
		})
	}
}

// TestLanguageNotDenylisted pins acceptance criterion 5: loc's denylist
// deliberately differs from internal/codeintel's, which drops testdata,
// bin, build and target by basename. Authored source under those
// directories counts here. It also pins the two suffixes that LOOK
// generated and are not.
func TestLanguageNotDenylisted(t *testing.T) {
	cases := []struct {
		name string
		path string
		lang Lang
		cat  Category
	}{
		{"testdata is not excluded", "testdata/x.go", LangGo, CategoryCode},
		{"nested testdata is not excluded", "internal/loc/testdata/lang/x.go", LangGo, CategoryCode},
		{"build is not excluded", "build/y.go", LangGo, CategoryCode},
		{"bin is not excluded", "bin/z.go", LangGo, CategoryCode},
		{"target is not excluded", "target/w.rs", LangRust, CategoryCode},
		{"obj is not excluded", "obj/v.cs", LangCSharp, CategoryCode},
		{"stringer output is not generated", "internal/models/kind_string.go", LangGo, CategoryCode},
		{"d.ts is not generated", "web/types/index.d.ts", LangTypeScript, CategoryCode},
		{"lowercase pods is not vendored", "internal/k8s/pods/list.go", LangGo, CategoryCode},
		{"a file named dist is not a dist dir", "scripts/dist", LangUnknown, CategoryUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lang, cat := Language(tc.path)
			if lang != tc.lang || cat != tc.cat {
				t.Errorf("Language(%q) = (%q, %q), want (%q, %q)",
					tc.path, lang, cat, tc.lang, tc.cat)
			}
		})
	}
}

// allLangs is every Lang constant declared in types.go except
// LangUnknown. It is maintained by hand so that adding a constant without
// a lexer row or a way to reach it fails loudly.
var allLangs = []Lang{
	LangGo, LangC, LangCPP, LangCSharp, LangJava, LangKotlin, LangSwift,
	LangRust, LangJavaScript, LangTypeScript, LangJSX, LangTSX, LangPython,
	LangRuby, LangPHP, LangPerl, LangShell, LangPowerShell, LangLua,
	LangSQL, LangHTML, LangXML, LangCSS, LangSCSS, LangYAML, LangJSON,
	LangTOML, LangINI, LangMarkdown, LangText, LangProto, LangGraphQL,
	LangDockerfile, LangMakefile, LangVue, LangSvelte, LangDart, LangScala,
	LangElixir, LangHaskell, LangR, LangMatlab, LangTerraform, LangZig,
	LangNim, LangJulia, LangClojure, LangLisp, LangErlang, LangOCaml,
	LangFSharp, LangVB, LangGroovy, LangNotebook,
}

// TestEveryLangIsReachable asserts that every declared language has a
// path that resolves to it.
//
// LangMatlab is the single documented exception: its only extension,
// `.m`, is shared with Objective-C and the two disagree about the comment
// character, so Language deliberately reports LangUnknown for it rather
// than guessing (see languageTable's doc comment). LangMatlab still has a
// lexer row for a caller that knows the language another way.
func TestEveryLangIsReachable(t *testing.T) {
	reached := map[Lang]bool{}
	for _, e := range languageTable {
		reached[e.lang] = true
	}
	for _, e := range basenameTable {
		reached[e.lang] = true
	}
	for _, lang := range allLangs {
		if lang == LangMatlab {
			continue
		}
		if !reached[lang] {
			t.Errorf("Lang %q is declared but no path resolves to it", lang)
		}
	}
}

// TestEveryLangHasLexTableRow pins that every declared language, MATLAB
// included, can be classified.
func TestEveryLangHasLexTableRow(t *testing.T) {
	for _, lang := range allLangs {
		if _, ok := lexTable[lang]; !ok {
			t.Errorf("Lang %q has no lexTable row", lang)
		}
	}
	if _, ok := lexTable[LangUnknown]; ok {
		t.Error("LangUnknown must NOT have a lexTable row: it selects the conservative fallback")
	}
}

// TestGeneratedPathConventions pins review finding L3's path half. This
// repository's OWN oapi-codegen output (`server.gen.go`) and the
// controller-gen convention (`zz_generated.deepcopy.go`) classified as
// hand-written Go code.
func TestGeneratedPathConventions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path string
		want Category
	}{
		// The reviewer's executed probe paths.
		{"internal/orgserver/dashboard/gen/server.gen.go", CategoryGenerated},
		{"api/zz_generated.deepcopy.go", CategoryGenerated},
		// The rest of the two conventions.
		{"pkg/apis/zz_generated.defaults.go", CategoryGenerated},
		{"internal/store/queries_gen.go", CategoryGenerated},
		{"schema.gen.go", CategoryGenerated},
		// Already covered, kept so a table rewrite cannot lose them.
		{"api/service.pb.go", CategoryGenerated},
		{"api/models_generated.ts", CategoryGenerated},
		// NOT generated: the rules must not swallow ordinary names that
		// merely contain the same letters.
		{"internal/gen/regen.go", CategoryCode},
		{"internal/codegen.go", CategoryCode},
		{"cmd/gen.go", CategoryCode},
		{"internal/generator.go", CategoryCode},
		// Deliberately absent from the rules (stringer output is routinely
		// hand-edited once committed).
		{"internal/loc/lang_string.go", CategoryCode},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			lang, cat := Language(tt.path)
			if cat != tt.want {
				t.Errorf("Language(%q) category = %q, want %q", tt.path, cat, tt.want)
			}
			if tt.want == CategoryGenerated && lang != LangUnknown {
				t.Errorf("Language(%q) lang = %q, want unknown — a generated file must "+
					"never report a language it would then be lexed with", tt.path, lang)
			}
		})
	}
}
