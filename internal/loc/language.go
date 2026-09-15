package loc

import "strings"

// langEntry is one row of the language tables: the normalized language a
// path is written in, and the coarse Category it counts under.
type langEntry struct {
	lang Lang
	cat  Category
}

// Language reports the normalized language and coarse category for a
// path.
//
// The path may use either separator: the live corpus mixes POSIX targets
// from claude-code/codex with Windows targets such as
// `C:\programsx\app\main.go` from cross-mount sessions, so both `/` and
// `\` split path segments here.
//
// Resolution order — the denylists are consulted BEFORE the language
// tables, so a vendored or generated file never reports a language it
// would then be lexed with:
//
//  1. path-segment vendored denylist   → (LangUnknown, CategoryVendored)
//  2. path-segment generated denylist  → (LangUnknown, CategoryGenerated)
//  3. lockfile basename denylist       → (LangUnknown, CategoryGenerated)
//  4. generated basename/suffix rules  → (LangUnknown, CategoryGenerated)
//  5. binary/asset extension denylist  → (LangUnknown, CategoryGenerated)
//  6. basenameTable (whole lowercased basename)
//  7. languageTable (lowercased extension)
//  8. otherwise                        → (LangUnknown, CategoryUnknown)
//
// Step 6 runs before step 7 rather than only for extension-less files,
// because several basename rows carry an extension that would otherwise
// win and be wrong: `CMakeLists.txt` is not documentation and `go.mod` is
// not a `.mod` file. Extension-less names (`Makefile`, `Dockerfile`,
// `LICENSE`, `.bashrc`) are the same lookup.
//
// This table is deliberately loc's OWN and is not shared with
// internal/codeintel: that package drops `testdata`, `bin`, `build` and
// `target` by basename (correct for symbol indexing, wrong for counting
// authored lines) and has no docs or config bucket at all. Source files
// under `testdata/` and `build/` count here (plan §5, criterion 5).
func Language(path string) (Lang, Category) {
	segments := splitSegments(path)
	if len(segments) == 0 {
		return LangUnknown, CategoryUnknown
	}
	base := strings.ToLower(segments[len(segments)-1])
	ext := extensionOf(base)

	if cat, ok := denylisted(segments, base, ext); ok {
		return LangUnknown, cat
	}
	if e, ok := basenameTable[base]; ok {
		return e.lang, e.cat
	}
	if ext != "" {
		if e, ok := languageTable[ext]; ok {
			return e.lang, e.cat
		}
	}
	return LangUnknown, CategoryUnknown
}

// splitSegments splits a path on both separators and drops empty
// segments, so `a//b`, `a\b` and `C:\a\b` all yield usable segments.
func splitSegments(path string) []string {
	fields := strings.FieldsFunc(path, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	return fields
}

// extensionOf returns the lowercased extension of an already-lowercased
// basename, without the dot. A dotfile with no further dot (`.bashrc`)
// has no extension — its whole name is the lookup key.
func extensionOf(base string) string {
	idx := strings.LastIndexByte(base, '.')
	if idx <= 0 || idx == len(base)-1 {
		return ""
	}
	return base[idx+1:]
}

// denylisted applies the five denylist rules in order. It returns the
// Category to report and true when the path is excluded from counting.
//
// Directory rules examine every segment EXCEPT the last, so a source file
// merely named `dist` or `out` is not mistaken for a build directory.
func denylisted(segments []string, base, ext string) (Category, bool) {
	for i := 0; i < len(segments)-1; i++ {
		seg := segments[i]
		if _, ok := vendoredSegmentsExact[seg]; ok {
			return CategoryVendored, true
		}
		if _, ok := vendoredSegments[strings.ToLower(seg)]; ok {
			return CategoryVendored, true
		}
	}
	for i := 0; i < len(segments)-1; i++ {
		if _, ok := generatedSegments[strings.ToLower(segments[i])]; ok {
			return CategoryGenerated, true
		}
	}
	if _, ok := lockfileBasenames[base]; ok {
		return CategoryGenerated, true
	}
	if generatedBasename(base, ext) {
		return CategoryGenerated, true
	}
	if ext != "" {
		if _, ok := binaryExtensions[ext]; ok {
			return CategoryGenerated, true
		}
	}
	return CategoryUnknown, false
}

// generatedBasename applies the basename/suffix generated rules.
//
// The stem rules (`*_generated.*`, `*.generated.*`, `zz_generated*`) match
// on the name with its extension removed, so they fire for any language.
// `zz_generated` is a PREFIX rule because that is how the convention is
// written: controller-gen emits `zz_generated.deepcopy.go`,
// `zz_generated.defaults.go`, and the varying part is the tail.
// Deliberately ABSENT: `*_string.go` (stringer output is routinely
// hand-edited and is indistinguishable from ordinary code once committed)
// and `*.d.ts` (TypeScript declaration files are frequently hand-written).
func generatedBasename(base, ext string) bool {
	for _, suffix := range generatedSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	stem := base
	if ext != "" {
		stem = base[:len(base)-len(ext)-1]
	}
	return strings.HasSuffix(stem, "_generated") ||
		strings.HasSuffix(stem, ".generated") ||
		strings.HasPrefix(stem, "zz_generated")
}

// generatedHeaderScanLines is how far into a file the `Code generated …
// DO NOT EDIT.` banner is looked for. Every generator that emits one puts
// it in the first line or two (a build tag or a shebang may precede it);
// scanning further would start matching prose ABOUT generated code.
const generatedHeaderScanLines = 3

// generatedHeaderMarkers are the two halves of Go's canonical
// machine-generated banner, as fixed by cmd/go
// (`^// Code generated .* DO NOT EDIT\.$`). Both must be present on the
// SAME line, which is what keeps a doc comment that merely mentions
// "code generated by" from silently zeroing a hand-written file.
//
// The comment leader is deliberately NOT part of the match: oapi-codegen
// writes `// Code generated …`, protoc-gen-* the same, sqlc `-- Code
// generated …` in SQL and Python tools `# Code generated …`. Requiring a
// specific leader would have made this a Go-only rule.
var generatedHeaderMarkers = [2]string{"Code generated ", "DO NOT EDIT."}

// HasGeneratedHeader reports whether a file's CONTENT carries the
// canonical machine-generated banner in its first few lines.
//
// It exists because the path is not always enough: this repository's own
// `internal/orgserver/dashboard/gen/server.gen.go` is caught by the
// `.gen.go` suffix, but `api/models.go` emitted by the same run is not,
// and neither is a `schema.py` from a code generator that names its
// output whatever the spec said. The after-image of a whole-file write is
// in hand at count time, so the banner is free to check there (review
// finding L3).
//
// It is only consulted for WHOLE-CONTENT shapes. A fragment edit
// (old_string/new_string, a patch hunk) does not carry the top of the
// file, so there is nothing to sniff and the path rules stand alone.
func HasGeneratedHeader(content string) bool {
	if content == "" {
		return false
	}
	for i, line := range SplitLines(content) {
		if i >= generatedHeaderScanLines {
			return false
		}
		if strings.Contains(line, generatedHeaderMarkers[0]) &&
			strings.Contains(line, generatedHeaderMarkers[1]) {
			return true
		}
	}
	return false
}

// vendoredSegments are directory names whose contents were written by a
// package manager or copied wholesale from another project. Compared
// case-insensitively.
var vendoredSegments = map[string]struct{}{
	"node_modules":     {},
	"vendor":           {},
	".venv":            {},
	"venv":             {},
	"site-packages":    {},
	"third_party":      {},
	"thirdparty":       {},
	"bower_components": {},
	".yarn":            {},
	".pnpm-store":      {},
	".git":             {},
}

// vendoredSegmentsExact are vendored directory names matched with their
// exact case. `Pods` is CocoaPods' checkout directory; a lowercase `pods`
// is a plausible ordinary package name (Kubernetes manifests, for one),
// so only the capitalised form is excluded.
var vendoredSegmentsExact = map[string]struct{}{
	"Pods": {},
}

// generatedSegments are directory names holding build or tool output.
//
// `testdata`, `bin`, `build` and `target` are deliberately NOT here even
// though internal/codeintel excludes them: `testdata/` holds authored
// fixtures, and `build/`, `bin/` and `target/` are ordinary source
// directory names in many projects (plan §5, criterion 5).
var generatedSegments = map[string]struct{}{
	"dist":        {},
	".next":       {},
	".nuxt":       {},
	"out":         {},
	"coverage":    {},
	"__pycache__": {},
	".terraform":  {},
	".gradle":     {},
	".svelte-kit": {},
}

// generatedSuffixes are basename suffixes that mark tool output.
//
// `.gen.go` / `_gen.go` cover the dominant Go convention (oapi-codegen,
// mockgen, ent, sqlc all emit one of the two); this repository's own
// `internal/orgserver/dashboard/gen/server.gen.go` is the worked example
// that the review caught classifying as hand-written code (L3).
var generatedSuffixes = []string{
	".gen.go",
	"_gen.go",
	".pb.go",
	".pb.cc",
	".pb.h",
	"_pb2.py",
	".g.dart",
	".freezed.dart",
	".min.js",
	".min.css",
	".map",
}

// lockfileBasenames are dependency lockfiles: machine-authored, large,
// and never meaningful as authored lines.
var lockfileBasenames = map[string]struct{}{
	"package-lock.json":  {},
	"yarn.lock":          {},
	"pnpm-lock.yaml":     {},
	"bun.lockb":          {},
	"cargo.lock":         {},
	"go.sum":             {},
	"poetry.lock":        {},
	"pipfile.lock":       {},
	"composer.lock":      {},
	"gemfile.lock":       {},
	"mix.lock":           {},
	"flake.lock":         {},
	"packages.lock.json": {},
}

// binaryExtensions are binaries, archives, fonts and images. They are
// recognised rather than dropped so the UI can report how many files a
// change touched that carry no countable lines.
var binaryExtensions = map[string]struct{}{
	"svg": {}, "png": {}, "jpg": {}, "jpeg": {}, "gif": {}, "ico": {},
	"bmp": {}, "webp": {}, "woff": {}, "woff2": {}, "ttf": {}, "otf": {},
	"eot": {}, "pdf": {}, "zip": {}, "gz": {}, "tgz": {}, "bz2": {},
	"xz": {}, "tar": {}, "wasm": {}, "exe": {}, "dll": {}, "so": {},
	"dylib": {}, "class": {}, "jar": {}, "bin": {}, "o": {}, "a": {},
	"pyc": {}, "pyo": {},
}

// basenameTable maps a whole lowercased basename to its language. It is
// consulted before languageTable (see Language).
var basenameTable = map[string]langEntry{
	"makefile":      {LangMakefile, CategoryCode},
	"gnumakefile":   {LangMakefile, CategoryCode},
	"dockerfile":    {LangDockerfile, CategoryCode},
	"containerfile": {LangDockerfile, CategoryCode},
	"rakefile":      {LangRuby, CategoryCode},
	"gemfile":       {LangRuby, CategoryCode},
	"vagrantfile":   {LangRuby, CategoryCode},
	"brewfile":      {LangRuby, CategoryCode},
	// CMake has no Lang constant and therefore no token table; reporting
	// LangUnknown is the honest answer (every non-blank line becomes
	// ClassUnknown) while still bucketing the file as code.
	"cmakelists.txt": {LangUnknown, CategoryCode},
	"go.mod":         {LangText, CategoryConfig},
	".gitignore":     {LangText, CategoryConfig},
	".gitattributes": {LangText, CategoryConfig},
	".dockerignore":  {LangText, CategoryConfig},
	".npmignore":     {LangText, CategoryConfig},
	".env":           {LangText, CategoryConfig},
	".editorconfig":  {LangINI, CategoryConfig},
	".npmrc":         {LangINI, CategoryConfig},
	".yarnrc":        {LangINI, CategoryConfig},
	".babelrc":       {LangJSON, CategoryConfig},
	".eslintrc":      {LangJSON, CategoryConfig},
	".prettierrc":    {LangJSON, CategoryConfig},
	".bashrc":        {LangShell, CategoryCode},
	".bash_profile":  {LangShell, CategoryCode},
	".zshrc":         {LangShell, CategoryCode},
	".zshenv":        {LangShell, CategoryCode},
	".zprofile":      {LangShell, CategoryCode},
	".profile":       {LangShell, CategoryCode},
	"license":        {LangText, CategoryDocs},
	"licence":        {LangText, CategoryDocs},
	"notice":         {LangText, CategoryDocs},
	"readme":         {LangText, CategoryDocs},
	"authors":        {LangText, CategoryDocs},
	"changelog":      {LangText, CategoryDocs},
}

// languageTable maps a lowercased extension (without the dot) to its
// language and category.
//
// Two documented ambiguities:
//
//   - `.h` is claimed by C, C++ and Objective-C. It maps to LangC; the
//     three share `//`, `/* */` and `"…"`, so the line lexer behaves
//     identically for all three and only the reported Lang differs.
//   - `.m` is claimed by MATLAB (`%` comments) and Objective-C (`//`
//     comments), and the two disagree about which character starts a
//     comment — guessing wrong moves lines between the code and comment
//     buckets. It therefore maps to LangUnknown with CategoryCode: the
//     file counts as code but its lines degrade to ClassUnknown rather
//     than being confidently miscounted. LangMatlab consequently has a
//     token table but no extension that reaches it; a caller that knows
//     the language by other means can still pass it to ClassifyLines.
var languageTable = map[string]langEntry{
	"go": {LangGo, CategoryCode},

	"c": {LangC, CategoryCode},
	"h": {LangC, CategoryCode},

	"cc": {LangCPP, CategoryCode}, "cpp": {LangCPP, CategoryCode},
	"cxx": {LangCPP, CategoryCode}, "c++": {LangCPP, CategoryCode},
	"hpp": {LangCPP, CategoryCode}, "hh": {LangCPP, CategoryCode},
	"hxx": {LangCPP, CategoryCode}, "ipp": {LangCPP, CategoryCode},
	"mm": {LangCPP, CategoryCode},

	"cs": {LangCSharp, CategoryCode},

	"java": {LangJava, CategoryCode},

	"kt": {LangKotlin, CategoryCode}, "kts": {LangKotlin, CategoryCode},

	"swift": {LangSwift, CategoryCode},

	"rs": {LangRust, CategoryCode},

	"js": {LangJavaScript, CategoryCode}, "mjs": {LangJavaScript, CategoryCode},
	"cjs": {LangJavaScript, CategoryCode},

	"ts": {LangTypeScript, CategoryCode}, "mts": {LangTypeScript, CategoryCode},
	"cts": {LangTypeScript, CategoryCode},

	"jsx": {LangJSX, CategoryCode},
	"tsx": {LangTSX, CategoryCode},

	"py": {LangPython, CategoryCode}, "pyi": {LangPython, CategoryCode},
	"pyw": {LangPython, CategoryCode},

	"rb": {LangRuby, CategoryCode}, "rake": {LangRuby, CategoryCode},
	"gemspec": {LangRuby, CategoryCode},

	"php": {LangPHP, CategoryCode}, "phtml": {LangPHP, CategoryCode},

	"pl": {LangPerl, CategoryCode}, "pm": {LangPerl, CategoryCode},

	"sh": {LangShell, CategoryCode}, "bash": {LangShell, CategoryCode},
	"zsh": {LangShell, CategoryCode}, "ksh": {LangShell, CategoryCode},

	"ps1": {LangPowerShell, CategoryCode}, "psm1": {LangPowerShell, CategoryCode},
	"psd1": {LangPowerShell, CategoryCode},

	"lua": {LangLua, CategoryCode},

	"sql": {LangSQL, CategoryCode},

	"html": {LangHTML, CategoryCode}, "htm": {LangHTML, CategoryCode},

	"xml": {LangXML, CategoryCode}, "xsd": {LangXML, CategoryCode},
	"xsl": {LangXML, CategoryCode}, "xslt": {LangXML, CategoryCode},

	"css": {LangCSS, CategoryCode},

	"scss": {LangSCSS, CategoryCode}, "sass": {LangSCSS, CategoryCode},
	"less": {LangSCSS, CategoryCode},

	"yaml": {LangYAML, CategoryConfig}, "yml": {LangYAML, CategoryConfig},

	"json": {LangJSON, CategoryConfig}, "jsonc": {LangJSON, CategoryConfig},
	"json5": {LangJSON, CategoryConfig},

	"toml": {LangTOML, CategoryConfig},

	"ini": {LangINI, CategoryConfig}, "cfg": {LangINI, CategoryConfig},
	"conf": {LangINI, CategoryConfig}, "properties": {LangINI, CategoryConfig},

	"env": {LangText, CategoryConfig},

	"md": {LangMarkdown, CategoryDocs}, "markdown": {LangMarkdown, CategoryDocs},
	"mdx": {LangMarkdown, CategoryDocs},

	"txt": {LangText, CategoryDocs}, "rst": {LangText, CategoryDocs},
	"adoc": {LangText, CategoryDocs},

	"proto": {LangProto, CategoryCode},

	"graphql": {LangGraphQL, CategoryCode}, "gql": {LangGraphQL, CategoryCode},

	"mk": {LangMakefile, CategoryCode},

	"vue":    {LangVue, CategoryCode},
	"svelte": {LangSvelte, CategoryCode},

	"dart": {LangDart, CategoryCode},

	"scala": {LangScala, CategoryCode}, "sbt": {LangScala, CategoryCode},

	"ex": {LangElixir, CategoryCode}, "exs": {LangElixir, CategoryCode},

	"hs": {LangHaskell, CategoryCode}, "lhs": {LangHaskell, CategoryCode},

	"r": {LangR, CategoryCode},

	// See the doc comment above: ".m" is deliberately unresolved.
	"m": {LangUnknown, CategoryCode},

	"tf": {LangTerraform, CategoryCode}, "tfvars": {LangTerraform, CategoryCode},
	"hcl": {LangTerraform, CategoryCode},

	"zig": {LangZig, CategoryCode},

	"nim": {LangNim, CategoryCode}, "nims": {LangNim, CategoryCode},

	"jl": {LangJulia, CategoryCode},

	"clj": {LangClojure, CategoryCode}, "cljs": {LangClojure, CategoryCode},
	"cljc": {LangClojure, CategoryCode}, "edn": {LangClojure, CategoryCode},

	"lisp": {LangLisp, CategoryCode}, "lsp": {LangLisp, CategoryCode},
	"el": {LangLisp, CategoryCode}, "scm": {LangLisp, CategoryCode},
	"ss": {LangLisp, CategoryCode}, "rkt": {LangLisp, CategoryCode},

	"erl": {LangErlang, CategoryCode}, "hrl": {LangErlang, CategoryCode},

	"ml": {LangOCaml, CategoryCode}, "mli": {LangOCaml, CategoryCode},

	"fs": {LangFSharp, CategoryCode}, "fsx": {LangFSharp, CategoryCode},
	"fsi": {LangFSharp, CategoryCode},

	"vb": {LangVB, CategoryCode}, "vbs": {LangVB, CategoryCode},
	"bas": {LangVB, CategoryCode},

	"groovy": {LangGroovy, CategoryCode}, "gradle": {LangGroovy, CategoryCode},

	"ipynb": {LangNotebook, CategoryCode},
}
