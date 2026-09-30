package heuristic

import (
	"regexp"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
)

// buildRules constructs the per-language rule table once. The patterns
// generalize the proven shapes in internal/codeintel/parse/livesym (re-
// implemented here to keep the package self-contained and pure). Symbol
// rules are ordered MOST-SPECIFIC FIRST since the engine takes the first
// match per line.
//
// Kind mapping onto the fixed vocabulary
// ("function"|"method"|"class"|"interface"|"type"):
//   - rust struct/impl -> class, trait -> interface, enum -> type
//   - python module-level def -> function (indent can't reliably tell a
//     method from a function at the regex tier, so all def -> function;
//     documented over-simplification)
//   - ts/js class -> class, interface -> interface, function/arrow -> function, type -> type
//
// ExactSpans is false for every language (set in servedCapability).
func buildRules() map[codeintel.Language]langRules {
	tsRules := jsTsSymbolRules()
	tsImports := jsTsImportRules()

	return map[codeintel.Language]langRules{
		parse.LangPython: {
			braceLang: false,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*class\s+([A-Za-z_]\w*)\s*[:\(]`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(`), kind: "function", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*from\s+([\w.]+)\s+import\b`), path: 1},
				{re: regexp.MustCompile(`^\s*import\s+([\w.]+)(?:\s+as\s+([A-Za-z_]\w*))?`), path: 1, alias: 2},
			},
		},

		parse.LangTypeScript: {braceLang: true, symbols: tsRules, imports: tsImports},
		parse.LangTSX:        {braceLang: true, symbols: tsRules, imports: tsImports},
		parse.LangJavaScript: {braceLang: true, symbols: tsRules, imports: tsImports},
		parse.LangJSX:        {braceLang: true, symbols: tsRules, imports: tsImports},

		parse.LangRust: {
			braceLang: true,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?trait\s+([A-Za-z_]\w*)`), kind: "interface", name: 1},
				{re: regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*impl(?:\s*<[^>]*>)?\s+(?:[A-Za-z_][\w:<>, ]*\s+for\s+)?([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?enum\s+([A-Za-z_]\w*)`), kind: "type", name: 1},
				{re: regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?type\s+([A-Za-z_]\w*)`), kind: "type", name: 1},
				{re: regexp.MustCompile(`^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:const\s+)?(?:unsafe\s+)?(?:extern\s+(?:"[^"]*"\s+)?)?fn\s+([A-Za-z_]\w*)`), kind: "function", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*(?:pub\s+)?use\s+([\w:]+(?:::\*)?)`), path: 1},
				{re: regexp.MustCompile(`^\s*(?:pub\s+)?(?:extern\s+crate|mod)\s+([A-Za-z_]\w*)`), path: 1},
			},
		},

		parse.LangJava: {
			braceLang: true,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|abstract\s+|final\s+|static\s+)*interface\s+([A-Za-z_]\w*)`), kind: "interface", name: 1},
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|abstract\s+|final\s+|static\s+)*(?:class|enum|record)\s+([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|static\s+|final\s+|abstract\s+|synchronized\s+|native\s+)+[A-Za-z_][\w<>\[\], .]*\s+([A-Za-z_]\w*)\s*\(`), kind: "method", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*import\s+(?:static\s+)?([\w.]+(?:\.\*)?)\s*;`), path: 1},
			},
		},

		parse.LangC: {
			braceLang: true,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*(?:typedef\s+)?struct\s+([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*(?:typedef\s+)?enum\s+([A-Za-z_]\w*)`), kind: "type", name: 1},
				{re: regexp.MustCompile(`^\s*(?:static\s+|inline\s+|extern\s+)*[A-Za-z_][\w *]*\s+\**([A-Za-z_]\w*)\s*\(`), kind: "function", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*#\s*include\s+[<"]([^>"]+)[>"]`), path: 1},
			},
		},

		parse.LangCPP: {
			braceLang: true,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*(?:template\s*<[^>]*>\s*)?class\s+([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*(?:template\s*<[^>]*>\s*)?struct\s+([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*(?:typedef\s+)?enum(?:\s+class)?\s+([A-Za-z_]\w*)`), kind: "type", name: 1},
				{re: regexp.MustCompile(`^\s*namespace\s+([A-Za-z_]\w*)`), kind: "type", name: 1},
				{re: regexp.MustCompile(`^\s*(?:static\s+|inline\s+|virtual\s+|explicit\s+|extern\s+|constexpr\s+)*[A-Za-z_][\w:<>, *&]*\s+\**([A-Za-z_]\w*)\s*\(`), kind: "function", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*#\s*include\s+[<"]([^>"]+)[>"]`), path: 1},
			},
		},

		parse.LangCSharp: {
			braceLang: true,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|internal\s+|abstract\s+|sealed\s+|partial\s+|static\s+)*interface\s+([A-Za-z_]\w*)`), kind: "interface", name: 1},
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|internal\s+|abstract\s+|sealed\s+|partial\s+|static\s+)*(?:class|struct|enum|record)\s+([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|internal\s+|static\s+|virtual\s+|override\s+|async\s+|sealed\s+)+[A-Za-z_][\w<>\[\], .]*\s+([A-Za-z_]\w*)\s*\(`), kind: "method", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*using\s+(?:static\s+)?(?:([A-Za-z_]\w*)\s*=\s*)?([\w.]+)\s*;`), path: 2, alias: 1},
			},
		},

		parse.LangRuby: {
			braceLang: false,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*module\s+([A-Za-z_]\w*)`), kind: "interface", name: 1},
				{re: regexp.MustCompile(`^\s*class\s+([A-Za-z_][\w:]*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*def\s+(?:self\.)?([A-Za-z_]\w*[!?=]?)`), kind: "method", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*(?:require|require_relative|load)\s+['"]([^'"]+)['"]`), path: 1},
			},
		},

		parse.LangPHP: {
			braceLang: true,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*(?:abstract\s+|final\s+)*interface\s+([A-Za-z_]\w*)`), kind: "interface", name: 1},
				{re: regexp.MustCompile(`^\s*trait\s+([A-Za-z_]\w*)`), kind: "interface", name: 1},
				{re: regexp.MustCompile(`^\s*(?:abstract\s+|final\s+)*class\s+([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|static\s+|abstract\s+|final\s+)*function\s+([A-Za-z_]\w*)\s*\(`), kind: "function", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*(?:use|require|require_once|include|include_once)\s+(?:['"])?([\w\\/.-]+)(?:['"])?(?:\s+as\s+([A-Za-z_]\w*))?`), path: 1, alias: 2},
			},
		},

		parse.LangKotlin: {
			braceLang: true,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|internal\s+|abstract\s+|open\s+|sealed\s+)*interface\s+([A-Za-z_]\w*)`), kind: "interface", name: 1},
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|internal\s+|abstract\s+|open\s+|sealed\s+|data\s+|enum\s+)*class\s+([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|protected\s+|internal\s+|override\s+|open\s+|suspend\s+|inline\s+)*fun\s+(?:<[^>]*>\s+)?([A-Za-z_]\w*)\s*\(`), kind: "function", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*import\s+([\w.]+(?:\.\*)?)(?:\s+as\s+([A-Za-z_]\w*))?`), path: 1, alias: 2},
			},
		},

		parse.LangSwift: {
			braceLang: true,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|internal\s+|fileprivate\s+|open\s+)*protocol\s+([A-Za-z_]\w*)`), kind: "interface", name: 1},
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|internal\s+|fileprivate\s+|open\s+|final\s+)*(?:class|struct|actor|extension)\s+([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|internal\s+|fileprivate\s+|open\s+)*enum\s+([A-Za-z_]\w*)`), kind: "type", name: 1},
				{re: regexp.MustCompile(`^\s*(?:public\s+|private\s+|internal\s+|fileprivate\s+|open\s+|static\s+|class\s+|override\s+|final\s+)*func\s+([A-Za-z_]\w*)`), kind: "function", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*import\s+([A-Za-z_][\w.]*)`), path: 1},
			},
		},

		parse.LangScala: {
			braceLang: true,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*(?:sealed\s+|final\s+)*trait\s+([A-Za-z_]\w*)`), kind: "interface", name: 1},
				{re: regexp.MustCompile(`^\s*(?:sealed\s+|final\s+|abstract\s+|case\s+)*(?:class|object)\s+([A-Za-z_]\w*)`), kind: "class", name: 1},
				{re: regexp.MustCompile(`^\s*type\s+([A-Za-z_]\w*)`), kind: "type", name: 1},
				{re: regexp.MustCompile(`^\s*(?:override\s+|final\s+|private\s+|protected\s+|implicit\s+)*def\s+([A-Za-z_]\w*)`), kind: "function", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*import\s+([\w.]+(?:\.[_{][^;]*)?)`), path: 1},
			},
		},

		parse.LangBash: {
			braceLang: true,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*function\s+([A-Za-z_]\w*)\s*(?:\(\s*\))?`), kind: "function", name: 1},
				{re: regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*\(\s*\)\s*\{`), kind: "function", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`^\s*(?:source|\.)\s+(\S+)`), path: 1},
			},
		},

		parse.LangLua: {
			braceLang: false,
			symbols: []symRule{
				{re: regexp.MustCompile(`^\s*(?:local\s+)?function\s+([A-Za-z_][\w.:]*)`), kind: "function", name: 1},
				{re: regexp.MustCompile(`^\s*(?:local\s+)?([A-Za-z_][\w.]*)\s*=\s*function\b`), kind: "function", name: 1},
			},
			imports: []impRule{
				{re: regexp.MustCompile(`require\s*\(?\s*['"]([^'"]+)['"]`), path: 1},
			},
		},
	}
}

// jsTsSymbolRules returns the shared symbol rule set for TS/TSX/JS/JSX.
// Functions matched: `function f(`, exported/arrow `const f = (…) =>`,
// classes, interfaces (TS), and `type X =` aliases (TS).
func jsTsSymbolRules() []symRule {
	return []symRule{
		{re: regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)`), kind: "class", name: 1},
		{re: regexp.MustCompile(`^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)`), kind: "interface", name: 1},
		{re: regexp.MustCompile(`^\s*(?:export\s+)?type\s+([A-Za-z_$][\w$]*)\s*[=<]`), kind: "type", name: 1},
		{re: regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*[<(]`), kind: "function", name: 1},
		{re: regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>`), kind: "function", name: 1},
	}
}

// jsTsImportRules returns the shared import rule set for TS/TSX/JS/JSX:
// ES `import … from 'x'` (default-import alias captured) and CommonJS
// `const x = require('y')`.
func jsTsImportRules() []impRule {
	return []impRule{
		{re: regexp.MustCompile(`^\s*import\s+(?:([A-Za-z_$][\w$]*)\s*,?\s*)?(?:\{[^}]*\}\s*)?(?:\*\s+as\s+[A-Za-z_$][\w$]*\s+)?(?:from\s+)?['"]([^'"]+)['"]`), path: 2, alias: 1},
		{re: regexp.MustCompile(`^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]`), path: 2, alias: 1},
	}
}
