package cloudevidence

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// normalize.go is the ONE place every OUTBOUND LABEL is passed through before
// it can reach an envelope: an action's kind, an action's category, and the
// session's model family.
//
// WHY ONE PLACE (A2). The structural lane's whole promise is "we upload no
// string the developer wrote". Three fields quietly broke it, each in the same
// way and each fixed independently would have broken again:
//
//   - `activity_mix` ran its keys through a MEMBERSHIP table, but the very same
//     kinds shipped verbatim as `actions[].kind`, so an action_type of
//     "payroll.csv" counted as "unclassified" in the mix and shipped as
//     "payroll.csv" in the action list;
//   - a path-derived category was accepted on SHAPE ("short alphanumerics"),
//     which `payroll` and `acmemerger` both satisfy — a shape check cannot
//     distinguish a file extension from a codename;
//   - `model_family` copied the local model string verbatim, so a custom
//     endpoint's "acme-internal-llm-v3" uploaded intact.
//
// The rule is the same for all three and is stated once here: an outbound label
// is a member of a table WE wrote, or it is the table's honest fallback. There
// is no shape check and no "plausible slug" heuristic anywhere on this path,
// because a well-shaped attacker value satisfies one by construction.

// LabelUnclassified is the honest bucket for an action kind that is not a
// member of the closed kind vocabulary.
const LabelUnclassified = unclassifiedMixKey

// LabelOther is the honest bucket for a category that is not a member of the
// closed category vocabulary.
const LabelOther = "other"

// The model-family labels this file may emit. They are DEFINED in
// internal/cloudcontract and only aliased here, for the same reason the failure
// classes are: the hosted side reads the vocabulary from the contract, so a
// label spelled independently on this side would be one the model was never
// shown (A10's rule, applied to the second vocabulary that had the problem).
const (
	ModelFamilyClaude   = cloudcontract.ModelFamilyClaude
	ModelFamilyGPT      = cloudcontract.ModelFamilyGPT
	ModelFamilyOSeries  = cloudcontract.ModelFamilyOSeries
	ModelFamilyGemini   = cloudcontract.ModelFamilyGemini
	ModelFamilyGemma    = cloudcontract.ModelFamilyGemma
	ModelFamilyLlama    = cloudcontract.ModelFamilyLlama
	ModelFamilyQwen     = cloudcontract.ModelFamilyQwen
	ModelFamilyMistral  = cloudcontract.ModelFamilyMistral
	ModelFamilyDeepSeek = cloudcontract.ModelFamilyDeepSeek
	ModelFamilyGrok     = cloudcontract.ModelFamilyGrok
	ModelFamilyPhi      = cloudcontract.ModelFamilyPhi
	ModelFamilyKimi     = cloudcontract.ModelFamilyKimi
	ModelFamilyGLM      = cloudcontract.ModelFamilyGLM
	ModelFamilyMiniMax  = cloudcontract.ModelFamilyMiniMax
	ModelFamilyNova     = cloudcontract.ModelFamilyNova
	ModelFamilyCohere   = cloudcontract.ModelFamilyCohere
	ModelFamilyGranite  = cloudcontract.ModelFamilyGranite
	ModelFamilyFalcon   = cloudcontract.ModelFamilyFalcon
	ModelFamilyYi       = cloudcontract.ModelFamilyYi
	ModelFamilyUnknown  = cloudcontract.ModelFamilyUnknown
)

// NormalizeActionKind returns kind when it is a member of the closed action-kind
// vocabulary (knownActionKinds — the mirror of internal/models' Action*
// constants), else LabelUnclassified. Case and surrounding space are folded, so
// a stored " Run_Command " still lands on its real kind rather than the bucket.
//
// It is the SAME membership test buildActivityMix applies, deliberately: the
// mix and the action list must agree about what a kind is, or one of them is
// uploading a string the other refused.
func NormalizeActionKind(kind string) string {
	k := strings.ToLower(strings.TrimSpace(kind))
	if knownActionKinds[k] {
		return k
	}
	return LabelUnclassified
}

// closedExtensions is the CLOSED allow-list of file extensions that may ship as
// a path-derived category. It covers the source, config, markup, data and
// asset extensions a coding session actually touches; anything else — an
// unusual suffix, a dotted codename, a command tail — is LabelOther.
//
// It is an ALLOW-LIST rather than a shape check because ".acme-merger" and
// ".payroll" are perfectly well-shaped extensions, and shipping them would
// upload the very kind of string this lane refuses. A missing extension costs
// one label's precision; a leaked one costs the promise.
var closedExtensions = map[string]bool{
	// Go.
	"go": true, "mod": true, "sum": true, "tmpl": true, "gotmpl": true,
	// JS / TS.
	"ts": true, "tsx": true, "js": true, "jsx": true, "mjs": true, "cjs": true,
	"mts": true, "cts": true, "vue": true, "svelte": true, "astro": true,
	// Python / Ruby / PHP / Perl.
	"py": true, "pyi": true, "ipynb": true, "rb": true, "erb": true, "rake": true,
	"gemspec": true, "php": true, "pl": true, "pm": true,
	// Systems / JVM / .NET / mobile.
	"rs": true, "c": true, "h": true, "cc": true, "cpp": true, "cxx": true,
	"hpp": true, "hh": true, "cs": true, "java": true, "kt": true, "kts": true,
	"scala": true, "swift": true, "m": true, "mm": true, "dart": true,
	"zig": true, "nim": true, "v": true, "asm": true, "s": true,
	// Functional / scientific / other languages.
	"hs": true, "ex": true, "exs": true, "erl": true, "clj": true, "cljs": true,
	"lua": true, "r": true, "jl": true, "f90": true, "sol": true, "elm": true,
	// Shell / batch.
	"sh": true, "bash": true, "zsh": true, "fish": true, "ps1": true,
	"bat": true, "cmd": true, "nu": true,
	// Config / data.
	"json": true, "jsonc": true, "json5": true, "yaml": true, "yml": true,
	"toml": true, "ini": true, "cfg": true, "conf": true, "properties": true,
	"env": true, "xml": true, "plist": true, "lock": true, "nix": true,
	"tf": true, "tfvars": true, "hcl": true, "proto": true, "graphql": true,
	"gql": true, "sql": true, "prisma": true, "csv": true, "tsv": true,
	"gradle": true, "cmake": true, "mk": true, "make": true, "dockerfile": true,
	"editorconfig": true, "gitignore": true, "gitattributes": true,
	"npmrc": true, "nvmrc": true, "prettierrc": true, "eslintrc": true,
	// Markup / docs / web.
	"md": true, "mdx": true, "rst": true, "adoc": true, "txt": true,
	"html": true, "htm": true, "css": true, "scss": true, "sass": true,
	"less": true, "styl": true, "hbs": true, "ejs": true, "pug": true,
	"twig": true, "tex": true, "pdf": true,
	// Assets / archives / artifacts.
	"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true,
	"webp": true, "ico": true, "woff": true, "woff2": true, "ttf": true,
	"zip": true, "tar": true, "gz": true, "tgz": true, "wasm": true,
	// Misc engineering artifacts.
	"log": true, "patch": true, "diff": true, "snap": true, "po": true,
	"pot": true, "sqlite": true, "db": true, "bin": true, "pb": true,
}

// categoryVocabulary is the CLOSED set of every label that may appear as an
// action category: the extension allow-list, plus the command classes, the MCP
// family labels, and the fixed labels the strategy table emits, plus
// LabelOther. Built once from the SAME tables those labels are emitted from, so
// a new command class or MCP family cannot be emitted and then rejected here.
var categoryVocabulary = func() map[string]bool {
	m := map[string]bool{LabelOther: true}
	for ext := range closedExtensions {
		m[ext] = true
	}
	for _, r := range commandRules {
		m[r.label] = true
	}
	// The two classes CommandClass can return that are not a commandRules label.
	m["test"] = true
	m["build"] = true
	m["shell"] = true
	for _, label := range mcpServerLabels {
		m[label] = true
	}
	for _, r := range mcpServerPrefixLabels {
		m[r.label] = true
	}
	m[mcpFallbackLabel] = true
	for _, label := range fixedActionCategories {
		m[label] = true
	}
	return m
}()

// NormalizeCategory returns cat when it is a member of the closed category
// vocabulary, else LabelOther. It is the final gate every action category
// passes through, whichever derivation produced it.
func NormalizeCategory(cat string) string {
	c := strings.ToLower(strings.TrimSpace(cat))
	if categoryVocabulary[c] {
		return c
	}
	return LabelOther
}

// modelFamilyExactTokens are model-id tokens that name a family only when they
// stand alone. The OpenAI reasoning series is spelled "o1"/"o3"/"o4" — two
// characters that a prefix rule would match inside half the ids in existence.
var modelFamilyExactTokens = map[string]string{
	"o1": ModelFamilyOSeries, "o3": ModelFamilyOSeries,
	"o4": ModelFamilyOSeries, "o5": ModelFamilyOSeries,
}

// modelFamilyTokenPrefixes is the ORDERED family table. A model id is split
// into tokens on its separators and each token is tested against these
// prefixes; the FIRST hit names the family.
//
// Matching a token PREFIX (not the whole id) is what makes the table survive the
// zoo of real ids: "anthropic/claude-opus-4-8", "us.anthropic.claude-3-5-sonnet",
// "gpt-4o-2024-11-20", "qwen2.5-coder:32b", "openai/gpt-5.6-codex" all resolve.
// The OUTPUT is always our constant, never the matched token, so a hostile id
// that happens to contain "gpt" yields the label "gpt" and nothing of its own.
var modelFamilyTokenPrefixes = []struct{ prefix, family string }{
	{"claude", ModelFamilyClaude},
	{"sonnet", ModelFamilyClaude},
	{"opus", ModelFamilyClaude},
	{"haiku", ModelFamilyClaude},
	{"gpt", ModelFamilyGPT},
	{"chatgpt", ModelFamilyGPT},
	{"gemini", ModelFamilyGemini},
	{"gemma", ModelFamilyGemma},
	{"codellama", ModelFamilyLlama},
	{"llama", ModelFamilyLlama},
	{"qwen", ModelFamilyQwen},
	{"qwq", ModelFamilyQwen},
	{"codestral", ModelFamilyMistral},
	{"devstral", ModelFamilyMistral},
	{"magistral", ModelFamilyMistral},
	{"mixtral", ModelFamilyMistral},
	{"mistral", ModelFamilyMistral},
	{"ministral", ModelFamilyMistral},
	{"deepseek", ModelFamilyDeepSeek},
	{"grok", ModelFamilyGrok},
	{"phi", ModelFamilyPhi},
	{"kimi", ModelFamilyKimi},
	{"glm", ModelFamilyGLM},
	{"minimax", ModelFamilyMiniMax},
	{"nova", ModelFamilyNova},
	{"command", ModelFamilyCohere},
	{"cohere", ModelFamilyCohere},
	{"granite", ModelFamilyGranite},
	{"falcon", ModelFamilyFalcon},
	{"yi", ModelFamilyYi},
}

// modelIDSeparators are the characters that separate an id's tokens.
const modelIDSeparators = "/-_.: @\t"

// NormalizeModelFamily maps a raw local model string onto a member of the
// closed model-family vocabulary, or ModelFamilyUnknown.
//
// The raw string never survives: every return value is one of this package's
// constants. A session with no recorded model, or one whose model this table
// does not recognize, is honestly "unknown" — the same direction every other
// label in this file takes.
func NormalizeModelFamily(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if m == "" {
		return ModelFamilyUnknown
	}
	for _, tok := range strings.FieldsFunc(m, func(r rune) bool {
		return strings.ContainsRune(modelIDSeparators, r)
	}) {
		if fam, ok := modelFamilyExactTokens[tok]; ok {
			return fam
		}
		for _, r := range modelFamilyTokenPrefixes {
			if strings.HasPrefix(tok, r.prefix) {
				return r.family
			}
		}
	}
	return ModelFamilyUnknown
}
