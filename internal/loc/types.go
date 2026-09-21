package loc

// Version is the classifier version stamped onto every row loc produces.
//
// It covers the language table, the line lexer, the diff pairing rules
// and the class-transition table together — anything that could change a
// count for the same input. The store upserts a row only when the
// incoming Version is STRICTLY GREATER than the stored one, so bumping
// this constant and re-running `observer backfill --loc` replaces every
// row exactly once (plan §3.2).
//
// Bump it whenever a change to this package would produce a different
// Stats for an input it already handled.
//
// v2 (2026-09-07, review fixes): a deleted `--` comment inside a hunk is
// no longer skipped as a diff header (L1); cline `replace_in_file` and
// goose `write` payloads now count instead of landing as `unrecognized`
// (L2); a `Code generated … DO NOT EDIT.` banner in a whole-content write
// makes the row generated (L3). The H2 digest change does not alter any
// Stats, but it does change input_digest, so the rows must be rewritten
// for the read-side collapse to take effect on an existing corpus —
// which is the other reason this bump is required and not cosmetic.
//
// NOTE (2026-09-21, sub-agent LOC split): the sub-agent LOC split is a
// PURE READ-TIME fold — a parent session's card treats its sub-agent
// children's rows as sidechain at read time (internal/store/locread.go),
// leaving each child's stored file_changes.sidechain HONEST for the
// child's own card. Nothing about loc.Extract's stored output changed, so
// this constant is deliberately NOT bumped. Populating file_changes for a
// sparsely-covered corpus (so any sidechain split has rows to fold) is an
// operational `observer backfill --loc`, run daemon-quiesced by the
// operator — not a classifier-version re-count.
const Version = 2

// Category is the coarse bucket a path falls into. Only CategoryCode
// contributes to the headline "lines of code" number; the others are
// reported separately so a documentation-heavy session is visibly
// documentation-heavy rather than silently inflating a code count.
type Category string

// The Category values. Generated and vendored files are counted with
// zero lines — they are recorded so the UI can say "N files skipped as
// generated" rather than silently dropping them.
const (
	CategoryCode      Category = "code"
	CategoryDocs      Category = "docs"
	CategoryConfig    Category = "config"
	CategoryGenerated Category = "generated"
	CategoryVendored  Category = "vendored"
	CategoryUnknown   Category = "unknown"
)

// Counted reports whether lines in this category are counted at all.
// Generated and vendored files are recognised but never counted.
func (c Category) Counted() bool {
	return c == CategoryCode || c == CategoryDocs || c == CategoryConfig
}

// Lang is a normalized language identifier. It is the key into the line
// lexer's token table; LangUnknown selects the conservative fallback
// lexer (blank detection only, everything else code).
type Lang string

// The languages loc's lexer has a token table for. LangUnknown is the
// zero value and is deliberately usable: an unrecognised extension still
// yields blank/non-blank line counts, just with lower confidence.
const (
	LangUnknown    Lang = ""
	LangGo         Lang = "go"
	LangC          Lang = "c"
	LangCPP        Lang = "cpp"
	LangCSharp     Lang = "csharp"
	LangJava       Lang = "java"
	LangKotlin     Lang = "kotlin"
	LangSwift      Lang = "swift"
	LangRust       Lang = "rust"
	LangJavaScript Lang = "javascript"
	LangTypeScript Lang = "typescript"
	LangJSX        Lang = "jsx"
	LangTSX        Lang = "tsx"
	LangPython     Lang = "python"
	LangRuby       Lang = "ruby"
	LangPHP        Lang = "php"
	LangPerl       Lang = "perl"
	LangShell      Lang = "shell"
	LangPowerShell Lang = "powershell"
	LangLua        Lang = "lua"
	LangSQL        Lang = "sql"
	LangHTML       Lang = "html"
	LangXML        Lang = "xml"
	LangCSS        Lang = "css"
	LangSCSS       Lang = "scss"
	LangYAML       Lang = "yaml"
	LangJSON       Lang = "json"
	LangTOML       Lang = "toml"
	LangINI        Lang = "ini"
	LangMarkdown   Lang = "markdown"
	LangText       Lang = "text"
	LangProto      Lang = "proto"
	LangGraphQL    Lang = "graphql"
	LangDockerfile Lang = "dockerfile"
	LangMakefile   Lang = "makefile"
	LangVue        Lang = "vue"
	LangSvelte     Lang = "svelte"
	LangDart       Lang = "dart"
	LangScala      Lang = "scala"
	LangElixir     Lang = "elixir"
	LangHaskell    Lang = "haskell"
	LangR          Lang = "r"
	LangMatlab     Lang = "matlab"
	LangTerraform  Lang = "terraform"
	LangZig        Lang = "zig"
	LangNim        Lang = "nim"
	LangJulia      Lang = "julia"
	LangClojure    Lang = "clojure"
	LangLisp       Lang = "lisp"
	LangErlang     Lang = "erlang"
	LangOCaml      Lang = "ocaml"
	LangFSharp     Lang = "fsharp"
	LangVB         Lang = "vb"
	LangGroovy     Lang = "groovy"
	LangNotebook   Lang = "notebook"
)

// LineClass is what one line of a fragment was classified as.
type LineClass uint8

// The line classes. ClassUnknown is the honest degradation for a line
// the fragment lexer cannot place — an unterminated block comment, a
// partial first/last line, a language with no token table. It is never
// folded into ClassBlank or ClassCode.
const (
	ClassUnknown LineClass = iota
	ClassCode
	ClassComment
	ClassBlank
)

// String renders a LineClass for test failures and debug output.
func (c LineClass) String() string {
	switch c {
	case ClassCode:
		return "code"
	case ClassComment:
		return "comment"
	case ClassBlank:
		return "blank"
	default:
		return "unknown"
	}
}

// Confidence grades how much of a result rests on a guess.
type Confidence string

// The confidence levels.
//
//   - ConfidenceHigh: a known language, a fragment with no unresolved
//     block state, both before- and after-images present.
//   - ConfidenceMedium: a known language but the fragment had an
//     unresolved boundary, or a before-image reconstructed from a
//     preceding read rather than from the tool input itself.
//   - ConfidenceLow: no token table for the language, a diff that fell
//     back to plain counting, or a before-image that is only a line
//     COUNT with no text.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Min returns the weaker of two confidences, so a result is never graded
// higher than its weakest input.
func (c Confidence) Min(other Confidence) Confidence {
	rank := map[Confidence]int{ConfidenceLow: 0, ConfidenceMedium: 1, ConfidenceHigh: 2}
	if rank[other] < rank[c] {
		return other
	}
	return c
}

// Stats is the bucket set for one file in one action. Every bucket is a
// LINE COUNT; nothing here is bytes and nothing here is content.
//
// The buckets are disjoint by construction: a line contributes to
// exactly one bucket per side of the change, so AddedCode + ModifiedCode
// + ... is the total number of line slots the change touched.
type Stats struct {
	// AddedCode is code lines present in the after-image with no
	// counterpart in the before-image.
	AddedCode int `json:"added_code"`
	// ModifiedCode is code lines replaced by other code lines — one
	// count per PAIR, not two. A one-line replacement is 1.
	ModifiedCode int `json:"modified_code"`
	// DeletedCode is code lines present in the before-image with no
	// counterpart in the after-image.
	DeletedCode int `json:"deleted_code"`
	// AddedComment and DeletedComment are the comment-line equivalents.
	// There is deliberately no ModifiedComment: a comment replaced by
	// another comment counts as one deleted + one added, because the
	// schema carries no modified-comment column and inventing one for
	// comments only would make the code and comment buckets asymmetric
	// in a way the UI cannot explain.
	AddedComment   int `json:"added_comment"`
	DeletedComment int `json:"deleted_comment"`
	// Whitespace is lines that are identical after whitespace
	// normalization but differ in raw text — a reindent, a retab, a
	// trailing-space strip. A 200-line reindent is 200 whitespace and
	// 0 modified.
	Whitespace int `json:"whitespace"`
	// Blank is blank lines added or removed.
	Blank int `json:"blank"`
	// Unknown is lines the classifier could not place, and lines whose
	// counterpart text was never available (an overwrite whose
	// before-image is only a line count).
	Unknown int `json:"unknown"`
}

// Add accumulates other into s.
func (s *Stats) Add(other Stats) {
	s.AddedCode += other.AddedCode
	s.ModifiedCode += other.ModifiedCode
	s.DeletedCode += other.DeletedCode
	s.AddedComment += other.AddedComment
	s.DeletedComment += other.DeletedComment
	s.Whitespace += other.Whitespace
	s.Blank += other.Blank
	s.Unknown += other.Unknown
}

// Total is the number of line slots the change touched, across every
// bucket. Zero means the change contributed nothing countable.
func (s Stats) Total() int {
	return s.AddedCode + s.ModifiedCode + s.DeletedCode +
		s.AddedComment + s.DeletedComment +
		s.Whitespace + s.Blank + s.Unknown
}

// Op is the kind of a diff hunk.
type Op uint8

// The diff ops. OpEqual covers lines that pair up after whitespace
// normalization — Count decides from the raw text whether such a pair is
// untouched or a whitespace-only change.
const (
	OpEqual Op = iota
	OpDelete
	OpInsert
)

// String renders an Op for test failures.
func (o Op) String() string {
	switch o {
	case OpDelete:
		return "delete"
	case OpInsert:
		return "insert"
	default:
		return "equal"
	}
}

// Hunk is one aligned region produced by Diff. Indices are half-open
// into the line slices Diff was given.
//
// For OpEqual, OldEnd-OldStart == NewEnd-NewStart and the i-th old line
// pairs with the i-th new line. For OpDelete, NewStart == NewEnd; for
// OpInsert, OldStart == OldEnd.
type Hunk struct {
	Op       Op
	OldStart int
	OldEnd   int
	NewStart int
	NewEnd   int
}

// Shape names the input shape the ladder matched for one file. It is
// recorded so a count can always be traced back to the parser that
// produced it, and so the ladder's coverage over a live corpus is
// measurable.
type Shape string

// The shapes of the input ladder (plan §3.1). One golden per shape.
const (
	ShapeOldNewString   Shape = "old_string/new_string" // claude-code, gemini, cowork, command-code
	ShapeOldNewCamel    Shape = "oldString/newString"   // opencode
	ShapeOldNewSnakeAbb Shape = "old_str/new_str"       // copilot-cli
	ShapeEdits          Shape = "edits[]"               // MultiEdit
	ShapeNewSource      Shape = "new_source"            // NotebookEdit
	ShapeContent        Shape = "content"               // Write
	ShapeFileText       Shape = "file_text"             // goose developer-extension write
	ShapeSearchReplace  Shape = "search_replace"        // cline/kilo replace_in_file diff blocks
	ShapeCodexChanges   Shape = "codex_changes"         // patch_apply_end changes map
	ShapeCodexPatch     Shape = "codex_begin_patch"     // bare *** Begin Patch envelope
	ShapeCodexJS        Shape = "codex_js_wrapper"      // unified-exec JS program
	ShapePlainContent   Shape = "plain_content"         // junie: bare after-content text
	ShapePathOnly       Shape = "path_only"             // cursor afterFileEdit hook
	ShapeTruncated      Shape = "truncated"             // …[truncated] marker
	ShapeUnrecognized   Shape = "unrecognized"          // parsed as JSON but no known keys
)

// FileStats is loc's per-file result: one row's worth of counts for one
// file touched by one action.
type FileStats struct {
	// Path is the path exactly as the tool reported it — absolute for
	// claude-code, often project-relative for codex, and on a foreign OS
	// for a cross-mount session. The CALLER normalizes it to
	// project-relative and hashes it (plan §2); loc never hashes a path
	// itself because only the caller knows the project root.
	Path string
	// Lang and Category come from Language(Path).
	Lang     Lang
	Category Category
	// Stats is the bucket set. It is the zero value for a file whose
	// Category is not Counted.
	Stats Stats
	// Confidence grades the whole file result.
	Confidence Confidence
	// Shape is the ladder row that produced this result.
	Shape Shape
	// InputDigest is sha256(normalized per-file patch text), hex. Codex
	// emits the same patch twice — once as the model's invocation and
	// once as the executor's result — and the store collapses the pair
	// on (session_id, file_path_hash, input_digest).
	InputDigest string
	// DeletedFile marks a file the change removed entirely. Its deleted
	// lines are Unknown unless the input carried the removed body.
	DeletedFile bool
	// Overwrite marks a whole-content write over a file that already
	// existed, where the before-image is a reconstructed line count
	// rather than text. The UI must label these.
	Overwrite bool
	// NewFile marks a whole-content write that created the file.
	NewFile bool
}

// Input is one edit/write action, as the store seam hands it to Extract.
type Input struct {
	// RawToolInput is the already-scrubbed, already-capped
	// actions.raw_tool_input value. Extract never re-scrubs it and never
	// stores it.
	RawToolInput string
	// ActionType is models.ActionEditFile or models.ActionWriteFile.
	// Extract takes it as a plain string so loc need not import
	// internal/models.
	ActionType string
	// Target is the action's target path, used to disambiguate a
	// path-only hook row and to name a file whose payload carries none.
	Target string
	// BeforeLines, when >= 0, is a before-image LINE COUNT for a
	// whole-content write, recovered by the caller from the preceding
	// read of the same file. -1 means "not known".
	BeforeLines int
	// Existed reports whether the store already knew the file (a
	// file_state row exists). It separates a new file (NewFile, high
	// confidence) from an overwrite (Overwrite, medium at best).
	Existed bool
}
