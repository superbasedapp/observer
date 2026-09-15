package loc

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Table export for non-Go consumers (plan §3.3, review disposition m7).
//
// WHY THIS EXISTS. The VS Code extension has to classify a human's saved
// lines the SAME way the daemon classifies an agent's, or the two halves
// of "AI vs human" are measured with different rulers and the comparison
// is meaningless. Two hand-maintained tables in two languages drift; one
// table exported from its single Go owner and consumed by both does not.
//
// The Go tables here are the ONE owner. `internal/loc.MarshalTables`
// serializes them; the extension consumes the committed JSON; and
// TestClassifierTablesJSONIsCurrent fails when the committed file no
// longer matches what Go would emit, so drift is loud at test time rather
// than silent in the numbers.
//
// The export deliberately carries the DATA, not the algorithm: extension
// and daemon each implement the same documented rules over the same
// tables. A rule change is therefore a code change on both sides — which
// is the honest cost of having a classifier in two runtimes at all.

// TablesVersion is bumped whenever the EXPORTED SHAPE changes (a new
// field, a renamed key), independently of Version, which tracks whether
// counts change. A consumer that reads a shape it does not know must
// degrade rather than guess.
const TablesVersion = 1

// ExportedTables is the serialized classifier table set.
type ExportedTables struct {
	// TablesVersion is the shape version (see TablesVersion).
	TablesVersion int `json:"tables_version"`
	// ClassifierVersion is loc.Version — the version any counts produced
	// with these tables must be stamped with.
	ClassifierVersion int `json:"classifier_version"`

	// Extensions maps a lowercased extension WITHOUT its leading dot
	// ("go", "tsx", "yaml") to a language/category pair. The consumer
	// strips the dot before looking up.
	Extensions map[string]ExportedLangEntry `json:"extensions"`
	// Basenames maps a whole lowercased basename (Makefile, go.mod,
	// CMakeLists.txt) to a language/category pair. It is consulted
	// BEFORE Extensions.
	Basenames map[string]ExportedLangEntry `json:"basenames"`

	// VendoredSegments are path segments matched case-INSENSITIVELY that
	// make a file vendored.
	VendoredSegments []string `json:"vendored_segments"`
	// VendoredSegmentsExact are matched case-SENSITIVELY (CocoaPods'
	// `Pods`, where a lowercase `pods/` is plausibly real code).
	VendoredSegmentsExact []string `json:"vendored_segments_exact"`
	// GeneratedSegments are path segments that make a file generated.
	GeneratedSegments []string `json:"generated_segments"`
	// GeneratedSuffixes are basename suffixes (".pb.go", ".min.js").
	GeneratedSuffixes []string `json:"generated_suffixes"`
	// LockfileBasenames are whole basenames that are always generated.
	LockfileBasenames []string `json:"lockfile_basenames"`
	// BinaryExtensions are extensions whose files are never counted.
	BinaryExtensions []string `json:"binary_extensions"`

	// Lex is the per-language token table.
	Lex map[string]ExportedLangTokens `json:"lex"`
}

// ExportedLangEntry is a language/category pair.
type ExportedLangEntry struct {
	Lang     string `json:"lang"`
	Category string `json:"category"`
}

// ExportedLangTokens is one language's lexer row.
type ExportedLangTokens struct {
	LineComments []string              `json:"line_comments,omitempty"`
	AnchoredLine []string              `json:"anchored_line,omitempty"`
	Blocks       []ExportedBlockPair   `json:"blocks,omitempty"`
	Strings      []ExportedStringDelim `json:"strings,omitempty"`
	// Heredoc is "", "shell" or "php".
	Heredoc string `json:"heredoc,omitempty"`
}

// ExportedBlockPair is a block-comment delimiter pair.
type ExportedBlockPair struct {
	Open        string `json:"open"`
	Close       string `json:"close"`
	Anchored    bool   `json:"anchored,omitempty"`
	DetectStray bool   `json:"detect_stray,omitempty"`
}

// ExportedStringDelim is a string-literal delimiter.
type ExportedStringDelim struct {
	Open      string `json:"open"`
	Close     string `json:"close"`
	Multiline bool   `json:"multiline,omitempty"`
	Escape    bool   `json:"escape,omitempty"`
	Docstring bool   `json:"docstring,omitempty"`
}

// heredocNames maps the internal heredoc enum onto its exported spelling.
var heredocNames = map[heredocKind]string{
	heredocNone:  "",
	heredocShell: "shell",
	heredocPHP:   "php",
}

// Tables returns the classifier tables in their exported shape.
func Tables() ExportedTables {
	out := ExportedTables{
		TablesVersion:         TablesVersion,
		ClassifierVersion:     Version,
		Extensions:            make(map[string]ExportedLangEntry, len(languageTable)),
		Basenames:             make(map[string]ExportedLangEntry, len(basenameTable)),
		VendoredSegments:      sortedSetKeys(vendoredSegments),
		VendoredSegmentsExact: sortedSetKeys(vendoredSegmentsExact),
		GeneratedSegments:     sortedSetKeys(generatedSegments),
		GeneratedSuffixes:     copySlice(generatedSuffixes),
		LockfileBasenames:     sortedSetKeys(lockfileBasenames),
		BinaryExtensions:      sortedSetKeys(binaryExtensions),
		Lex:                   make(map[string]ExportedLangTokens, len(lexTable)),
	}
	for ext, e := range languageTable {
		out.Extensions[ext] = ExportedLangEntry{Lang: string(e.lang), Category: string(e.cat)}
	}
	for base, e := range basenameTable {
		out.Basenames[base] = ExportedLangEntry{Lang: string(e.lang), Category: string(e.cat)}
	}
	for lang, tok := range lexTable {
		// The token SLICES keep their runtime order, deliberately: a
		// consumer must try them in the same order Go does, or two
		// line-comment tokens where one is a prefix of the other could
		// classify a line differently in the two runtimes. Only
		// SET-derived lists below are sorted, and those are sorted
		// because Go map iteration is unordered, not because order is
		// meaningless there.
		row := ExportedLangTokens{
			LineComments: copySlice(tok.lineComments),
			AnchoredLine: copySlice(tok.anchoredLine),
			Heredoc:      heredocNames[tok.heredoc],
		}
		for _, b := range tok.blocks {
			row.Blocks = append(row.Blocks, ExportedBlockPair{
				Open: b.open, Close: b.close,
				Anchored: b.anchored, DetectStray: b.detectStray,
			})
		}
		for _, sd := range tok.strings {
			row.Strings = append(row.Strings, ExportedStringDelim{
				Open: sd.open, Close: sd.close,
				Multiline: sd.multiline, Escape: sd.escape, Docstring: sd.docstring,
			})
		}
		out.Lex[string(lang)] = row
	}
	return out
}

// MarshalTables renders the classifier tables as the exact bytes the
// committed JSON file must contain: indented with two spaces and
// newline-terminated, so a regeneration produces a clean diff and the
// drift test can compare bytes rather than re-parsing.
func MarshalTables() ([]byte, error) {
	body, err := json.MarshalIndent(Tables(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("loc.MarshalTables: %w", err)
	}
	return append(body, '\n'), nil
}

// sortedSetKeys returns a set's keys in a stable order. Map iteration is
// unordered, and an unordered export would make the committed JSON churn
// on every regeneration.
func sortedSetKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// copySlice returns a copy of a slice in its ORIGINAL order, leaving the
// source table untouched. Ordered token lists are exported verbatim: see
// the note in Tables.
func copySlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return append([]string(nil), in...)
}
