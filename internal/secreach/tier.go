package secreach

import (
	"sort"
	"strings"
)

// Level is the closed tier vocabulary of section 14.5.
type Level string

// The tiers. "called" comes from the exact Go symbol check (3b,
// symbol.go) or the approximate Rust call-site match (3c, Tier.Approximate
// set); NotCalled is 3b's; PotentiallyAffected is the one tier a build
// artifact has before a symbol check.
const (
	// Called: project code calls a function the advisory lists. From the
	// Rust call-site match it is approximate (a name match, not a resolved
	// call), and nothing ever reads "not called".
	Called Level = "called"
	// Imported: project code imports the affected package (or, for an
	// advisory that lists no import paths, a package of the affected
	// module).
	Imported Level = "imported"
	// NotImportedDirectly: no project file imports the affected package.
	// It may still be reached through another dependency; never read it as
	// "unreachable".
	NotImportedDirectly Level = "not_imported_directly"
	// Unknown: not checked (no import data, an ecosystem without a
	// mapping, an incomplete import list, no advisory record).
	Unknown Level = "unknown"
	// PotentiallyAffected: the finding is a Go binary's embedded standard
	// library, matched by the Go release in the binary's build info (item 4
	// Go stdlib, operator ruling 2026-11-05 (d)). It says the binary was
	// built with an affected release; it says nothing about whether the
	// binary reaches the affected code, so it is a label and a ranking,
	// never a severity change. Only symbol evidence (3b-bin, BinaryEvidence)
	// moves it, and a stripped binary stays Unknown.
	PotentiallyAffected Level = "potentially_affected"
	// NotCalled (3b): a symbol list was checked against this finding's
	// binary (or go.mod) and no listed function is reachable there. Tests,
	// other build tags and other platforms are outside the check; never
	// read it as "unreachable".
	NotCalled Level = "not_called"
)

// Sources a tier rests on (Tier.Source, ImportSet.Source).
const (
	// SourceGoImports: the imports-only parse of the project's .go files.
	SourceGoImports = "go imports"
	// SourceCodeIntel: the imports the project's codeintel index holds.
	SourceCodeIntel = "codeintel"
	// SourceGoBuildinfo: the Go release a binary's build info names (a
	// PotentiallyAffected tier).
	SourceGoBuildinfo = "go-buildinfo"
	// SourceRustCallSite: a codeintel Rust call site whose callee name
	// matches a function a RUSTSEC record lists (approximate).
	SourceRustCallSite = "codeintel-rust-callsite"
	// SourceGovulncheckBinary: govulncheck -mode binary over a Go binary
	// the project built (3b-bin).
	SourceGovulncheckBinary = "govulncheck-binary"
	// SourceGovulncheckSource: govulncheck's call analysis over one go.mod
	// (3b-src, through osv-scanner).
	SourceGovulncheckSource = "govulncheck-source"
)

// Reason says why a tier is Unknown (closed vocabulary; "" for a decided
// tier).
type Reason string

// The unknown reasons.
const (
	// ReasonNoImportData: no import list for the ecosystem's language.
	ReasonNoImportData Reason = "no_import_data"
	// ReasonNoMapping: the ecosystem has no import mapping (yet).
	ReasonNoMapping Reason = "no_import_mapping"
	// ReasonNoAdvisory: no advisory record naming the package was read.
	ReasonNoAdvisory Reason = "no_advisory_record"
	// ReasonIncomplete: the import list is incomplete (a bound was hit, a
	// file did not parse), so an absent import proves nothing.
	ReasonIncomplete Reason = "import_list_incomplete"
	// ReasonNotALibrary: the affected package is not an importable library
	// (the Go toolchain).
	ReasonNotALibrary Reason = "not_a_library"
	// ReasonNoArtifactMapping: a build artifact of an ecosystem with no
	// artifact rule.
	ReasonNoArtifactMapping Reason = "no_artifact_mapping"
	// ReasonNoCodeIntel: the codeintel index holds no indexed source file
	// of the language (codeintel off, the project not indexed, or no file
	// of the language). JavaScript, TypeScript, Python and Rust import
	// lists come from the index only.
	ReasonNoCodeIntel Reason = "no_codeintel_index"
	// ReasonNoNameMapping: the Python distribution's import names are not
	// known (no installed metadata, no built-in row) and its name as a
	// module is not imported, so absence proves nothing.
	ReasonNoNameMapping Reason = "no_name_mapping"
	// ReasonUseOnly: the Rust crate is in no `use` declaration; codeintel
	// does not index paths written elsewhere (types, macros, fully
	// qualified expressions), so absence proves nothing.
	ReasonUseOnly Reason = "rust_use_only"
	// ReasonPending: the project's import list is still being built in the
	// background (a view that does not wait for a cold parse, such as the
	// Code security findings list); ask again shortly. View-time only, never
	// stored.
	ReasonPending Reason = "reach_pending"
)

// reasonText is the label text of each unknown reason.
var reasonText = map[Reason]string{
	ReasonNoImportData: "no import data",
	ReasonNoMapping:    "no import mapping for this ecosystem",
	ReasonNoAdvisory:   "advisory not in the local database",
	ReasonIncomplete:   "import list incomplete",
	ReasonNotALibrary:  "the Go toolchain, not an import",
	// ReasonNoArtifactMapping is not a missing import list: the artifact
	// has no rule for its ecosystem.
	ReasonNoArtifactMapping: "no rule for this kind of build artifact",
	ReasonNoCodeIntel:       "no code intelligence index for this language",
	ReasonNoNameMapping:     "import name of this distribution not known",
	ReasonUseOnly:           "crate in no use declaration; other paths are not indexed",
	ReasonPending:           "still being checked",
	// The symbol check's (symbol.go).
	ReasonStripped:          "stripped binary",
	ReasonSymbolCheckFailed: "the check failed",
	ReasonOutOfMemory:       "ran out of memory: not checked",
	ReasonTimedOut:          "timed out: not checked",
	ReasonNoToolchain:       "no Go toolchain",
	ReasonUnsupportedBinary: "binary format not supported",
	ReasonBinaryCap:         "more binaries than one scan checks",
	ReasonModuleCap:         "more go.mod files than one source check runs",
	ReasonToolchainTooOld:   "the go.mod needs a newer Go than the local toolchain",
	ReasonModulesMissing:    "a required module is not downloaded",
}

// Text is the reason in words ("stripped binary"); "" for an unknown one.
func (r Reason) Text() string { return reasonText[r] }

// Tier is one finding's reachability tier, its source and why.
type Tier struct {
	Level Level
	// Source is SourceGoImports, SourceCodeIntel or SourceRustCallSite
	// for a decided tier, "" when nothing was checked.
	Source string
	// TestsOnly: Imported or Called, but only from test files (_test.go,
	// and the per-language test-file table, testFileRows).
	TestsOnly bool
	// Approximate: the decision rests on a name heuristic, not an exact
	// match (a Rust call site matched by callee name; a Python module
	// matched by the distribution's own name with no known mapping).
	Approximate bool
	// Match is what decided the tier: the project import (Imported) or
	// the advisory's function path (Called); "" else.
	Match string
	// Reason says why the tier is Unknown.
	Reason Reason
	// Target is the project-relative binary or go.mod a 3b tier (Called,
	// NotCalled) rests on; "" for a 3a tier.
	Target string
	// SymbolNote, on a 3a tier, says why a symbol check that covered the
	// finding could not decide (a stripped binary, a failed run); "" when
	// none did. It never changes the tier or its rank.
	SymbolNote Reason
	// AssumedGo, on a source-mode 3b tier of the standard library, is the
	// Go release the check evaluated it at (the go.mod's toolchain or go
	// line, not the Go that builds); "" otherwise.
	AssumedGo string
}

// UnknownTier is the Unknown tier for reason r.
func UnknownTier(r Reason) Tier { return Tier{Level: Unknown, Reason: r} }

// Label is the tier as a finding view shows it, with its source:
// "imported (go imports)", "imported, tests only (codeintel)",
// "called, approximate (codeintel-rust-callsite)",
// "potentially affected (go-buildinfo)",
// "not imported directly (go imports)", "unknown (import list incomplete)",
// "called: jwt.Parse (govulncheck-binary, bin/app)",
// "not called (govulncheck-binary, bin/app)"; a tier a symbol check could
// not decide adds "; symbol check unknown: stripped binary"; a source-mode
// standard library tier adds "; stdlib at go1.27.0 from the go.mod".
func (t Tier) Label() string {
	return t.label() + t.noteText() + t.assumedText()
}

// assumedText names the Go release a source-mode stdlib tier assumed.
func (t Tier) assumedText() string {
	if t.AssumedGo == "" || (t.Level != Called && t.Level != NotCalled) {
		return ""
	}
	v := t.AssumedGo
	if !strings.HasPrefix(v, "go") {
		v = "go" + v
	}
	return "; stdlib at " + v + " from the go.mod, not the Go that builds it"
}

func (t Tier) label() string {
	src := ""
	if t.Source != "" {
		src = " (" + t.Source + ")"
	}
	if t.Target != "" && t.Source != "" {
		src = " (" + t.Source + ", " + t.Target + ")"
	}
	qual := ""
	if t.TestsOnly {
		qual += ", tests only"
	}
	if t.Approximate {
		qual += ", approximate"
	}
	switch t.Level {
	case Called:
		// A 3b tier (Target set) names the reachable function; the
		// approximate Rust match (3c) does not.
		if t.Target != "" && t.Match != "" {
			return "called: " + t.Match + qual + src
		}
		return "called" + qual + src
	case NotCalled:
		return "not called" + src
	case Imported:
		return "imported" + qual + src
	case PotentiallyAffected:
		return "potentially affected" + src
	case NotImportedDirectly:
		return "not imported directly" + src
	}
	if txt, ok := reasonText[t.Reason]; ok {
		return "unknown (" + txt + ")"
	}
	return "unknown"
}

func (t Tier) noteText() string {
	if t.SymbolNote == "" || t.Level == Called || t.Level == NotCalled {
		return ""
	}
	if txt, ok := reasonText[t.SymbolNote]; ok {
		return "; symbol check unknown: " + txt
	}
	return "; symbol check unknown"
}

// SortRank orders findings for a list (higher first): Called 7, Imported
// 6, Called tests only 5, Imported tests only 4, PotentiallyAffected 3,
// Unknown 2, NotCalled 1, NotImportedDirectly 0. A binary's
// PotentiallyAffected sits under every import or call the project's own
// code makes (a direct use is stronger evidence than a version match) and
// over Unknown (the embedded release is known to be affected). NotCalled
// ranks below imported (a listed function was checked and is not
// reachable in the covered build) and, like NotImportedDirectly, below
// unknown (evidence of absence ranks under an unchecked finding). It is a
// ranking only (ruling Q14-4): it never closes, hides or re-grades a
// finding.
func (t Tier) SortRank() int {
	switch t.Level {
	case Called:
		if t.TestsOnly {
			return 5
		}
		return 7
	case Imported:
		if t.TestsOnly {
			return 4
		}
		return 6
	case PotentiallyAffected:
		return 3
	case NotCalled:
		return 1
	case NotImportedDirectly:
		return 0
	}
	return 2
}

// Advisory is the advisory data of one dependency finding: the OSV
// ecosystem ("Go", "npm", "PyPI", "crates.io"), the package (a Go module
// path, or "stdlib" / "toolchain"; an npm, PyPI or crate name) and the
// records that name the package.
type Advisory struct {
	Ecosystem string
	Package   string
	Records   []Record
	// Artifact: the finding was read out of a build artifact (a Go
	// binary's build info), not a dependency file, so there is no import
	// list to decide it against (ClassifyArtifact).
	Artifact bool
}

// Record is one OSV record's affected import paths for the package (Go:
// affected[].ecosystem_specific.imports[].path of the entries naming the
// package) and affected functions (RUSTSEC:
// affected[].ecosystem_specific.affects.functions, "crate::Type::fn");
// each empty when the record lists none.
type Record struct {
	ID          string
	ImportPaths []string
	Functions   []string
}

// Use is how project code uses one import path.
type Use struct {
	// NonTest: imported by at least one non-test file.
	NonTest bool
	// Test: imported by at least one test file (_test.go).
	Test bool
}

// ImportSet is one language's project import list.
type ImportSet struct {
	// Source is SourceGoImports or SourceCodeIntel.
	Source string
	// Complete: every in-scope file was read and parsed. An incomplete set
	// can prove Imported, never NotImportedDirectly.
	Complete bool
	// Uses maps an import key to its use. The key is the language's
	// (ImportKey): a Go import path, an npm package name, a Python dotted
	// module path, a Rust crate name ("-" as "_").
	Uses map[string]Use
	// Provides maps a PEP 503 normalised Python distribution name to the
	// module paths it installs, read from the project's installed metadata
	// (a RECORD or top_level.txt; PythonModulesFromRecord). It wins over
	// the built-in table. Python only, optional.
	Provides map[string][]string
	// Calls are call sites of the project whose callee name one of the
	// findings' listed functions ends with (Rust only); CallsRead reports
	// that they were read (false: the call level is not checked).
	Calls     []Call
	CallsRead bool
	// FileImports maps a project file to the import keys its own import
	// sites name (Rust: the crates a file's use declarations name), for
	// the per-file call rule. Optional.
	FileImports map[string][]string
	// Modules are the module paths of the build graph (Go: go.mod's module
	// and requires, go.sum's modules), used to tell a nested module from a
	// package of the affected module. Optional.
	Modules []string
}

// Call is one call site of project code (Rust): the file, the callee
// name, a bounded excerpt of the call expression from its start (the
// qualified path, if any, is read from it) and whether the file is a test
// file.
type Call struct {
	File string
	Name string
	Text string
	Test bool
}

// sortedPaths is the import paths in a stable order (Match is
// deterministic).
func (s ImportSet) sortedPaths() []string {
	out := make([]string, 0, len(s.Uses))
	for p := range s.Uses {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
