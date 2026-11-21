// Package secreach is the reachability RANKING of dependency findings
// (security plan 2026-11-04 section 14.5): items 3a and 3c, the import
// level and the approximate Rust call level, and item 3b's symbol level
// (symbol.go). For 3a, given one
// dependency finding's advisory data (the OSV ecosystem, the package and,
// per record, the affected import paths or functions) and the project's
// import list, it returns a Tier: "called" (Rust only, approximate),
// "imported", "not_imported_directly" or "unknown", with the source the
// tier rests on ("go imports", "codeintel", "codeintel-rust-callsite") for
// the label.
//
// The rule it exists to keep (ruling Q14-4): a tier RANKS and LABELS a
// finding; it never closes, hides or downgrades one, and the posture's
// severity and the commit gate do not read it in v1. "not_imported_directly"
// never reads "unreachable": the import list is the project's own code only,
// so a package reached through another dependency is invisible here. Nothing
// ever reads "not called".
//
// Ecosystems (ecosystemRows): Go (exact, against the records' import
// paths or the module path), npm (the package name each JavaScript or
// TypeScript specifier names, jsKeyRules), PyPI (the module paths a
// distribution installs: the project's installed metadata, else the
// built-in table pythonDistModules, else the distribution's own name as an
// approximate positive only; an unknown mapping is "unknown", never "not
// imported") and crates.io (the crate a use declaration names; a name
// matched call of a function a RUSTSEC record lists is an approximate
// "called", rustCallRules; a crate in no use declaration is "unknown",
// because the index holds no other Rust path).
//
// It is PURE (CLAUDE.md "Module Boundaries" rule 1): no database/sql, no
// net/http, no os, no os/exec, no fsnotify (imports_test.go). The import
// list is built outside, at one seam (internal/secreachsvc: an imports-only
// parse of the project's .go files, or the codeintel index, plus capped
// reads of installed Python metadata), and handed in as an ImportSet; the
// metadata bytes are parsed here (PythonModulesFromRecord,
// PythonModulesFromTopLevel).
//
// Decision logic is table-driven (rule 5): the ecosystem mapping is one
// table (ecosystemRows; an ecosystem without a row is "unknown"), the Go
// per-record rules one ordered table (goRecordRules), the specifier rules
// one table per language (keyRulesByLang), the test-file convention one
// table (testFileRows), the Rust call rules one table (rustCallRules) and
// the unknown reasons one table (reasonText), each walked top-down. Nothing
// is guessed silently: no import data, an incomplete import list, no
// advisory record (Go) or an unknown name mapping each yield "unknown" with
// a reason, never "not_imported_directly", and a heuristic match carries
// Tier.Approximate.
//
// Item 3b (symbol.go, spike RG-0) adds two tiers, "called" and "not_called"
// (sources "govulncheck-binary" and "govulncheck-source"), and two tables:
// symbolRules, Observer's own reading of one govulncheck result for one
// (record, module), and applyRules, which combines the stored symbol checks
// with the 3a tier at view time so a result applies only to the build it
// covered. "not_called" ranks below unknown and never reads "unreachable".
package secreach
